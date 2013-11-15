package main

import (
	"code.google.com/p/go.crypto/nacl/secretbox"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"time"
	"bytes"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"

	"code.google.com/p/goprotobuf/proto"
	"github.com/andres-erbsen/sgp"
)

const TICK_INTERVAL = 10*time.Second
const S2S_PORT = "6362"

type Dename struct {
	db             *sql.DB
	our_sk         sgp.SecretKey
	our_index      int
	our_ip         string
	addr2peer      map[string]*Peer
	peer_broadcast chan []byte
	peer_connected chan net.Conn
	peer_lnr       *net.TCPListener
	client_lnr     net.Listener
}

func (dn *Dename) CreateTables() {
	db := dn.db
	_, err := db.Exec(`PRAGMA foreign_keys = ON;`)
	if err != nil {
		log.Fatal("Cannot PRAGMA foreign_keys = ON: ", err)
	}

	// servers
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS servers (
		id integer not null primary key);`)
	if err != nil {
		log.Fatal("Cannot create table servers: ", err)
	}

	// rounds
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS rounds (
		id integer not null primary key);`)
	if err != nil {
		log.Fatal("Cannot create table rounds: ", err)
	}

	// round_keys
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS round_keys (
		id integer not null primary key,
		round integer not null,
		server integer not null,
		key blob not null,
		FOREIGN KEY(round) REFERENCES rounds(id),
		FOREIGN KEY(server) REFERENCES servers(id));`)
	if err != nil {
		log.Fatal("Cannot create table round_keys: ", err)
	}

	// transaction_queue
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS transaction_queue (
		id integer not null primary key autoincrement,
		round integer not null,
		introducer integer not null,
		request blob not null,
		FOREIGN KEY(round) REFERENCES rounds(id),
		FOREIGN KEY(introducer) REFERENCES servers(id));`)
	if err != nil {
		log.Fatal("Cannot create table transaction_queue: ", err)
	}

	// commitments
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS commitments (
		id integer not null primary key,
		round integer not null,
		commiter integer not null,
		acknowledger integer not null,
		signature blob not null,
		FOREIGN KEY(round) REFERENCES rounds(id),
		FOREIGN KEY(commiter) REFERENCES servers(id),
		FOREIGN KEY(acknowledger) REFERENCES servers(id));`)
	if err != nil {
		log.Fatal("Cannot create table commitments: ", err)
	}

	// name_mapping
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS name_mapping (
		id integer not null primary key,
		name blob not null,
		pubkey blob not null);`)
	if err != nil {
		log.Fatal("Cannot create table name_mapping: ", err)
	}
}

func (dn *Dename) HandleClient(conn net.Conn) {
	db := dn.db
	defer conn.Close()
	rq_bs, err := ioutil.ReadAll(conn)
	if err != nil {
		return
	}

	signed_rq := &sgp.Signed{}
	err = proto.Unmarshal(rq_bs, signed_rq)
	if err != nil {
		return
	}

	new_mapping := &sgp.Attribution{}
	err = proto.Unmarshal(signed_rq.Message, new_mapping)
	if err != nil {
		return
	}

	new_pk := &sgp.Entity{}
	err = new_pk.Parse(new_mapping.Pubkey)
	if err != nil {
		return
	}

	var pk_bytes []byte
	pk := &sgp.Entity{}
	err = db.QueryRow("SELECT pubkey FROM name_mapping WHERE name = ?", new_mapping.Name).Scan(&pk_bytes)
	if err == nil {
		err = pk.Parse(pk_bytes)
		if err != nil {
			log.Fatal("Bad pk in database", err)
		}
	} else if err == sql.ErrNoRows {
		// new name being claimed
		pk = new_pk
	} else {
		log.Fatal(err) // FIXME: check error type
	}

	if !pk.Verify(signed_rq) {
		return
	}
	log.Print("valid transfer of \"", string(new_mapping.Name), "\"")

	// Look up the key we use to encrypt this round's queue messages
	var key_slice []byte
	var round int
	err = db.QueryRow("SELECT round,key FROM round_keys WHERE server = ? ORDER BY id DESC LIMIT 1;", dn.our_index).Scan(&round, &key_slice)
	if err != nil {
		log.Fatal("Cannot get latest round key: ", err)
	}
	key := new([32]byte)
	copy(key[:], key_slice)

	nonce := new([24]byte)
	_, err = io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		log.Fatal(err)
	}

	var rq_box []byte
	rq_box = secretbox.Seal(rq_box[:0], rq_bs, nonce, key)
	rq_box = append(rq_box, nonce[:]...)
	_, err = db.Exec("INSERT INTO transaction_queue(round,introducer,request) VALUES(?,?,?);",
		round, dn.our_index, rq_box)
	if err != nil {
		log.Print(round, dn.our_index, rq_box)
		log.Fatal("Cannot insert new transaction to queue: ", err)
	}
	dn.peer_broadcast <- append([]byte{1}, rq_box...)
}

type Peer struct {
	index int
	addr  string
	pk    *sgp.Entity
	conn  net.Conn
}

func (dn *Dename) HandleMessage(peer *Peer, msg []byte) (err error) {
	log.Print("Received ", len(msg), " bytes from ", peer.addr)
	if msg[0] == 1 {
		_, err = dn.db.Exec("INSERT INTO transaction_queue(round,introducer,request) VALUES(?,?,?);", round, peer.index, msg[1:])
		if err != nil {
			log.Fatal("Cannot insert new transaction to queue: ", err)
		}
	}
	return nil
}

func (dn *Dename) ReceiveLoop(peer *Peer) (err error) {
	conn := peer.conn
	for {
		err = nil
		sz := 2
		n := 0
		nn := 0
		buf := make([]byte, 1600)
		for err == nil && n < sz {
			nn, err = conn.Read(buf[n:sz])
			// log.Print("Read ", nn, " bytes from ", peer.addr)
			n += nn
			if n == 2 {
				sz = 2 + (int(buf[0]) | (int(buf[1]) << 8))
			}
		}
		if err != nil {
			conn.Close()
			if err == io.EOF {
				// the other end closed the connection, not us in HandleConnection
				// FIXME: ensure thread-safety by a non-hack
				log.Print("peer: ", peer.addr, " connection lost: ", conn)
				peer.conn = nil
			}
			return err
		}
		go dn.HandleMessage(peer, buf[2:sz])
	}
	return nil
}

func (dn *Dename) HandleConnection(peer *Peer, conn net.Conn) error {
	rport := strings.SplitN(conn.RemoteAddr().String(), ":", 2)[1]
	new_is_better := true
	log.Print("peer: ", peer.addr, " old conn: ", peer.conn, " new: ", conn)
	if peer.conn != nil {
		// keep the connection where the client has the lower pk
		if rport == S2S_PORT {
			new_is_better = bytes.Compare(dn.our_sk.Entity.Bytes, peer.pk.Bytes) < 0
		} else { // they started the new connection
			new_is_better = bytes.Compare(dn.our_sk.Entity.Bytes, peer.pk.Bytes) >= 0
		}
	}
	if !new_is_better {
		return conn.Close()
	}
	if peer.conn != nil {
		peer.conn.Close() // kills the old ReceiveLoop with errClosed (not EOF)
	}
	peer.conn = conn
	go dn.ReceiveLoop(peer)
	return nil
}

func (dn *Dename) ListenForPeers() {
	for {
		conn, err := dn.peer_lnr.AcceptTCP()
		if err == nil {
			conn.SetNoDelay(false)
			// TODO: create a new goroutine that sends all the old updates and blocks, only then add to the set of normal peers
			dn.peer_connected <- conn
		} else {
			log.Print(err)
		}
	}
}

func (dn *Dename) ListenForClients() {
	for {
		conn, _ := dn.client_lnr.Accept()
		go dn.HandleClient(conn)
	}
}

func (dn *Dename) HandleAllPeers() {
	for {
		select {
		case conn := <-dn.peer_connected:
			raddr := strings.SplitN(conn.RemoteAddr().String(), ":", 2)[0]
			peer := dn.addr2peer[raddr]
			if peer == nil {
				log.Print(raddr, " is not our friend")
				continue
			}
			dn.HandleConnection(peer, conn)
		case msg := <-dn.peer_broadcast:
			log.Print("broadcast ", len(msg), " bytes")
			for _, peer := range dn.addr2peer {
				conn := peer.conn
				if conn == nil {
					continue
				}
				buf := make([]byte, 2+len(msg))
				buf[0] = byte(len(msg) & 0x00ff)
				buf[1] = byte((len(msg) >> 8) & 0xff)
				copy(buf[2:], msg)
				_, err := conn.Write(buf)
				if err != nil {
					log.Print(err)
				}
			}
		}
	}
}

func (dn *Dename) Tick() (err error) {
	var key_slice []byte
	var round int
	err = dn.db.QueryRow("SELECT round,key FROM round_keys WHERE server = ? ORDER BY id DESC LIMIT 1;", dn.our_index).Scan(&round, &key_slice)
	if err != nil {
		log.Fatal("Cannot get latest round key: ", err)
	}
	dn.peer_broadcast <- append([]byte{2}, key_slice...)
	return nil
}

func (dn *Dename) WaitForTicks() {
	var planned_next time.Time
	for {
		t := time.Now()
		next := t.Add(TICK_INTERVAL).Truncate(TICK_INTERVAL)
		if next != planned_next { // `planned_next` just passed
			go dn.Tick()
		}
		planned_next = next
		time.Sleep(planned_next.Sub(t))		
	}
}

func main() {
	var err error
	dn := &Dename{our_ip: "0.0.0.0",
		our_index:      -1,
		addr2peer:      make(map[string]*Peer),
		peer_broadcast: make(chan []byte),
		peer_connected: make(chan net.Conn, 100)}
	if len(os.Args) >= 2 {
		dn.our_ip = os.Args[1]
	}
	dn.db, err = sql.Open("sqlite3", "dename.db")
	if err != nil {
		log.Fatal("Cannot open dename.db", err)
	}
	defer dn.db.Close()
	dn.CreateTables()

	dn.our_sk, err = sgp.LoadSecretKeyFromFile("sk")
	if err != nil {
		log.Fatal("Cannot load secret key from \"sk\"", err)
	}

	peersfile, err := os.Open("peers.txt")
	if err != nil {
		log.Fatal("Cannot open peers.txt", err)
	}

	// TODO: "infinite size"
	for i := 0; ; i++ {
		var host, pk_type, pk_b64 string
		_, err := fmt.Fscanf(peersfile, "%s %s %s\n", &host, &pk_type, &pk_b64)
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal("Syntax error in peers.txt on line ", i, ":", err)
		}
		if pk_type != "sgp" {
			log.Fatal("pk_type != sgp in peers.txt on line ", i)
		}
		pk_bytes, err := base64.StdEncoding.DecodeString(pk_b64)
		if err != nil {
			log.Fatal("Bad base64 in peers.txt on line ", i)
		}

		pk := &sgp.Entity{}
		err = pk.Parse(pk_bytes)
		if err != nil {
			log.Fatal("Bad pk in peers.txt on line ", i, " for ", host, ": ", err)
		}
		addr_struct, err := net.ResolveIPAddr("", host)
		if err != nil {
			log.Fatal("Cannot lookup ", host, err)
		}
		addr := addr_struct.String()
		dn.addr2peer[addr] = &Peer{index: i, addr: addr, pk: pk}

		_, err = dn.db.Exec("INSERT OR IGNORE INTO servers(id) VALUES(?)", i)
		if err != nil {
			log.Fatal("Cannot insert server ", i, ": ", err)
		}

		if bytes.Equal(dn.our_sk.Entity.Bytes, pk_bytes) { // this entry refers to us
			dn.our_index = i
			continue
		}

		// pick an ephermal port with the given ip as local address
		laddr_ip, err := net.ResolveIPAddr("", dn.our_ip)
		if err != nil {
			log.Fatal("resolve our ip: ", err)
		}
		laddr := &net.TCPAddr{IP: laddr_ip.IP}

		raddr, err := net.ResolveTCPAddr("tcp", host+":"+S2S_PORT)
		if err != nil {
			log.Fatal(err)
		}
		conn, err := net.DialTCP("tcp", laddr, raddr)
		if err == nil {
			conn.SetNoDelay(false)
			dn.peer_connected <- conn
		} else {
			log.Print("connect to peer: ", err, laddr, raddr)
		}
	}

	if dn.our_index == -1 {
		log.Fatal("We are not on the peers list")
	}

	// first round and round key
	ok := 0
	err = dn.db.QueryRow("SELECT EXISTS(SELECT 1 FROM round_keys)").Scan(&ok)
	if err != nil {
		log.Fatal("Cannot read table rounds: ", err)
	}
	if ok == 0 {
		_, err = dn.db.Exec("INSERT INTO rounds(id) VALUES(0)")
		if err != nil {
			log.Fatal("Cannot initialize table rounds: ", err)
		}
		var key [32]byte
		_, err = io.ReadFull(rand.Reader, key[:])
		if err != nil {
			log.Fatal(err)
		}
		_, err = dn.db.Exec("INSERT INTO round_keys(id,round,server,key) VALUES(0,0,?,?)", dn.our_index, key[:])
		if err != nil {
			log.Fatal("Cannot initialize table round_keys: ", err)
		}
	}

	go dn.HandleAllPeers()

	our_server_tcpaddr, err := net.ResolveTCPAddr("tcp", dn.our_ip+":"+S2S_PORT)
	if err != nil {
		log.Fatal(err)
	}
	dn.peer_lnr, err = net.ListenTCP("tcp", our_server_tcpaddr)
	if err != nil {
		log.Fatal(err)
	}
	go dn.ListenForPeers()

	dn.client_lnr, err = net.Listen("tcp", dn.our_ip+":6263")
	if err != nil {
		log.Fatal(err)
	}
	dn.ListenForClients()
}
