package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	_ "github.com/bmizerany/pq"
	"log"
	"net"
	"sort"
	"time"

	"code.google.com/p/gcfg"
	"github.com/andres-erbsen/sgp"
)

type Cfg struct {
	General struct {
		Host          string
		SecretKeyFile string
	}

	Peer map[string]*struct {
		Host string
	}
	Database struct {
		Name     string
		Host     string
		Port     string
		Username string
		Password string
	}
	Genesis struct {
		Time int64
	}
}

func main() {
	cfg := new(Cfg)
	err := gcfg.ReadFileInto(cfg, "dename.cfg")
	if err != nil {
		log.Fatalf("Failed to parse gcfg data: %s", err)
	}
	dename(cfg)
}

func dename(cfg *Cfg) {
	var err error
	dn := &Dename{
		addr2peer: make(map[string]*Peer),
		peers:     make(map[int]*Peer),

		acks_for_consensus: make(chan VerifiedAckedCommitment),
		keys_for_consensus: make(chan *RoundKey)}

	dn.db, err = sql.Open("postgres", "user="+cfg.Database.Username+" password="+cfg.Database.Password+" dbname="+cfg.Database.Name+" sslmode=disable")
	if err != nil {
		log.Fatalf("Cannot open database: %f", err)
	}
	defer dn.db.Close()
	dn.CreateTables()

	dn.our_sk, err = sgp.LoadSecretKeyFromFile(cfg.General.SecretKeyFile)
	if err != nil {
		log.Fatal("Cannot load secret key from \"sk\"", err)
	}

	// sort the peers by public keys
	peer_b64_pks := make([]string, len(cfg.Peer))
	i := 0
	for k, _ := range cfg.Peer {
		peer_b64_pks[i] = k
		i++
	}
	sort.Strings(peer_b64_pks)

	for i, pk_b64 := range peer_b64_pks {
		host := cfg.Peer[pk_b64].Host
		pk_bytes, err := base64.StdEncoding.DecodeString(pk_b64)
		if err != nil {
			log.Fatalf("Bad base64 as public key: %f (for %f)", err, host)
		}

		pk := &sgp.Entity{}
		err = pk.Parse(pk_bytes)
		if err != nil {
			log.Fatal("Bad pk: %f (for %f)", err, host)
		}
		addr_struct, err := net.ResolveIPAddr("", host)
		if err != nil {
			log.Fatal("Cannot look up ", host, err)
		}
		addr := addr_struct.String()
		dn.addr2peer[addr] = &Peer{index: i, addr: addr, pk: pk}
		dn.peers[i] = dn.addr2peer[addr]

		dn.db.Exec("INSERT INTO servers(id) VALUES($1)", i)
		// TODO: should we catch any errors here?

		if bytes.Equal(dn.our_sk.Entity.Bytes, pk_bytes) { // this entry refers to us
			dn.us = dn.peers[i]
			continue
		}
	}

	var round, round_end_u int64 // the newest round open for clients
	err = dn.db.QueryRow(`SELECT id,end_time FROM rounds WHERE id=(SELECT round
			FROM round_keys WHERE server = $1 ORDER
			BY id DESC LIMIT 1);`, dn.us.index).Scan(&round, &round_end_u)
	if err == nil {
		log.Printf("Resuming round %d for clients", round)
	} else if err == sql.ErrNoRows {
		round = 0
		round_end_u = cfg.Genesis.Time
		_, err = dn.db.Exec(`INSERT INTO rounds(id, end_time)
			VALUES($1,$2)`, round, round_end_u)
		if err != nil {
			log.Fatal("Cannot insert round 0: ", err)
		}
		dn.ClientsToRound(round, time.Unix(round_end_u, 0))
	} else if err != nil {
		log.Fatal("Cannot read table rounds: ", err)
	}

	// pick an ephermal port with the given ip as local address
	laddr_ip, err := net.ResolveIPAddr("", dn.us.addr)
	if err != nil {
		log.Fatal("resolve our ip: ", err)
	}

	for _, peer := range dn.peers {
		if peer == dn.us {
			continue
		}
		laddr := &net.TCPAddr{IP: laddr_ip.IP}

		raddr, err := net.ResolveTCPAddr("tcp", peer.addr+":"+S2S_PORT)
		if err != nil {
			log.Fatal(err)
		}
		conn, err := net.DialTCP("tcp", laddr, raddr)
		if err == nil {
			conn.SetNoDelay(false)
			dn.PeerConnected(conn)
		} else {
			log.Print("connect to peer: ", err, laddr, raddr)
		}
	}

	if dn.us.index == -1 {
		log.Fatal("We are not on the peers list")
	}

	our_server_tcpaddr, err := net.ResolveTCPAddr("tcp", dn.us.addr+":"+S2S_PORT)
	if err != nil {
		log.Fatal(err)
	}
	dn.peer_lnr, err = net.ListenTCP("tcp", our_server_tcpaddr)
	if err != nil {
		log.Fatal(err)
	}
	go dn.ListenForPeers()

	dn.client_lnr, err = net.Listen("tcp", dn.us.addr+":6263")
	if err != nil {
		log.Fatal(err)
	}
	go dn.ListenForClients()

	if round > 0 {
		have_consensus := false
		err = dn.db.QueryRow(`SELECT (commit_time IS NOT NULL) FROM rounds
				WHERE id = $1`, round-1).Scan(&have_consensus)
		if err != nil {
			log.Fatalf("Check if round %d reached consensus: %s", round-1, err)
		}
		if !have_consensus {
			log.Printf("Running consensus for round %d", round-1)
			dn.Tick(round - 1)
		}
	}

	dn.WaitForTicks(round, time.Unix(round_end_u, 0))
}
