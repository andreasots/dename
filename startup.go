package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	_ "github.com/bmizerany/pq"
	"log"
	"net"
	"time"
	"sort"

	"github.com/andres-erbsen/sgp"
	"code.google.com/p/gcfg"
)

type Cfg struct {
    General struct {
		Host string
		SecretKeyFile string
	}

    Peer map[string]*struct {
        Host string
    }
    Database struct {
		Name string
	    Host string
		Port string
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

		peer_broadcast:     make(chan []byte),
		acks_for_consensus: make(chan VerifiedAckedCommitment)}

	dn.db, err = sql.Open("postgres", "user="+cfg.Database.Username+" password="+cfg.Database.Password +" dbname="+cfg.Database.Name+" sslmode=disable")
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
	
	for i, pk_b64 := range(peer_b64_pks) {
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

	round := -1 // -1 is a dummy round before the beginning of time.
	round_end_u := cfg.Genesis.Time
	err = dn.db.QueryRow("SELECT id,end_time FROM rounds ORDER BY id DESC LIMIT 1").Scan(&round, &round_end_u)
	if err != nil && err != sql.ErrNoRows {
		log.Fatal("Cannot read table rounds: ", err)
	}

	round_end := time.Unix(round_end_u, 0)
	go dn.WaitForTicks(round, round_end)

	go dn.HandleBroadcasts()

	our_server_tcpaddr, err := net.ResolveTCPAddr("tcp", dn.us.addr+":"+S2S_PORT)
	if err != nil {
		log.Fatal(err)
	}
	dn.peer_lnr, err = net.ListenTCP("tcp", our_server_tcpaddr)
	if err != nil {
		log.Fatal(err)
	}
	go dn.ListenForPeers()

	if round == -1 { // wait for the dummy round to end before accepting clients
		time.Sleep(time.Now().Sub(round_end))
	}
	dn.client_lnr, err = net.Listen("tcp", dn.us.addr+":6263")
	if err != nil {
		log.Fatal(err)
	}
	dn.ListenForClients()
}
