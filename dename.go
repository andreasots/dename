package main

import (
	"bytes"
	"code.google.com/p/gcfg"
	"database/sql"
	"encoding/base64"
	"fmt"
	"github.com/andres-erbsen/dename/consensus"
	"github.com/andres-erbsen/dename/prng"
	"github.com/andres-erbsen/sgp"
	"github.com/daniel-ziegler/merklemap"
	"log"
	"net"
	"sync"
	"time"
)

type Peer struct {
	id   int64
	addr string
	pk   *sgp.Entity

	sync.RWMutex
	// mutable:
	conn      net.Conn
	closeOnce *sync.Once
}

func (peer *Peer) PK() *sgp.Entity {
	return peer.pk
}

type Dename struct {
	db        *sql.DB
	our_sk    sgp.SecretKey
	us        *Peer
	peers     map[int64]*Peer
	addr2peer map[string]*Peer

	merklemap *merklemap.Map
	c         *consensus.Consensus
}

type Cfg struct {
	General struct {
		Host          string
		SecretKeyFile string
	}

	Peer map[string]*struct {
		PublicKey string
		Host      string
	}
	Database struct {
		Name           string
		Host           string
		Port           string
		User           string
		Password       string
		MaxConnections int
	}
	Naming struct {
		StartTime int64
		File      string
	}
}

func main() {
	cfg := new(Cfg)
	err := gcfg.ReadFileInto(cfg, "dename.cfg")
	if err != nil {
		log.Fatalf("Failed to parse gcfg data: %s", err)
	}
	dn := &Dename{peers: make(map[int64]*Peer, len(cfg.Peer)),
		addr2peer: make(map[string]*Peer, len(cfg.Peer))}
	dn.db, err = sql.Open("postgres", "user="+cfg.Database.User+" password="+cfg.Database.Password+" dbname="+cfg.Database.Name+" sslmode=disable")
	if err != nil {
		log.Fatalf("Cannot open database: %s", err)
	}
	defer dn.db.Close()
	dn.CreateTables()

	dn.our_sk, err = sgp.LoadSecretKeyFromFile(cfg.General.SecretKeyFile)
	if err != nil {
		log.Fatalf("Load secret key from \"sk\": %s", err)
	}

	dn.merklemap, err = merklemap.Open(cfg.Naming.File)
	if err != nil {
		log.Fatalf("merklemap.Open(cfg.Naming.File): %s", err)
	}

	for id_str, peercfg := range cfg.Peer {
		peer := &Peer{pk: new(sgp.Entity)}
		if _, err := fmt.Sscan(id_str, &peer.id); err != nil {
			log.Fatal("Peer names must be integers, for example [peer \"1\"]")
		}
		pk_bs, err := base64.StdEncoding.DecodeString(peercfg.PublicKey)
		if err != nil {
			log.Fatalf("Bad base64 as public key: %s (for %d)", err, peer.id)
		}
		if err := peer.pk.Parse(pk_bs); err != nil {
			log.Fatalf("Bad pk for %d: %s", peer.id, err)
		}
		addr_struct, err := net.ResolveIPAddr("", peercfg.Host)
		if err != nil {
			log.Fatal("net.ResolveIPAddr(\"\", %s): %s", peercfg.Host, err)
		}
		peer.addr = addr_struct.String()
		if _, already := dn.peers[peer.id]; already {
			log.Fatal("Two peers with id %d", peer.id)
		}
		dn.peers[peer.id] = peer
		dn.addr2peer[peer.addr] = peer
		if bytes.Equal(dn.our_sk.Entity.Bytes, pk_bs) {
			dn.us = peer
		}
	}

	peers := make(map[int64]consensus.Peer_, len(dn.peers))
	for k, v := range dn.peers {
		peers[k] = v
	}
	dn.c = consensus.NewConsensus(dn.db, &dn.our_sk, dn.us.id,
		func(rqs map[int64]*[][]byte, _ *prng.PRNG) []byte {
			fmt.Print(rqs)
			return []byte("HASH1234HASH5678HASH8765HASH4321")
		},
		time.Now(), 4*time.Second, peers)
	go dn.c.Run()

	go dn.ListenForPeers()
	go dn.ConnectToPeers()
	go dn.ListenForClients()
	select {}
}
