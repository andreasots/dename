package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/andres-erbsen/sgp"
)

func main() {
	if len(os.Args) != 2 && len(os.Args) != 3 {
		log.Fatal("USAGE: ", os.Args[0], " LOCALIP [STARTTIME]")
	}

	var err error
	dn := &Dename{
		addr2peer: make(map[string]*Peer),
		peers:     make(map[int]*Peer),

		peer_broadcast:     make(chan []byte),
		acks_for_consensus: make(chan VerifiedAckedCommitment)}
	dn.db, err = sql.Open("sqlite3", "file:dename.db?cache=shared")
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
		dn.peers[i] = dn.addr2peer[addr]

		_, err = dn.db.Exec("INSERT OR IGNORE INTO servers(id) VALUES(?)", i)
		if err != nil {
			log.Fatal("Cannot insert server ", i, ": ", err)
		}

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
	if len(os.Args) >= 2 {
		dn.us.addr = os.Args[1]
	}

	round := -1 // -1 is a dummy round before the beginning of time.
	var round_end_u int64
	var round_end time.Time
	err = dn.db.QueryRow("SELECT id,end_time FROM rounds ORDER BY id DESC LIMIT 1").Scan(&round, &round_end_u)
	if err != nil && err != sql.ErrNoRows {
		log.Fatal("Cannot read table rounds: ", err)
	}
	if round == -1 {
		if len(os.Args) < 3 {
			log.Fatal("Need to specify start itme of first round")
		}
		reftime, _ := time.Parse("", "")
		intime, err := time.Parse("15:04:05", os.Args[2])
		if err != nil {
			log.Fatal("Bad time input")
		}
		round_end = time.Now().Truncate(24 * time.Hour).Add(intime.Sub(reftime))
		log.Print("First round will end at ", round_end)
	} else {
		if len(os.Args) > 2 {
			log.Fatal("Extroneous start time of first round")
		}
		round_end = time.Unix(round_end_u, 0)
	}
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
