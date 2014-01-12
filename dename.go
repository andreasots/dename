package main

import (
	"bytes"
	"code.google.com/p/gcfg"
	"code.google.com/p/goprotobuf/proto"
	"database/sql"
	"encoding/base64"
	"fmt"
	"github.com/andres-erbsen/dename/consensus"
	"github.com/andres-erbsen/dename/pgutil"
	"github.com/andres-erbsen/dename/prng"
	"github.com/andres-erbsen/dename/protocol"
	"github.com/andres-erbsen/sgp"
	"github.com/daniel-ziegler/merklemap"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
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
	go func() {
		ch := make(chan os.Signal)
		signal.Notify(ch, os.Interrupt)
		<-ch
		panic("Interrupted!")
	}()
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

	consensus_peers := make(map[int64]consensus.Peer_, len(dn.peers))
	for k, v := range dn.peers {
		consensus_peers[k] = v
	}
	dn.c = consensus.NewConsensus(dn.db, &dn.our_sk, dn.us.id, dn.QueueProcessor,
		time.Now(), 4*time.Second, consensus_peers, protocol.ConsensusSignTags)

	go dn.ListenForPeers()
	go dn.ConnectToPeers()
	go dn.ListenForClients()
	dn.c.Run()
}

func (dn *Dename) HandleClient(conn net.Conn) {
	defer conn.Close()
	msg_bs, err := ioutil.ReadAll(conn)
	if err != nil {
		return
	}
	msg := new(protocol.C2SMessage)
	if err = proto.Unmarshal(msg_bs, msg); err != nil {
		return
	}

	switch {
	case msg.TransferName != nil:
		dn.HandleClientTransfer(msg.TransferName)
	case msg.Lookup != nil:
		// TODO: dn.HandleLookup(conn, *msg.Lookup)
	}
}

func (dn *Dename) HandleClientTransfer(rq_bs []byte) {
	name, _, err := dn.ValidateRequest(rq_bs)
	if err != nil {
		return
	}
	dn.c.IncomingRequests <- rq_bs
	_, err = dn.db.Exec(`INSERT INTO name_locked(name,request) VALUES($1,$2)`,
		name, rq_bs)
	if err == nil {
		dn.c.IncomingRequests <- rq_bs
	} else if pgutil.IsError(err, pgutil.ErrUniqueViolation) {
		return // could not acquire lock
	} else {
		log.Fatalf("HandleClientTransfer: Lock a name: %s", err)
	}
}

func (dn *Dename) ValidateRequest(rq_bs []byte) (name []byte, new_pk *sgp.Entity, err error) {
	rq_signed := &sgp.Signed{}
	if err = proto.Unmarshal(rq_bs, rq_signed); err != nil {
		return
	}
	transfer := &protocol.TransferName{}
	if err = proto.Unmarshal(rq_signed.Message, transfer); err != nil {
		return
	}
	new_pk = new(sgp.Entity)
	if err = new_pk.Parse(transfer.PublicKey); err != nil {
		return
	}

	var old_pk_bs []byte
	var old_pk *sgp.Entity
	err = dn.db.QueryRow("SELECT pubkey FROM name_mapping WHERE name = $1",
		transfer.Name).Scan(&old_pk_bs)
	if err == nil { // name already in use; transfer
		old_pk = new(sgp.Entity)
		if err := old_pk.Parse(old_pk_bs); err != nil {
			log.Fatalf("Bad pk in database: %s", err)
		}
	} else if err == sql.ErrNoRows { // new name; registration
		old_pk = new_pk
	} else { // barf
		log.Fatalf("Load old pk from db: %s", err)
	}

	if _, err = old_pk.Verify(rq_bs, protocol.SIGN_TAG_TRANSFER); err != nil {
		return nil, nil, err
	}
	// TODO: require a proof of freshnesh of the request
	return
}

func (dn *Dename) QueueProcessor(peer_rq_map map[int64]*[][]byte,
	shared_prng *prng.PRNG) []byte {
	var last_snapshot int64 // TODO: load last_snapshot
	// everything here must be idempotent as this function may be run multiple times
	mapHandle, err := dn.merklemap.GetSnapshot(last_snapshot).OpenHandle()
	if err != nil {
		log.Fatalf("dn.merklemap.GetSnapshot(last_snapshot).OpenHandle(): %s", err)
	}

	create, err := dn.db.Prepare(`INSERT INTO name_mapping(name) VALUES($1)`)
	if err != nil {
		log.Fatalf("PREPARE: INSERT name INTO name_mapping: %s", err)
	}
	defer create.Close()

	assign, err := dn.db.Prepare(`UPDATE name_mapping
		SET pubkey = $1 WHERE name = $2`)
	if err != nil {
		log.Fatalf("PREPARE: UPDATE pubkey WERE name: %s", err)
	}
	defer assign.Close()

	unlock, err := dn.db.Prepare(`DELETE FROM name_locked
		WHERE name = $1 AND request = $2`)
	if err != nil {
		log.Fatalf("PREPARE: DELETE FROM name_locked WHERE name = $1: %s", err)
	}
	defer unlock.Close()

	name_modified := make(map[string]int)
	for peer_id := range rand.New(shared_prng).Perm(len(peer_rq_map)) {
		for _, rq_bs := range *peer_rq_map[int64(peer_id)] {
			name, pk, err := dn.ValidateRequest(rq_bs)
			if err != nil {
				log.Fatal("%d accepted a bad request: %s", peer_id, err)
			}
			if winner_id, already := name_modified[string(name)]; already {
				log.Printf("Tie over %s between %d and %d broken in favor of %d",
					string(name), peer_id, winner_id, winner_id)
				continue
			}
			err = mapHandle.Set(merklemap.Hash(name), merklemap.Hash(pk.Bytes))
			if err != nil {
				log.Fatalf("mapHandle.Set(name,pk): %s", err)
			}
			if _, err = create.Exec(name); err != nil {
				log.Fatalf("QueueProcessor: create.Exec(name): %s", err)
			}
			if _, err = assign.Exec(name, pk.Bytes); err != nil {
				log.Fatalf("QueueProcessor: create.Exec(name): %s", err)
			}
			if _, err = unlock.Exec(name, rq_bs); err != nil {
				log.Fatalf("QueueProcessor: unlock.Exec(name): %s", err)
			}
		}
	}
	rootHash, err := mapHandle.GetRootHash()
	if err != nil {
		log.Fatalf("mapHandle.GetRootHash(): %s", err)
	}
	newNaming, err := mapHandle.FinishUpdate()
	if err != nil {
		log.Fatalf("mapHandle.FinishUpdate(): %s", err)
	}
	new_snapshot := newNaming.GetId()
	_ = new_snapshot // TODO: save the new snapshot
	return rootHash[:]
}
