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
			log.Fatalf("Bad pk for %d: %s; %x", peer.id, err, pk_bs)
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
		dn.HandleClientLookup(conn, msg.Lookup)
	}
}

func (dn *Dename) HandleClientLookup(conn net.Conn, name []byte) {
	name_hash := merklemap.Hash(name)
	var signed_root []byte
	var round, snapshot int64
	err := dn.db.QueryRow(`SELECT id, signed_result from rounds WHERE
	signed_result is not NULL ORDER BY id DESC`).Scan(&round, &signed_root)
	if err != nil {
		log.Fatalf("SELECT last signed round: %s", err)
	}
	err = dn.db.QueryRow(`SELECT snapshot from naming_snapshots
		WHERE round = $1`, round).Scan(&snapshot)
	if err != nil {
		log.Fatalf("SELECT snapshot for round %d: %s", round, err)
	}
	mapHandle, err := dn.merklemap.GetSnapshot(snapshot).OpenHandle()
	if err != nil {
		log.Fatalf("mm.GetSnapshot(%d).OpenHandle(): %s", snapshot, err)
	}
	pk := dn.Resolve(name)
	if pk == nil {
		return
	}
	_, path, err := mapHandle.GetPath(name_hash)
	if path == nil {
		log.Fatal("Name %s in db but not in merklemap: %s", name, err)
	}
	path_bs, err := proto.Marshal(path)
	if err != nil {
		panic(err)
	}
	response_bs, err := proto.Marshal(&protocol.LookupResponse{
		Root: signed_root, Path: path_bs, PublicKey: pk.Bytes})
	if err != nil {
		panic(err)
	}
	conn.Write(response_bs)
}

// Resolve does a Name -> Public key lookup. Returns nil if not found.
func (dn *Dename) Resolve(name []byte) (pk *sgp.Entity) {
	var pk_bs []byte
	err := dn.db.QueryRow("SELECT pubkey FROM name_mapping WHERE name = $1",
		name).Scan(&pk_bs)
	if err == sql.ErrNoRows || len(pk_bs) == 0 {
		// (the pk could be empty if the name was inserted but not updated yet)
	} else if err == nil { // name already in use; transfer
		pk = new(sgp.Entity)
		if err := pk.Parse(pk_bs); err != nil {
			log.Fatalf("Bad pk in database: %s; %x", err, pk_bs)
		}
	} else { // barf
		log.Fatalf("Load old pk from db: %s", err)
	}
	return pk
}

func (dn *Dename) HandleClientTransfer(rq_bs []byte) {
	name, _, err := dn.ValidateRequest(rq_bs)
	if err != nil {
		return
	}
	_, err = dn.db.Exec(`INSERT INTO name_locked(name,request) VALUES($1,$2)`,
		name, rq_bs)
	if err == nil {
		dn.c.IncomingRequests <- rq_bs
	} else if pgutil.IsError(err, pgutil.ErrUniqueViolation) {
		log.Printf("Name %s already locked for a transaction", name)
		return
	} else {
		log.Fatalf("HandleClientTransfer: Lock a name: %s", err)
	}
}

func (dn *Dename) ValidateRequest(rq_bs []byte) ([]byte, *sgp.Entity, error) {
	rq_signed := &sgp.Signed{}
	if err := proto.Unmarshal(rq_bs, rq_signed); err != nil {
		return nil, nil, err
	}
	transfer := &protocol.TransferName{}
	if err := proto.Unmarshal(rq_signed.Message, transfer); err != nil {
		return nil, nil, err
	}
	new_pk := new(sgp.Entity)
	if err := new_pk.Parse(transfer.PublicKey); err != nil {
		return nil, nil, err
	}

	old_pk := dn.Resolve(transfer.Name)
	if old_pk == nil {
		old_pk = new_pk
	}
	if _, err := old_pk.Verify(rq_bs, protocol.SIGN_TAG_TRANSFER); err != nil {
		return nil, nil, err
	}
	// TODO: require a proof of freshnesh of the request
	return transfer.Name, new_pk, nil
}

func (dn *Dename) QueueProcessor(peer_rq_map map[int64]*[][]byte,
	shared_prng *prng.PRNG, round_id int64) []byte {
	// everything here must be idempotent
	var last_snapshot int64
	if round_id != 0 {
		err := dn.db.QueryRow(`SELECT snapshot from naming_snapshots
			WHERE round = $1`, round_id-1).Scan(&last_snapshot)
		if err != nil {
			log.Fatalf("SELECT snapshot for round %d: %s", round_id-1, err)
		}
	}

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

	peer_ids := make([]int64, 0, len(peer_rq_map))
	for id := range peer_rq_map {
		peer_ids = append(peer_ids, id)
	}
	name_modified := make(map[string]int64)
	for i := range rand.New(shared_prng).Perm(len(peer_rq_map)) {
		peer_id := peer_ids[i]
		for _, rq_bs := range *peer_rq_map[peer_id] {
			name, pk, err := dn.ValidateRequest(rq_bs)
			if err != nil {
				log.Fatalf("%d accepted a bad request: %s", peer_id, err)
			}
			if _, already := name_modified[string(name)]; already {
				continue
			}
			name_modified[string(name)] = peer_id
			err = mapHandle.Set(merklemap.Hash(name), merklemap.Hash(pk.Bytes))
			if err != nil {
				log.Fatalf("mapHandle.Set(name,pk): %s", err)
			}
			_, err = create.Exec(name)
			if err != nil && !pgutil.IsError(err, pgutil.ErrUniqueViolation) {
				log.Fatalf("QueueProcessor: create.Exec(name): %s", err)
			}
			if _, err = assign.Exec(pk.Bytes, name); err != nil {
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

	_, err = dn.db.Exec(`INSERT INTO naming_snapshots(round, snapshot)
		VALUES($1,$2)`, round_id, new_snapshot)
	if err != nil && !pgutil.IsError(err, pgutil.ErrUniqueViolation) {
		log.Fatalf("INSERT round %d snapshot %d: %s", round_id, new_snapshot, err)
	}

	log.Printf("QueueProcessor: round %d with %d transfers: snapshot %d\n = %x",
		round_id, len(name_modified), new_snapshot, *rootHash)
	return rootHash[:]
}
