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
	"sort"
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
	peer_ids  []int

	merklemap *merklemap.Map
	c         *consensus.Consensus

	lockednames_mutex sync.Mutex
	lockednames       map[string]struct{}
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
		addr2peer:   make(map[string]*Peer, len(cfg.Peer)),
		lockednames: make(map[string]struct{})}
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

	dn.peer_ids = make([]int, 0, len(dn.peers))
	consensus_peers := make(map[int64]consensus.Peer_, len(dn.peers))
	for id, peer := range dn.peers {
		consensus_peers[id] = peer
		dn.peer_ids = append(dn.peer_ids, int(id))
	}
	sort.IntSlice(dn.peer_ids).Sort()

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
	case msg.Lookup != nil:
		dn.HandleClientLookup(conn, msg.Lookup)
	case msg.TransferName != nil:
		dn.HandleClientTransfer(msg.TransferName)
	}
}

func (dn *Dename) HandleClientLookup(conn net.Conn, name []byte) {
	var signed_root []byte
	var round, snapshot int64
	err := dn.db.QueryRow(`SELECT id, signed_result from rounds WHERE
	signed_result is not NULL ORDER BY id DESC`).Scan(&round, &signed_root)
	if err != nil {
		log.Fatalf("SELECT last signed round: %s", err)
	}
	err = dn.db.QueryRow(`SELECT snapshot from naming_snapshots
		WHERE round = $1`, round).Scan(&snapshot)
	if err != nil && err != sql.ErrNoRows {
		log.Fatalf("SELECT snapshot for round %d: %s", round, err)
	}
	mapHandle, err := dn.merklemap.GetSnapshot(snapshot).OpenHandle()
	if err != nil {
		log.Fatalf("mm.GetSnapshot(%d).OpenHandle(): %s", snapshot, err)
	}
	defer mapHandle.Close()
	pk, path := dn.Resolve(mapHandle, name)
	if pk == nil {
		return
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

// Resolve does a Name -> PublicKey,MerkleProof lookup. Returns nil if not found
func (dn *Dename) Resolve(mapHandle *merklemap.Handle, name []byte) (*sgp.Entity, *merklemap.MerklePath) {
	pk_hash, path, err := mapHandle.GetPath(merklemap.Hash(name))
	if err != nil {
		log.Fatal("mapHandle.GetPath(h(%s)): %s", string(name), err)
	} else if pk_hash == nil {
		return nil, nil
	}
	var pk_bs []byte
	err = dn.db.QueryRow(`SELECT preimage FROM rainbow
		WHERE hash = $1`, pk_hash[:]).Scan(&pk_bs)
	if err != nil && err != sql.ErrNoRows {
		log.Fatalf("SELECT pk for \"%s\" from db: %s", string(name), err)
	}
	pk := new(sgp.Entity)
	if err := pk.Parse(pk_bs); err != nil {
		log.Fatal("Bad pk in database")
	}
	return pk, path
}

func (dn *Dename) HandleClientTransfer(rq_bs []byte) {
	name, _, err := dn.ValidateRequest(rq_bs)
	if err != nil {
		return
	}
	dn.lockednames_mutex.Lock()
	if _, locked := dn.lockednames[string(name)]; locked {
		dn.lockednames_mutex.Unlock()
		log.Printf("Name \"%s\" already locked for update", string(name))
		return
	} else {
		dn.lockednames[string(name)] = struct{}{}
		dn.lockednames_mutex.Unlock()
		dn.c.IncomingRequests <- rq_bs
	}
}

func (dn *Dename) ValidateRequest(rq_bs []byte) (name []byte, new_pk *sgp.Entity, err error) {
	name, new_pk, err = NaiveParseRequest(rq_bs)
	if err != nil {
		return
	}
	snapshot := int64(0) // if ErrNoRows
	err = dn.db.QueryRow(`SELECT snapshot from naming_snapshots
		ORDER BY round DESC LIMIT 1`).Scan(&snapshot)
	if err != nil && err != sql.ErrNoRows {
		log.Fatalf("SELECT latest snapshot: %s", err)
	}
	mapHandle, err := dn.merklemap.GetSnapshot(snapshot).OpenHandle()
	if err != nil {
		log.Fatalf("mm.GetSnapshot(%d).OpenHandle(): %s", snapshot, err)
	}
	defer mapHandle.Close()
	old_pk, _ := dn.Resolve(mapHandle, name)
	if old_pk == nil {
		old_pk = new_pk
	}
	if _, err = old_pk.Verify(rq_bs, protocol.SIGN_TAG_TRANSFER); err != nil {
		return
	}
	// TODO: require a proof of freshness of the request
	return name, new_pk, nil
}

func NaiveParseRequest(rq_bs []byte) ([]byte, *sgp.Entity, error) {
	rq_signed := new(sgp.Signed)
	if err := proto.Unmarshal(rq_bs, rq_signed); err != nil {
		return nil, nil, err
	}
	transfer := new(protocol.TransferName)
	if err := proto.Unmarshal(rq_signed.Message, transfer); err != nil {
		return nil, nil, err
	}
	new_pk := new(sgp.Entity)
	if err := new_pk.Parse(transfer.PublicKey); err != nil {
		return nil, nil, err
	}
	return transfer.Name, new_pk, nil
}

func (dn *Dename) QueueProcessor(peer_rq_map map[int64]*[][]byte,
	shared_prng *prng.PRNG, round int64) []byte {
	rnd := rand.New(shared_prng)
	last_round, snapshot := int64(0), int64(0) // if ErrNoRows
	err := dn.db.QueryRow(`SELECT round, snapshot from naming_snapshots
		ORDER BY round DESC LIMIT 1`).Scan(&last_round, &snapshot)
	if err != nil && err != sql.ErrNoRows {
		log.Fatalf("SELECT latest snapshot: %s", err)
	}
	mapHandle, err := dn.merklemap.GetSnapshot(snapshot).OpenHandle()
	if err != nil {
		log.Fatalf("merklemap GetSnapshot(%d).OpenHandle(): %s", snapshot, err)
	}
	defer mapHandle.Close()

	if last_round > round {
		log.Fatalf("QueueProcessor(r%d) after done round %d", round, last_round)
	} else if round == last_round { // already processed
		if rootHash, err := mapHandle.GetRootHash(); err == nil {
			return rootHash[:]
		} else {
			log.Fatalf("mapHandle.GetRootHash(): %s", err)
		}
	} else if last_round < round-1 {
		log.Fatalf("Skipped rounds between %d and %d", last_round, round)
	}

	rainbow_insert, err := dn.db.Prepare(`INSERT INTO rainbow(hash, preimage)
		VALUES($1,$2)`)
	if err != nil {
		log.Fatalf("PREPARE rainbow_insert: %s", err)
	}
	defer rainbow_insert.Close()

	name_modified := make(map[string]int64)
	for _, i := range rnd.Perm(len(peer_rq_map)) {
		peer_id := int64(dn.peer_ids[i])
		for _, rq_bs := range *peer_rq_map[peer_id] {
			name, pk, err := dn.ValidateRequest(rq_bs)
			if err != nil {
				log.Printf("qpr: invalid transfer of \"%s\" by %d (%s)", string(name), peer_id, err)
				continue
			} else if winner, already := name_modified[string(name)]; already {
				log.Printf("qpr: duplicate transfer of \"%s\" by %d after %d",
					string(name), peer_id, winner)
				continue
			}
			name_modified[string(name)] = peer_id
			pk_hash := merklemap.Hash(pk.Bytes)
			if err = mapHandle.Set(merklemap.Hash(name), pk_hash); err != nil {
				log.Fatalf("mapHandle.Set(name,pk): %s", err)
			}
			_, err = rainbow_insert.Exec(pk_hash[:], pk.Bytes)
			if err != nil && !pgutil.IsError(err, pgutil.ErrUniqueViolation) {
				log.Fatalf("QueueProcessor: rainbow_insert.Exec(...): %s", err)
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

	log.Printf("#%d = %x", round, *rootHash)
	_, err = dn.db.Exec(`INSERT INTO naming_snapshots(round, snapshot)
		VALUES($1,$2)`, round, newNaming.GetId())
	if err != nil {
		log.Fatalf("INSERT round %d snapshot %d: %s", round, newNaming.GetId(), err)
	}

	dn.lockednames_mutex.Lock()
	for _, rq_bs := range *peer_rq_map[dn.us.id] {
		if name, _, err := NaiveParseRequest(rq_bs); err == nil {
			delete(dn.lockednames, string(name))
		} else {
			panic(err)
		}
	}
	dn.lockednames_mutex.Unlock()
	return rootHash[:]
}
