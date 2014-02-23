package main

import (
	"bytes"
	"code.google.com/p/gcfg"
	"code.google.com/p/goprotobuf/proto"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/andres-erbsen/dename/consensus"
	"github.com/andres-erbsen/dename/pgutil"
	"github.com/andres-erbsen/dename/prng"
	"github.com/andres-erbsen/dename/protocol"
	"github.com/andres-erbsen/sgp"
	"github.com/daniel-ziegler/merklemap"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	_ "net/http/pprof"
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
	peer_ids  []int64

	merklemap *merklemap.Map
	c         *consensus.Consensus

	lockednames_mutex sync.Mutex
	lockednames       map[string]struct{}

	freshnessThreshold int64
	expirationTicks    int64
	ticketer_pk        *sgp.Entity

	// mutable state:
	round_completed struct {
		sync.RWMutex
		*consensus.RoundSummary
		Snapshot int64
	}
	round_processed struct {
		sync.RWMutex
		Id, Snapshot int64
	}
	fresh struct {
		sync.RWMutex
		roots [][]byte
	}

	// prepared queries
	sql_use_regtoken, sql_rainbow_lookup, sql_rainbow_insert *sql.Stmt
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
		StartTime       int64
		ExpirationTicks int64
		Interval        string
		File            string
	}
	Clients struct {
		Host               string
		FreshnessThreshold int64
		TicketerPublicKey  string
	}
}

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
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
		addr2peer:          make(map[string]*Peer, len(cfg.Peer)),
		lockednames:        make(map[string]struct{}),
		ticketer_pk:        new(sgp.Entity),
		expirationTicks:    cfg.Naming.ExpirationTicks,
		freshnessThreshold: cfg.Clients.FreshnessThreshold,
	}
	dn.db, err = sql.Open("postgres", "user="+cfg.Database.User+" password="+cfg.Database.Password+" dbname="+cfg.Database.Name+" sslmode=disable")
	if err != nil {
		log.Fatalf("Cannot open database: %s", err)
	}
	defer dn.db.Close()
	dn.db.SetMaxOpenConns(cfg.Database.MaxConnections)
	dn.CreateTables()

	dn.sql_use_regtoken, err = dn.db.Prepare(`INSERT INTO used_tokens(nonce) VALUES($1)`)
	if err != nil {
		log.Fatalf("Prepare dn.sql_use_regtoken: %s", err)
	}
	defer dn.sql_use_regtoken.Close()
	dn.sql_rainbow_lookup, err = dn.db.Prepare(`SELECT preimage FROM rainbow WHERE hash = $1`)
	if err != nil {
		log.Fatalf("Prepare dn.sql_rainbow_lookup: %s", err)
	}
	defer dn.sql_rainbow_lookup.Close()
	dn.sql_rainbow_insert, err = dn.db.Prepare(`INSERT INTO rainbow(hash, preimage) VALUES($1,$2)`)
	if err != nil {
		log.Fatalf("PREPARE rainbow_insert: %s", err)
	}
	defer dn.sql_rainbow_insert.Close()

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

	ticketer_pk_bs, err := base64.StdEncoding.DecodeString(cfg.Clients.TicketerPublicKey)
	if err != nil {
		log.Fatalf("Bad base64 as public key for ticketer")
	}
	if err := dn.ticketer_pk.Parse(ticketer_pk_bs); err != nil {
		log.Fatalf("Bad pk for ticketer")
	}

	dn.peer_ids = make([]int64, 0, len(dn.peers))
	consensus_peers := make(map[int64]consensus.Peer, len(dn.peers))
	for id, peer := range dn.peers {
		consensus_peers[id] = peer
		dn.peer_ids = append(dn.peer_ids, id)
	}
	sort.Sort(Int64Slice(dn.peer_ids))

	t0 := time.Unix(cfg.Naming.StartTime, 0)
	dt, err := time.ParseDuration(cfg.Naming.Interval)
	if err != nil {
		log.Fatal("Bad interval in configuration file")
	}
	dn.c = consensus.NewConsensus(dn.db, &dn.our_sk, dn.us.id,
		dn.QueueProcessor, t0, dt, consensus_peers, dn.peer_ids,
		dn.RoundCallback, protocol.ConsensusSignTags)

	dn.round_completed.RoundSummary = dn.c.LastRoundCompleted()

	// load last round we processed
	err = dn.db.QueryRow(`SELECT round, snapshot from naming_snapshots
		ORDER BY round DESC LIMIT 1`,
	).Scan(&dn.round_processed.Id, &dn.round_processed.Snapshot)
	if err == sql.ErrNoRows {
		dn.round_processed.Id, dn.round_processed.Snapshot = -1, 0
	} else if err != nil {
		log.Fatalf("SELECT latest snapshot: %s", err)
	}

	// last snapshot published
	if dn.round_completed.Id == dn.round_processed.Id {
		dn.round_completed.Snapshot = dn.round_processed.Snapshot
	} else {
		err := dn.db.QueryRow(`SELECT snapshot from naming_snapshots WHERE
		round = $1`, dn.round_completed.Id).Scan(&dn.round_completed.Snapshot)
		if err != nil && err != sql.ErrNoRows {
			log.Fatalf("SELECT snapshot for round las_completed: %s", err)
		}
	}

	go dn.ListenForPeers()
	go dn.ConnectToPeers()
	if cfg.Clients.Host != "" {
		go dn.ListenForClients(cfg.Clients.Host)
	}
	go dn.MaintainFreshness(t0, dt)
	dn.c.Run()
}

func (dn *Dename) RoundCallback(r *consensus.RoundSummary) bool {
	dn.round_processed.RLock()
	defer dn.round_processed.RUnlock()
	dn.fresh.Lock()
	defer dn.fresh.Unlock()
	dn.round_completed.Lock()
	defer dn.round_completed.Unlock()

	if dn.round_processed.Id != r.Id {
		panic("round_completed > round_processed")
	}
	if int64(len(dn.fresh.roots)) == dn.freshnessThreshold {
		dn.fresh.roots = dn.fresh.roots[1:]
	}
	dn.fresh.roots = append(dn.fresh.roots, r.Result)
	dn.round_completed.Snapshot = dn.round_processed.Snapshot
	dn.round_completed.RoundSummary = r
	return true
}

func (dn *Dename) HandleClient(conn net.Conn) {
	fmt.Printf("[(%d, 'read'),\n", time.Now().UnixNano())
	defer conn.Close()
	var sz uint16
	err := binary.Read(conn, binary.LittleEndian, &sz)
	if err != nil {
		return
	}
	msg_bs := make([]byte, sz)
	_, err = io.ReadFull(conn, msg_bs)
	if err != nil {
		return
	}
	fmt.Printf("(%d, 'parse'),\n", time.Now().UnixNano())
	msg := new(protocol.C2SMessage)
	if err = proto.Unmarshal(msg_bs, msg); err != nil {
		return
	}

	fmt.Printf("(%d, 'take round and root'),\n", time.Now().UnixNano())
	reply := new(protocol.S2CMessage)

	dn.round_completed.RLock()
	if dn.round_completed.RoundSummary == nil {
		dn.round_completed.RUnlock()
		return
	}
	round := dn.round_completed
	dn.round_completed.RUnlock()

	fmt.Printf("(%d, 'handle'),\n", time.Now().UnixNano())
	if msg.GetRoot != nil {
		reply.Root = round.SignedResult
	}
	if msg.Lookup != nil {
		dn.HandleClientLookup(reply, round.Snapshot, msg.Lookup)
	}
	if msg.Transfer != nil {
		dn.HandleClientTransfer(reply, round.Id, msg.RegToken, msg.Transfer)
	}
	if msg.GetFreshness != nil {
		dn.HandleClientFreshness(reply, round.Id)
	}

	reply_bs, err := proto.Marshal(reply)
	if err != nil {
		panic(err)
	}
	fmt.Printf("(%d, 'send reply'),\n", time.Now().UnixNano())
	conn.Write(reply_bs)
	fmt.Printf("(%d, '')]\n", time.Now().UnixNano())
}

func (dn *Dename) HandleClientLookup(reply *protocol.S2CMessage,
	snapshot int64, name []byte) {
	mapHandle, err := dn.merklemap.GetSnapshot(snapshot).OpenHandle()
	if err != nil {
		log.Fatalf("mm.GetSnapshot(%d).OpenHandle(): %s", snapshot, err)
	}
	reply.LookupResponse = new(protocol.LookupResponse)
	defer mapHandle.Close()
	pk, path := dn.Resolve(mapHandle, name)
	if pk != nil {
		reply.LookupResponse.PublicKey = pk.Bytes
		reply.LookupResponse.Path, err = proto.Marshal(path)
		if err != nil {
			panic(err)
		}
	} else {
		// TODO: merklemap: proof of absence
	}
}

// Resolve does a Name -> PublicKey,MerkleProof lookup. Returns nil if not found
func (dn *Dename) Resolve(mapHandle *merklemap.Handle, name []byte) (*sgp.Entity, *merklemap.MerklePath) {
	fmt.Printf("(%d, 'resolve'),\n", time.Now().UnixNano())
	pk_hash, path, err := mapHandle.GetPath(merklemap.Hash(name))
	if err != nil {
		log.Fatal("mapHandle.GetPath(h(%s)): %s", string(name), err)
	} else if pk_hash == nil {
		return nil, nil
	}
	var pk_bs []byte
	fmt.Printf("(%d, 'select rainbow'),\n", time.Now().UnixNano())
	err = dn.sql_rainbow_lookup.QueryRow(pk_hash[:]).Scan(&pk_bs)
	if err != nil && err != sql.ErrNoRows {
		log.Fatalf("SELECT pk for \"%s\" from db: %s", string(name), err)
	}
	pk := new(sgp.Entity)
	if err := pk.Parse(pk_bs); err != nil {
		log.Fatal("Bad pk in database")
	}
	return pk, path
}

func (dn *Dename) HandleClientTransfer(reply *protocol.S2CMessage, round int64,
	regtoken, rq_bs []byte) {
	_true, _false := true, false
	reply.TransferLooksGood = &_false
	ticket_fresh := make(chan bool)
	if regtoken != nil {
		fmt.Printf("(%d, 'verify ticket'),\n", time.Now().UnixNano())
		nonce, err := dn.ticketer_pk.Verify(regtoken, protocol.SIGN_TAG_PERSONATICKET)
		if err != nil {
			regtoken = nil
		}
		go func() {
			_, err = dn.sql_use_regtoken.Exec(nonce)
			if pgutil.IsError(err, pgutil.ErrUniqueViolation) {
				ticket_fresh <- false
			} else if err != nil {
				log.Fatalf("Lookup hash from blacklist: %s", err)
			} else {
				ticket_fresh <- true
			}
		}()
	}
	name, old_pk, _, err := dn.ValidateRequest(round+1, rq_bs)
	if err != nil {
		return
	}
	fmt.Printf("(%d, '<-ticket_fresh'),\n", time.Now().UnixNano())
	if old_pk == nil && (regtoken == nil || !<-ticket_fresh) {
		// FIXME: uncomment the next line to use ticketer to enable rate-limiting
		// return
	}
	fmt.Printf("(%d, 'lock name'),\n", time.Now().UnixNano())
	dn.lockednames_mutex.Lock()
	if _, locked := dn.lockednames[string(name)]; locked {
		dn.lockednames_mutex.Unlock()
		log.Printf("Name \"%s\" already locked for update", string(name))
		return
	} else {
		reply.TransferLooksGood = &_true
		dn.lockednames[string(name)] = struct{}{}
		dn.lockednames_mutex.Unlock()
		fmt.Printf("(%d, 'hand to round'),\n", time.Now().UnixNano())
		dn.c.IncomingRequests <- rq_bs
		// TODO: signed promise to transfer the name
	}
}

func (dn *Dename) ValidateRequest(dst_round int64, rq_bs []byte) (name []byte,
	old_pk, new_pk *sgp.Entity, err error) {
	fmt.Printf("(%d, 'NaiveParseRequest'),\n", time.Now().UnixNano())
	name, new_pk, proposedRoot, err := NaiveParseRequest(rq_bs)
	if err != nil {
		return
	}
	fmt.Printf("(%d, 'take snapshot id'),\n", time.Now().UnixNano())
	dn.round_processed.RLock()
	snapshot := dn.round_processed.Snapshot
	dn.round_processed.RUnlock()

	fmt.Printf("(%d, 'open snapshot'),\n", time.Now().UnixNano())
	mapHandle, err := dn.merklemap.GetSnapshot(snapshot).OpenHandle()
	if err != nil {
		log.Fatalf("mm.GetSnapshot(%d).OpenHandle(): %s", snapshot, err)
	}
	defer mapHandle.Close()
	old_pk, _ = dn.Resolve(mapHandle, name)
	if old_pk != nil {
		fmt.Printf("(%d, 'verify accept'),\n", time.Now().UnixNano())
		accept_bs, err := new_pk.Verify(rq_bs, protocol.SIGN_TAG_ACCEPT)
		if err != nil {
			return nil, nil, nil, err
		}
		accept := new(protocol.AcceptTransfer)
		if err := proto.Unmarshal(accept_bs, accept); err != nil {
			return nil, nil, nil, err
		}
		fmt.Printf("(%d, 'verify transfer'),\n", time.Now().UnixNano())
		if _, err = old_pk.Verify(accept.Transfer, protocol.SIGN_TAG_TRANSFER); err != nil {
			return nil, nil, nil, err
		}
	}

	fmt.Printf("(%d, 'check freshness'),\n", time.Now().UnixNano())
	fresh := false
	dn.fresh.RLock()
	for _, fresh_root := range dn.fresh.roots {
		if fresh = bytes.Equal(proposedRoot, fresh_root); fresh {
			break
		}
	}
	dn.fresh.RUnlock()
	if !fresh {
		return nil, nil, nil, errors.New("Not fresh enough")
	}
	return name, old_pk, new_pk, nil
}

func NaiveParseRequest(accept_signed_bs []byte) ([]byte, *sgp.Entity, []byte, error) {
	accept_signed := new(sgp.Signed)
	if err := proto.Unmarshal(accept_signed_bs, accept_signed); err != nil {
		return nil, nil, nil, err
	}
	accept := new(protocol.AcceptTransfer)
	if err := proto.Unmarshal(accept_signed.Message, accept); err != nil {
		return nil, nil, nil, err
	}
	transfer_signed := new(sgp.Signed)
	if err := proto.Unmarshal(accept.Transfer, transfer_signed); err != nil {
		return nil, nil, nil, err
	}
	transfer := new(protocol.TransferName)
	if err := proto.Unmarshal(transfer_signed.Message, transfer); err != nil {
		return nil, nil, nil, err
	}
	new_pk := new(sgp.Entity)
	if err := new_pk.Parse(transfer.PublicKey); err != nil {
		return nil, nil, nil, err
	}
	return transfer.Name, new_pk, accept.FreshRoot, nil
}

func (dn *Dename) HandleClientFreshness(reply *protocol.S2CMessage, round int64) {
	dn.round_completed.Lock()
	defer dn.round_completed.Unlock()
	for _, aux_bs_p := range dn.round_completed.AuxResults {
		reply.FreshnessAssertions = append(reply.FreshnessAssertions, *aux_bs_p)
	}
}

func (dn *Dename) QueueProcessor(peer_rq_map map[int64]*[][]byte,
	shared_prng *prng.PRNG, round int64) ([]byte, []byte) {
	rnd := rand.New(shared_prng)

	dn.round_processed.RLock()
	last_round, snapshot := dn.round_processed.Id, dn.round_processed.Snapshot
	dn.round_processed.RUnlock()

	var rootHash *[32]byte
	mapHandle, err := dn.merklemap.GetSnapshot(snapshot).OpenHandle()
	if err != nil {
		log.Fatalf("merklemap GetSnapshot(%d).OpenHandle(): %s", snapshot, err)
	}
	defer mapHandle.Close()

	if last_round > round {
		log.Fatalf("QueueProcessor(r%d) after done round %d", round, last_round)
	} else if last_round < round-1 {
		log.Fatalf("Skipped rounds between %d and %d", last_round, round)
	} else if round == last_round { // already processed
		if rootHash, err = mapHandle.GetRootHash(); err != nil {
			log.Fatalf("mapHandle.GetRootHash(): %s", err)
		}
	} else {
		// checking the modification times is non-idempotent, so do it in a tx
		tx, err := dn.db.Begin()
		if err != nil {
			log.Fatalf("dn.db.Begin(): %s", err)
		}
		defer func() {
			if err := tx.Commit(); err != nil {
				log.Fatalf("Commit last_modified and root: %s", err)
			}
		}()

		reset_modified, err := tx.Prepare(`DELETE from last_modified WHERE name = $1;`)
		if err != nil {
			log.Fatalf("PREPARE reset_modified: %s", err)
		}
		defer reset_modified.Close()
		set_modified, err := tx.Prepare(`INSERT INTO last_modified(name, round)
			VALUES($1,` + fmt.Sprint(round) + `);`)
		if err != nil {
			log.Fatalf("PREPARE set_modified: %s", err)
		}
		defer set_modified.Close()

		name_modified := make(map[string]int64)
		for _, i := range rnd.Perm(len(peer_rq_map)) {
			peer_id := int64(dn.peer_ids[i])
			for _, rq_bs := range *peer_rq_map[peer_id] {
				name, _, pk, err := dn.ValidateRequest(round, rq_bs)
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
				_, err = dn.sql_rainbow_insert.Exec(pk_hash[:], pk.Bytes)
				if err != nil && !pgutil.IsError(err, pgutil.ErrUniqueViolation) {
					log.Fatalf("QueueProcessor: rainbow_insert.Exec(...): %s", err)
				}
				if _, err := reset_modified.Exec(name); err != nil {
					log.Fatalf("reset_modified.Exec(name): %s", err)
				}
				if _, err := set_modified.Exec(name); err != nil {
					log.Fatalf("set_modified.Exec(name): %s", err)
				}
			}
		}

		rows, err := tx.Query(`SELECT name FROM last_modified WHERE round = $1`,
			round-dn.expirationTicks)
		if err != nil {
			log.Fatalf("last modified: %s", err)
		}
		names := make([][]byte, 0)
		for rows.Next() {
			var name []byte
			if err := rows.Scan(&name); err != nil {
				log.Fatalf("last_modified[i].Scan(&name): %s", err)
			}
			names = append(names, name)
		}
		rows.Close() // close before reusing tx due to postgres protocol

		for _, name := range names {
			log.Printf("mapHandle.Delete(merklemap.Hash(\"%s\"))", name)
			// if err = mapHandle.Delete(merklemap.Hash(name)); err != nil {
			//	log.Fatalf("mapHandle.Delete(name): %s", err)
			// }
			if _, err := reset_modified.Exec(name); err != nil {
				log.Fatalf("expiration: reset_modified.Exec(\"%s\"): %s", name, err)
			}
		}

		rootHash, err = mapHandle.GetRootHash()
		if err != nil {
			log.Fatalf("mapHandle.GetRootHash(): %s", err)
		}
		newNaming, err := mapHandle.FinishUpdate()
		if err != nil {
			log.Fatalf("mapHandle.FinishUpdate(): %s", err)
		}
		new_snapshot := newNaming.GetId()

		log.Printf("#%d = %x", round, *rootHash)
		_, err = tx.Exec(`INSERT INTO naming_snapshots(round, snapshot)
			VALUES($1,$2)`, round, new_snapshot)
		if err != nil {
			log.Fatalf("INSERT round %d snapshot %d: %s", round, new_snapshot, err)
		}

		dn.lockednames_mutex.Lock()
		for _, rq_bs := range *peer_rq_map[dn.us.id] {
			if name, _, _, err := NaiveParseRequest(rq_bs); err == nil {
				delete(dn.lockednames, string(name))
			} else {
				panic(err)
			}
		}
		dn.lockednames_mutex.Unlock()

		dn.round_processed.Lock()
		if dn.round_processed.Id != last_round {
			panic("dn.round_processed changed outside QueueProcessor")
		}
		dn.round_processed.Id, dn.round_processed.Snapshot = round, new_snapshot
		dn.round_processed.Unlock()
	}

	return rootHash[:], dn.MakeFreshnessAssertion(round, rootHash[:], false)
}

func (dn *Dename) MakeFreshnessAssertion(round int64, rootHash []byte, finalized bool) []byte {
	t := new(int64)
	*t = time.Now().Unix()
	freshness_bs, err := proto.Marshal(&protocol.FreshnessAssertion{
		Time: t, Root: rootHash, Round: &round, Finalized: &finalized})
	if err != nil {
		panic(err)
	}
	return dn.our_sk.Sign(freshness_bs, protocol.SIGN_TAG_FRESHNESS)
}

func (dn *Dename) MaintainFreshness(t0 time.Time, dt time.Duration) {
	time.Sleep(t0.Sub(time.Now()))
	d_half := dt / 2
	halves_passed := time.Now().Sub(t0) / d_half
	next_midpoint := t0.Add(halves_passed*d_half + d_half)
	if halves_passed%2 == 1 { // we are at a midpoint, wait more
		next_midpoint = next_midpoint.Add(d_half)
	}
	time.Sleep(next_midpoint.Sub(time.Now()))
	for t := range time.Tick(dt) {
		dn.round_completed.RLock()
		if dn.round_completed.RoundSummary == nil {
			dn.round_completed.RUnlock()
			continue
		}
		round, rootHash := dn.round_completed.Id, dn.round_completed.Result
		dn.round_completed.RUnlock()
		expected_round_finalized := int64(t.Sub(t0) / dt)
		if round > expected_round_finalized {
			log.Fatal("Ahead of schedule")
		} else if round == expected_round_finalized || round == -1 {
			continue // we are on time
		} // we are behind, let's compensate with freshness assertions
		freshness_signed_bs := dn.MakeFreshnessAssertion(round, rootHash, true)
		_, err := dn.db.Exec(`INSERT INTO auxresults(round,sender,result)
			VALUES($1,$2,$3)`, round, dn.us.id, freshness_signed_bs)
		if err != nil {
			log.Fatalf("Insert freshness to db %x: %s", freshness_signed_bs, err)
		}
		dn.round_completed.Lock()
		if dn.round_completed.Id != round {
			dn.round_completed.Unlock()
			continue
		}
		*dn.round_completed.AuxResults[dn.us.id] = freshness_signed_bs
		dn.round_completed.Unlock()
		for _, peer := range dn.peers {
			peer.DenameSend(freshness_signed_bs)
		}
	}
}

func (dn *Dename) FreshnessReceived(peer_id int64, freshness_signed_bs []byte) {
	freshness_bs, err := dn.peers[peer_id].pk.Verify(freshness_signed_bs,
		protocol.SIGN_TAG_FRESHNESS)
	if err != nil {
		log.Fatalf("%d Verify(freshness_signed_bs): %s", peer_id, err)
	}
	freshness := new(protocol.FreshnessAssertion)
	if err := proto.Unmarshal(freshness_bs, freshness); err != nil {
		log.Fatalf("%d proto.Unmarshal(freshness_bs, freshness): %s", peer_id, err)
	}
	var round_present int
	err = dn.db.QueryRow(`SELECT COUNT(1) FROM rounds WHERE id = $1 AND result = $2
		LIMIT 1`, *freshness.Round, freshness.Root).Scan(&round_present)
	if err != nil {
		log.Fatalf("SELECT round for freshness: %s (root %x)", err, freshness.Root)
	} else if round_present == 0 {
		log.Fatalf("Freshness for unknown round %d", *freshness.Round)
	}
	_, err = dn.db.Exec(`INSERT INTO auxresults(round,sender,result)
		VALUES($1,$2,$3)`, *freshness.Round, peer_id, freshness_signed_bs)
	if err != nil {
		log.Fatalf("Insert freshness to db %v: %s", freshness_signed_bs, err)
	}
	dn.round_completed.Lock()
	if *freshness.Round == dn.round_completed.Id {
		*dn.round_completed.AuxResults[peer_id] = freshness_signed_bs
	}
	dn.round_completed.Unlock()
}

type Int64Slice []int64

func (a Int64Slice) Len() int           { return len(a) }
func (a Int64Slice) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a Int64Slice) Less(i, j int) bool { return a[i] < a[j] }
