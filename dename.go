package main

import (
	"bytes"
	"code.google.com/p/go.crypto/nacl/secretbox"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	_ "github.com/mattn/go-sqlite3"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"code.google.com/p/goprotobuf/proto"
	"github.com/andres-erbsen/sgp"
	"github.com/daniel-ziegler/merklemap"
)

var errTag = errors.New("Bad tag on signed message")

type Peer struct {
	index int64
	addr  string
	pk    *sgp.Entity

	sync.RWMutex
	conn      net.Conn // mutable
	closeOnce *sync.Once
}

type Dename struct {
	db        *sql.DB
	our_sk    sgp.SecretKey
	us        *Peer
	peers     map[int64]*Peer
	addr2peer map[string]*Peer

	peer_lnr        *net.TCPListener
	client_lnr      net.Listener
	RoundForClients sync.RWMutex

	acks_for_consensus  chan *Acknowledgement
	keys_for_consensus  chan *S2SMessage
	roots_for_consensus chan *S2SMessage

	merklemap *merklemap.Map
}

func (dn *Dename) HandleMessage(peer *Peer, msg_bs []byte) (err error) {
	msg := new(S2SMessage)
	err = proto.Unmarshal(msg_bs, msg)
	if err != nil {
		return
	}
	if *msg.Server != peer.index {
		err = errors.New("HandleMessage: one peer impersonathing another")
	}
	round := *msg.Round

	switch {
	case msg.PushQueue != nil:
		return dn.HandlePush(peer, round, msg.PushQueue)
	case msg.Commitment != nil:
		return dn.HandleCommitment(peer, msg)
	case msg.Ack != nil:
		return dn.HandleAck(peer, msg.Ack)
	case msg.RoundKey != nil:
		return dn.HandleRoundKey(msg)
	case msg.Publish != nil:
		return dn.HandlePublish(peer, msg)
	default:
		return errors.New("Unknown message type")
	}
}

func (dn *Dename) HandlePush(peer *Peer, round int64, rq []byte) (err error) {
	_, err = dn.db.Exec(`INSERT INTO transaction_queue(round,introducer,request)
			VALUES($1,$2,$3);`, round, peer.index, rq)
	if isPGError(err, pgErrorUniqueViolation) {
		// log.Print("Ignoring duplicate transaction from ", peer.index)
		err = nil
	} else if err != nil {
		log.Fatal("Cannot insert new transaction to queue: ", err)
	}
	return
}

func (peer *Peer) UnmarshalVerify(signed_bs []byte, tag string,
	pb proto.Message, signed_msg_bs_p *[]byte) (err error) {
	if signed_msg_bs_p == nil {
		signed_msg_bs_p = &[]byte{}
	}
	*signed_msg_bs_p, err = peer.pk.Verify(signed_bs)
	if err != nil {
		return
	}
	signed_msg_bs := *signed_msg_bs_p
	if string(signed_msg_bs[:len(tag)]) != tag {
		return errTag
	}
	err = proto.Unmarshal(signed_msg_bs[len(tag):], pb)
	if err != nil {
		return
	}
	return
}

func (dn *Dename) HandleCommitment(peer *Peer, msg *S2SMessage) (err error) {
	commitment_msg := &Commitment{}
	commitment_msg_bs := &[]byte{}
	err = peer.UnmarshalVerify(msg.Commitment, "COMM",
		commitment_msg, commitment_msg_bs)
	if err != nil {
		return
	}
	if *commitment_msg.Server != peer.index {
		return errors.New("Bad server id on commitment")
	}
	ack_msg := &Acknowledgement{Acker: &dn.us.index, Commiter: &peer.index,
		Commitment: msg.Commitment}
	ack_bs, err := proto.Marshal(ack_msg)
	if err != nil {
		panic(err)
	}
	signed_ack_bs := dn.our_sk.Sign(append([]byte("ACKN"), ack_bs...))
	err = dn.HandleAck(dn.us, signed_ack_bs)
	if err != nil {
		panic(err)
	}
	dn.Broadcast(&S2SMessage{Round: msg.Round, Ack: signed_ack_bs})
	return nil
}

func (dn *Dename) HandleAck(acker *Peer, signed_ack_bs []byte) (err error) {
	ack_msg := new(Acknowledgement)
	acker.UnmarshalVerify(signed_ack_bs, "ACKN", ack_msg, nil)
	if err != nil {
		return
	}
	if *ack_msg.Acker != acker.index {
		return errors.New("Bad acker id on ack")
	}
	commiter := dn.peers[*ack_msg.Commiter]
	commitment_msg := &Commitment{}
	err = commiter.UnmarshalVerify(ack_msg.Commitment, "COMM", commitment_msg, nil)
	if err != nil {
		return
	}
	if *commitment_msg.Server != commiter.index {
		return errors.New("Bad server id on commitment")
	}
	_, err = dn.db.Exec(`INSERT INTO
			commitments(round,commiter,acknowledger,signature)
			VALUES($1,$2,$3,$4)`,
		*commitment_msg.Round, commiter.index, acker.index, signed_ack_bs)
	if isPGError(err, pgErrorUniqueViolation) {
		// log.Print("Ignoring duplicate ack from ", peer.index)
		err = nil
		return
	}
	// log.Print(peer.index, " acked ", *commitment.Server, " (round ", *commitment.Round, ")")
	// log.Print("Ack ", *commitment.Server, " from ", peer.index)
	go func() { // for efficency, one would use ana ctual elastic buffer channel
		dn.acks_for_consensus <- ack_msg
	}()
	return
}

func (dn *Dename) HandleRoundKey(msg *S2SMessage) (err error) {
	_, err = dn.db.Exec(`INSERT INTO round_keys(round,server,key)
			VALUES($1,$2,$3)`, *msg.Round, *msg.Server, msg.RoundKey)
	if isPGError(err, pgErrorUniqueViolation) {
		log.Print("Ignoring duplicate roundkey from ", msg.Server)
		err = nil
		return
	}
	go func() { // for efficency, one would use an actual elastic buffer channel
		dn.keys_for_consensus <- msg
	}()
	return
}

func (dn *Dename) HandlePublish(peer *Peer, msg *S2SMessage) (err error) {
	mapping_root_msg := new(MappingRoot)
	peer.UnmarshalVerify(msg.Publish, "ROOT", mapping_root_msg, nil)
	if err != nil {
		return
	}
	_, err = dn.db.Exec(`INSERT INTO round_signatures(round,server,signature)
			VALUES($1,$2,$3)`, *mapping_root_msg.Round, peer.index, mapping_root_msg.Root)
	if isPGError(err, pgErrorUniqueViolation) {
		log.Print("Ignoring duplicate signature from ", peer.index)
		err = nil
		return
	} else if err != nil {
		log.Fatal("Insert signature from peer: ", err)
	}
	go func() { // for efficency, one would use an actual elastic buffer channel
		dn.roots_for_consensus <- msg
	}()
	return
}

func (dn *Dename) WaitForTicks(round int64, end time.Time) (err error) {
	for {
		log.Print(round, time.Now().Second(), end.Second())
		if time.Now().After(end) {
			end = end.Add(TICK_INTERVAL)
			round++
			err = dn.ClientsToRound(round, end)
			if err != nil {
				log.Fatal("Cannot advance round: ", err)
			}
			if round > 0 {
				dn.Tick(round - 1)
			}
		}
		time.Sleep(end.Sub(time.Now()))
	}
}

func (dn *Dename) ClientsToRound(round int64, end time.Time) (err error) {
	var key [32]byte
	_, err = io.ReadFull(rand.Reader, key[:])
	if err != nil {
		return
	}
	dn.RoundForClients.Lock()
	defer dn.RoundForClients.Unlock()
	tx, err := dn.db.Begin()
	if err != nil {
		return
	}
	// to accept pushes into next round from peers
	_, err = tx.Exec(`INSERT INTO rounds(id, end_time)
		VALUES($1,$2)`, round+1, end.Add(TICK_INTERVAL).Unix())
	if err != nil {
		tx.Rollback()
		log.Fatal("Cannot insert to table rounds: ", err)
	}
	// we put new rq-s to the newest round that has a key
	_, err = tx.Exec(`INSERT INTO round_keys(round,server,key)
			VALUES($1,$2,$3)`, round, dn.us.index, key[:])
	if err != nil {
		tx.Rollback()
		return
	}
	tx.Commit()
	return
}

func (dn *Dename) ReadQueue(round, server int64) [][]byte {
	ret := make([][]byte, 0, 1)
	rows, err := dn.db.Query(`SELECT request FROM transaction_queue WHERE round
			= $1 AND introducer = $2 ORDER BY id`, round, server)
	if err != nil {
		log.Fatal("Cannot load transactions for tick: ", err)
	}
	defer rows.Close()
	var transaction []byte
	for rows.Next() {
		err := rows.Scan(&transaction)
		if err != nil {
			log.Fatal("Cannot load transaction for tick: ", err)
		}
		ret = append(ret, transaction)
	}
	ByteSlices(ret).Sort()
	// log.Printf("Queue of %d at %d has %d entries", server, round, len(ret))
	return ret
}

func HashCommitData(round, commiter int64, key []byte, Q [][]byte) (cdata []byte, err error) {
	commit_data_bytes, err := proto.Marshal(&CommitData{Round: &round, Server: &commiter, RoundKey: key, TransactionQueue: Q})
	if err != nil {
		panic(err)
	}
	h := sha256.New()
	_, err = h.Write(commit_data_bytes)
	if err != nil {
		return
	}
	log.Printf("Hashing queue of %d: %d items", commiter, len(Q))
	return h.Sum(nil), nil
}

func (dn *Dename) BringUpToDate(peer *Peer) {
	var round int64
	err := dn.db.QueryRow(`SELECT id FROM rounds
			WHERE commit_time IS NULL
			ORDER BY id ASC LIMIT 1`).Scan(&round)
	if err != nil {
		log.Fatal("Select last uncommited round: ", err)
	}
	if round > 0 {
		dn.RePushState(peer, round-1)
	}
	dn.RePushState(peer, round)
}

func (dn *Dename) RePushState(peer *Peer, round int64) {
	for _, rq_box := range dn.ReadQueue(round, dn.us.index) {
		dn.SendToPeer(peer, &S2SMessage{Round: &round, PushQueue: rq_box})
	}

	rows, err := dn.db.Query(`SELECT commiter, signature FROM
			commitments WHERE round = $1 AND acknowledger = $2`,
		round, dn.us.index)
	if err != nil {
		log.Fatal("BringUpToDate: Cannot load acks for round ", round, ": ", err)
	}
	defer rows.Close()
	for rows.Next() {
		var commiter int64
		var signed_ack_bs []byte
		err := rows.Scan(&commiter, &signed_ack_bs)
		if err != nil {
			log.Fatal("Cannot load ack from database: ", err)
		}
		// As we do not store commitments separately, send our own when seen
		if commiter == dn.us.index {
			ack_msg := &Acknowledgement{}
			err = dn.us.UnmarshalVerify(signed_ack_bs, "ACKN", ack_msg, nil)
			if err != nil {
				log.Fatal("RePushState: our self-ack in DB is bad")
			}
			dn.SendToPeer(peer, &S2SMessage{Round: &round, Commitment: ack_msg.Commitment})
		}
		dn.SendToPeer(peer, &S2SMessage{Round: &round, Ack: signed_ack_bs})
	}
	rows.Close()

	var our_round_key []byte
	err = dn.db.QueryRow(`SELECT key FROM round_keys WHERE
			server = $1 AND round = $2;`, dn.us.index, round).Scan(&our_round_key)
	if err != nil {
		log.Fatalf("RePushState: Cannot extract our round %d key: %f", round, err)
	}
	dn.Broadcast(&S2SMessage{Round: &round, RoundKey: our_round_key})
}

func (dn *Dename) Tick(round int64) {
	log.Print("Round ", round, " ended")
	//===== Commit to the queue and round key =====//
	var our_round_key []byte
	err := dn.db.QueryRow(`SELECT key FROM round_keys WHERE
			server = $1 AND round = $2;`, dn.us.index, round).Scan(&our_round_key)
	if err != nil {
		log.Fatalf("Cannot extract our round %d key: %f", round, err)
	}
	Q := dn.ReadQueue(round, dn.us.index)
	qh, err := HashCommitData(round, dn.us.index, our_round_key, Q)
	if err != nil {
		return
	}
	commitment_bs, err := proto.Marshal(&Commitment{Round: &round,
		Server: &dn.us.index, Hash: qh})
	if err != nil {
		panic(err)
	}
	signed_commitment_bs := dn.our_sk.Sign(append([]byte("COMM"), commitment_bs...))
	commitment_s2s := &S2SMessage{Round: &round, Commitment: signed_commitment_bs}
	err = dn.HandleCommitment(dn.us, commitment_s2s)
	if err != nil {
		log.Fatal(err)
	}
	dn.Broadcast(commitment_s2s)

	//===== Receive commitments and acknowledgements =====//
	n := len(dn.addr2peer)
	queueHash := make([][]byte, n)
	hasAcked := make([][]bool, n)
	for i := range hasAcked {
		hasAcked[i] = make([]bool, n)
	}
	acks_remaining := n * n

	rows, err := dn.db.Query("SELECT commiter,acknowledger,signature FROM commitments WHERE round = $1", round)
	if err != nil {
		log.Fatal("Cannot load commitments for round ", round, ": ", err)
	}
	quit := make(chan struct{})
	go func() {
		defer rows.Close()
		for rows.Next() {
			var commiter, acker int64
			var signed_ack_bs []byte
			err := rows.Scan(&commiter, &acker, &signed_ack_bs)
			if err != nil {
				log.Fatal("Cannot load ack from database: ", err)
			}
			ack_msg := new(Acknowledgement)
			dn.peers[acker].UnmarshalVerify(signed_ack_bs, "ACKN", ack_msg, nil)
			if err != nil {
				log.Fatal("Bad ack in database: ", err)
			}
			select {
			case dn.acks_for_consensus <- ack_msg:
			case <-quit:
				return
			}
		}
		<-quit
		log.Print("Loaded all relevant acks from table")
	}()

	for ack_msg := range dn.acks_for_consensus {
		commitment_msg := &Commitment{}
		err = dn.peers[*ack_msg.Commiter].UnmarshalVerify(ack_msg.Commitment,
			"COMM", commitment_msg, nil)
		if err != nil || *commitment_msg.Server != *ack_msg.Commiter {
			log.Fatal("Bad ack in validated zone: ", err)
		}
		if *commitment_msg.Round != round {
			continue
		}
		if queueHash[*commitment_msg.Server] == nil {
			queueHash[*commitment_msg.Server] = commitment_msg.Hash
		} else {
			if !bytes.Equal(queueHash[*commitment_msg.Server], commitment_msg.Hash) {
				log.Fatal("Server ", *commitment_msg.Server, " commited to multiple things")
			}
		}
		if !hasAcked[*ack_msg.Acker][*commitment_msg.Server] {
			acks_remaining--
			hasAcked[*ack_msg.Acker][*commitment_msg.Server] = true
		}
		if acks_remaining == 0 {
			break
		}
		//log.Print(a, " @ ", c, "; need ", acks_remaining, " more")
	}
	quit <- struct{}{}

	//===== Broadcast our round key =====//
	dn.Broadcast(&S2SMessage{Round: &round, RoundKey: our_round_key})

	//===== Receive round keys =====//
	hasKeyed := make([]bool, n)
	roundKeys := make([][32]byte, n)
	keys_remaining := n
	random_seed := int64(0)

	rows, err = dn.db.Query("SELECT server,key FROM round_keys WHERE round = $1", round)
	if err != nil {
		log.Fatal("Cannot load keys for round ", round, ": ", err)
	}
	go func() {
		defer rows.Close()
		for rows.Next() {
			var key []byte
			var server int64
			err := rows.Scan(&server, &key)
			if err != nil {
				log.Fatal("Cannot load key from database: ", err)
			}
			select {
			case dn.keys_for_consensus <- &S2SMessage{Round: &round, Server: &server, RoundKey: key}:
			case <-quit:
				return
			}
		}
		<-quit
	}()

	for msg := range dn.keys_for_consensus {
		log.Print("Round key from ", *msg.Server)
		if *msg.Round != round {
			continue
		}
		if !hasKeyed[*msg.Server] {
			if len(msg.RoundKey) != 32 {
				log.Fatal("Key of wrong size from %d", *msg.Server)
			}
			keys_remaining--
			hasKeyed[*msg.Server] = true
			copy(roundKeys[*msg.Server][:], msg.RoundKey)
			var rnd int64
			err = binary.Read(bytes.NewBuffer(msg.RoundKey), binary.LittleEndian, rnd)
			if err != nil {
				log.Fatal("Cannot read uint64LE from key ", err)
			}
			random_seed ^= rnd
		} else if !bytes.Equal(roundKeys[*msg.Server][:], msg.RoundKey) {
			log.Print(len(roundKeys[*msg.Server][:]), len(msg.RoundKey))
			log.Fatalf("Multiple round keys from %d in round %d", *msg.Server, round)
		}
		if keys_remaining == 0 {
			break
		}
	}
	quit <- struct{}{}

	//===== Check the commitments =====//
	queue := make([][][]byte, n)
	queueOk := make([]bool, n)
	for i := range dn.peers {
		go func(i int64) {
			var err error
			queue[i] = dn.ReadQueue(round, i)
			qh, err := HashCommitData(round, i, roundKeys[i][:], queue[i])
			if err != nil {
				log.Fatal("Cannot hash queue: ", err)
			}
			queueOk[i] = bytes.Equal(qh, queueHash[i])
			if !queueOk[i] {
				log.Printf("%d has bad queue hash", i)
			}
			quit <- struct{}{}
		}(i)
	}
	for _ = range dn.peers {
		<-quit
	}
	all_ok := true
	for i := range dn.peers {
		all_ok = all_ok && queueOk[i]
	}
	if !all_ok {
		log.Fatal("The commitments do not check out: ", queueOk)
	}
	log.Print("All commitments verified")

	//===== Decrypt the queues =====//
	peers_rq := make([]map[string][]byte, n)
	for i := range dn.peers { // only modify peers_rq in the main thread
		peers_rq[i] = make(map[string][]byte)
	}
	for i := range dn.peers {
		go func(i int64) {
			var nonce [24]byte
			for j, rq_box := range queue[i] {
				copy(nonce[:], rq_box[:24])
				var ok bool
				var err error
				rq_bs := []byte{}
				rq_bs, ok = secretbox.Open(rq_bs, rq_box[24:], &nonce, &roundKeys[i])
				if !ok {
					log.Fatal("Decryption failed at %d from %d in round %d", i, j, round)
				}
				name, err := dn.ValidateRequest(rq_bs)
				if err != nil {
					log.Fatal("Validation failed for \"%s\" from %d in round %d",
						name, i, round)
				}
				if _, present := peers_rq[i][name]; present {
					log.Fatalf("Multiple requests for \"%s\" from %d in round %d",
						name, i, round)
				}
				peers_rq[i][name] = rq_bs
			}
			quit <- struct{}{}
		}(i)
	}
	for _ = range dn.peers {
		<-quit
	}

	//===== Resolve conflicts =====//
	name_rqs := make(map[string][][]byte)
	for i := range dn.peers {
		for name, rq_bs := range peers_rq[i] {
			name_rqs[name] = append(name_rqs[name], rq_bs)
		}
	}
	name_rq := make(map[string][]byte)
	for name, rqs := range name_rqs {
		ByteSlices(rqs).Sort()
		d := uint64(random_seed) % uint64(len(rqs))
		name_rq[name] = rqs[d]
		log.Printf("Name \"%s\" transferred by option %d of %d", name, d+1, len(rqs))
	}

	prev_snapshot := int64(0)
	if round != 0 {
		err = dn.db.QueryRow(`SELECT naming_snapshot FROM rounds
				WHERE id = $1`, round-1).Scan(&prev_snapshot)
		if err != nil {
			log.Fatal("Get naming snapshot id of last round: ", err)
		}
	}

	stmt, err := dn.db.Prepare(`UPDATE name_mapping SET pubkey = $1 WHERE name = $2`)
	if err != nil {
		log.Fatal("PREPARE: Update names in database: %s", err)
	}
	defer stmt.Close()
	naming := dn.merklemap.GetSnapshot(prev_snapshot)
	for name, pk := range name_rq {
		_, err = stmt.Exec(pk, name)
		if err != nil {
			log.Fatal("Update name \"%s\" in database: %s", name, err)
		}
		name_hash := merklemap.Hash([]byte(name))
		pk_hash := merklemap.Hash(pk)
		err = naming.Set(name_hash, pk_hash)
		if err != nil {
			log.Fatal("Update name \"%s\" in merklemap: %s", name, err)
		}
	}
	stmt.Close()

	r, err := dn.db.Exec(`UPDATE rounds SET commit_time = $1, naming_snapshot = $2
		WHERE id = $3 AND commit_time IS NULL`, time.Now().Unix(), naming.Id, round)
	if err != nil {
		log.Fatalf("Mark round %d as commited in database: %s", round, err)
	}
	n_updates, _ := r.RowsAffected()
	if n_updates != 1 {
		log.Fatalf("Wanted to set commit_time for 1 round, hit %d instead", n_updates)
	}

	rh, _ := naming.GetRootHash()
	log.Printf("end dn.Tick(%d) -> %x", round, *rh)
}
