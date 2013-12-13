package main

import (
	"bytes"
	"code.google.com/p/go.crypto/nacl/secretbox"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"code.google.com/p/goprotobuf/proto"
	"github.com/andres-erbsen/dename/protocol"
	"github.com/andres-erbsen/sgp"
	"github.com/daniel-ziegler/merklemap"
)

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

	acks_for_consensus  chan *protocol.Acknowledgement
	keys_for_consensus  chan *protocol.S2SMessage
	roots_for_consensus chan *protocol.S2SMessage

	merklemap *merklemap.Map
}

func (dn *Dename) HandleMessage(peer *Peer, msg_bs []byte) (err error) {
	msg := new(protocol.S2SMessage)
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

func (peer *Peer) UnmarshalVerify(signed_bs []byte, tag uint64,
	pb proto.Message, signed_msg_bs_p *[]byte) (err error) {
	if signed_msg_bs_p == nil {
		signed_msg_bs_p = &[]byte{}
	}
	*signed_msg_bs_p, err = peer.pk.Verify(signed_bs, tag)
	if err != nil {
		return
	}
	err = proto.Unmarshal(*signed_msg_bs_p, pb)
	if err != nil {
		return
	}
	return
}

func (dn *Dename) HandleCommitment(peer *Peer, msg *protocol.S2SMessage) (err error) {
	commitment_msg := &protocol.Commitment{}
	err = peer.UnmarshalVerify(msg.Commitment, protocol.SIGN_TAG_COMMIT, commitment_msg, nil)
	if err != nil {
		return
	}
	if *commitment_msg.Server != peer.index {
		return errors.New("Bad server id on commitment")
	}
	ack_msg := &protocol.Acknowledgement{Acker: &dn.us.index, Commiter: &peer.index,
		Commitment: msg.Commitment}
	ack_bs, err := proto.Marshal(ack_msg)
	if err != nil {
		panic(err)
	}
	signed_ack_bs := dn.our_sk.Sign(ack_bs, protocol.SIGN_TAG_ACK)
	err = dn.HandleAck(dn.us, signed_ack_bs)
	if err != nil {
		panic(err)
	}
	dn.Broadcast(&protocol.S2SMessage{Round: msg.Round, Ack: signed_ack_bs})
	return nil
}

func (dn *Dename) HandleAck(acker *Peer, signed_ack_bs []byte) (err error) {
	ack_msg := new(protocol.Acknowledgement)
	acker.UnmarshalVerify(signed_ack_bs, protocol.SIGN_TAG_ACK, ack_msg, nil)
	if err != nil {
		return
	}
	if *ack_msg.Acker != acker.index {
		return errors.New("Bad acker id on ack")
	}
	commiter := dn.peers[*ack_msg.Commiter]
	commitment_msg := &protocol.Commitment{}
	err = commiter.UnmarshalVerify(ack_msg.Commitment, protocol.SIGN_TAG_COMMIT, commitment_msg, nil)
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

func (dn *Dename) HandleRoundKey(msg *protocol.S2SMessage) (err error) {
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

func (dn *Dename) HandlePublish(peer *Peer, msg *protocol.S2SMessage) (err error) {
	mapping_root_msg := new(protocol.MappingRoot)
	peer.UnmarshalVerify(msg.Publish, protocol.SIGN_TAG_PUBLISH, mapping_root_msg, nil)
	if err != nil {
		return
	}
	_, err = dn.db.Exec(`INSERT INTO round_signatures(round,server,signature)
			VALUES($1,$2,$3)`, *mapping_root_msg.Round, peer.index, msg.Publish)
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
	commit_data_bytes, err := proto.Marshal(&protocol.CommitData{Round: &round, Server: &commiter, RoundKey: key, TransactionQueue: Q})
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
		prev_round := round - 1
		dn.RePushState(peer, prev_round)
		var our_round_key []byte
		err = dn.db.QueryRow(`SELECT key FROM round_keys WHERE
				server = $1 AND round = $2;`, dn.us.index, prev_round).Scan(&our_round_key)
		if err != nil {
			log.Fatalf("RePushState: Cannot extract our round %d key: %f", prev_round, err)
		}
		dn.Broadcast(&protocol.S2SMessage{Round: &prev_round, RoundKey: our_round_key})
	}
	dn.RePushState(peer, round)
}

func (dn *Dename) RePushState(peer *Peer, round int64) {
	for _, rq_box := range dn.ReadQueue(round, dn.us.index) {
		dn.SendToPeer(peer, &protocol.S2SMessage{Round: &round, PushQueue: rq_box})
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
			ack_msg := &protocol.Acknowledgement{}
			err = dn.us.UnmarshalVerify(signed_ack_bs, protocol.SIGN_TAG_ACK, ack_msg, nil)
			if err != nil {
				log.Fatal("RePushState: our self-ack in DB is bad")
			}
			dn.SendToPeer(peer, &protocol.S2SMessage{Round: &round, Commitment: ack_msg.Commitment})
		}
		dn.SendToPeer(peer, &protocol.S2SMessage{Round: &round, Ack: signed_ack_bs})
	}
	rows.Close()

	var our_signed_publish_bs []byte
	err = dn.db.QueryRow(`SELECT signature FROM round_signatures
			WHERE round = $1 AND server = $2`, round, dn.us.index).Scan(&our_signed_publish_bs)
	if err != nil {
		log.Print("Cannot load our signature for round ", round, ": ", err)
	}
	dn.SendToPeer(peer, &protocol.S2SMessage{Round: &round, Publish: our_signed_publish_bs})
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
	commitment_bs, err := proto.Marshal(&protocol.Commitment{
		Round: &round, Server: &dn.us.index, Hash: qh})
	if err != nil {
		panic(err)
	}
	signed_commitment_bs := dn.our_sk.Sign(commitment_bs, protocol.SIGN_TAG_COMMIT)
	commitment_s2s := &protocol.S2SMessage{Round: &round, Commitment: signed_commitment_bs}
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
			ack_msg := new(protocol.Acknowledgement)
			dn.peers[acker].UnmarshalVerify(signed_ack_bs, protocol.SIGN_TAG_ACK, ack_msg, nil)
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
		commitment_msg := &protocol.Commitment{}
		err = dn.peers[*ack_msg.Commiter].UnmarshalVerify(ack_msg.Commitment,
			protocol.SIGN_TAG_COMMIT, commitment_msg, nil)
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
	dn.Broadcast(&protocol.S2SMessage{Round: &round, RoundKey: our_round_key})

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
			case dn.keys_for_consensus <- &protocol.S2SMessage{
				Round: &round, Server: &server, RoundKey: key}:
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
				log.Fatalf("Key of wrong size from %d", *msg.Server)
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
	peer_name_newpks := make([]map[string][]byte, n)
	for i := range dn.peers { // only modify _name_newpks in the main thread
		peer_name_newpks[i] = make(map[string][]byte)
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
					log.Fatalf("Decryption failed at %d from %d in round %d", i, j, round)
				}
				name, pk, err := dn.ValidateRequest(rq_bs)
				if err != nil {
					log.Fatalf("Validation failed for \"%s\" from %d in round %d",
						name, i, round)
				}
				if _, present := peer_name_newpks[i][name]; present {
					log.Fatalf("Multiple requests for \"%s\" from %d in round %d",
						name, i, round)
				}
				peer_name_newpks[i][name] = pk.Bytes
			}
			quit <- struct{}{}
		}(i)
	}
	for _ = range dn.peers {
		<-quit
	}

	//===== Resolve conflicts =====//
	name_newpks := make(map[string][][]byte)
	for i := range dn.peers {
		for name, pk := range peer_name_newpks[i] {
			name_newpks[name] = append(name_newpks[name], pk)
		}
	}
	name_newpk := make(map[string][]byte)
	for name, pks := range name_newpks {
		ByteSlices(pks).Sort()
		d := uint64(random_seed) % uint64(len(pks))
		name_newpk[name] = pks[d]
		log.Printf("Name \"%s\" transferred by option %d of %d", name, d+1, len(pks))
	}

	//===== Update names locally =====//
	prev_snapshot := int64(0)
	if round != 0 {
		err = dn.db.QueryRow(`SELECT naming_snapshot FROM rounds
				WHERE id = $1`, round-1).Scan(&prev_snapshot)
		if err != nil {
			log.Fatal("Get naming snapshot id of last round: ", err)
		}
	}

	naming := dn.merklemap.GetSnapshot(prev_snapshot)
	mapHandle, err := naming.OpenHandle()

	stmt1, err := dn.db.Prepare(`UPDATE name_mapping
				SET pubkey = $1, last_modified = $2
				WHERE name = $3;`)
	if err != nil {
		log.Fatalf("PREPARE: Update names in database: %s", err)
	}
	defer stmt1.Close()
	stmt2, err := dn.db.Prepare(`
				INSERT INTO name_mapping (pubkey, last_modified, name)
				SELECT $1,$2,$3
				WHERE NOT EXISTS (SELECT 1 FROM name_mapping WHERE name=$3);`)
	if err != nil {
		log.Fatalf("PREPARE: Update names in database: %s", err)
	}
	defer stmt2.Close()
	if err != nil {
		log.Fatalf("Error opening merklemap handle: %s", err)
	}
	for name, pk := range name_newpk {
		_, err = stmt1.Exec(pk, round, name)
		if err != nil {
			log.Fatalf("Update name \"%s\" in database: %s", name, err)
		}
		_, err = stmt2.Exec(pk, round, name)
		if err != nil {
			log.Fatalf("Insert name \"%s\" to database: %s", name, err)
		}
		name_hash := merklemap.Hash([]byte(name))
		pk_hash := merklemap.Hash(pk)
		err = mapHandle.Set(name_hash, pk_hash)
		if err != nil {
			log.Fatalf("Update name \"%s\" in merklemap: %s", name, err)
		}
	}
	stmt1.Close()
	stmt2.Close()

	rootHash, err := mapHandle.GetRootHash()
	if err != nil {
		log.Fatalf("Error getting root hash: %s", err)
	}

	newNaming, err := mapHandle.FinishUpdate()
	if err != nil {
		log.Fatalf("Error closing merklemap handle: %s", err)
	}

	//===== Sign the new mapping =====//
	our_publish_bs, err := proto.Marshal(&protocol.MappingRoot{
		Round: &round, Root: rootHash[:]})
	if err != nil {
		panic(err)
	}
	signed_root := dn.our_sk.SignPb(our_publish_bs, protocol.SIGN_TAG_PUBLISH)
	our_signed_publish_bs, err := proto.Marshal(signed_root)
	if err != nil {
		panic(err)
	}
	publish_s2s := &protocol.S2SMessage{Server: &dn.us.index,
		Round: &round, Publish: our_signed_publish_bs}
	err = dn.HandlePublish(dn.us, publish_s2s)
	if err != nil {
		panic(err)
	}
	dn.Broadcast(publish_s2s)

	//===== Collect signatures from peers =====//
	hasSigned := make([]bool, n)
	sigs_remaining := n
	rows, err = dn.db.Query("SELECT server,signature FROM round_signatures WHERE round = $1", round)
	if err != nil {
		log.Fatal("Cannot load signatures for round ", round, ": ", err)
	}
	go func() {
		defer rows.Close()
		for rows.Next() {
			var signed_publish_bs []byte
			var server int64
			err := rows.Scan(&server, &signed_publish_bs)
			if err != nil {
				log.Fatal("Cannot load round signature from database: ", err)
			}
			pub_tmp := &protocol.S2SMessage{Server: &server,
				Round: &round, Publish: signed_publish_bs[:]}
			select {
			case dn.roots_for_consensus <- pub_tmp:
			case <-quit:
				return
			}
		}
		<-quit
	}()

	for msg := range dn.roots_for_consensus {
		if *msg.Round != round {
			continue
		}
		peer := dn.peers[*msg.Server]
		signed := new(sgp.Signed)
		err = proto.Unmarshal(msg.Publish, signed)
		if err != nil {
			log.Fatal("Bad publish from %d: %f", peer.index, err)
		}
		if len(signed.Sigs) != 1 {
			log.Fatalf("len(signed.Sigs) != 1 for publish from %d", peer.index)
		}
		if len(signed.KeyIds) != 1 {
			log.Fatalf("len(signed.KeyIds) != 1 for publish from %d", peer.index)
		}
		if !peer.pk.VerifyPb(signed, protocol.SIGN_TAG_PUBLISH) {
			log.Fatal("Invalid signature on publish from %d: %f", peer.index, err)
		}
		if !bytes.Equal(signed.Message, our_publish_bs) {
			log.Fatalf("Peer %d deviates from consensus:\n  %v\n  %v", peer.index, our_publish_bs, signed.Message)
		}
		if !hasSigned[peer.index] {
			sigs_remaining--
			hasSigned[peer.index] = true
			signed_root.Sigs = append(signed_root.Sigs, signed.Sigs[0])
			signed_root.KeyIds = append(signed_root.KeyIds, signed.KeyIds[0])
		}
		if sigs_remaining == 0 {
			break
		}
	}
	quit <- struct{}{}
	signed_root_bs, err := proto.Marshal(signed_root)
	if err != nil {
		panic(err)
	}

	r, err := dn.db.Exec(`UPDATE rounds SET commit_time = $1, naming_snapshot = $2,
		signed_root = $3 WHERE id = $4 AND commit_time IS NULL`,
		time.Now().Unix(), newNaming.GetId(), signed_root_bs, round)
	if err != nil {
		log.Fatalf("Mark round %d as commited in database: %s", round, err)
	}
	n_updates, _ := r.RowsAffected()
	if n_updates != 1 {
		log.Fatalf("Wanted to set commit_time for 1 round, hit %d instead", n_updates)
	}

	log.Printf("Round %d reached consensus at %x", round, *rootHash)
}
