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

type Peer struct {
	index int
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
	peers     map[int]*Peer
	addr2peer map[string]*Peer

	peer_lnr        *net.TCPListener
	client_lnr      net.Listener
	RoundForClients sync.RWMutex

	acks_for_consensus chan VerifiedAckedCommitment
	keys_for_consensus chan *RoundKey

	merklemap *merklemap.Map
}

type VerifiedAckedCommitment struct {
	Commitment   *Commitment
	Acknowledger int
}

func (dn *Dename) HandleMessage(peer *Peer, msg []byte) (err error) {
	// log.Print("Received ", len(msg), " bytes from ", peer.addr)
	switch msg[0] {
	case 1:
		err = dn.HandlePush(peer, msg[1:])
	case 2:
		err = dn.HandleCommitment(peer, msg[1:])
	case 3:
		err = dn.HandleAck(peer, msg[1:])
	case 4:
		err = dn.HandleRoundKey(peer, msg[1:])
	default:
		err = errors.New("Unknown message type")
	}
	return err
}
func (dn *Dename) HandlePush(peer *Peer, rq []byte) (err error) {
	buf := bytes.NewBuffer(rq)
	var round uint64
	err = binary.Read(buf, binary.LittleEndian, &round)
	if err != nil {
		return
	}
	_, err = dn.db.Exec(`INSERT INTO transaction_queue(round,introducer,request)
			VALUES($1,$2,$3);`, round, peer.index, rq[8:])
	if isPGError(err, pgErrorUniqueViolation) {
		// log.Print("Ignoring duplicate transaction from ", peer.index)
		err = nil
	} else if err != nil {
		log.Fatal("Cannot insert new transaction to queue: ", err)
	}
	return
}

func (dn *Dename) HandleCommitment(peer *Peer, signed_commitment []byte) (err error) {
	// log.Print("Commit from ", peer.index)
	commitment, err := peer.pk.Verify(signed_commitment)
	if err != nil {
		return
	}
	if string(commitment[:4]) != "COMM" {
		return errors.New("Bad tag on commitment")
	}
	cd := &Commitment{}
	err = proto.Unmarshal(commitment[4:], cd)
	if err != nil {
		return
	}
	if *cd.Server != int64(peer.index) {
		return errors.New("Bad server id commitment")
	}
	ack := dn.our_sk.Sign(append([]byte("ACKN"), signed_commitment...))
	err = dn.HandleAck(dn.peers[dn.us.index], ack)
	if err != nil {
		panic(err)
	}
	dn.Broadcast(append([]byte{3}, ack...))
	return nil
}

func (dn *Dename) UnpackAckCommitment(c, a int, signed_ack_bs []byte) (commitdata *Commitment, err error) {
	// c = -1 means "extract c from commitment"
	if a >= len(dn.peers) || c >= len(dn.peers) || c < -1 || a < 0 {
		return nil, errors.New("No such peer")
	}
	ackdata, err := dn.peers[a].pk.Verify(signed_ack_bs)
	if err != nil {
		return nil, err
	}
	if string(ackdata[:4]) != "ACKN" {
		return nil, errors.New("Bad tag on ack")
	}
	if c == -1 {
		signed_commitment := &sgp.Signed{}
		err = proto.Unmarshal(ackdata[4:], signed_commitment)
		if err != nil {
			return nil, err
		}
		commitdata_ := &Commitment{}
		err = proto.Unmarshal(signed_commitment.Message[4:], commitdata_)
		if err != nil {
			return nil, err
		}
		c = int(*commitdata_.Server)
	}
	commitment, err := dn.peers[c].pk.Verify(ackdata[4:])
	if err != nil {
		return nil, err
	}
	if string(commitment[:4]) != "COMM" {
		return nil, errors.New("Bad tag on commitment")
	}
	commitdata = new(Commitment)
	err = proto.Unmarshal(commitment[4:], commitdata)
	if err != nil {
		return nil, err
	}
	if commitdata.GetServer() != int64(dn.peers[c].index) {
		return nil, errPeer
	}
	return
}

func UnverifiedUnpackAckCommitment(signed_ack_bs []byte) (commitdata *Commitment) { // for debugging
	commitdata = new(Commitment)
	signed_ack := &sgp.Signed{}
	err := proto.Unmarshal(signed_ack_bs, signed_ack)
	if err != nil {
		log.Fatal(err)
	}
	signed_commitment_bs := signed_ack.Message[4:] // starts with "ACKN"
	signed_commitment := &sgp.Signed{}
	err = proto.Unmarshal(signed_commitment_bs, signed_commitment)
	if err != nil {
		log.Fatal(err)
	}
	commitdata_bs := signed_commitment.Message[4:] // starts with "COMM"
	err = proto.Unmarshal(commitdata_bs, commitdata)
	if err != nil {
		log.Fatal(err)
	}
	return
}

func (dn *Dename) HandleAck(peer *Peer, signed_ack []byte) (err error) {
	commitment, err := dn.UnpackAckCommitment(-1, peer.index, signed_ack)
	if err != nil {
		return
	}
	_, err = dn.db.Exec(`INSERT INTO
			commitments(round,commiter,acknowledger,signature)
			VALUES($1,$2,$3,$4)`,
		commitment.Round, commitment.Server, peer.index, signed_ack)
	if isPGError(err, pgErrorUniqueViolation) {
		// log.Print("Ignoring duplicate ack from ", peer.index)
		err = nil
		return
	}
	// log.Print(peer.index, " acked ", *commitment.Server, " (round ", *commitment.Round, ")")
	// log.Print("Ack ", *commitment.Server, " from ", peer.index)
	go func() { // for efficency, one would use ana ctual elastic buffer channel
		dn.acks_for_consensus <- VerifiedAckedCommitment{
			Commitment: commitment, Acknowledger: peer.index}
	}()
	return
}

func (dn *Dename) HandleRoundKey(peer *Peer, rk_msg []byte) (err error) {
	rk_pb := new(RoundKey)
	err = proto.Unmarshal(rk_msg, rk_pb)
	if err != nil {
		return
	}
	if rk_pb.GetServer() != int64(peer.index) {
		return errPeer
	}
	_, err = dn.db.Exec(`INSERT INTO round_keys(round,server,key)
			VALUES($1,$2,$3)`, int(rk_pb.GetRound()), peer.index, rk_pb.Key)
	if isPGError(err, pgErrorUniqueViolation) {
		log.Print("Ignoring duplicate roundkey from ", peer.index)
		err = nil
		return
	}
	go func() { // for efficency, one would use ana ctual elastic buffer channel
		dn.keys_for_consensus <- rk_pb
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

func (dn *Dename) ReadQueue(round int64, server int) *Queue {
	round_, server_ := int64(round), int64(server)
	Q := &Queue{Round: &round_, Server: &server_, Entries: make([][]byte, 0, 1)}
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
		Q.Entries = append(Q.Entries, transaction)
	}
	ByteSlices(Q.Entries).Sort()
	// log.Printf("Queue of %d at %d has %d entries", server, round, len(Q.Entries))
	return Q
}

func HashKeyAndQueue(key []byte, Q *Queue) (cdata []byte, err error) {
	Q_bytes, err := proto.Marshal(Q)
	if err != nil {
		return
	}
	h := sha256.New()
	_, err = h.Write(key)
	if err != nil {
		return
	}
	_, err = h.Write(Q_bytes)
	if err != nil {
		return
	}
	log.Printf("Hashing queue of %d: %d items", Q.GetServer(), len(Q.Entries))
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
	for _, rq_box := range dn.ReadQueue(round, dn.us.index).Entries {
		mb := new(bytes.Buffer)
		mb.WriteByte(1)
		binary.Write(mb, binary.LittleEndian, uint64(round))
		mb.Write(rq_box)
		dn.SendToPeer(peer, mb.Bytes())
	}

	rows, err := dn.db.Query(`SELECT commiter, signature FROM
			commitments WHERE round = $1 AND acknowledger = $2`,
		round, dn.us.index)
	if err != nil {
		log.Fatal("BringUpToDate: Cannot load acks for round ", round, ": ", err)
	}
	defer rows.Close()
	for rows.Next() {
		var commiter int
		var signed_ack []byte
		err := rows.Scan(&commiter, &signed_ack)
		if err != nil {
			log.Fatal("Cannot load ack from database: ", err)
		}
		// As we do not store commitments separately, send our own when seen
		if commiter == dn.us.index {
			signed_ack_pb := &sgp.Signed{}
			err = proto.Unmarshal(signed_ack, signed_ack_pb)
			if err != nil {
				log.Fatal("BringUpToDate: our self-ack in DB is bad")
			}
			if string(signed_ack_pb.Message[:4]) != "ACKN" {
				log.Fatal("Our self-ack has bad tag in DB")
			}
			dn.SendToPeer(peer, append([]byte{2}, signed_ack_pb.Message[4:]...))
		}
		dn.SendToPeer(peer, append([]byte{3}, signed_ack...))
	}
	rows.Close()

	var our_round_key []byte
	err = dn.db.QueryRow(`SELECT key FROM round_keys WHERE
			server = $1 AND round = $2;`, dn.us.index, round).Scan(&our_round_key)
	if err != nil {
		log.Fatalf("BringUpToDate: Cannot extract our round %d key: %f", round, err)
	}
	rk_msg, err := proto.Marshal(roundKey(round, dn.us.index, our_round_key))
	if err != nil {
		log.Fatalf("BringUpToDate: Cannot marshal our round %d key: %f", round, err)
	}
	dn.SendToPeer(peer, append([]byte{4}, rk_msg...))
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
	qh, err := HashKeyAndQueue(our_round_key, Q)
	if err != nil {
		return
	}
	C := &Commitment{Round: Q.Round, Server: Q.Server, QueueHash: qh}
	commitdata, err := proto.Marshal(C)
	if err != nil {
		log.Fatal("Serialize commitment data: ", err)
	}
	commitment := dn.our_sk.Sign(append([]byte("COMM"), commitdata...))
	err = dn.HandleCommitment(dn.us, commitment)
	if err != nil {
		log.Fatal(err)
	}
	dn.Broadcast(append([]byte{2}, commitment...))

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
			var c, a int // commiter and acknowledger
			var ack []byte
			err := rows.Scan(&c, &a, &ack)
			if err != nil {
				log.Fatal("Cannot load ack from database: ", err)
			}
			commitment, err := dn.UnpackAckCommitment(c, a, ack)
			if err != nil {
				log.Fatal("Bad ack in database: ", err)
			}
			select {
			case dn.acks_for_consensus <- VerifiedAckedCommitment{
				Commitment:   commitment,
				Acknowledger: a}:
			case <-quit:
				return
			}
		}
		<-quit
		log.Print("Loaded all relevant acks from table")
	}()

	for ack := range dn.acks_for_consensus {
		if ack.Commitment.GetRound() != round {
			continue
		}
		a := ack.Acknowledger
		c := int(*ack.Commitment.Server)
		qh := ack.Commitment.QueueHash
		if queueHash[c] == nil {
			queueHash[c] = qh
		} else {
			if !bytes.Equal(queueHash[c], qh) {
				log.Fatal("Server ", c, " commited to multiple things")
			}
		}
		if !hasAcked[a][c] {
			acks_remaining--
			hasAcked[a][c] = true
		}
		if acks_remaining == 0 {
			break
		}
		//log.Print(a, " @ ", c, "; need ", acks_remaining, " more")
	}
	quit <- struct{}{}

	//===== Broadcast our round key =====//
	msg, err := proto.Marshal(roundKey(round, dn.us.index, our_round_key))
	if err != nil {
		log.Fatal(err)
	}
	dn.Broadcast(append([]byte{4}, msg...))

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
			var server int
			err := rows.Scan(&server, &key)
			if err != nil {
				log.Fatal("Cannot load key from database: ", err)
			}
			select {
			case dn.keys_for_consensus <- roundKey(round, server, key):
			case <-quit:
				return
			}
		}
		<-quit
	}()

	for keying := range dn.keys_for_consensus {
		log.Print("Round key from ", *keying.Server)
		if keying.GetRound() != int64(round) {
			continue
		}
		if !hasKeyed[*keying.Server] {
			if len(keying.Key) != 32 {
				log.Fatal("Key of wrong size from %d", *keying.Server)
			}
			keys_remaining--
			hasKeyed[*keying.Server] = true
			copy(roundKeys[*keying.Server][:], keying.Key)
			var a int64
			err = binary.Read(bytes.NewBuffer(keying.Key), binary.LittleEndian, &a)
			if err != nil {
				log.Fatal("Cannot read int64LE from key ", err)
			}
			random_seed ^= a
		} else if !bytes.Equal(roundKeys[*keying.Server][:], keying.Key) {
			log.Print(len(roundKeys[*keying.Server][:]), len(keying.Key))
			log.Fatalf("Multiple round keys from %d in round %d", *keying.Server, round)
		}
		if keys_remaining == 0 {
			break
		}
	}
	quit <- struct{}{}

	//===== Check the commitments =====//
	queue := make([]*Queue, n)
	queueOk := make([]bool, n)
	for i := range dn.peers {
		go func(i int) {
			var err error
			queue[i] = dn.ReadQueue(round, i)
			qh, err := HashKeyAndQueue(roundKeys[i][:], queue[i])
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
		go func(i int) {
			var nonce [24]byte
			for j, rq_box := range queue[i].Entries {
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

func roundKey(round int64, server int, key []byte) *RoundKey {
	server_ := int64(server)
	return &RoundKey{Round: &round, Server: &server_, Key: key}
}
