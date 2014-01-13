package consensus

import (
	"bytes"
	"code.google.com/p/go.crypto/nacl/secretbox"
	"code.google.com/p/goprotobuf/proto"
	"crypto/rand"
	"crypto/sha256"
	"github.com/andres-erbsen/dename/pgutil"
	"github.com/andres-erbsen/dename/prng"
	"github.com/andres-erbsen/dename/ringchannel"
	"github.com/andres-erbsen/sgp"
	"log"
	"sort"
	"sync"
	"time"
)

// round is a sequence of communication and computation steps that results in
// zero or requests being handled, possibly mutating some shared state.
type round struct {
	c *Consensus // const pointer, target not mutated from round

	id               int64     // const
	openAtLeastUntil time.Time // const
	next             *round    // pointer set by the .previous after keys

	// const
	afterRequests         chan struct{}
	afterCommitments      chan struct{}
	afterAcknowledgements chan struct{}
	afterKeys             chan struct{}
	afterWeHavePublished  chan struct{}
	afterPublishes        chan struct{}

	// the maps are const, pointer targets are mutable
	requests map[int64]*[][]byte           // populated by key handler decryptor (us: rq handler)
	pushes   map[int64]map[[24]byte][]byte // populated by push handler (us: rq handler)
	commited map[int64]*[]byte             // set by commitment handler

	our_round_key *[32]byte  // const
	shared_prng   *prng.PRNG // pointer set at the end of key handler after
	signed_result *sgp.Signed
}

func newRound(id int64, t time.Time, c *Consensus) (r *round) {
	r = new(round)
	r.id = id
	r.openAtLeastUntil = t
	r.c = c
	r.afterRequests = make(chan struct{})
	r.afterCommitments = make(chan struct{})
	r.afterAcknowledgements = make(chan struct{})
	r.afterKeys = make(chan struct{})
	r.afterWeHavePublished = make(chan struct{})
	r.afterPublishes = make(chan struct{})
	r.requests = make(map[int64]*[][]byte, len(r.c.Peers))
	r.pushes = make(map[int64]map[[24]byte][]byte, len(r.c.Peers))
	r.commited = make(map[int64]*[]byte, len(r.c.Peers))
	r.our_round_key = new([32]byte)

	for id := range c.Peers {
		r.requests[id] = new([][]byte)
		r.pushes[id] = make(map[[24]byte][]byte)
		r.commited[id] = new([]byte)
	}
	*r.requests[r.c.our_id] = make([][]byte, 0)

	if _, err := rand.Read(r.our_round_key[:]); err != nil {
		log.Fatalf("rand.Read(r.our_round_key[:]):]): %s", err)
	}

	_, err := r.c.db.Exec(`INSERT INTO rounds(id, our_key, close_time)
		VALUES($1,$2,$3)`, id, r.our_round_key[:], t.Unix())
	if pgutil.IsError(err, pgutil.ErrUniqueViolation) {
		var key_bs []byte
		if err := r.c.db.QueryRow(`SELECT our_key FROM rounds
			WHERE id = $1`, id).Scan(&key_bs); err != nil {
			log.Fatalf("our_key FROM rounds: %s", err)
		}
		copy(r.our_round_key[:], key_bs)
	} else if err != nil {
		log.Fatalf("Insert round id,close_time: %s", err)
	}
	return
}

func (r *round) haveWeCommitted() bool {
	var count int
	err := r.c.db.QueryRow(`SELECT COUNT(*) FROM messages WHERE round = $1
		AND sender = $2 AND type = $3`, r.id, r.c.our_id, COMMITMENT).Scan(&count)
	if err != nil {
		log.Fatalf("haveWeCommitted() round %d: %s", r.id, err)
	}
	return count > 0
}

// ColdStart starts the first round in a sequence, possibly right after newRound
func (r *round) ColdStart() {
	if r.haveWeCommitted() {
		// Don't actually open this round for clients again
		go func() {
			// (but do pretend to close it at the end)
			<-r.afterRequests
		}()
	} else {
		go r.acceptRequests(r.c.IncomingRequests)
	}
	r.startAcceptingPushes()
	r.startHandlingCommitments()
	r.startHandlingAcknowledgements()
	r.next.startAcceptingPushes()
	go r.Process()
}

// Process processes the requests a round has received. It is assumed that the
// round is currently receiving requests.
//
// Each round goes through the following general phases:
//
// 	1. Accept requests from clients until the end time is reached or the
// 	previous round is finalized, whichever happens later. All requests are
// 	encrypted and then pushed to other servers automatically.
//	2. Commit to the queue of requests and wait for each server's
//	commitment to be acknowledged by every other server.
//	3. Reveal the queue and wait for others to reveal their queues
// 	4. Process the requests
//	5. Sign the resulting state and receive signatures from other servers
//
// At most three rounds can be active at once. If we have not published the
// signed result round i, other servers cannot have finalized it so the last
// round they can be accepting requests for is i+1. If we have published the
// signed result but have not yet received the results from others, it may be
// still the case that they have proceeded: they may be processing round i+1 and
// accepting requests for i+2 and pushing them to us.
func (r *round) Process() {
	time.Sleep(r.openAtLeastUntil.Sub(time.Now()))
	log.Printf("processing round %v", r.id)
	r.afterRequests <- struct{}{}
	close(r.afterRequests)
	go r.next.acceptRequests(r.c.IncomingRequests)
	r.commitToQueue()

	<-r.afterCommitments
	log.Printf("round %v: got commitments", r.id)
	r.c.router.Close(r.id, PUSH)
	<-r.afterAcknowledgements
	log.Printf("round %v: got acks", r.id)

	r.startHandlingPublishes()
	r.revealRoundKey()

	<-r.afterKeys
	log.Printf("round %v: got keys", r.id)
	result := r.c.QueueProcessor(r.requests, r.shared_prng, r.id)
	r.next.startHandlingCommitments()
	r.next.startHandlingAcknowledgements()
	r.next.next = newRound(r.next.id+1, r.next.openAtLeastUntil.Add(r.c.TickInterval), r.c)
	r.next.next.startAcceptingPushes()
	r.Publish(result)

	<-r.afterPublishes
	log.Printf("round %v: got publishes", r.id)
	go r.next.Process()
}

// acceptRequests accepts clients.
// A round starts acceptRequests on the next round as soon soon as it
// stops handling requests itself, handing the channel of incoming requests over
// to the next round.
func (r *round) acceptRequests(rqs <-chan []byte) {
loop:
	for {
		select {
		case rq_bs := <-rqs:
			*r.requests[r.c.our_id] = append(*r.requests[r.c.our_id], rq_bs)
			nonce := new([24]byte)
			if _, err := rand.Read(nonce[:]); err != nil {
				log.Fatalf("rand.Read(rq_box): %s", err)
			}
			rq_box := secretbox.Seal(nonce[:], rq_bs, nonce, r.our_round_key)
			r.pushes[r.c.our_id][*nonce] = rq_box
			r.c.broadcast(&ConsensusMSG{Round: &r.id, PushQueue: rq_box})
		case <-r.afterRequests:
			break loop
		}
	}
}

// startAcceptingPushes handles pushes from servers.
// A round should be accept pushes as long as any other server may be
// accept requests for that round.
// When round i publishes the last message other servers would need from us to
// finalize that round, other servers may start processing the next round and
// accept requests to the round after that. Therefore, startAcceptingPushes
// is called on round i+2.
func (r *round) startAcceptingPushes() {
	r.c.router.Receive(r.id, PUSH, func(msg *ConsensusMSG) bool {
		nonce := [24]byte{}
		copy(nonce[:], msg.PushQueue[:24])
		r.pushes[*msg.Server][nonce] = msg.PushQueue
		return false
	})
}

// commitToQueue hashes our queue, signs it and publishes the result
func (r *round) commitToQueue() {
	our_id := r.c.our_id
	qh := HashCommitData(r.id, our_id, r.our_round_key[:], r.pushes[our_id])
	log.Printf("queue hash: %v, %x", len(r.pushes[our_id]), qh)
	commitment_bs, err := proto.Marshal(&Commitment{
		Round: &r.id, Server: &our_id, Hash: qh})
	if err != nil {
		panic(err)
	}
	signed_commitment_bs := r.c.our_sk.Sign(commitment_bs, r.c.sign_tags[COMMITMENT])
	s2s := &ConsensusMSG{Round: &r.id, Commitment: signed_commitment_bs}
	r.c.broadcast(s2s)
}

// checkCommitmentUnique checks that a commitment is valid and the peer has
// not commited to anything else in this round
func (r *round) checkCommitmentUnique(peer_id int64, signed_bs []byte) {
	peer := r.c.Peers[peer_id]
	commitment_bs, err := peer.PK().Verify(signed_bs, r.c.sign_tags[COMMITMENT])
	if err != nil {
		log.Fatalf("peer.PK().Verify(bs, r.c.sign_tags[COMMITMENT]): %s", err)
	}
	commitment := new(Commitment)
	if err := proto.Unmarshal(commitment_bs, commitment); err != nil {
		log.Fatalf("proto.Unmarshal(commitment_bs, commitment): %s", err)
	}
	if *commitment.Round != r.id || *commitment.Server != peer_id {
		log.Fatalf("Inconsistently labelled commitment")
	}
	if peer_id != r.c.our_id {
		if *r.commited[peer_id] == nil {
			*r.commited[peer_id] = commitment.Hash
		} else if !bytes.Equal(*r.commited[peer_id], commitment.Hash) {
			log.Fatalf("Multiple different commitments from %d: %v and %v", peer_id, *r.commited[peer_id], commitment.Hash)
		}
	}
}

// startHandlingCommitments acknowledges commitments
// received from other servers. As a server may start processing a round as soon
// as it finalizes the previous one, a round calls startHandlingCommitments on
// the next one right before sending out the last message other servers have to
// wait for.
func (r *round) startHandlingCommitments() {
	ack := &Acknowledgement{Acker: &r.c.our_id}
	hasCommited := make(map[int64]struct{})
	r.c.router.Receive(r.id, COMMITMENT, func(msg *ConsensusMSG) bool {
		r.checkCommitmentUnique(*msg.Server, msg.Commitment)
		hasCommited[*msg.Server] = struct{}{}
		done := len(hasCommited) == len(r.c.Peers)-1
		if done {
			r.startHandlingKeys()
		}
		// send an ack
		ack.Commiter, ack.Commitment = msg.Server, msg.Commitment
		ack_bs, err := proto.Marshal(ack)
		if err != nil {
			panic(err)
		}
		signed_ack_bs := r.c.our_sk.Sign(ack_bs, r.c.sign_tags[ACKNOWLEDGEMENT])
		r.c.broadcast(&ConsensusMSG{Round: msg.Round, Ack: signed_ack_bs})
		if done {
			close(r.afterCommitments)
		}
		return done
	})
}

// startHandlingAcknowledgements receives acknowledgements.
// Called together with startHandlingCommitments because as soon as a commitment
// is sent out, acknowledgements from all servers should follow.
func (r *round) startHandlingAcknowledgements() {
	acknowledgersRemaining := len(r.c.Peers) - 1 // don't track our own acks
	hasAcked := make(map[int64]map[int64]struct{})
	for id := range r.c.Peers {
		if id != r.c.our_id {
			hasAcked[id] = make(map[int64]struct{})
		}
	}
	ack := new(Acknowledgement)
	r.c.router.Receive(r.id, ACKNOWLEDGEMENT, func(msg *ConsensusMSG) bool {
		peer := r.c.Peers[*msg.Server]
		ack_bs, err := peer.PK().Verify(msg.Ack, r.c.sign_tags[ACKNOWLEDGEMENT])
		if err != nil {
			log.Fatalf("peer.PK().Verify(msg.Ack, r.c.sign_tags[ACKNOWLEDGEMENT]): %s", err)
		}
		if err := proto.Unmarshal(ack_bs, ack); err != nil {
			log.Fatalf("proto.Unmarshal(ack_bs, ack): %s", err)
		}
		if *msg.Server != *ack.Acker {
			log.Fatalf("Peer %d acked as %d", *msg.Server, *ack.Acker)
		}
		if *ack.Commiter == *ack.Acker {
			log.Printf("Peer %d acked themselves", *msg.Server)
			return false
		}
		r.checkCommitmentUnique(*ack.Commiter, ack.Commitment)
		if _, already := hasAcked[*ack.Acker][*ack.Commiter]; !already {
			hasAcked[*ack.Acker][*ack.Commiter] = struct{}{}
			if len(hasAcked[*ack.Acker]) == len(r.c.Peers)-1 {
				acknowledgersRemaining--
			}
		}
		done := acknowledgersRemaining == 0
		if done {
			close(r.afterAcknowledgements)
		}
		return done
	})
}

func (r *round) revealRoundKey() {
	r.c.broadcast(&ConsensusMSG{Round: &r.id, RoundKey: r.our_round_key[:]})
}

// startHandlingKeys receives
// keys and spawns workers to decrypt the queues.
// As a server should not reveal their round key before they have seen all the
// acknowledgements, startHandlingKeys is called before we acknowledge the last
// commitment of that round.
func (r *round) startHandlingKeys() {
	var decryptions sync.WaitGroup
	keys := make(map[int64]*[32]byte, len(r.c.Peers))
	keys[r.c.our_id] = r.our_round_key
	decryptions.Add(2*len(r.c.Peers) - 2)
	r.c.router.Receive(r.id, ROUNDKEY, func(msg *ConsensusMSG) bool {
		if _, already := keys[*msg.Server]; !already {
			keys[*msg.Server] = new([32]byte)
			copy(keys[*msg.Server][:], msg.RoundKey)
		} else if bytes.Equal(keys[*msg.Server][:], msg.RoundKey) {
			log.Printf("%d sent same key twice", *msg.Server)
			return false
		} else {
			log.Fatalf("%d keys: %v and %v", *msg.Server, keys[*msg.Server][:], msg.RoundKey)
		}
		go func(peer_id int64, key *[32]byte) { // decrypt requests
			defer decryptions.Done()
			rqs := make([][]byte, len(r.pushes[peer_id]))
			i := 0
			for nonce, rq_box := range r.pushes[peer_id] {
				var ok bool
				rqs[i], ok = secretbox.Open(nil, rq_box[24:], &nonce, key)
				if !ok {
					log.Fatalf("Failed to decrypt %d's queue %x key %x", peer_id, rq_box, *key)
				}
				i++
			}
			*r.requests[peer_id] = rqs
		}(*msg.Server, keys[*msg.Server])
		go func(peer_id int64, key *[32]byte) { // verify commitments
			defer decryptions.Done()
			qh := HashCommitData(r.id, peer_id, key[:], r.pushes[peer_id])
			if !bytes.Equal(qh, *r.commited[peer_id]) {
				log.Fatalf("%d has bad queue hash: %v, %x, %x", peer_id, len(r.pushes[peer_id]), qh, *r.commited[peer_id])
			}
		}(*msg.Server, keys[*msg.Server])
		return len(keys) == len(r.c.Peers)
	})
	go func() {
		decryptions.Wait()
		// seed the shared prng
		h := sha256.New()
		for id := range r.c.Peers {
			h.Write(keys[id][:])
		}
		seed := new([32]byte)
		seed_bs := h.Sum(nil)
		copy(seed[:], seed_bs)
		r.shared_prng = prng.NewPRNG(seed)
		close(r.afterKeys)
	}()
}

func (r *round) Publish(result []byte) {
	publish_bs, err := proto.Marshal(&ConsensusResult{
		Round: &r.id, Result: result})
	if err != nil {
		panic(err)
	}
	r.signed_result = r.c.our_sk.SignPb(publish_bs, r.c.sign_tags[PUBLISH])
	signed_bs, err := proto.Marshal(r.signed_result)
	if err != nil {
		panic(err)
	}
	r.c.broadcast(&ConsensusMSG{Server: &r.c.our_id,
		Round: &r.id, Publish: signed_bs})
	close(r.afterWeHavePublished)
}

// startHandlingPublishes receives publish messages and verifies them.
// As a server should not publish the result of a round before decrypting all
// the queues, startHandlingPublishes is called right before we reveal the key used to
// encrypt our queue.
func (r *round) startHandlingPublishes() {
	// actually chan *sgp.Signed
	publishesIn := make(chan interface{})
	publishesNext := make(chan interface{})
	go ringchannel.RingIQ(publishesIn, publishesNext)
	hasPublished := make(map[int64]struct{})
	r.c.router.Receive(r.id, PUBLISH, func(msg *ConsensusMSG) bool {
		signed := new(sgp.Signed)
		err := proto.Unmarshal(msg.Publish, signed)
		if err != nil {
			log.Fatalf("Bad publish from %d: %f", *msg.Server, err)
		}
		if len(signed.Sigs) != 1 {
			log.Fatalf("len(signed.Sigs) != 1 for publish from %d", *msg.Server)
		}
		if len(signed.KeyIds) != 1 {
			log.Fatalf("len(signed.KeyIds) != 1 for publish from %d", *msg.Server)
		}
		if !r.c.Peers[*msg.Server].PK().VerifyPb(signed, r.c.sign_tags[PUBLISH]) {
			log.Fatalf("Invalid signature on publish from %d: %f", *msg.Server, err)
		}
		if _, already := hasPublished[*msg.Server]; !already {
			hasPublished[*msg.Server] = struct{}{}
			// Continue verification once we've published
			publishesIn <- signed
		}
		done := len(hasPublished) == len(r.c.Peers)-1
		if done {
			close(publishesIn)
		}
		return done
	})
	go func() {
		<-r.afterWeHavePublished
		// Finish verifying & aggregating publishes
		for item := range publishesNext {
			signed := item.(*sgp.Signed)
			if !bytes.Equal(signed.Message, r.signed_result.Message) {
				log.Fatalf("Peer deviates from consensus")
			}
			r.signed_result.Sigs = append(r.signed_result.Sigs, signed.Sigs[0])
			r.signed_result.KeyIds = append(r.signed_result.KeyIds, signed.KeyIds[0])
		}
		signed_result_bs, err := proto.Marshal(r.signed_result)
		if err != nil {
			panic(err)
		}
		rs, err := r.c.db.Exec(`UPDATE rounds SET signed_result = $1 WHERE id = $2
				AND signed_result IS NULL`, signed_result_bs, r.id)
		n, _ := rs.RowsAffected()
		if err != nil || n > 1 {
			log.Fatalf("UPDATE rounds SET signed_result (%d rows): %s", n, err)
		}
		close(r.afterPublishes)
	}()
}

func HashCommitData(round, commiter int64, key []byte,
	pushes_map map[[24]byte][]byte) []byte {
	pushes := make([][]byte, len(pushes_map))
	i := 0
	for _, rq_box := range pushes_map {
		pushes[i] = rq_box
		i++
	}
	sort.Sort(ByteSlices(pushes))
	commit_data_bytes, err := proto.Marshal(&CommitData{Round: &round,
		Server: &commiter, RoundKey: key, TransactionQueue: pushes})
	if err != nil {
		panic(err)
	}
	h := sha256.New()
	h.Write(commit_data_bytes)
	return h.Sum(nil)
}

type ByteSlices [][]byte

func (p ByteSlices) Len() int           { return len(p) }
func (p ByteSlices) Less(i, j int) bool { return bytes.Compare(p[i], p[j]) < 0 }
func (p ByteSlices) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
