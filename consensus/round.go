package consensus

import (
	"bytes"
	"code.google.com/p/go.crypto/nacl/secretbox"
	"code.google.com/p/goprotobuf/proto"
	"crypto/rand"
	"crypto/sha256"
	"github.com/andres-erbsen/dename/pgutil"
	"github.com/andres-erbsen/dename/prng"
	"github.com/andres-erbsen/dename/protocol"
	"github.com/andres-erbsen/sgp"
	"log"
	"sync"
	"time"
)

// round is a sequence of communication and computation steps that results in
// zero or requests being handled, possibly mutating some shared state.
type round struct {
	c *Consensus

	id               int64
	openAtLeastUntil time.Time
	next             *round

	afterRequests         chan struct{}
	afterCommitments      chan struct{}
	afterAcknowledgements chan struct{}
	afterKeys             chan struct{}
	afterWeHavePublished  chan struct{}
	afterPublishes        chan struct{}

	requests map[int64]*[][]byte
	pushes   map[int64]*[][]byte
	commited map[int64]*[]byte

	our_round_key *[32]byte
	shared_prng   *prng.PRNG
	signed_result *sgp.Signed

	commitmentsRemaining int
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
	r.pushes = make(map[int64]*[][]byte, len(r.c.Peers))
	r.commited = make(map[int64]*[]byte, len(r.c.Peers))
	r.commitmentsRemaining = len(r.c.Peers)
	r.our_round_key = new([32]byte)

	for id := range c.Peers {
		r.requests[id] = new([][]byte)
		r.pushes[id] = new([][]byte)
		r.commited[id] = new([]byte)
	}
	if _, err := rand.Read(r.our_round_key[:]); err != nil {
		log.Fatalf("rand.Read(r.our_round_key[:]):]): %s", err)
	}

	_, err := r.c.db.Exec(`INSERT INTO rounds(id, our_key, close_time)
		VALUES($1,$2,$3)`, id, r.our_round_key[:], t.Unix())
	if pgutil.IsError(err, pgutil.ErrUniqueViolation) {
		key_bs := r.our_round_key[:]
		if err := r.c.db.QueryRow(`SELECT our_key FROM rounds
			WHERE id = $1`, id).Scan(&key_bs); err != nil {
			log.Fatalf("our_key FROM rounds: %s", err)
		}
	} else if err != nil {
		log.Fatalf("Insert round id,close_time: %s", err)
	}
	return
}

// ColdStart starts the first round in a sequence, possibly right after newRound
func (r *round) ColdStart() {
	go r.acceptRequests(r.c.IncomingRequests)
	go r.acceptPushes()
	go r.handleCommitments()
	go r.handleAcknowledgements()
	r.next = newRound(r.id+1, r.openAtLeastUntil.Add(r.c.TickInterval), r.c)
	go r.next.acceptPushes()
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
// round they can be accpeting requests for is i+1. If we have published the
// signed result but have not yet received the results from others, it may be
// still the case that they have proceeded: they may be processing round i+1 and
// accepting requests for i+2 and pushing them to us.
func (r *round) Process() {
	time.Sleep(r.openAtLeastUntil.Sub(time.Now()))
	close(r.afterRequests)
	r.commitToQueue()

	<-r.afterCommitments
	r.c.router.Close(r.id, S2S_PUSH)
	<-r.afterAcknowledgements

	go r.handlePublishes()
	r.revealRoundKey()

	<-r.afterKeys
	result := r.c.QueueProcessor(r.requests, r.shared_prng)
	go r.next.handleCommitments()
	go r.next.handleAcknowledgements()
	r.next.next = newRound(r.next.id+1, r.next.openAtLeastUntil.Add(r.c.TickInterval), r.c)
	go r.next.next.acceptPushes()
	r.Publish(result)

	<-r.afterPublishes
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
			// 24:nonce || ...:encrypted message || secretbox.Overhead:auth
			rq_box := make([]byte, 24, 24+len(rq_bs)+secretbox.Overhead)
			if _, err := rand.Read(rq_box[:24]); err != nil {
				log.Fatalf("rand.Read(rq_box[:24]): %f", err)
			}
			nonce := new([24]byte)
			copy(nonce[:], rq_box[:24])
			secretbox.Seal(rq_box[24:], rq_bs, nonce, r.our_round_key)
			*r.pushes[r.c.our_id] = append(*r.pushes[r.c.our_id], rq_box)
			*r.requests[r.c.our_id] = append(*r.requests[r.c.our_id], rq_box)
			r.c.broadcast(&protocol.S2SMessage{Round: &r.id, PushQueue: rq_box})
		case <-r.afterRequests:
			break loop
		}
	}
	go r.next.acceptRequests(rqs) // TODO: tail call optimization?
}

// acceptPushes handles pushes from servers.
// A round should be accept pushes as long as any other server may be
// accept requests for that round.
// When round i publishes the last message other servers would need from us to
// finalize that round, other servers may start processing the next round and
// accept requests to the round after that. Therefore, acceptPushes
// is started on round i+2.
func (r *round) acceptPushes() {
	r.c.router.Receive(r.id, S2S_PUSH, func(msg *protocol.S2SMessage) bool {
		*r.pushes[*msg.Server] = append(*r.pushes[*msg.Server], msg.PushQueue)
		return false
	})
}

// commitToQueue hashes our queue, signs it and publishes the result
func (r *round) commitToQueue() {
	our_id := r.c.our_id
	qh := HashCommitData(r.id, our_id, r.our_round_key[:], *r.pushes[our_id])
	commitment_bs, err := proto.Marshal(&protocol.Commitment{
		Round: &r.id, Server: &our_id, Hash: qh})
	if err != nil {
		panic(err)
	}
	signed_commitment_bs := r.c.our_sk.Sign(commitment_bs, protocol.SIGN_TAG_COMMIT)
	s2s := &protocol.S2SMessage{Round: &r.id, Commitment: signed_commitment_bs}
	r.c.broadcast(s2s)
}

// checkCommitmentUnique checks that a commitment is valid and the peer has
// not commited to anything else in this round
func (r *round) checkCommitmentUnique(peer_id int64, signed_bs []byte) {
	peer := r.c.Peers[peer_id]
	commitment_bs, err := peer.PK().Verify(signed_bs, protocol.SIGN_TAG_COMMIT)
	if err != nil {
		log.Fatalf("peer.PK().Verify(bs, protocol.SIGN_TAG_COMMIT): %s", err)
	}
	commitment := new(protocol.Commitment)
	if err := proto.Unmarshal(commitment_bs, commitment); err != nil {
		log.Fatalf("proto.Unmarshal(commitment_bs, commitment): %s", err)
	}
	if *commitment.Round != r.id || *commitment.Server != peer_id {
		log.Fatalf("Inconsistently labelled commitment")
	}
	if *r.commited[peer_id] == nil {
		*r.commited[peer_id] = commitment.Hash
		r.commitmentsRemaining--
	} else if !bytes.Equal(*r.commited[peer_id], commitment.Hash) {
		log.Printf("Multiple different commitments from %d: %v and %v", peer_id, *r.commited[peer_id], commitment.Hash)
	}
}

// handleCommitments acknowledges commitments
// received from other servers. As a server may start processing a round as soon
// as it finalizes the previous one, a round starts handleCommitments on
// the next one right before sending out the last message other servers have to
// wait for.
func (r *round) handleCommitments() {
	ack := &protocol.Acknowledgement{Acker: &r.c.our_id}
	r.c.router.Receive(r.id, S2S_COMMITMENT, func(msg *protocol.S2SMessage) bool {
		r.checkCommitmentUnique(*msg.Server, msg.Commitment)
		done := r.commitmentsRemaining == 0
		if done {
			go r.handleKeys()
		}
		// send an ack
		ack.Commiter, ack.Commitment = msg.Server, msg.Commitment
		ack_bs, err := proto.Marshal(ack)
		if err != nil {
			panic(err)
		}
		signed_ack_bs := r.c.our_sk.Sign(ack_bs, protocol.SIGN_TAG_ACK)
		r.c.broadcast(&protocol.S2SMessage{Round: msg.Round, Ack: signed_ack_bs})
		return done
	})
	close(r.afterCommitments)
}

// handleAcknowledgements receives acknowledgements.
// Called together with handleCommitments because as soon as a commitment
// is sent out, acknowledgements from all servers should follow.
func (r *round) handleAcknowledgements() {
	acknowledgersRemaining := len(r.c.Peers) - 1 // don't track our own acks
	hasAcked := make(map[int64]map[int64]struct{})
	for id := range r.c.Peers {
		if id != r.c.our_id {
			hasAcked[id] = make(map[int64]struct{})
		}
	}
	ack := new(protocol.Acknowledgement)
	r.c.router.Receive(r.id, S2S_ACKNOWLEDGEMENT, func(msg *protocol.S2SMessage) bool {
		peer := r.c.Peers[*msg.Server]
		ack_bs, err := peer.PK().Verify(msg.Ack, protocol.SIGN_TAG_ACK)
		if err != nil {
			log.Fatalf("peer.PK().Verify(msg.Ack, protocol.SIGN_TAG_ACK): %s", err)
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
		return acknowledgersRemaining == 0
	})
	close(r.afterAcknowledgements)
}

func (r *round) revealRoundKey() {
	r.c.broadcast(&protocol.S2SMessage{Round: &r.id, RoundKey: r.our_round_key[:]})
}

// handleKeys receives
// keys and spawns workers to decrypt the queues.
// As a server should not reveal their round key before they have seen all the
// acknowledgements, handleKeys is started before we acknowledge the last
// commitment of that round.
func (r *round) handleKeys() {
	var decryptions sync.WaitGroup
	keys := make(map[int64]*[32]byte, len(r.c.Peers))
	keys[r.c.our_id] = r.our_round_key
	r.c.router.Receive(r.id, S2S_ROUNDKEY, func(msg *protocol.S2SMessage) bool {
		if _, already := keys[*msg.Server]; !already {
			keys[*msg.Server] = new([32]byte)
			copy(keys[*msg.Server][:], msg.RoundKey)
		} else if bytes.Equal(keys[*msg.Server][:], msg.RoundKey) {
			log.Printf("%d sent same key twice", *msg.Server)
			return false
		} else {
			log.Fatalf("%d keys: %v and %v", *msg.Server, keys[*msg.Server][:], msg.RoundKey)
		}
		decryptions.Add(2)
		go func(peer_id int64, key *[32]byte) { // decrypt requests
			defer decryptions.Done()
			rqs := make([][]byte, len(*r.pushes[peer_id]))
			nonce := new([24]byte)
			for i, rq_box := range *r.pushes[peer_id] {
				var ok bool
				copy(nonce[:], rq_box[:24])
				rqs[i], ok = secretbox.Open(nil, rq_box[24:], nonce, key)
				if !ok {
					log.Fatalf("Failed to decrypt %d's queue", peer_id)
				}
			}
			*r.requests[peer_id] = rqs
		}(*msg.Server, keys[*msg.Server])
		go func(peer_id int64, key *[32]byte) { // verify commitments
			defer decryptions.Done()
			qh := HashCommitData(r.id, peer_id, key[:], *r.pushes[peer_id])
			if !bytes.Equal(qh, *r.commited[peer_id]) {
				log.Fatalf("%d has bad queue hash", peer_id)
			}
		}(*msg.Server, keys[*msg.Server])
		return len(keys) == len(r.c.Peers)
	})

	// seed the shared prng
	h := sha256.New()
	for id := range r.c.Peers {
		h.Write(keys[id][:])
	}
	seed := new([32]byte)
	seed_bs := h.Sum(nil)
	copy(seed[:], seed_bs)
	r.shared_prng = prng.NewPRNG(seed)

	decryptions.Wait()
	close(r.afterKeys)
}

func (r *round) Publish(result []byte) {
	publish_bs, err := proto.Marshal(&protocol.MappingRoot{
		Round: &r.id, Root: result})
	if err != nil {
		panic(err)
	}
	r.signed_result = r.c.our_sk.SignPb(publish_bs, protocol.SIGN_TAG_PUBLISH)
	signed_bs, err := proto.Marshal(r.signed_result)
	if err != nil {
		panic(err)
	}
	r.c.broadcast(&protocol.S2SMessage{Server: &r.c.our_id,
		Round: &r.id, Publish: signed_bs})
	close(r.afterWeHavePublished)
}

// handlePublishes receives publish messages and verifies them.
// As a server should not publish the result of a round before decrypting all
// the queues, handlePublishes is started right before we reveal the key used to
// encrypt our queue.
func (r *round) handlePublishes() {
	signed := new(sgp.Signed)
	hasPublished := make(map[int64]struct{})
	r.c.router.Receive(r.id, S2S_PUBLISH, func(msg *protocol.S2SMessage) bool {
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
		if !r.c.Peers[*msg.Server].PK().VerifyPb(signed, protocol.SIGN_TAG_PUBLISH) {
			log.Fatalf("Invalid signature on publish from %d: %f", *msg.Server, err)
		}
		if !bytes.Equal(signed.Message, r.signed_result.Message) {
			log.Fatalf("Peer %d deviates from consensus", *msg.Server)
		}
		if _, already := hasPublished[*msg.Server]; !already {
			hasPublished[*msg.Server] = struct{}{}
			r.signed_result.Sigs = append(r.signed_result.Sigs, signed.Sigs[0])
			r.signed_result.KeyIds = append(r.signed_result.KeyIds, signed.KeyIds[0])
		}
		return len(hasPublished) == len(r.c.Peers)-1
	})
	signed_result_bs, err := proto.Marshal(r.signed_result)
	if err != nil {
		panic(err)
	}
	rs, err := r.c.db.Exec(`UPDATE rounds SET signed_result = $1 WHERE id = $2
			AND signed_result IS NULL`, signed_result_bs, r.id)
	n, _ := rs.RowsAffected()
	if err != nil || n != 1 {
		log.Fatalf("UPDATE rounds SET signed_result (%d rows): %s", n, err)
	}
	close(r.afterPublishes)
}

func HashCommitData(round, commiter int64, key []byte, pushes [][]byte) []byte {
	commit_data_bytes, err := proto.Marshal(&protocol.CommitData{Round: &round,
		Server: &commiter, RoundKey: key, TransactionQueue: pushes})
	if err != nil {
		panic(err)
	}
	h := sha256.New()
	h.Write(commit_data_bytes)
	return h.Sum(nil)
}
