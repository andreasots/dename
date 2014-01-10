package main

import (
	"code.google.com/p/go.crypto/nacl/secretbox"
	"crypto/rand"
	"github.com/andres-erbsen/dename/prng"
	"github.com/andres-erbsen/dename/protocol"
	"log"
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

	keys        map[int64]*[32]byte
	requests    map[int64]*[][]byte
	pushes      map[int64]*[][]byte
	shared_prng *prng.PRNG
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
	r.keys = make(map[int64]*[32]byte)
	r.requests = make(map[int64]*[][]byte)
	r.pushes = make(map[int64]*[][]byte)

	for id := range c.Peers {
		r.keys[id] = new([32]byte)
		r.requests[id] = new([][]byte)
		r.pushes[id] = new([][]byte)
	}
	r.keys[c.our_id] = new([32]byte)
	if _, err := rand.Read(r.keys[c.our_id][:]); err != nil {
		log.Fatalf("rand.Read(r.keys[c.our_id][:]): %s", err)
	}

	_, err := r.c.db.Exec(`INSERT INTO rounds(id, our_key, close_time)
		VALUES($1,$2)`, id, r.keys[c.our_id][:], t.Unix())
	if isPGError(err, pgErrorUniqueViolation) {
		if err := r.c.db.QueryRow(`SELECT our_key FROM rounds
			WHERE id = $1`, id).Scan(r.keys[c.our_id][:]); err != nil {
			log.Fatalf("our_key FROM rounds: %s", err)
		}
	} else if err != nil {
		log.Fatalf("Insert round id,close_time: %s", err)
	}
	return
}

// acceptRequests accepts clients.
// A round starts acceptRequests on the next round as soon soon as it
// stops handling requests itself, handing the channel of incoming requests over
// to the next round.
func (r *round) acceptRequests(rqs <-chan []byte) {
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
			secretbox.Seal(rq_box[24:], rq_bs, nonce, r.keys[r.c.our_id])
			*r.pushes[r.c.our_id] = append(*r.pushes[r.c.our_id], rq_box)
			r.c.broadcast(&protocol.S2SMessage{Round: &r.id, PushQueue: rq_box})
		case <-r.afterRequests:
			break
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
		// TODO
		return false
	})
}

// handleCommitments acknowledges commitments
// received from other servers. As a server may start processing a round as soon
// as it finalizes the previous one, a round starts handleCommitments on
// the next one right before sending out the last message other servers have to
// wait for.
func (r *round) handleCommitments() {
	r.c.router.Receive(r.id, S2S_COMMITMENT, func(msg *protocol.S2SMessage) bool {
		// TODO
		// checkCommitmentUnique(msg.Commitment)
		// TODO
		// if done {
		// go r.handleKeys()
		// }
		// TODO send out the ack
		// return done
	})
	close(r.afterCommitments)
}

// handleAcknowledgements receives acknowledgements.
// Called together with handleCommitments because as soon as a commitment
// is sent out, acknowledgements from all servers should follow.
func (r *round) handleAcknowledgements() {
	r.c.router.Receive(r.id, S2S_ACKNOWLEDGEMENT, func(msg *protocol.S2SMessage) bool {
		// TODO
		// r.checkCommitmentUnique(ack.Commitment)
		// TODO
		// return done
	})
	close(r.afterAcknowledgements)
}

// handleKeys receives
// keys and spawns workers to decrypt the queues.
// As a server should not reveal their round key before they have seen all the
// acknowledgements, handleKeys is started before we acknowledge the last
// commitment of that round.
func (r *round) handleKeys() {
	r.c.router.Receive(r.id, S2S_ROUNDKEY, func(msg *protocol.S2SMessage) bool {
		// TODO
		// return done
	})
	close(r.afterKeys)
}

// handlePublishes receives publish messages and verifies them.
// As a server should not publish the result of a round before decrypting all
// the queues, handlePublishes is started right before we reveal the key used to
// encrypt our queue.
func (r *round) handlePublishes() {
	r.c.router.Receive(r.id, S2S_PUBLISH, func(msg *protocol.S2SMessage) bool {
		// TODO
		// return done
	})
	close(r.afterPublishes)
}

func (r *round) Publish(result []byte) {
	close(r.afterWeHavePublished)
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

	// r.commitToQueue()

	<-r.afterCommitments
	r.c.router.Close(r.id, S2S_PUSH)
	<-r.afterAcknowledgements

	go r.handlePublishes()
	// r.revealRoundKey()

	<-r.afterKeys
	result := r.c.QueueProcessor(r.requests, r.shared_prng)
	go r.next.handleCommitments()
	go r.next.handleAcknowledgements()
	r.next.next = newRound(r.next.id+1, r.next.openAtLeastUntil.Add(TICK_INTERVAL), r.c)
	go r.next.next.acceptPushes()
	r.Publish(result)

	<-r.afterPublishes
	go r.next.Process()
}

func (r *round) ColdStart() {
	go r.acceptRequests(r.c.IncomingRequests)
	go r.acceptPushes()
	go r.handleCommitments()
	go r.handleAcknowledgements()
	r.next = newRound(r.id+1, r.openAtLeastUntil.Add(TICK_INTERVAL), r.c)
	go r.next.acceptPushes()
	go r.Process()
}
