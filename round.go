package main

import (
	"github.com/andres-erbsen/dename/protocol"
	"time"
)

// Round is a sequence of communication and computation steps that results in
// zero or requests being handled, possibly mutating some shared state.
type Round struct {
	Id               int64
	OpenAtLeastUntil time.Time
	Next             *Round

	router *Router

	afterRequests         chan struct{}
	afterPushes           chan struct{}
	afterCommitments      chan struct{}
	afterAcknowledgements chan struct{}
	afterKeys             chan struct{}
	afterPublishes        chan struct{}
}

func newRound(id int64, t time.Time) (r *Round) {
	r = new(Round)
	r.Id = id
	r.OpenAtLeastUntil = t
	r.afterRequests = make(chan struct{})
	r.afterPushes = make(chan struct{})
	r.afterCommitments = make(chan struct{})
	r.afterAcknowledgements = make(chan struct{})
	r.afterKeys = make(chan struct{})
	r.afterPublishes = make(chan struct{})
	return
}

// acceptRequests accepts clients.
// A round starts acceptRequests on the next round as soon soon as it
// stops handling requests itself, handing the channel of incoming requests over
// to the next round.
func (r *Round) acceptRequests(rqs <-chan *protocol.TransferName) {
	for {
		select {
		case <-rqs:
			// TOCO: handle request
		case <-r.afterRequests:
			break
		}
	}
	go r.Next.acceptRequests(rqs) // TODO: tail call optimization?
}

// acceptPushes handles pushes from servers.
// A round should be accept pushes as long as any other server may be
// accept requests for that round.
// When round i publishes the last message other servers would need from us to
// finalize that round, other servers may start processing the next round and
// accept requests to the round after that. Therefore, acceptPushes
// is started on round i+2.
func (r *Round) acceptPushes() {
	incoming := r.router.Receive(r.Id, S2S_PUSH)
	for {
		select {
		case _, chan_open := <-incoming:
			if !chan_open {
				break
			}
			// TODO: handle
		case <-r.afterPushes:
			r.router.Close(incoming)
		}
	}
}

// handleCommitments acknowledges commitments
// received from other servers. As a server may start processing a round as soon
// as it finalizes the previous one, a round starts handleCommitments on
// the next one right before sending out the last message other servers have to
// wait for.
func (r *Round) handleCommitments() {
	incoming := r.router.Receive(r.Id, S2S_COMMITMENT)
	for _ = range incoming {
		// TODO
		// checkCommitmentUnique(commitment)
		// TODO
		// if done { // before ending out the ack
		// go r.handleKeys()
		// }
		// if done {
		r.router.Close(incoming)
		// }
	}
	close(r.afterCommitments)
}

// handleAcknowledgements receives acknowledgements.
// Called together with handleCommitments because as soon as a commitment
// is sent out, acknowledgements from all servers should follow.
func (r *Round) handleAcknowledgements() {
	incoming := r.router.Receive(r.Id, S2S_ACKNOWLEDGEMENT)
	for _ = range incoming {
		// TODO
		// r.checkCommitmentUnique(commitment)
		// TODO
		// if done {
		r.router.Close(incoming)
		// }
	}
	close(r.afterAcknowledgements)
}

// handleKeys receives
// keys and spawns workers to decrypt the queues.
// As a server should not reveal their round key before they have seen all the
// acknowledgements, handleKeys is started before we acknowledge the last
// commitment of that round.
func (r *Round) handleKeys() {
	incoming := r.router.Receive(r.Id, S2S_ROUNDKEY)
	for _ = range incoming {
		// TODO
		// if done {
		r.router.Close(incoming)
		// }
	}
	close(r.afterKeys)
}

// handlePublishes receives publish messages and verifies them.
// As a server should not publish the result of a round before decrypting all
// the queues, handlePublishes is started right before we reveal the key used to
// encrypt our queue.
func (r *Round) handlePublishes() {
	incoming := r.router.Receive(r.Id, S2S_PUBLISH)
	for _ = range incoming {
		// TODO
		// if done {
		r.router.Close(incoming)
		// }
	}
	close(r.afterPublishes)
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
// round they can be after requests to is i+1. If we have published the
// signed result but have not yet received the results from others, it may be
// still the case that they have proceeded: they may be processing round i+1 and
// after requests for i+2 and pushing them to us.
func (r *Round) Process() {
	time.Sleep(r.OpenAtLeastUntil.Sub(time.Now()))
	close(r.afterRequests)

	// r.commitToQueue()

	<-r.afterCommitments
	close(r.afterPushes)
	<-r.afterAcknowledgements

	go r.handlePublishes()
	// r.revealRoundKey()

	<-r.afterKeys
	// result := r.ProcessRequests()
	go r.Next.handleCommitments()
	go r.Next.handleAcknowledgements()
	r.Next.Next = newRound(r.Next.Id+1, r.Next.OpenAtLeastUntil.Add(TICK_INTERVAL))
	go r.Next.Next.acceptPushes()
	// r.Publish(result)

	<-r.afterPublishes
	go r.Next.Process()
}
