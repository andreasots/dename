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
	"log"
	"sort"
	"sync"
	"time"
)

type RoundSummary struct {
	Id                   int64
	OpenAtLeastUntil     time.Time
	Requests             map[int64]*[][]byte
	Result, SignedResult []byte
	AuxResults           map[int64]*[]byte
}

type Request interface {
	Bytes() []byte
}

// round is a sequence of communication and computation steps that results in
// zero or requests being handled, possibly mutating some shared state.
type round struct {
	RoundSummary
	c    *Consensus // const pointer, target not mutated from round
	next *round     // pointer set by the .previous after keys

	// const
	afterRequests         chan struct{}
	afterCommitments      chan struct{}
	afterAcknowledgements chan struct{}
	afterKeys             chan struct{}
	afterWeHavePublished  chan struct{}
	afterPublishes        chan struct{}

	// the maps are const, pointer targets are mutable
	pushes   map[int64]map[[24]byte][]byte // populated by push handler (us: rq handler)
	commited map[int64]*[]byte             // set by commitment handler
	acked    map[int64]*[]byte             // set by acknowledgement handler

	our_round_key *[32]byte  // const
	shared_prng   *prng.PRNG // pointer set at the end of key handler after

	signed_result        SignedConsensusResult
	signatures_on_result int
}

func newRound(id int64, t time.Time, c *Consensus) (r *round) {
	r = new(round)
	r.Id = id
	r.OpenAtLeastUntil = t
	r.c = c
	r.afterRequests = make(chan struct{})
	r.afterCommitments = make(chan struct{})
	r.afterAcknowledgements = make(chan struct{})
	r.afterKeys = make(chan struct{})
	r.afterWeHavePublished = make(chan struct{})
	r.afterPublishes = make(chan struct{})
	r.Requests = make(map[int64]*[][]byte, len(r.c.Peers))
	r.AuxResults = make(map[int64]*[]byte, len(r.c.Peers))
	r.pushes = make(map[int64]map[[24]byte][]byte, len(r.c.Peers))
	r.commited = make(map[int64]*[]byte, len(r.c.Peers))
	r.acked = make(map[int64]*[]byte, len(r.c.Peers))
	r.our_round_key = new([32]byte)

	for id := range c.Peers {
		r.Requests[id] = new([][]byte)
		r.AuxResults[id] = new([]byte)
		r.pushes[id] = make(map[[24]byte][]byte)
		r.commited[id] = new([]byte)
		r.acked[id] = new([]byte)
	}
	*r.Requests[r.c.our_id] = make([][]byte, 0)

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
		AND sender = $2 AND type = $3`, r.Id, r.c.our_id, COMMITMENT).Scan(&count)
	if err != nil {
		log.Fatalf("haveWeCommitted() round %d: %s", r.Id, err)
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
	if time.Now().After(r.OpenAtLeastUntil) {
		log.Printf("round %d processing started LATE!", r.Id)
	}
	time.Sleep(r.OpenAtLeastUntil.Sub(time.Now()))
	// log.Printf("processing round %v", r.Id)
	r.afterRequests <- struct{}{}
	close(r.afterRequests)
	go r.next.acceptRequests(r.c.IncomingRequests)
	r.commitToQueue()

	<-r.afterCommitments
	// log.Printf("round %v: got commitments", r.Id)
	r.startHandlingKeys()
	r.acknowledgeCommitments()
	r.c.router.Close(r.Id, PUSH)
	<-r.afterAcknowledgements
	// log.Printf("round %v: got acks", r.Id)
	r.checkAcknowledgements()

	r.startHandlingPublishes()
	r.revealRoundKey()

	<-r.afterKeys
	// log.Printf("round %v: got keys", r.Id)
	for _, rqs := range r.Requests {
		sort.Sort(ByteSlices(*rqs))
	}
	r.Result, *r.AuxResults[r.c.our_id] = r.c.QueueProcessor(r.Requests, r.shared_prng, r.Id)
	r.next.startHandlingCommitments()
	r.next.startHandlingAcknowledgements()
	r.next.next = newRound(r.next.Id+1, r.next.OpenAtLeastUntil.Add(r.c.TickInterval), r.c)
	r.next.next.startAcceptingPushes()
	r.Publish()

	<-r.afterPublishes
	// log.Printf("round %v: got publishes", r.Id)
	if r.c.round_completion_callback(&r.RoundSummary) {
		go r.next.Process()
	}
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
			*r.Requests[r.c.our_id] = append(*r.Requests[r.c.our_id], rq_bs)
			nonce := new([24]byte)
			if _, err := rand.Read(nonce[:]); err != nil {
				log.Fatalf("rand.Read(rq_box): %s", err)
			}
			rq_box := secretbox.Seal(nonce[:], rq_bs, nonce, r.our_round_key)
			r.pushes[r.c.our_id][*nonce] = rq_box
			r.c.broadcast(&ConsensusMSG{Round: &r.Id, PushQueue: rq_box})
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
	r.c.router.Receive(r.Id, PUSH, func(msg *ConsensusMSG) bool {
		nonce := [24]byte{}
		copy(nonce[:], msg.PushQueue[:24])
		r.pushes[*msg.Server][nonce] = msg.PushQueue
		return false
	})
}

// commitToQueue hashes our queue, signs it and publishes the result
func (r *round) commitToQueue() {
	our_id := r.c.our_id
	qh := HashCommitData(r.Id, our_id, r.our_round_key[:], r.pushes[our_id])
	// log.Printf("queue hash: %v, %x", len(r.pushes[our_id]), qh)
	*r.commited[r.c.our_id] = qh
	commitment_bs, err := proto.Marshal(&Commitment{
		Round: &r.Id, Server: &our_id, Hash: qh})
	if err != nil {
		panic(err)
	}
	signed_commitment_bs := r.c.our_sk.Sign(commitment_bs, r.c.sign_tags[COMMITMENT])
	s2s := &ConsensusMSG{Round: &r.Id, Commitment: signed_commitment_bs}
	r.c.broadcast(s2s)
}

// startHandlingCommitments accepts commitments
// received from other servers. As a server may start processing a round as soon
// as it finalizes the previous one, a round calls startHandlingCommitments on
// the next one right before sending out the last message other servers have to
// wait for.
func (r *round) startHandlingCommitments() {
	remaining := len(r.c.Peers) - 1
	r.c.router.Receive(r.Id, COMMITMENT, func(msg *ConsensusMSG) bool {
		commitment_bs, err := r.c.Peers[*msg.Server].Verify(
			msg.Commitment, r.c.sign_tags[COMMITMENT])
		if err != nil {
			log.Fatalf("peer.Verify(bs, r.c.sign_tags[COMMITMENT]): %s", err)
		}
		commitment := new(Commitment)
		if err := proto.Unmarshal(commitment_bs, commitment); err != nil {
			log.Fatalf("proto.Unmarshal(commitment_bs, commitment): %s", err)
		}
		if *commitment.Round != r.Id || *commitment.Server != *msg.Server {
			log.Fatalf("Inconsistently labelled commitment")
		}
		if *r.commited[*msg.Server] == nil {
			*r.commited[*msg.Server] = commitment.Hash
			remaining--
		} else if !bytes.Equal(*r.commited[*msg.Server], commitment.Hash) {
			log.Fatalf("Multiple different commitments from %d: %v and %v", *msg.Server, commitment.Hash)
		}
		if remaining == 0 {
			close(r.afterCommitments)
			return true
		}
		return false
	})
}

// startHandlingAcknowledgements receives acknowledgements.
// Called together with startHandlingCommitments because as soon as a commitment
// is sent out, acknowledgements from all servers should follow.
func (r *round) startHandlingAcknowledgements() {
	remaining := len(r.c.Peers) - 1
	r.c.router.Receive(r.Id, ACKNOWLEDGEMENT, func(msg *ConsensusMSG) bool {
		peer := r.c.Peers[*msg.Server]
		ack_bs, err := peer.Verify(msg.Ack, r.c.sign_tags[ACKNOWLEDGEMENT])
		if err != nil {
			log.Fatalf("peer.Verify(msg.Ack, r.c.sign_tags[ACKNOWLEDGEMENT]): %s", err)
		}
		ack := new(Acknowledgement)
		if err := proto.Unmarshal(ack_bs, ack); err != nil {
			log.Fatalf("proto.Unmarshal(ack_bs, ack): %s", err)
		}
		if *msg.Server != *ack.Server {
			log.Fatalf("Peer %d acked as %d", *msg.Server, *ack.Server)
		}
		if *r.acked[*msg.Server] == nil {
			*r.acked[*msg.Server] = ack.HashOfCommitments
			remaining--
		} else if !bytes.Equal(*r.acked[*msg.Server], ack.HashOfCommitments) {
			log.Fatalf("Multiple different acks from %d: %v and %v", *msg.Server, *r.acked[*msg.Server], ack.HashOfCommitments)
		}
		if remaining == 0 {
			close(r.afterAcknowledgements)
			return true
		}
		return false
	})
}

func (r *round) acknowledgeCommitments() {
	ack := &Acknowledgement{Round: &r.Id, Server: &r.c.our_id,
		HashOfCommitments: r.HashAckData(r.commited)}
	*r.acked[r.c.our_id] = ack.HashOfCommitments
	ack_bs, err := proto.Marshal(ack)
	if err != nil {
		panic(err)
	}
	signed_ack_bs := r.c.our_sk.Sign(ack_bs, r.c.sign_tags[ACKNOWLEDGEMENT])
	r.c.broadcast(&ConsensusMSG{Round: &r.Id, Ack: signed_ack_bs})
}

func (r *round) checkAcknowledgements() {
	h0 := *r.acked[r.c.our_id]
	for id, h := range r.acked {
		if !bytes.Equal(*h, h0) {
			log.Print("The commitments we saw: ")
			for i, c := range r.commited {
				log.Printf("  %d: %f", i, c)
			}
			log.Fatalf("We acked %x but %v acked %x", h0, id, *h)
		}
	}
}

func (r *round) revealRoundKey() {
	r.c.broadcast(&ConsensusMSG{Round: &r.Id, RoundKey: r.our_round_key[:]})
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
	r.c.router.Receive(r.Id, ROUNDKEY, func(msg *ConsensusMSG) bool {
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
			*r.Requests[peer_id] = rqs
		}(*msg.Server, keys[*msg.Server])
		go func(peer_id int64, key *[32]byte) { // verify commitments
			defer decryptions.Done()
			qh := HashCommitData(r.Id, peer_id, key[:], r.pushes[peer_id])
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

func (r *round) Publish() {
	aux := *r.AuxResults[r.c.our_id]
	_, err := r.c.db.Exec(`INSERT INTO auxresults(round,sender,result)
		VALUES($1,$2,$3)`, r.Id, r.c.our_id, aux)
	if err != nil && !pgutil.IsError(err, pgutil.ErrUniqueViolation) {
		log.Fatalf("Insert aux result: %s", err)
	}
	publish_bs, err := proto.Marshal(&ConsensusResult{
		Round: &r.Id, Result: r.Result})
	if err != nil {
		panic(err)
	}
	sig := r.c.our_sk.SignDetached(publish_bs, r.c.sign_tags[PUBLISH])
	r.signed_result.ConsensusResult = publish_bs
	r.signed_result.Signatures = [][]byte{sig}
	r.signed_result.Signers = []int64{r.c.our_id}
	// do not set r.SignedResult :: []byte yet, wait for peers' signatures
	rs, err := r.c.db.Exec(`UPDATE rounds SET result = $1 WHERE id = $2
			AND result IS NULL`, r.Result, r.Id)
	if err != nil {
		log.Fatalf("UPDATE rounds SET result: %s", err)
	}
	if n, _ := rs.RowsAffected(); n > 1 {
		log.Fatalf("UPDATE rounds SET result affected %d rows", n)
	}
	r.c.broadcast(&ConsensusMSG{Server: &r.c.our_id,
		Round: &r.Id, Publish: &Result{Canonical: &r.signed_result, Aux: aux}})
	// initialize signed_result for other peers' signatures
	r.signed_result.Signatures = make([][]byte, len(r.c.Peers))
	r.signed_result.Signers = make([]int64, len(r.c.Peers))
	r.signed_result.Signatures[r.signatures_on_result] = sig
	r.signed_result.Signers[r.signatures_on_result] = r.c.our_id
	r.signatures_on_result++
	close(r.afterWeHavePublished)
}

// startHandlingPublishes receives publish messages and verifies them.
// As a server should not publish the result of a round before decrypting all
// the queues, startHandlingPublishes is called right before we reveal the key used to
// encrypt our queue.
func (r *round) startHandlingPublishes() {
	// actually chan *ConsensusMSG
	publishesIn := make(chan interface{})
	publishesNext := make(chan interface{})
	go ringchannel.RingIQ(publishesIn, publishesNext)
	hasPublished := make(map[int64]struct{})
	r.c.router.Receive(r.Id, PUBLISH, func(msg *ConsensusMSG) bool {
		crs := msg.Publish.Canonical
		if len(crs.Signatures) != 1 {
			log.Fatalf("!= 1 signatures for publish from %d: %v", *msg.Server, crs.Signatures)
		}
		if err := r.c.Peers[*msg.Server].VerifyDetached(crs.ConsensusResult,
			crs.Signatures[0], r.c.sign_tags[PUBLISH]); err != nil {
			log.Fatalf("Invalid signature on publish from %d: %f", *msg.Server, err)
		}
		*r.AuxResults[*msg.Server] = msg.Publish.Aux
		_, err := r.c.db.Exec(`INSERT INTO auxresults(round,sender,result)
			VALUES($1,$2,$3)`, *msg.Round, *msg.Server, msg.Publish.Aux)
		if err != nil && !pgutil.IsError(err, pgutil.ErrUniqueViolation) {
			log.Fatalf("Insert aux result: %s", err)
		}
		if _, already := hasPublished[*msg.Server]; !already {
			hasPublished[*msg.Server] = struct{}{}
			// Continue verification once we've published
			publishesIn <- msg
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
			msg := item.(*ConsensusMSG)
			crs := msg.Publish.Canonical
			if !bytes.Equal(crs.ConsensusResult, r.signed_result.ConsensusResult) {
				log.Fatalf("Peer deviates from consensus")
			}
			r.signed_result.Signatures[r.signatures_on_result] = crs.Signatures[0]
			r.signed_result.Signers[r.signatures_on_result] = *msg.Server
		}
		r.signatures_on_result++
		signed_result_bs, err := proto.Marshal(&r.signed_result)
		if err != nil {
			panic(err)
		}
		rs, err := r.c.db.Exec(`UPDATE rounds SET signed_result = $1 WHERE id = $2
				AND signed_result IS NULL`, signed_result_bs, r.Id)
		if err != nil {
			log.Fatalf("UPDATE rounds SET signed_result: %s", err)
		}
		if n, _ := rs.RowsAffected(); n > 1 {
			log.Fatalf("UPDATE rounds SET signed_result affected %d rows", n)
		}
		r.SignedResult = signed_result_bs
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

func (r *round) HashAckData(commited map[int64]*[]byte) []byte {
	h := sha256.New()
	for _, id := range r.c.peer_ids {
		h.Write(*commited[int64(id)])
	}
	return h.Sum(nil)
}

type ByteSlices [][]byte

func (p ByteSlices) Len() int           { return len(p) }
func (p ByteSlices) Less(i, j int) bool { return bytes.Compare(p[i], p[j]) < 0 }
func (p ByteSlices) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
