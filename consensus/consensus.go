package consensus

import (
	"code.google.com/p/go.crypto/nacl/secretbox"
	"code.google.com/p/goprotobuf/proto"
	"database/sql"
	"github.com/andres-erbsen/dename/pgutil"
	"github.com/andres-erbsen/dename/prng"
	"github.com/andres-erbsen/dename/ringchannel"
	"github.com/andres-erbsen/sgp"
	"log"
	"time"
)

// QueueProcessor takes a map (server -> []request) and handles the
// requests in some way. A randomness source shared between the servers
// is also available, but care has to be taken to read from it in a
// deterministic way. QueueProcessor should return a short description
// (usually a hash) of the new state. Last argument is round number.
// QueueProcessor :: Map Server [Request] -> Rand -> Int64 -> State -> State
type QueueProcessor func(map[int64]*[][]byte, *prng.PRNG, int64) []byte

type Peer_ interface {
	Send([]byte) error
	PK() *sgp.Entity
}

type Consensus struct {
	db             *sql.DB
	our_sk         *sgp.SecretKey
	our_id         int64
	QueueProcessor QueueProcessor
	genesisTime    time.Time
	TickInterval   time.Duration

	router    *Router
	Peers     map[int64]Peer_
	sign_tags map[int]uint64 // COMMITMENT, ACKNOWLEDGEMENT, PUBLISH -> tag

	IncomingRequests chan []byte
	// Actually channels of *ConsensusMSG
	incomingMessagesIn, incomingMessagesNext chan interface{}
}

type serialized_msg struct {
	bytes []byte
	msg   *ConsensusMSG
}

func NewConsensus(db *sql.DB, our_sk *sgp.SecretKey, our_id int64,
	queueProcessor QueueProcessor, genesisTime time.Time,
	tickInterval time.Duration, peers map[int64]Peer_,
	sign_tags map[int]uint64) *Consensus {
	c := new(Consensus)
	c.db = db
	c.our_sk = our_sk
	c.our_id = our_id
	c.QueueProcessor = queueProcessor
	c.TickInterval = tickInterval
	c.genesisTime = genesisTime
	c.router = newRouter()
	c.Peers = peers
	c.sign_tags = sign_tags
	c.IncomingRequests = make(chan []byte)

	c.incomingMessagesIn = make(chan interface{})
	c.incomingMessagesNext = make(chan interface{})
	go ringchannel.RingIQ(c.incomingMessagesIn, c.incomingMessagesNext)

	c.createTables()
	for id := range c.Peers {
		_, err := c.db.Exec(`INSERT INTO servers(id) VALUES($1)`, id)
		if err != nil && !pgutil.IsError(err, pgutil.ErrUniqueViolation) {
			log.Fatalf("INSERT INTO servers(id) %d: %d", id, err)
		}
	}

	return c
}

func (c *Consensus) broadcast(msg *ConsensusMSG) {
	msg.Server = &c.our_id
	msg_bs, err := proto.Marshal(msg)
	if err != nil {
		log.Fatalf("Marshal our message %v: %s", msg, err)
	}
	c.savemsg(msg, msg_bs)
	for id, peer := range c.Peers {
		if id != c.our_id {
			if err := peer.Send(msg_bs); err != nil {
				log.Printf("peer%d.Send(msg_bs{%d %s} = %x): %s", id, *msg.Round, msgtypeName[msgtype(msg)], msg_bs, err)
			}
		}
	}
}

func (c *Consensus) RefreshPeer(id int64) (err error) {
	last_round_they_signed := int64(-1)
	err = c.db.QueryRow(`SELECT round FROM messages WHERE sender = $1 AND
		type = $2 ORDER BY round DESC LIMIT 1`, id, PUBLISH).Scan(
		&last_round_they_signed)
	if err != nil && err != sql.ErrNoRows {
		log.Fatalf("last_round_they_signed: %s", err)
	}

	// they may be missing our signature from the round they signed
	rows, err := c.db.Query(`SELECT message FROM messages WHERE sender = $1
		AND ((round = $2 AND type = $3) OR $2 < round) ORDER BY id`,
		c.our_id, last_round_they_signed, PUBLISH)
	if err != nil {
		log.Fatalf("Cannot load outgoing messages: %s", err)
	}
	defer rows.Close()

	for rows.Next() {
		var msg_bs []byte
		if err := rows.Scan(&msg_bs); err != nil {
			log.Fatalf("our msg from db: rows.Scan(&msg_bs): %s", err)
		}
		if err := c.Peers[id].Send(msg_bs); err != nil {
			log.Printf("RefreshPeer: c.Peers[id].Send(msg_bs): %s", err)
			return err
		}
	}
	return nil
}

func (c *Consensus) Run() {
	rows, err := c.db.Query(`SELECT id, close_time FROM rounds
		WHERE signed_result IS NULL ORDER BY id`)
	if err != nil {
		log.Fatalf("Cannot load outgoing messages: %s", err)
	}
	defer rows.Close()

	id := int64(0)
	t := c.genesisTime
	three_rounds := false
	if rows.Next() { // 1st
		var close_time_u int64
		if err := rows.Scan(&id, &close_time_u); err != nil {
			log.Fatalf("rows.Scan(&id, &close_time_u) 1: %s", err)
		}
		t = time.Unix(close_time_u, 0)
		if !rows.Next() { //2nd
			log.Fatal("Only one unfinished round!")
		}
		three_rounds = rows.Next() // 3rd
		if rows.Next() {           // 4th
			log.Fatal("More than three unfinished rounds")
		}
	}
	rows.Close()

	round := newRound(id, t, c)
	round.next = newRound(round.id+1, t.Add(c.TickInterval), c)
	c.reloadRequests(round)
	c.reloadRequests(round.next)
	round.ColdStart()

	c.replayRound(id)
	c.replayRound(id + 1)
	if three_rounds {
		<-round.afterWeHavePublished
		c.replayRound(id + 2)
	}

	c.handleMessages()
}

func (c *Consensus) reloadRequests(r *round) {
	rows, err := c.db.Query(`SELECT message FROM messages
		WHERE round = $1 AND sender = $2 AND type = $3 ORDER BY id ASC`, r.id, c.our_id, PUSH)
	if err != nil {
		log.Fatalf("Cannot load outgoing pushes for round %d: %s", r.id, err)
	}
	defer rows.Close()
	var msg_bs []byte
	msg := new(ConsensusMSG)
	for rows.Next() {
		err := rows.Scan(&msg_bs)
		if err != nil {
			log.Fatalf("msg from db: rows.Scan(&msg_bs): %s", err)
		}
		err = proto.Unmarshal(msg_bs, msg)
		if err != nil {
			log.Fatalf("reloadRequests(%d): proto.Unmarshal(msg_bs, msg): %s", r.id, err)
		}
		rq_box := msg.PushQueue
		var nonce [24]byte
		copy(nonce[:], rq_box[:24])
		r.pushes[c.our_id][nonce] = rq_box
		rq, ok := secretbox.Open(nil, rq_box[24:], &nonce, r.our_round_key)
		if !ok {
			log.Fatalf("reloadRequests(%d): Failed to decrypt our queue %x key %x", r.id, rq_box, *r.our_round_key)
		}
		*r.requests[c.our_id] = append(*r.requests[c.our_id], rq)
	}
}

func (c *Consensus) replayRound(round_n int64) {
	rows, err := c.db.Query(`SELECT message FROM messages
		WHERE round = $1 AND sender != $2 ORDER BY id ASC`, round_n, c.our_id)
	if err != nil {
		log.Fatalf("Cannot load incoming messages for round %d: %s", round_n, err)
	}
	defer rows.Close()
	var msg_bs []byte
	msg := new(ConsensusMSG)
	for rows.Next() {
		err := rows.Scan(&msg_bs)
		if err != nil {
			log.Fatalf("msg from db: rows.Scan(&msg_bs): %s", err)
		}
		err = proto.Unmarshal(msg_bs, msg)
		if err != nil {
			log.Fatalf("replayRound(%d): proto.Unmarshal(msg_bs, msg): %s", round_n, err)
		}
		c.router.SendWait(msg)
	}
}

func (c *Consensus) OnMessage(peer_id int64, msg_bs []byte) {
	msg := new(ConsensusMSG)
	err := proto.Unmarshal(msg_bs, msg)
	if err != nil {
		log.Fatalf("OnMessage(%d,%x): proto.Unmarshal(msg_bs, msg): %s", peer_id, msg_bs, err)
	}
	if *msg.Server != peer_id {
		log.Fatalf("%d tried to impersonate %d: %v", peer_id, *msg.Server, *msg)
	}

	c.incomingMessagesIn <- serialized_msg{msg_bs, msg}
}

func (c *Consensus) handleMessages() {
	for item := range c.incomingMessagesNext {
		msg := item.(serialized_msg).msg
		c.savemsg(msg, item.(serialized_msg).bytes)
		err := c.router.Send(msg)
		if err != nil {
			log.Printf("%d-> %d:%v: %s", *msg.Server, *msg.Round, msgtypeName[msgtype(msg)], err)
		}
	}
}

func (c *Consensus) savemsg(msg *ConsensusMSG, msg_bs []byte) {
	_, err := c.db.Exec(`INSERT INTO messages(round,type,sender,message)
		VALUES($1,$2,$3,$4)`, *msg.Round, msgtype(msg), *msg.Server, msg_bs)
	if err != nil && !pgutil.IsError(err, pgutil.ErrUniqueViolation) {
		log.Fatalf("Insert message to db %v: %s", *msg, err)
	}
}
