package main

import (
	"code.google.com/p/goprotobuf/proto"
	"database/sql"
	"github.com/andres-erbsen/dename/prng"
	"github.com/andres-erbsen/dename/protocol"
	"github.com/andres-erbsen/dename/ringchannel"
	"github.com/andres-erbsen/sgp"
	"log"
	"time"
)

// QueueProcessor takes a map (server -> []request) and handles the
// requests in some way. A randomness source shared between the servers
// is also available, but care has to be taken to read from it in a
// deterministic way. QueueProcessor should return a short description
// (usually a hash) of the new state.
// QueueProcessor :: Map Server [Request] -> Rand -> State -> State
type QueueProcessor func(map[int64][]*protocol.TransferName, *prng.PRNG) []byte

type Peer_ interface {
	Send([]byte)
	PK() *sgp.Entity
}

type Consensus struct {
	db             *sql.DB
	our_sk         *sgp.SecretKey
	our_id         int64
	QueueProcessor QueueProcessor

	router *Router
	Peers  map[int64]Peer_

	IncomingRequests chan *protocol.TransferName

	incomingMessagesIn, incomingMessagesNext chan []byte
}

func (c *Consensus) Init() {
	incomingMessagesIn = make(chan []byte)
	incomingMessagesNext = make(chan []byte)
	go ringchannel.RingIQ(c.incomingMessagesIn, c.incomingMessagesNext)
}

func (c *Consensus) broadcast(msg *protocol.S2SMessage) {
	*msg.Server = c.our_id
	msg_bs, err := proto.Marshal(msg)
	if err != nil {
		log.Fatalf("Marshal our message %v: %s", msg, err)
	}
	_, err = c.db.Exec(`INSERT INTO messages(round,type,from,message)
		VALUES($1,$2,$3,$4)`, *msg.Round, msgtype(msg), *msg.Server, msg_bs)
	if err != nil {
		log.Fatalf("Insert our message to db %v: %s", msg, err)
	}
	for _, peer := range c.Peers {
		go peer.Send(msg_bs)
	}
}

func (c *Consensus) RefreshPeer(id int64) {
	last_round_they_signed := int64(-1)
	err := c.db.QueryRow(`SELECT round FROM messages WHERE from = $1 AND
		type = $2 ORDER BY round DESC LIMIT 1`, id, S2S_PUBLISH).Scan(
		&last_round_they_signed)
	if err != nil && err != sql.ErrNoRows {
		log.Fatalf("last_round_they_signed: %s", err)
	}
	last_round_we_sent_messages_in := int64(-1)
	err = c.db.QueryRow(`SELECT round FROM messages WHERE from = $1 ORDER BY round
		DESC LIMIT 1`, c.our_id).Scan(&last_round_we_sent_messages_in)
	if err != nil && err != sql.ErrNoRows {
		log.Fatalf("last_round_we_sent_messages_in: %s", err)
	}

	// they may be missing our signature from the round they signed
	rows, err := c.db.Query(`SELECT message FROM messages WHERE from = $1
		AND ((round = $2 AND type = $4) OR ($2 < round AND round <= $3))`,
		c.our_id, last_round_they_signed, last_round_we_sent_messages_in, S2S_PUBLISH)
	if err != nil {
		log.Fatalf("Cannot load outgoing messages: %s", err)
	}
	defer rows.Close()

	for rows.Next() {
		var msg_bs []byte
		err := rows.Scan(&msg_bs)
		if err != nil {
			log.Fatalf("our msg from db: rows.Scan(&msg_bs): %s", err)
		}
		c.Peers[id].Send(msg_bs)
	}
}

func (c *Consensus) Run(genesisTime time.Time) {
	for id := range c.Peers {
		go c.RefreshPeer(id)
	}

	rows, err := c.db.Query(`SELECT id, close_time FROM rounds
		WHERE signed_snapshot_hash IS NULL ORDER BY id`)
	if err != nil {
		log.Fatalf("Cannot load outgoing messages: %s", err)
	}
	defer rows.Close()

	id := int64(0)
	t := genesisTime
	three_rounds := false
	if rows.Next() { // 1st
		var id, close_time_u int64
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
	round.ColdStart()

	c.replayRound(id)
	c.replayRound(id + 1)
	if three_rounds {
		<-round.afterWeHavePublished
		c.replayRound(id + 2)
	}

	c.handleMessages()
}

func (c *Consensus) replayRound(round_n int64) {
	rows, err := c.db.Query(`SELECT message FROM messages
		WHERE round = $1 AND from != $2 ORDER BY id ASC`, round_n, c.our_id)
	if err != nil {
		log.Fatalf("Cannot load incoming messages for round %d: %s", round_n, err)
	}
	defer rows.Close()
	for rows.Next() {
		var msg_bs []byte
		err := rows.Scan(&msg_bs)
		if err != nil {
			log.Fatalf("msg from db: rows.Scan(&msg_bs): %s", err)
		}
		c.handleMessage(msg_bs)
	}
}

func (c *Consensus) OnMessage(msg_bs []byte) {
	c.incomingMessagesIn <- msg_bs
}

func (c *Consensus) handleMessages() {
	for msg_bs := range incomingMessagesNext {
		c.handleMessage(msg_bs)
	}
}

func (c *Consensus) handleMessage(msg_bs []byte) {
	msg := new(protocol.S2SMessage)
	err := proto.Unmarshal(msg_bs, msg)
	if err != nil {
		log.Fatalf("OnMessage: proto.Unmarshal(msg_bs, msg): %s", err)
	}
	_, err = c.db.Exec(`INSERT INTO messages(round,type,from,message)
		VALUES($1,$2,$3,$4)`, *msg.Round, msgtype(msg), *msg.Server, msg_bs)
	if err != nil {
		log.Fatalf("Insert our message to db %v: %s", msg, err)
	}
	c.router.Send(msg)
}
