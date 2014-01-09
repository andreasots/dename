package main

import (
	"code.google.com/p/goprotobuf/proto"
	"database/sql"
	"github.com/andres-erbsen/dename/prng"
	"github.com/andres-erbsen/dename/protocol"
	"github.com/andres-erbsen/sgp"
	"log"
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
	our_sk         sgp.SecretKey
	our_id         int64
	QueueProcessor QueueProcessor

	router *Router
	Peers  map[int64]Peer_

	IncomingRequests chan *protocol.TransferName
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

	rows, err := c.db.Query(`SELECT message FROM messages
		WHERE from = $1 AND $2 < round AND round <= $3`,
		c.our_id, last_round_they_signed, last_round_we_sent_messages_in)
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

func (c *Consensus) Run() {
	for id := range c.Peers {
		go c.RefreshPeer(id)
	}
}

func (c *Consensus) OnMessage(msg_bs []byte) {
	msg := new(protocol.S2SMessage)
	err := proto.Unmarshal(msg_bs, msg)
	if err != nil {
		log.Fatalf("OnMessage: proto.Unmarshal(msg_bs, msg): %s", err)
	}
	c.router.Send(msg)
}

func (c *Consensus) replayRound(round_n int64) {
	rows, err := c.db.Query(`SELECT message FROM messages
		WHERE round = $1 AND from != $2`, round_n, c.our_id)
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
		c.OnMessage(msg_bs)
	}
}
