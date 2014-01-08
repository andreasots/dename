package main

import (
	"code.google.com/p/goprotobuf/proto"
	"database/sql"
	"github.com/andres-erbsen/dename/prng"
	"github.com/andres-erbsen/dename/protocol"
	"github.com/andres-erbsen/sgp"
	"log"
)

type Request []byte

// QueueProcessor takes a map (server -> []request) and handles the
// requests in some way. A randomness source shared between the servers
// is also available, but care has to be taken to read from it in a
// deterministic way. QueueProcessor should return a short description
// (usually a hash) of the new state.
// QueueProcessor :: Map Server [Request] -> Rand -> State -> State
type QueueProcessor func(map[int64][]*Request, *prng.PRNG) []byte

type Peer_ interface {
	Send(*protocol.S2SMessage)
	PK() *sgp.Entity
}

type Consensus struct {
	db             *sql.DB
	our_sk         sgp.SecretKey
	QueueProcessor QueueProcessor

	Router *Router
	Peers  map[int64]Peer_

	IncomingRequests chan *protocol.TransferName
}

func (c *Consensus) Broadcast(msg *protocol.S2SMessage) {
	for _, peer := range c.Peers {
		go peer.Send(msg)
	}
}

func (c *Consensus) Run() {
}

func (c *Consensus) ReplayRound(round_n int64) {
	rows, err := c.db.Query(`SELECT message FROM messages WHERE round = $1`, round_n)
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
		msg := new(protocol.S2SMessage)
		err = proto.Unmarshal(msg_bs, msg)
		if err != nil {
			log.Fatalf("msg from db: proto.Unmarshal(msg_bs, msg): %s", err)
		}
		c.Router.Send(msg)
	}
}
