package consensus

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
type QueueProcessor func(map[int64]*[][]byte, *prng.PRNG) []byte

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

	router *Router
	Peers  map[int64]Peer_

	IncomingRequests                         chan []byte
	incomingMessagesIn, incomingMessagesNext chan *protocol.S2SMessage
}

func NewConsensus(db *sql.DB, our_sk *sgp.SecretKey, our_id int64,
	queueProcessor QueueProcessor, genesisTime time.Time,
	tickInterval time.Duration, peers map[int64]Peer_) *Consensus {
	c := new(Consensus)
	c.db = db
	c.our_sk = our_sk
	c.our_id = our_id
	c.QueueProcessor = queueProcessor
	c.TickInterval = tickInterval
	c.genesisTime = genesisTime
	c.router = newRouter()
	c.Peers = peers

	c.incomingMessagesIn = make(chan *protocol.S2SMessage)
	c.incomingMessagesNext = make(chan *protocol.S2SMessage)
	go ringchannel.RingIQ(c.incomingMessagesIn, c.incomingMessagesNext)
	return c
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
	for id, peer := range c.Peers {
		if id != c.our_id {
			go peer.Send(msg_bs)
		}
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

func (c *Consensus) Run() {
	c.createTables()
	// TODO: ensure all peers are present in the db

	for id := range c.Peers {
		if id != c.our_id {
			go c.RefreshPeer(id)
		}
	}

	rows, err := c.db.Query(`SELECT id, close_time FROM rounds
		WHERE signed_snapshot_hash IS NULL ORDER BY id`)
	if err != nil {
		log.Fatalf("Cannot load outgoing messages: %s", err)
	}
	defer rows.Close()

	id := int64(0)
	t := c.genesisTime
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
	var msg_bs []byte
	msg := new(protocol.S2SMessage)
	for rows.Next() {
		err := rows.Scan(&msg_bs)
		if err != nil {
			log.Fatalf("msg from db: rows.Scan(&msg_bs): %s", err)
		}
		err = proto.Unmarshal(msg_bs, msg)
		if err != nil {
			log.Fatalf("replayRound(%d): proto.Unmarshal(msg_bs, msg): %s", round_n, err)
		}
		c.router.Send(msg)
	}
}

func (c *Consensus) OnMessage(peer_id int64, msg_bs []byte) {
	msg := new(protocol.S2SMessage)
	err := proto.Unmarshal(msg_bs, msg)
	if err != nil {
		log.Fatalf("OnMessage(%d,_): proto.Unmarshal(msg_bs, msg): %s", peer_id, err)
	}
	if *msg.Server != peer_id {
		log.Fatalf("%d tried to impersonate %d: %v", peer_id, *msg.Server, *msg)
	}
	_, err = c.db.Exec(`INSERT INTO messages(round,type,from,message)
		VALUES($1,$2,$3,$4)`, *msg.Round, msgtype(msg), *msg.Server, msg_bs)
	if err != nil {
		log.Fatalf("Insert our message to db %v: %s", *msg, err)
	}
	c.incomingMessagesIn <- msg
}

func (c *Consensus) handleMessages() {
	for msg := range c.incomingMessagesNext {
		c.router.Send(msg)
	}
}
