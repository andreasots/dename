package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"sync"
	"time"
	"bytes"
	_ "github.com/mattn/go-sqlite3"
	"io"
	"log"
	"net"
	"errors"

	"code.google.com/p/goprotobuf/proto"
	"github.com/andres-erbsen/sgp"
)

const TICK_INTERVAL = 4*time.Second
const S2S_PORT = "6362"

type Peer struct {
	index int
	addr  string
	pk    *sgp.Entity

	sync.RWMutex
	conn  net.Conn // mutable
	closeOnce *sync.Once
}

type Dename struct {
	db             *sql.DB
	our_sk         sgp.SecretKey
	us             *Peer
	peers          map[int]*Peer
	addr2peer      map[string]*Peer

	peer_lnr       *net.TCPListener
	client_lnr     net.Listener

	peer_broadcast chan []byte
	acks_for_consensus  chan VerifiedAckedCommitment
}

type VerifiedAckedCommitment struct {
	Commitment *Commitment
	Acknowledger int
}

func (dn *Dename) HandleMessage(peer *Peer, msg []byte) (err error) {
	// log.Print("Received ", len(msg), " bytes from ", peer.addr)
	if msg[0] == 1 {
		_, err = dn.db.Exec("INSERT INTO transaction_queue(round,introducer,request) SELECT MAX(id),?,? FROM rounds;", peer.index, msg[1:])
		if err != nil {
			log.Fatal("Cannot insert new transaction to queue: ", err)
		}
	} else if msg[0] == 2 {
		return dn.HandleCommitment(peer, msg[1:])
	} else if msg[0] == 3 {
		return dn.HandleAck(peer, msg[1:])
	} else {
		log.Print("Unknown message of type ", msg[0]," from ", peer.index)
	}
	return
}


func (dn *Dename) HandleCommitment(peer *Peer, signed_commitment []byte) (err error) {
	log.Print("Commit from ", peer.index)
	commitment, err := peer.pk.Verify(signed_commitment)
	if err != nil {
		return
	}
	if string(commitment[:4]) != "COMM" {
		return errors.New("Bad tag on commitment")
	}
	cd := &Commitment{}
	err = proto.Unmarshal(commitment[4:], cd); if err != nil {
		return
	}
	if *cd.Server != int64(peer.index) {
		return errors.New("Bad server id commitment")
	}
	ack:= dn.our_sk.Sign(append([]byte("ACKN"), signed_commitment...))
	err = dn.HandleAck(dn.peers[dn.us.index], ack)
	if err != nil {
		panic(err)
	}
	dn.peer_broadcast <- append([]byte{3}, ack...)
	return nil
}

func (dn *Dename) UnpackAckCommitment(c, a int, signed_ack_bs []byte) (commitdata *Commitment, err error) {
	// c = -1 means "extract c from commitment"
	if a >= len(dn.peers) || c >= len(dn.peers) || c < -1 || a < 0 {
		return nil, errors.New("No such peer")
	}
	ackdata, err := dn.peers[a].pk.Verify(signed_ack_bs); if err != nil {
		return nil, err
	}
	if string(ackdata[:4]) != "ACKN" {
		return nil, errors.New("Bad tag on ack")
	}
	if c == -1 {
		signed_commitment := &sgp.Signed{}
		err = proto.Unmarshal(ackdata[4:], signed_commitment)
		if err != nil {
			return nil, err
		}
		commitdata_ := &Commitment{}
		err = proto.Unmarshal(signed_commitment.Message[4:], commitdata_)
		if err != nil {
			return nil, err
		}
		c = int(*commitdata_.Server)
	}
	commitment, err := dn.peers[c].pk.Verify(ackdata[4:]); if err != nil {
		return nil, err
	}
	if string(commitment[:4]) != "COMM" {
		return nil, errors.New("Bad tag on commitment")
	}
	commitdata = new(Commitment)
	err = proto.Unmarshal(commitment[4:], commitdata); if err != nil {
		return nil, err
	}
	return
}

func UnverifiedUnpackAckCommitment(signed_ack_bs []byte) (commitdata *Commitment) { // for debugging
	commitdata = new(Commitment)
	signed_ack := &sgp.Signed{}
	err := proto.Unmarshal(signed_ack_bs, signed_ack)
	if err != nil {
		log.Fatal(err)
	}
	signed_commitment_bs := signed_ack.Message[4:] // starts with "ACKN"
	signed_commitment := &sgp.Signed{}
	err = proto.Unmarshal(signed_commitment_bs, signed_commitment); if err != nil {
		log.Fatal(err)
	}
	commitdata_bs := signed_commitment.Message[4:] // starts with "COMM"
	err = proto.Unmarshal(commitdata_bs, commitdata); if err != nil {
		log.Fatal(err)
	}
	return
}

func (dn *Dename) HandleAck(peer *Peer, signed_ack []byte) (err error) {
	commitment, err := dn.UnpackAckCommitment(-1, peer.index, signed_ack)
	if err != nil {
		return
	}
	_, err = dn.db.Exec(`INSERT INTO
			commitments(round,commiter,acknowledger,signature)
			VALUES(?,?,?,?)`,
			commitment.Round, commitment.Server, peer.index, signed_ack)
	// log.Print(peer.index, " acked ", *commitment.Server, " (round ", *commitment.Round, ")")
	log.Print("Ack ",*commitment.Server ," from ", peer.index)
	go func() { // for efficency, one would use ana ctual elastic buffer channel
		dn.acks_for_consensus <- VerifiedAckedCommitment{
			Commitment:commitment, Acknowledger: peer.index}
	}()
	return
}

func (dn *Dename) WaitForTicks(round int, end time.Time) (err error) {
	for {
		log.Print(round, time.Now().Second(), end.Second())
		if time.Now().After(end) {
			end = end.Add(TICK_INTERVAL)
			round++
			// switch new requests to the new round first, then finalize the old
			err = dn.NextRound(round, end)
			if err != nil {
				log.Fatal("Cannot advance round: ", err)
			}
			if round-1 != -1 {
				dn.Tick(round-1)
			}
		}
		time.Sleep(end.Sub(time.Now()))
	}
}

func (dn *Dename) NextRound(round int, end time.Time) (err error) {
	var key [32]byte
	_, err = io.ReadFull(rand.Reader, key[:])
	if err != nil {
		return
	}
	tx, err := dn.db.Begin()
	if err != nil {
		return
	}
	_, err = tx.Exec("INSERT INTO rounds(id, end_time) VALUES(?,?)", round, end.Unix())
	if err != nil {
		tx.Rollback()
		log.Fatal("Cannot insert to table rounds: ", err)
	}
	_, err = tx.Exec("INSERT INTO round_keys(round,server,key) VALUES(?,?,?)",
			round, dn.us.index, key[:])
	if err != nil {
		tx.Rollback()
		return
	}
	tx.Commit()
	return
}

func (dn *Dename) ReadQueue(round int) *Queue {
	round_, server_ := int64(round), int64(dn.us.index)
	Q := &Queue{Round: &round_, Server: &server_, Entries: make([][]byte,1)}
	rows, err := dn.db.Query(`SELECT request FROM transaction_queue WHERE round
			= ? AND introducer = ? ORDER BY id`, round, dn.us.index)
	if err != nil {
        log.Fatal("Cannot load transactions for tick: ", err)
    }
	defer rows.Close()
	var transaction []byte
	for rows.Next() {
		err := rows.Scan(&transaction)
		if err != nil {
			log.Fatal("Cannot load transaction for tick: ", err)
		}
		Q.Entries = append(Q.Entries, transaction)
	}
	return Q
}

func QueueToCommitdata(Q *Queue) (cdata []byte, err error) {
	Q_bytes, err := proto.Marshal(Q)
	if err != nil {
		return
	}
	h := sha256.New()
	_, err = h.Write(Q_bytes)
	if err != nil {
		return
	}
	C := &Commitment{Round: Q.Round, Server: Q.Server, QueueHash: h.Sum(nil)}
	cdata, err = proto.Marshal(C)
	if err != nil {
		cdata = nil
	}
	return
}

func (dn *Dename) Tick(round int) {
	log.Print("Round ", round, " ended")
	// commit to the current queue
	Q := dn.ReadQueue(round)
	commitdata, err := QueueToCommitdata(Q)
	if err != nil {
		log.Fatal("Serialize commitment data: ", err)
	}
	commitment := dn.our_sk.Sign(append([]byte("COMM"), commitdata...))
	err = dn.HandleCommitment(dn.us, commitment)
	if err != nil {
		log.Fatal(err)
	}
	dn.peer_broadcast <- append([]byte{2}, commitment...)

	n := len(dn.addr2peer)
	queueHash := make([][]byte, n)
	hasAcked := make([][]bool, n)
	for i := range hasAcked {
		hasAcked[i] = make([]bool, n)
	}
	acks_remaining := n*n

	rows, err := dn.db.Query("SELECT commiter,acknowledger,signature FROM commitments WHERE round = ?", round)
	if err != nil {
        log.Fatal("Cannot load commitments for round ", round,": ", err)
    }
	go func () {
		defer rows.Close()
		for rows.Next() {
			var c, a int // commiter and acknowledger
			var ack []byte
			err = rows.Scan(&c, &a, &ack); if err != nil {
				log.Fatal("Bad ack in database: ", err)
			}
			commitment, err := dn.UnpackAckCommitment(c,a,ack)
			if err != nil {
				log.Fatal("Bad ack in database: ", err)
			}
			dn.acks_for_consensus <- VerifiedAckedCommitment{
				Commitment: commitment,
				Acknowledger: a}
		}
		// log.Print("Loaded all relevant acks from table")
	}()

	for ack := range dn.acks_for_consensus {
		if int(*ack.Commitment.Round) != round {
			continue
		}
		a := ack.Acknowledger
		c := int(*ack.Commitment.Server)
		qh := ack.Commitment.QueueHash
		if queueHash[c] == nil {
			queueHash[c] = qh
		}
		if ! bytes.Equal(queueHash[c], qh) {
			log.Fatal("Server ", c, " commited to multiple things")
		}
		if ! hasAcked[a][c] {
			acks_remaining--
		}
		hasAcked[a][c] = true
		if acks_remaining == 0 {
			break
		}
		log.Print( a," @ ",c,"; need ", acks_remaining, " more")
	}

	log.Print("end dn.Tick(", round, ")")
}

