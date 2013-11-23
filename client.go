package main

import (
	"code.google.com/p/go.crypto/nacl/secretbox"
	"crypto/rand"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"io"
	"io/ioutil"
	"log"
	"net"

	"code.google.com/p/goprotobuf/proto"
	"github.com/andres-erbsen/sgp"
)

func (dn *Dename) ValidateRequest(rq_bs []byte) (name string, err error) {
	signed_rq := &sgp.Signed{}
	err = proto.Unmarshal(rq_bs, signed_rq)
	if err != nil {
		return
	}

	new_mapping := &sgp.Attribution{}
	err = proto.Unmarshal(signed_rq.Message, new_mapping)
	if err != nil {
		return
	}

	new_pk := &sgp.Entity{}
	err = new_pk.Parse(new_mapping.Pubkey)
	if err != nil {
		return
	}

	name = string(new_mapping.Name)
	var pk_bytes []byte
	pk := &sgp.Entity{}
	err = dn.db.QueryRow("SELECT pubkey FROM name_mapping WHERE name = $1", name).Scan(&pk_bytes)
	if err == nil {
		err = pk.Parse(pk_bytes)
		if err != nil {
			log.Fatal("Bad pk in database", err)
		}
	} else if err == sql.ErrNoRows {
		// new name being claimed
		pk = new_pk
	} else {
		log.Fatal(err) // FIXME: check error type
	}

	if !pk.VerifyPb(signed_rq) {
		return
	}
	return name, nil
}

func (dn *Dename) HandleClient(conn net.Conn) {
	defer conn.Close()
	rq_bs, err := ioutil.ReadAll(conn)
	if err != nil {
		return
	}
	name, err := dn.ValidateRequest(rq_bs)
	if err != nil {
		return
	}

	// Look up the key we use to encrypt this round's queue messages
	var key_slice []byte
	var round int
	err = dn.db.QueryRow(`SELECT round,key FROM round_keys WHERE server = $1 ORDER
			BY id DESC LIMIT 1;`, dn.us.index).Scan(&round, &key_slice)
	if err != nil {
		log.Fatal("Cannot get latest round key: ", err)
	}
	key := new([32]byte)
	copy(key[:], key_slice)

	// Have we already accpedted a request to transfer this name this round
	var present int
	err = dn.db.QueryRow(`SELECT count(*) FROM names_we_transfer WHERE round =
			$1 AND name = $2`, round, name).Scan(&present)
	if err != nil {
		log.Fatal("Cannot check whether name is present: ", err)
	}

	if present != 0 {
		log.Print("Ignoring repeated transfer of \"", name, "\"")
		return
	}
	log.Print("Valid transfer of \"", name, "\"")

	if _, err = dn.db.Exec("INSERT INTO names_we_transfer(name,round) VALUES($1,$2);",
		name, round); err != nil {
		log.Fatalf("Cannot insert \"%f\" to names_we_transfer: %f", name, err)
	}

	nonce := new([24]byte)
	_, err = io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		log.Fatal(err)
	}

	var rq_box []byte
	rq_box = secretbox.Seal(rq_box[:0], rq_bs, nonce, key)
	rq_box = append(nonce[:], rq_box...)
	_, err = dn.db.Exec("INSERT INTO transaction_queue(round,introducer,request) VALUES($1,$2,$3);",
		round, dn.us.index, rq_box)
	if err != nil {
		log.Print(round, dn.us.index, rq_box)
		log.Fatal("Cannot insert new transaction to queue: ", err)
	}
	dn.peer_broadcast <- append([]byte{1}, rq_box...)
}
