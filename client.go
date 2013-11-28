package main

import (
	"bytes"
	"code.google.com/p/go.crypto/nacl/secretbox"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"github.com/bmizerany/pq"
	"io"
	"io/ioutil"
	"log"
	"net"

	"code.google.com/p/goprotobuf/proto"
	"github.com/andres-erbsen/sgp"
)

const pgErrorRetrySerializeable = "40001"

func isPGError(err error, code string) bool {
	if err == nil {
		return false
	}
	pqErr, ok := err.(pq.PGError)
	return ok && pqErr.Get('C') == code
}

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

	nonce := new([24]byte)
	_, err = io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		log.Fatal(err)
	}

	dn.RoundForClients.RLock()
	defer dn.RoundForClients.RUnlock()

	var round int64
	var rq_box []byte
retry_transaction:
	for {
		tx, err := dn.db.Begin()
		if err != nil {
			log.Fatalf("HandleClient: cannot start db transaction: %f", err)
		}
		defer tx.Rollback()
		_, err = tx.Exec("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
		if err != nil {
			log.Fatalf("HandleClient: cannot set db transaction level: %f", err)
		}

		var key_slice []byte
		err = tx.QueryRow(`SELECT round,key FROM round_keys WHERE server = $1 ORDER
				BY id DESC LIMIT 1;`, dn.us.index).Scan(&round, &key_slice)
		if err != nil {
			log.Fatal("Cannot get latest round key: ", err)
		}
		key := new([32]byte)
		copy(key[:], key_slice)

		// Have we already accpedted a request to transfer this name this round
		var present int
		err = tx.QueryRow(`SELECT count(*) FROM names_we_transfer WHERE round =
				$1 AND name = $2`, round, name).Scan(&present)
		if err != nil {
			log.Fatal("Cannot check whether name is present: ", err)
		}

		if present != 0 {
			log.Print("Ignoring repeated transfer of \"", name, "\"")
			return
		}
		log.Print("Valid transfer of \"", name, "\"")

		_, err = tx.Exec(`INSERT INTO names_we_transfer(name,round)
				VALUES($1,$2);`, name, round)
		if isPGError(err, pgErrorRetrySerializeable) {
			tx.Rollback()
			continue retry_transaction
		} else if err != nil {
			log.Fatalf("Cannot insert \"%f\" to names_we_transfer: %f", name, err)
		}

		rq_box = secretbox.Seal(rq_box[:0], rq_bs, nonce, key)
		rq_box = append(nonce[:], rq_box...)
		_, err = tx.Exec("INSERT INTO transaction_queue(round,introducer,request) VALUES($1,$2,$3);",
			round, dn.us.index, rq_box)
		if isPGError(err, pgErrorRetrySerializeable) {
			tx.Rollback()
			continue retry_transaction
		} else if err != nil {
			log.Print(round, dn.us.index, rq_box)
			log.Fatal("Cannot insert new transaction to queue: ", err)
		}
		err = tx.Commit()
		if isPGError(err, pgErrorRetrySerializeable) {
			tx.Rollback()
			continue retry_transaction
		} else if err != nil {
			log.Fatalf("HandleClient: cannot commit db transaction: %f", err)
		}
		break
	}

	mb := new(bytes.Buffer)
	mb.WriteByte(1)
	binary.Write(mb, binary.LittleEndian, uint64(round))
	mb.Write(rq_box)
	dn.peer_broadcast <- mb.Bytes()
}
