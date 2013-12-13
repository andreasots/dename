package main

import (
	"bytes"
	"code.google.com/p/go.crypto/nacl/secretbox"
	"crypto/rand"
	"database/sql"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net"

	"code.google.com/p/goprotobuf/proto"
	"github.com/andres-erbsen/dename/protocol"
	"github.com/andres-erbsen/sgp"
	"github.com/daniel-ziegler/merklemap"
)

func (dn *Dename) ValidateRequest(rq_bs []byte) (name string, new_pk *sgp.Entity, err error) {
	signed_rq := &sgp.Signed{}
	err = proto.Unmarshal(rq_bs, signed_rq)
	if err != nil {
		return
	}

	new_mapping := &protocol.TransferName{}
	err = proto.Unmarshal(signed_rq.Message, new_mapping)
	if err != nil {
		return
	}

	new_pk = new(sgp.Entity)
	err = new_pk.Parse(new_mapping.PublicKey)
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

	if !pk.VerifyPb(signed_rq, protocol.SIGN_TAG_TRANSFER) {
		return "", nil, errors.New("Signature verification failed")
	}
	err = nil
	return
}

func (dn *Dename) HandleClient(conn net.Conn) {
	defer conn.Close()
	msg_bs, err := ioutil.ReadAll(conn)
	if err != nil {
		return
	}
	msg := &protocol.C2SMessage{}
	err = proto.Unmarshal(msg_bs, msg)
	if err != nil {
		return
	}

	switch {
	case msg.TransferName != nil:
		dn.HandleTransfer(msg.TransferName)
	case msg.Lookup != nil:
		dn.HandleLookup(conn, *msg.Lookup)
	}
}

func (dn *Dename) HandleTransfer(rq_bs []byte) {
	name, _, err := dn.ValidateRequest(rq_bs)
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
			log.Fatalf("HandleClient: cannot start db transaction: %s", err)
		}
		defer tx.Rollback()
		_, err = tx.Exec("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
		if err != nil {
			log.Fatalf("HandleClient: cannot set db transaction level: %s", err)
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
			log.Fatalf("Cannot insert \"%f\" to names_we_transfer: %s", name, err)
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
			log.Fatalf("HandleClient: cannot commit db transaction: %s", err)
		}
		break
	}

	dn.Broadcast(&protocol.S2SMessage{Round: &round, PushQueue: rq_box})
}

func (dn *Dename) HandleLookup(conn net.Conn, name string) {
	var pk []byte
	var round int64
	err := dn.db.QueryRow(`SELECT pubkey, last_modified FROM name_mapping
							WHERE name = $1`, name).Scan(&pk, &round)
	if err == sql.ErrNoRows {
		log.Printf("Could not find public key for name \"%s\": %s", name, err)
		return
	} else if err != nil {
		log.Fatalf("HandleLookup: load pubkey for %s: %s", name, err)
	}
	var signed_root_bs []byte
	var snapshot int64
	err = dn.db.QueryRow(`SELECT naming_snapshot, signed_root FROM rounds
					WHERE id = $1`, round).Scan(&snapshot, &signed_root_bs)
	if err != nil {
		log.Fatalf("HandleLookup: load naming snapshot for round %d: %s", name, err)
	}
	naming := dn.merklemap.GetSnapshot(snapshot)
	mapHandle, err := naming.OpenHandle()
	if err != nil {
		log.Fatalf("Error opening merklemap handle: %s", err)
	}
	name_hash := merklemap.Hash([]byte(name))
	pk_hash, merkle_path, err := mapHandle.GetPath(name_hash)
	if err != nil {
		log.Fatalf("Read path to %s from merklemap: %s", name, err)
	}

	signed_root := new(sgp.Signed)
	err = proto.Unmarshal(signed_root_bs, signed_root)
	if err != nil {
		log.Fatal("Invalid signed root in db: ", err)
	}

	root := new(protocol.MappingRoot)
	err = proto.Unmarshal(signed_root.Message, root)
	if err != nil {
		log.Fatal("Invalid MappingRoot in db: ", err)
	}

	if !bytes.Equal(root.Root, merkle_path.ComputeRootHash(name_hash, pk_hash)) {
		log.Fatal("MappingRoot in db does not match merklemap")
	}

	path_bs, err := proto.Marshal(merkle_path)
	if err != nil {
		panic(err)
	}

	response_bs, err := proto.Marshal(&protocol.LookupResponse{
		Root: signed_root_bs, Path: path_bs, PublicKey: pk})
	if err != nil {
		panic(err)
	}
	_, err = conn.Write(response_bs)
	if err != nil {
		log.Print(err)
	}
}
