package main

import (
	"os"
	"io"
	"io/ioutil"
	"fmt"
	"encoding/base64" 
	"log"
	"net"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"code.google.com/p/go.crypto/nacl/secretbox"
	"crypto/rand"

	"code.google.com/p/goprotobuf/proto"
	"github.com/andres-erbsen/sgp"
)

const OUR_SERVER_ID = 0

func create_tables(db *sql.DB) {
	_, err := db.Exec(`PRAGMA foreign_keys = ON;`)
	if err != nil {
		log.Fatal("Cannot PRAGMA foreign_keys = ON: ", err)
	}

	// servers
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS servers (
		id integer not null primary key);`)
	if err != nil {
		log.Fatal("Cannot create table servers: ", err)
	}

	// rounds
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS rounds (
		id integer not null primary key);`)
	if err != nil {
		log.Fatal("Cannot create table rounds: ", err)
	}

	// round_keys
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS round_keys (
		id integer not null primary key,
		round integer not null,
		server integer not null,
		key blob not null,
		FOREIGN KEY(round) REFERENCES rounds(id),
		FOREIGN KEY(server) REFERENCES servers(id));`)
	if err != nil {
		log.Fatal("Cannot create table round_keys: ", err)
	}

	// transaction_queue
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS transaction_queue (
		id integer not null primary key autoincrement,
		round integer not null,
		introducer integer not null,
		request blob not null,
		FOREIGN KEY(round) REFERENCES round(id),
		FOREIGN KEY(introducer) REFERENCES servers(id));`)
	if err != nil {
		log.Fatal("Cannot create table transaction_queue: ", err)
	}

	// commitments
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS commitments (
		id integer not null primary key,
		round integer not null,
		commiter integer not null,
		acknowledger integer not null,
		signature blob not null,
		FOREIGN KEY(round) REFERENCES rounds(id),
		FOREIGN KEY(commiter) REFERENCES servers(id),
		FOREIGN KEY(acknowledger) REFERENCES servers(id));`)
	if err != nil {
		log.Fatal("Cannot create table commitments: ", err)
	}

	// name_mapping
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS name_mapping (
		id integer not null primary key,
		name blob not null,
		pubkey blob not null);`)
	if err != nil {
		log.Fatal("Cannot create table name_mapping: ", err)
	}

	// our server
	var ok int
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM servers)").Scan(&ok)
	if err != nil {
		log.Fatal("Cannot read table servers: ", err)
	}
	if ok == 0 {
		_, err = db.Exec("INSERT INTO servers(id) VALUES(?)", OUR_SERVER_ID)
		if err != nil {
			log.Fatal("Cannot initialize table servers: ", err)
		}
	}

	// first round and round key
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM round_keys)").Scan(&ok)
	if err != nil {
		log.Fatal("Cannot read table rounds: ", err)
	}
	if ok == 0 {
		_, err = db.Exec("INSERT INTO rounds(id) VALUES(0)")
		if err != nil {
			log.Fatal("Cannot initialize table rounds: ", err)
		}
		var key [32]byte
		_, err = io.ReadFull(rand.Reader, key[:])
		if err != nil {
			log.Fatal(err)
		}
		_, err = db.Exec("INSERT INTO round_keys(id,round,server,key) VALUES(0,0,0,?)", key[:])
		if err != nil {
			log.Fatal("Cannot initialize table round_keys: ", err)
		}
	}
}


func handleClient(db *sql.DB, conn net.Conn) {
	defer conn.Close()
	rq_bs, err := ioutil.ReadAll(conn)
	if err != nil {
		return
	}
	
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

	fmt.Println(string(new_mapping.Name))
	var pk_bytes []byte
	pk := &sgp.Entity{}
	err = db.QueryRow("SELECT pubkey FROM name_mapping WHERE name = ?", new_mapping.Name).Scan(&pk_bytes)
	if err == nil {
		err = pk.Parse(pk_bytes)
		if err != nil {
			log.Fatal("Bad pk in database", err)
		}
	} else if err == sql.ErrNoRows {
		// new name being claimed
		pk = new_pk
	} else  {
		log.Fatal(err) // FIXME: check error type
	}

	if ! pk.Verify(signed_rq) {
		return
	}
	log.Print("valid transfer of \"", string(new_mapping.Name), "\" to ", pk)

	// Is this update new to us?
	var exists int
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM transaction_queue WHERE request = ?)", rq_bs).Scan(&exists)
	if exists == 1 {
		log.Print("Request already in queue")
		return
	}

	// Look up the key we use to encrypt this round's queue messages
	var key_slice []byte
	err = db.QueryRow("SELECT key FROM rounds ORDER BY id DESC LIMIT 1;").Scan(&key_slice)
	if err != nil {
		log.Fatal(err)
	}
	var key [32]byte
	copy(key[:], key_slice)
	log.Print(key)
	
	var box []byte
	box = secretbox.Seal(box[:0], rq_bs, &[24]byte{}, &key)
}


func main () {
	db, err := sql.Open("sqlite3", "dename.db")
	if err != nil {
		log.Fatal("Cannot open dename.db", err)
	}
	defer db.Close()

	create_tables(db)

	peersfile, err := os.Open("peers.txt")
	if err != nil {
		log.Fatal("Cannot open peers.txt", err)
	}
	for i:=1; ; i++ {
		var host, pk_type, pk_b64 string
		_, err := fmt.Fscanf(peersfile, "%s %s %s\n", &host, &pk_type, &pk_b64)
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal("Syntax error in peers.txt on line ",i, ":", err)
		}
		if pk_type != "sgp" {
			log.Fatal("pk_type != sgp in peers.txt on line ",i)
		}
		_, err = base64.StdEncoding.DecodeString(pk_b64)
		if err != nil {
			log.Fatal("Bad base64 in peers.txt on line ",i)
		}
		// conn, err := net.Dial("tcp", host)
	}

	_, err = net.Listen("tcp", "0.0.0.0:6362")	
	if err != nil {
		log.Fatal(err)
	}
	// other servers...

	client_lnr, err := net.Listen("tcp", "0.0.0.0:6263")	
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, _ := client_lnr.Accept()
		go handleClient(db, conn)
	}
}
