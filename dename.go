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

	// look up the old pk from the database
	fmt.Println(string(new_mapping.Name))
	var pk_bytes []byte
	pk := &sgp.Entity{}
	err = db.QueryRow("select pubkey from name_mapping where name = ?", new_mapping.Name).Scan(&pk_bytes)
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
	// TODO: add transaction/xfer/change to queue
	
	var box []byte
	box = secretbox.Seal(box[:0], rq_bs, &[24]byte{}, &[32]byte{})

	var key [32]byte
	err = db.QueryRow("SELECT key from rounds ORDER BY id DESC LIMIT 1;").Scan(key[:])
	fmt.Println(key)
}


func main () {
	db, err := sql.Open("sqlite3", "dename.db")
	if err != nil {
		log.Fatal("Cannot open dename.db", err)
	}
	defer db.Close()

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS transaction_queue (
		id integer not null primary key autoincrement,
		round integer not null,
		request blob not null);`)
	if err != nil {
		log.Fatal("Cannot create table transaction_queue", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS name_mapping (
		id integer not null primary key,
		name blob not null,
		pubkey blob not null);`)
	if err != nil {
		log.Fatal("Cannot create table name_mapping", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS rounds (
		id integer not null primary key,
		key blob not null);`)
	if err != nil {
		log.Fatal("Cannot create table rounds", err)
	}

	var id int
	err = db.QueryRow("select id from rounds").Scan(&id)
	if err == sql.ErrNoRows {
		var key [32]byte
		_, err = io.ReadFull(rand.Reader, key[:])
		if err != nil {
			log.Fatal(err)
		}
		_, err = db.Exec("INSERT INTO rounds(id,key) VALUES(?,?)", 0, key[:])
		if err != nil {
			log.Fatal("Cannot initialize table rounds", err)
		}
	}

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
