package main

import (
	"code.google.com/p/goprotobuf/proto"
	"github.com/andres-erbsen/dename/protocol"
	"github.com/andres-erbsen/sgp"
	"github.com/daniel-ziegler/merklemap"
	// "github.com/andres-erbsen/sgp"
	"bytes"
	"code.google.com/p/gcfg"
	"encoding/base64"
	"io/ioutil"
	"log"
	"net"
	"os"
)

type Cfg struct {
	Peer map[string]*struct {
		Host string
	}
}

func main() {
	if len(os.Args) != 3 {
		log.Fatal("USAGE: ", os.Args[0], " CONFIG NAME")
	}
	cfg := new(Cfg)
	err := gcfg.ReadFileInto(cfg, os.Args[1])
	if err != nil {
		log.Fatalf("Failed to parse gcfg data: %s", err)
	}

	query_bs, err := proto.Marshal(&protocol.C2SMessage{Lookup: []byte(os.Args[2])})
	if err != nil {
		panic(err)
	}

	var host string
	for _, peer := range cfg.Peer {
		host = peer.Host
		break
	}
	conn, err := net.Dial("tcp", host+":6263")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	_, err = conn.Write(query_bs)
	if err != nil {
		log.Fatal(err)
	}

	response_bs, err := ioutil.ReadAll(conn)
	if err != nil {
		log.Fatal(err)
	}

	response := new(protocol.LookupResponse)
	err = proto.Unmarshal(response_bs, response)
	if err != nil {
		log.Fatalf("Bad response from server: %s", err)
	}
	root_signed := new(sgp.Signed)
	err = proto.Unmarshal(response.Root, root_signed)
	if err != nil {
		log.Fatalf("Bad response (signed root) from server: %s", err)
	}

	for pk_b64, peer := range cfg.Peer {
		pk_bytes, err := base64.StdEncoding.DecodeString(pk_b64)
		if err != nil {
			log.Fatalf("Bad base64 as public key: %f (for %f)", err, peer.Host)
		}
		pk := &sgp.Entity{}
		err = pk.Parse(pk_bytes)
		if err != nil {
			log.Fatalf("Bad pk: %f (for %f)", err, peer.Host)
		}
		if !pk.VerifyPb(root_signed, protocol.SIGN_TAG_PUBLISH) {
			log.Fatal("Bad signature from peer")
		}
	}

	rootdata := new(protocol.MappingRoot)
	err = proto.Unmarshal(root_signed.Message, rootdata)
	if err != nil {
		log.Fatalf("Bad response (root data) from server: %s", err)
	}
	root_hash := rootdata.Root

	path := new(merklemap.LookupResult)
	err = proto.Unmarshal(response.Path, path)
	if err != nil {
		log.Fatalf("Bad path from server: %s", err)
	}

	if !bytes.Equal(path.ComputeRootHash(), root_hash) {
		log.Fatal("Root hash does not match")
	}

	if !bytes.Equal(path.Value[:], (*merklemap.Hash(response.PublicKey))[:]) {
		log.Fatal("Public key does not match the hash")
	}
}
