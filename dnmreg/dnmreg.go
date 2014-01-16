package main

import (
	"code.google.com/p/goprotobuf/proto"
	"github.com/andres-erbsen/dename/protocol"
	"github.com/andres-erbsen/sgp"
	"io/ioutil"
	"log"
	"net"
	"os"
)

func main() {
	if len(os.Args) != 5 {
		log.Fatal("USAGE: ", os.Args[0], " SERVER NAME FROM.sk TO.pk")
	}
	sk, err := sgp.LoadSecretKeyFromFile(os.Args[3])
	if err != nil {
		log.Fatal(err)
	}
	if err != nil {
		log.Fatal(err)
	}

	pk_bs, err := ioutil.ReadFile(os.Args[4])

	attribution := &protocol.TransferName{}
	attribution.Name = []byte(os.Args[2])
	attribution.PublicKey = pk_bs

	atb_bytes, err := proto.Marshal(attribution)
	if err != nil {
		log.Fatal(err)
	}

	cert := sk.Sign(atb_bytes, protocol.SIGN_TAG_TRANSFER)
	msg_bs, err := proto.Marshal(&protocol.C2SMessage{TransferName: cert})
	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.Dial("tcp", os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	_, err = conn.Write([]byte{byte(len(msg_bs) & 0xff), (byte(len(msg_bs)>>8) & 0xff)})
	if err != nil {
		log.Fatal(err)
	}
	_, err = conn.Write(msg_bs)
	if err != nil {
		log.Fatal(err)
	}
}
