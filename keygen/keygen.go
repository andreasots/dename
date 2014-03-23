package main

import (
	"code.google.com/p/go.crypto/nacl/box"
	"code.google.com/p/goprotobuf/proto"
	"crypto/rand"
	"encoding/binary"
	"github.com/agl/ed25519"
	"github.com/andres-erbsen/dename/protocol"
	"os"
)

type secretKey struct {
	protocol.Curve25519Secret
	protocol.Ed25519Secret
}

func main() {
	signpk, signsk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	boxpk, boxsk, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	err = binary.Write(os.Stderr, binary.LittleEndian, secretKey{*boxsk, *signsk})
	if err != nil {
		panic(err)
	}
	pks, err := proto.Marshal(&protocol.PublicKey{Ed25519: signpk[:], Curve25519: boxpk[:]})
	if err != nil {
		panic(err)
	}
	_, err = os.Stdout.Write(pks)
	if err != nil {
		panic(err)
	}
}
