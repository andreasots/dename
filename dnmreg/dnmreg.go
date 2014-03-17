package main

import (
	"encoding/binary"
	"github.com/andres-erbsen/dename/dnmclient"
	"github.com/andres-erbsen/dename/protocol"
	"log"
	"os"
)

func main() {
	if len(os.Args) != 4 {
		log.Fatal("USAGE: ", os.Args[0], " sk NAME REGTOKEN")
	}
	var sk protocol.Ed25519Secret
	skfile, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatalf("Cannot open sk file \"%s\": %s", os.Args[1], err)
	}
	if err := binary.Read(skfile, binary.LittleEndian, &sk); err != nil {
		log.Fatalf("Load secret key from \"sk\": %s", err)
	}

	c, err := dnmclient.NewFromFile("dnmlookup.cfg", nil)
	if err != nil {
		log.Fatal("NewFromFile: ", err)
	}

	if err := c.Register(&sk, os.Args[3], os.Args[2]); err != nil {
		log.Fatal("Register: ", err)
	}
}
