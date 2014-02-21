package main

import (
	"github.com/andres-erbsen/dename/dnmclient"
	"github.com/andres-erbsen/sgp"
	"log"
	"os"
)

func main() {
	if len(os.Args) != 4 {
		log.Fatal("USAGE: ", os.Args[0], " sk NAME REGTOKEN")
	}
	sk, err := sgp.LoadSecretKeyFromFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	c, err := dnmclient.NewFromFile("run/dnmlookup.cfg", nil)
	if err != nil {
		log.Fatal(err)
	}

	if err := c.Register(&sk, os.Args[3], os.Args[2]); err != nil {
		log.Fatal(err)
	}
}
