package main

import (
	"github.com/andres-erbsen/dename/dnmclient"
	"github.com/andres-erbsen/sgp"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	if len(os.Args) != 4 {
		log.Fatal("USAGE: ", os.Args[0], " FROM.sk NAME TO.pk")
	}
	sk, err := sgp.LoadSecretKeyFromFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	pk_bs, err := ioutil.ReadFile(os.Args[3])
	pk := new(sgp.Entity)
	if err = pk.Parse(pk_bs); err != nil {
		log.Fatal(err)
	}
	if err = dnmclient.Transfer(&sk, os.Args[2], pk); err != nil {
		log.Fatal(err)
	}
}
