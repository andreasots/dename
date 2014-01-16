package main

import (
	"github.com/andres-erbsen/dename/dnmclient"
	"log"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("USAGE: ", os.Args[0], " NAME")
	}

	dnmc, err := dnmclient.New("dnmlookup.cfg", nil)
	if err != nil {
		panic(err)
	}

	pk, err := dnmc.Lookup([]byte(os.Args[1]))
	if err != nil {
		os.Stderr.Write([]byte(err.Error() + "\n"))
		os.Exit(1)
	}

	_, err = os.Stdout.Write(pk.Bytes)
	if err != nil {
		os.Stderr.Write([]byte(err.Error() + "\n"))
		os.Exit(1)
	}
}
