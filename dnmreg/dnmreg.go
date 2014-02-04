package main

import (
	"github.com/andres-erbsen/dename/dnmclient"
	"github.com/andres-erbsen/sgp"
	"log"
	"os"
)

func main() {
	if len(os.Args) != 3 && len(os.Args) != 4 {
		log.Fatal("USAGE: ", os.Args[0], " FROM.sk NAME [TO.sk]")
	}
	from, err := sgp.LoadSecretKeyFromFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	to := from
	if len(os.Args) == 4 {
		to, err = sgp.LoadSecretKeyFromFile(os.Args[3])
		if err != nil {
			log.Fatal(err)
		}
	}
	c, err := dnmclient.NewFromFile("run/dnmlookup.cfg", nil)
	if err != nil {
		log.Fatal(err)
	}

	transfer := c.Transfer(&from, os.Args[2], to.Entity)
	if err := c.Accept(&to, transfer); err != nil {
		log.Fatal(err)
	}
}
