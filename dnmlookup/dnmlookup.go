package main

import (
	"github.com/andres-erbsen/dename/dnmclient"
	"os"
)

func barf(s string, c int) {
	os.Stderr.Write([]byte(s))
	os.Exit(c)
}

func main() {
	if len(os.Args) != 2 {
		barf("USAGE: "+os.Args[0]+" NAME\n", 2)
	}
	pk, err := dnmclient.New(nil, "", nil).Lookup(os.Args[1])
	if err != nil {
		barf(err.Error(), 1)
	}
	if _, err = os.Stdout.Write(pk.Bytes); err != nil {
		barf(err.Error(), 1)
	}
}
