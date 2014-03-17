package main

import (
	"code.google.com/p/goprotobuf/proto"
	"github.com/andres-erbsen/dename/dnmclient"
	"os"
)

func barf(s string, c int) {
	os.Stderr.Write([]byte(s))
	os.Exit(c)
}

func main() {
	if len(os.Args) != 3 && len(os.Args) != 2 {
		barf("USAGE: "+os.Args[0]+" NAME [FIELD]\n", 2)
	}
	c, err := dnmclient.NewFromFile("dnmlookup.cfg", nil)
	if err != nil {
		barf(err.Error(), 1)
	}
	iden, err := c.Lookup(os.Args[1])
	if err != nil {
		barf(err.Error(), 1)
	}
	if len(os.Args) == 2 || os.Args[2] == "1" || os.Args[2] == "dename" {
		dename_bs, err := proto.Marshal(iden.Dename)
		if err != nil {
			panic(err)
		}
		if _, err = os.Stdout.Write(dename_bs); err != nil {
			barf(err.Error(), 1)
		}
	} else {
		barf("Unknown field type", 2)
	}
}
