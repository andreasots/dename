package main

import (
	"code.google.com/p/goprotobuf/proto"
	"fmt"
	"github.com/andres-erbsen/dename/dnmclient"
	"github.com/andres-erbsen/dename/protocol"
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
	c := dnmclient.New(nil, "", nil)
	iden, err := c.Lookup(os.Args[1])
	if err != nil {
		barf(err.Error(), 1)
	}

	if len(os.Args) == 2 {
		iden_bs, err := proto.Marshal(iden)
		if err != nil {
			panic(err)
		}
		if _, err = os.Stdout.Write(iden_bs); err != nil {
			barf(err.Error(), 1)
		}
	} else if os.Args[2] == "dename" || os.Args[2] == "1" {
		dename_bs, err := proto.Marshal(iden.Dename)
		if err != nil {
			panic(err)
		}
		if _, err = os.Stdout.Write(dename_bs); err != nil {
			barf(err.Error(), 1)
		}
	} else {
		n, lookup_ok := protocol.ProfileFields[os.Args[2]]
		_, scan_err := fmt.Sscan(os.Args[2], &n)
		if !(lookup_ok || scan_err == nil) {
			barf("set: unknown non-numeric field type", 2)
		}
		result_bs, err := iden.Get(n)
		if err != nil {
			barf(err.Error(), 1)
		}
		if _, err = os.Stdout.Write(result_bs); err != nil {
			barf(err.Error(), 1)
		}
	}
}
