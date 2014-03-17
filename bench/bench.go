package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/agl/ed25519"
	"github.com/andres-erbsen/dename/dnmclient"
	"github.com/andres-erbsen/dename/protocol"
	"io/ioutil"
	"log"
	"os"
	"time"
)

var tokenserver_mac_key []byte

func mktoken() string {
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	if err != nil {
		panic(err)
	}
	mac := hmac.New(sha256.New, tokenserver_mac_key)
	mac.Write(nonce[:])
	ticket := append(nonce, mac.Sum(nil)[:16]...)
	return base64.StdEncoding.EncodeToString(ticket)
}

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("usage: %s SECRETKEYFILE NUM_REGS", os.Args[0])
	}
	var err error
	tokenserver_mac_key, err = ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	var n int
	fmt.Sscan(os.Args[2], &n)

	connections := make(chan struct{}, 900)
	for i := 0; i < 900; i++ {
		connections <- struct{}{}
	}
	done := make(chan struct{}, n)
	pk, sk_arr, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	sk := (*protocol.Ed25519Secret)(sk_arr)
	iden := &protocol.Identity{Dename: &protocol.PublicKey{Ed25519: pk[:]}}

	c, err := dnmclient.NewFromFile("dnmlookup.cfg", nil)
	if err != nil {
		log.Fatal("NewFromFile: ", err)
	}

	s := time.Now().UnixNano()
	fmt.Println(s)
	t0 := time.Now()
	go func() {
		for i := 0; i < n; i++ {
			<-connections
			go func(i int) {
				for {
					err := c.Register(sk, iden, fmt.Sprint(s+int64(i)), mktoken())
					if err != nil {
						log.Print(i, err)
						continue
					}
					break
				}
				connections <- struct{}{}
				done <- struct{}{}
			}(i)
		}
	}()
	for remaining := n; remaining > 0; remaining-- {
		<-done
		log.Printf("%d remaining", remaining)
	}
	t := time.Now()
	ns := t.UnixNano() - t0.UnixNano()
	fmt.Printf("%d (%s, %f rq/s)\n", ns, t.Sub(t0).String(), float64(n)/(float64(ns)/1e9))
}
