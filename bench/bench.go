package main

import (
	"crypto/rand"
	"fmt"
	"github.com/andres-erbsen/dename/dnmclient"
	"github.com/andres-erbsen/sgp"
	"log"
	"os"
	"sync"
	"time"
)

const regtoken = "BPuWwRzl/gp279rMP3qgoAHbMi0bICSxOFJ+fjspJvU="

func main() {
	connections := make(chan struct{}, 900)
	for i := 0; i < 900; i++ {
		connections <- struct{}{}
	}
	if len(os.Args) != 2 {
		log.Fatal("USAGE: ", os.Args[0], " num_rqs")
	}
	var n int
	fmt.Sscan(os.Args[1], &n)
	_, sk, err := sgp.GenerateKey(rand.Reader, time.Now(), time.Duration(30*24)*time.Hour)

	c, err := dnmclient.NewFromFile("dnmlookup.cfg", nil)
	if err != nil {
		log.Fatal("NewFromFile: ", err)
	}

	var wg sync.WaitGroup
	wg.Add(n)
	s := time.Now().UnixNano()
	t0 := time.Now()
	for i := 0; i < n; i++ {
		<-connections
		go func(i int) {
			for {
				err := c.Register(sk, fmt.Sprint(s+int64(i)), regtoken)
				if err == nil {
					break
				}
				log.Print("Register: ", err)
			}
			log.Print("\t", i)
			connections <- struct{}{}
			wg.Done()
		}(i)
		log.Print(i)
	}
	wg.Wait()
	t := time.Now()
	ns := t.UnixNano() - t0.UnixNano()
	fmt.Printf("%d (%s, %f rq/s)\n", ns, t.Sub(t0).String(), float64(n)/(float64(ns)/1e9))
}
