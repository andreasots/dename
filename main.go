package main

import (
	"net"
	"log"
)

func main () {
	listener, err := net.Listen("tcp", "0.0.0.0:9876")
	if err != nil {
		log.Fatal("Cannot bind to port: ", err)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Print("listener.Accept(): ", err)
		}
	}
}
