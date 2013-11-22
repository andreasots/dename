package main

import (
	"bytes"
	_ "github.com/mattn/go-sqlite3"
	"io"
	"log"
	"net"
	"strings"
)


func (dn *Dename) HandleConnection(peer *Peer, conn net.Conn) error {
	rport := strings.SplitN(conn.RemoteAddr().String(), ":", 2)[1]
	new_is_better := true
	log.Print("peer: ", peer.addr, " old conn: ", peer.conn, " new: ", conn)
	if peer.conn != nil {
		// keep the connection where the client has the lower pk
		if rport == S2S_PORT {
			new_is_better = bytes.Compare(dn.our_sk.Entity.Bytes, peer.pk.Bytes) < 0
		} else { // they started the new connection
			new_is_better = bytes.Compare(dn.our_sk.Entity.Bytes, peer.pk.Bytes) >= 0
		}
	}
	if !new_is_better {
		return conn.Close()
	}
	if peer.conn != nil {
		peer.conn.Close() // kills the old ReceiveLoop with errClosed (not EOF)
	}
	peer.conn = conn
	go dn.ReceiveLoop(peer)
	return nil
}

func (dn *Dename) ListenForPeers() {
	for {
		conn, err := dn.peer_lnr.AcceptTCP()
		if err == nil {
			conn.SetNoDelay(false)
			// TODO: create a new goroutine that sends all the old updates and blocks, only then add to the set of normal peers
			dn.peer_connected <- conn
		} else {
			log.Print(err)
		}
	}
}

func (dn *Dename) ListenForClients() {
	for {
		conn, _ := dn.client_lnr.Accept()
		go dn.HandleClient(conn)
	}
}

func (dn *Dename) ReceiveLoop(peer *Peer) (err error) {
	conn := peer.conn
	for {
		err = nil
		sz := 2
		n := 0
		nn := 0
		buf := make([]byte, 1600)
		for err == nil && n < sz {
			nn, err = conn.Read(buf[n:sz])
			// log.Print("Read ", nn, " bytes from ", peer.addr)
			n += nn
			if n == 2 {
				sz = 2 + (int(buf[0]) | (int(buf[1]) << 8))
			}
		}
		if err != nil {
			conn.Close()
			if err == io.EOF {
				// the other end closed the connection, not us in HandleConnection
				// FIXME: ensure thread-safety by a non-hack
				log.Print("peer: ", peer.addr, " connection lost: ", conn)
				peer.conn = nil
			}
			return err
		}
		go dn.HandleMessage(peer, buf[2:sz])
	}
	return nil
}

func (dn *Dename) HandleAllPeers() {
	for {
		select {
		case conn := <-dn.peer_connected:
			raddr := strings.SplitN(conn.RemoteAddr().String(), ":", 2)[0]
			peer := dn.addr2peer[raddr]
			if peer == nil {
				log.Print(raddr, " is not our friend")
				continue
			}
			dn.HandleConnection(peer, conn)
		case msg := <-dn.peer_broadcast:
			log.Print("broadcast ", len(msg), " bytes")
			for _, peer := range dn.addr2peer {
				conn := peer.conn
				if conn == nil {
					continue
				}
				buf := make([]byte, 2+len(msg))
				buf[0] = byte(len(msg) & 0x00ff)
				buf[1] = byte((len(msg) >> 8) & 0xff)
				copy(buf[2:], msg)
				_, err := conn.Write(buf)
				if err != nil {
					log.Print(err)
				}
			}
		}
	}
}

