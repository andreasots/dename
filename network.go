package main

import (
	"bytes"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"net"
	"strings"
	"sync"
)

func (dn *Dename) ListenForClients() {
	for {
		conn, err := dn.client_lnr.Accept()
		if err == nil {
			go dn.HandleClient(conn)
		}
	}
}

func (dn *Dename) ListenForPeers() {
	for {
		conn, err := dn.peer_lnr.AcceptTCP()
		if err == nil {
			conn.SetNoDelay(false)
			go dn.PeerConnected(conn)
		}
	}
}

func (dn *Dename) PeerConnected(conn net.Conn) {
	raddr := strings.SplitN(conn.RemoteAddr().String(), ":", 2)[0]
	rport := strings.SplitN(conn.RemoteAddr().String(), ":", 2)[1]
	peer := dn.addr2peer[raddr]
	if peer == nil {
		log.Print(raddr, " is not our friend")
		conn.Close()
		return
	}
	peer.Lock()
	defer peer.Unlock()
	// determine whether to use this connection or keep the current
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
		conn.Close()
		return
	}
	if peer.conn != nil {
		peer.closeOnce.Do(peer.CloseConn)
	}
	peer.closeOnce = new(sync.Once)
	peer.conn = conn
	go dn.ReceiveLoop(peer)
}

func (dn *Dename) ReceiveLoop(peer *Peer) (err error) {
	peer.RLock()
	conn := peer.conn
	closeOnce := peer.closeOnce
	peer.RUnlock()
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
			peer.Lock()
			closeOnce.Do(peer.CloseConn)
			peer.Unlock()
			return err
		} else {
			go dn.HandleMessage(peer, buf[2:sz])
		}
	}
	return nil
}

func (peer *Peer) CloseConn() {
	peer.conn.Close()
	peer.conn = nil
}

func (dn *Dename) HandleBroadcasts() {
	for msg := range dn.peer_broadcast {
		// log.Print("broadcast ", len(msg), " bytes")
		for _, peer := range dn.addr2peer {
			peer.RLock()
			conn := peer.conn
			peer.RUnlock()
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
