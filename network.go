package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
)

func (dn *Dename) ListenForClients() {
	client_lnr, err := net.Listen("tcp", dn.us.addr+":6263")
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := client_lnr.Accept()
		if err == nil {
			_ = conn // TODO: client handling
		}
	}
}

func (dn *Dename) ListenForPeers() {
	our_server_tcpaddr, err := net.ResolveTCPAddr("tcp", dn.us.addr+":"+S2S_PORT)
	if err != nil {
		log.Fatal(err)
	}
	peer_lnr, err := net.ListenTCP("tcp", our_server_tcpaddr)
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := peer_lnr.AcceptTCP()
		if err == nil {
			conn.SetNoDelay(false)
			go dn.PeerConnected(conn)
		}
	}
}

func (dn *Dename) ConnectToPeers() {
	laddr_ip, err := net.ResolveIPAddr("", dn.us.addr)
	if err != nil {
		log.Fatal("resolve our ip: ", err)
	}

	for _, peer := range dn.peers {
		if peer == dn.us {
			continue
		}
		laddr := &net.TCPAddr{IP: laddr_ip.IP}

		raddr, err := net.ResolveTCPAddr("tcp", peer.addr+":"+S2S_PORT)
		if err != nil {
			log.Fatal(err)
		}
		conn, err := net.DialTCP("tcp", laddr, raddr)
		if err == nil {
			conn.SetNoDelay(false)
			dn.PeerConnected(conn)
		} else {
			log.Print("connect to peer: ", err, laddr, raddr)
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
	go dn.c.RefreshPeer(peer.id)
	go peer.ReceiveLoop(dn.c.OnMessage)
}

func (peer *Peer) ReceiveLoop(f func(int64, []byte)) (err error) {
	peer.RLock()
	conn := peer.conn
	closeOnce := peer.closeOnce
	peer.RUnlock()
	var sz uint16
	for {
		err := binary.Read(conn, binary.LittleEndian, &sz)
		if err != nil {
			break
		}
		buf := make([]byte, sz)
		_, err = io.ReadFull(conn, buf)
		if err != nil {
			break
		}
		go f(peer.id, buf)
	}
	if err != nil {
		peer.Lock()
		closeOnce.Do(peer.CloseConn)
		peer.Unlock()
	}
	return
}

func (peer *Peer) CloseConn() {
	peer.conn.Close()
	peer.conn = nil
}

func (peer *Peer) Send(msg_bs []byte) error {
	peer.RLock()
	conn := peer.conn
	peer.RUnlock()
	if conn == nil {
		return errors.New(fmt.Sprintf("SendToPeer: No connection to %v present", peer.id))
	}
	err := binary.Write(conn, binary.LittleEndian, uint16(len(msg_bs)))
	if err != nil {
		return err
	}
	_, err = conn.Write(msg_bs)
	if err != nil {
		return err
	}
	return nil
}
