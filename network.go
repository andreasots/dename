package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"runtime"
	"strings"
	"sync"
)

const S2S_PORT = "6362"
const C2S_PORT = "6263"

func (dn *Dename) ListenForClients(addr string) {
	client_lnr, err := net.Listen("tcp", addr+":"+C2S_PORT)
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := client_lnr.Accept()
		if err != nil {
			log.Printf("client_lnr.Accept(): %s", err)
			continue
		}
		dn.HandleClient(conn)
		runtime.Gosched()
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
		if err != nil {
			log.Printf("peer_lnr.AcceptTCP(): %s", err)
			continue
		}
		conn.SetNoDelay(false)
		dn.PeerConnected(conn)
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
	} else {
		if peer.conn != nil {
			peer.closeOnce.Do(peer.CloseConn)
		}
		peer.closeOnce = new(sync.Once)
		peer.conn = conn
	}
	go dn.c.RefreshPeer(peer.id)
	go peer.ReceiveLoop(dn.Dispatch)
}

func (peer *Peer) ReceiveLoop(handleFunc func(int64, []byte)) (err error) {
	peer.RLock()
	conn := peer.conn
	closeOnce := peer.closeOnce
	peer.RUnlock()
	var sz uint16
	for {
		err = binary.Read(conn, binary.LittleEndian, &sz)
		if err != nil {
			break
		}
		buf := make([]byte, sz)
		_, err = io.ReadFull(conn, buf)
		if err != nil {
			break
		}
		handleFunc(peer.id, buf)
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

func (peer *Peer) Send(tag uint8, msg_bs []byte) error {
	peer.RLock()
	conn := peer.conn
	peer.RUnlock()
	if conn == nil {
		return errors.New(fmt.Sprintf("SendToPeer: No connection to %v present", peer.id))
	}
	buf := bytes.NewBuffer(make([]byte, 0, 1+2+len(msg_bs)))
	err := binary.Write(buf, binary.LittleEndian, uint16(1+len(msg_bs)))
	if err != nil {
		panic(err)
	}
	err = binary.Write(buf, binary.LittleEndian, tag)
	if err != nil {
		panic(err)
	}
	_, err = conn.Write(append(buf.Bytes(), msg_bs...))
	if err != nil {
		return err
	}
	return nil
}

func (peer *Peer) ConsensusSend(msg_bs []byte) error {
	return peer.Send(0, msg_bs)
}

func (peer *Peer) DenameSend(msg_bs []byte) error {
	return peer.Send(1, msg_bs)
}

func (dn *Dename) Dispatch(peer_id int64, msg_bs []byte) {
	if len(msg_bs) == 0 {
		log.Fatal("Empty message")
	}
	switch msg_bs[0] {
	case 0:
		dn.c.OnMessage(peer_id, msg_bs[1:])
	case 1:
		dn.FreshnessReceived(peer_id, msg_bs[1:])
	default:
		log.Fatalf("Invalid message received from %v: type %v", peer_id, msg_bs[0])
	}
}
