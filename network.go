package main

import (
	"bytes"
	"code.google.com/p/goprotobuf/proto"
	"encoding/binary"
	"errors"
	"fmt"
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
	go dn.BringUpToDate(peer)
	go dn.ReceiveLoop(peer)
}

const FRAME_SIZE = 1600

func (dn *Dename) ReceiveLoop(peer *Peer) (err error) {
	peer.RLock()
	conn := peer.conn
	closeOnce := peer.closeOnce
	peer.RUnlock()
	for {
		err = nil
		sz := 2 // uint16 content_sz header
		n := 0
		nn := 0
		buf := make([]byte, FRAME_SIZE)
		for n < sz {
			nn, err = conn.Read(buf[n:sz])
			if err != nil {
				break
			}
			// log.Print("Read ", nn, " bytes from ", peer.addr)
			n += nn
			if n == 2 {
				var content_sz uint16
				binary.Read(bytes.NewBuffer(buf[:2]), binary.LittleEndian, &content_sz)
				sz += int(content_sz)
				if sz > FRAME_SIZE {
					err = errors.New("ReceiveLoop: Incoming message too big")
					break
				}
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

func (dn *Dename) SendToPeer(peer *Peer, msg *S2SMessage) error {
	if msg.Server == nil {
		msg.Server = &dn.us.index
	}
	sz := proto.Size(msg)
	buf := bytes.NewBuffer(make([]byte, 0, 2+sz))
	binary.Write(buf, binary.LittleEndian, uint16(sz))
	msg_bs, err := proto.Marshal(msg)
	if err != nil {
		panic(err)
	}
	buf.Write(msg_bs)

	peer.RLock()
	conn := peer.conn
	peer.RUnlock()
	if conn == nil {
		return errors.New(fmt.Sprintf("SendToPeer: No connection to %v present (%v)", peer.index, dn.us.index))
	}
	_, err = conn.Write(buf.Bytes())
	if err != nil {
		return err
	}
	return nil
}

func (dn *Dename) Broadcast(msg *S2SMessage) {
	for _, peer := range dn.addr2peer {
		if peer.index != dn.us.index {
			go func(peer *Peer) {
				err := dn.SendToPeer(peer, msg)
				if err != nil {
					log.Print(err)
				}
			}(peer)
		}
	}
}
