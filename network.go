package main

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/codahale/chacha20poly1305"
	"io"
	"log"
	"net"
	"runtime"
	"time"
)

func concat(slices ...[]byte) (ret []byte) {
	var l, i int
	for _, s := range slices {
		l += len(s)
	}
	ret = make([]byte, l)
	for _, s := range slices {
		copy(ret[i:i+len(s)], s)
		i += len(s)
	}
	return
}

func (dn *Dename) ListenForClients(addr string) {
	client_lnr, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := client_lnr.Accept()
		if err != nil {
			log.Printf("client_lnr.Accept(): %s", err)
			continue
		}
		go dn.HandleClient(conn)
		runtime.Gosched()
	}
}

func (dn *Dename) ListenForPeers(addr string) {
	lnr, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Listen(%s): %s", addr, err)
	}
	for {
		conn, err := lnr.Accept()
		if err != nil {
			log.Printf("peer_lnr.Accept(): %s", err)
			continue
		}
		dn.peerConnected(conn, false)
	}
}

func (dn *Dename) ConnectToPeers(cfg *Cfg) {
	for {
		for id_str, peer := range cfg.Peer {
			var id int64
			fmt.Sscan(id_str, &id)
			dn.peers[id].Lock()
			connected := len(dn.peers[id].connections) > 0
			dn.peers[id].Unlock()
			if id == dn.us.id || connected {
				continue
			}
			if conn, err := net.Dial("tcp", peer.ConnectTo); err == nil {
				dn.peerConnected(conn, true)
			} else {
				log.Printf("connect to peer %v at %s: %s", id, peer.ConnectTo, err)
			}
		}
		time.Sleep(time.Second) // TODO: replace with callback on connection drop
	}
}

type authConn struct {
	conn   net.Conn
	cipher cipher.AEAD
	nonce  uint64
}

func (dn *Dename) peerConnected(conn net.Conn, openedByUs bool) {
	var our_challenge, peer_challenge [32]byte
	if _, err := rand.Read(our_challenge[:]); err != nil {
		panic(err)
	}

	if err := binary.Write(conn, binary.LittleEndian, dn.us.id); err != nil {
		return
	}
	if _, err := conn.Write(our_challenge[:]); err != nil {
		return
	}
	var peer_id int64
	if err := binary.Read(conn, binary.LittleEndian, &peer_id); err != nil {
		return
	}
	peer, ok := dn.peers[peer_id]
	if !ok {
		return
	}
	if _, err := io.ReadFull(conn, peer_challenge[:]); err != nil {
		return
	}

	shared, err := dn.our_sk.KeyAgreement(&peer.PublicKey)
	if err != nil {
		return
	}

	w_key := sha256.Sum256(concat(our_challenge[:], peer_challenge[:], shared))
	write_cipher, err := chacha20poly1305.NewChaCha20Poly1305(w_key[:])
	if err != nil {
		panic(err)
	}
	writeAuth(conn, write_cipher, 0, nil)

	r_key := sha256.Sum256(concat(peer_challenge[:], our_challenge[:], shared))
	read_cipher, err := chacha20poly1305.NewChaCha20Poly1305(r_key[:])
	if err != nil {
		panic(err)
	}

	if _, err := readAuth(conn, read_cipher, 0); err != nil {
		return // if they did not have the shared key, this will return
	}

	wConn := &authConn{conn, write_cipher, 1} // 0 has been used for handshake
	peer.Lock()
	peer.connections[wConn] = struct{}{}
	peer.Unlock()

	log.Printf("Established connection to %d (%d total)", peer.id, len(peer.connections))
	go dn.c.RefreshPeer(peer_id)
	go peer.receiveLoop(conn, read_cipher, wConn, dn.dispatch)
}

func writeAuth(conn net.Conn, cipher cipher.AEAD, nonce uint64, msg []byte) (
	err error) {
	if len(msg)+cipher.Overhead() > 65535 {
		panic("sencMessage: message too long")
	}
	var sz [2]byte
	binary.LittleEndian.PutUint16(sz[:], uint16(len(msg)+cipher.Overhead()))
	var nonce_bs [8]byte
	binary.LittleEndian.PutUint64(nonce_bs[:], nonce)
	_, err = conn.Write(concat(sz[:], cipher.Seal(nil, nonce_bs[:], nil, msg), msg))
	return
}

func readAuth(conn net.Conn, cipher cipher.AEAD, nonce uint64) (
	msg []byte, err error) {
	var sz uint16
	if err = binary.Read(conn, binary.LittleEndian, &sz); err != nil {
		return
	}
	buf := make([]byte, sz)
	if _, err = io.ReadFull(conn, buf); err != nil {
		return
	}
	var nonce_bs [8]byte
	binary.LittleEndian.PutUint64(nonce_bs[:], nonce)
	msg = buf[cipher.Overhead():]
	_, err = cipher.Open(nil, nonce_bs[:], buf[:cipher.Overhead()], msg)
	if err != nil {
		return nil, err
	}
	return
}

func (peer *Peer) receiveLoop(conn net.Conn, cipher cipher.AEAD,
	writeConn *authConn, handleFunc func(int64, []byte)) {
	defer func() {
		peer.Lock()
		conn.Close()
		delete(peer.connections, writeConn)
		peer.Unlock()
	}()
	for nonce := uint64(1); nonce != 0; nonce++ {
		msg, err := readAuth(conn, cipher, nonce)
		if err != nil {
			return
		}
		handleFunc(peer.id, msg)
	}
}

func (peer *Peer) send(tag uint8, msg []byte) error {
	for {
		peer.Lock()
		if len(peer.connections) == 0 {
			peer.Unlock()
			return errors.New(fmt.Sprintf("SendToPeer: No connection to %d", peer.id))
		}
		var w *authConn
		for w = range peer.connections {
			break
		}
		nonce := w.nonce
		w.nonce++
		peer.Unlock()

		err := writeAuth(w.conn, w.cipher, nonce, append(msg, tag))
		if err == nil {
			return nil
		}
		peer.Lock()
		delete(peer.connections, w)
		peer.Unlock()
	}
}

func (peer *Peer) ConsensusSend(msg_bs []byte) error {
	return peer.send(0, msg_bs)
}

func (peer *Peer) DenameSend(msg_bs []byte) error {
	return peer.send(1, msg_bs)
}

func (dn *Dename) dispatch(peer_id int64, msg_bs []byte) {
	if len(msg_bs) == 0 {
		log.Fatal("Empty message")
	}
	l := len(msg_bs) - 1
	switch msg_bs[l] {
	case 0:
		dn.c.OnMessage(peer_id, msg_bs[:l])
	case 1:
		dn.FreshnessReceived(peer_id, msg_bs[:l])
	default:
		log.Fatalf("Invalid message received from %v: type %v", peer_id, msg_bs[l])
	}
}
