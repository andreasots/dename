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
		dn.peerConnected(conn)
	}
}

func (dn *Dename) ConnectToPeers() {
	for id, peer := range dn.peers {
		if id != dn.us.id {
			go peer.spawnConnection()
		}
	}
}

func (peer *Peer) spawnConnection() {
	for {
		conn, err := net.Dial("tcp", peer.connectTo)
		if err != nil {
			log.Printf("connect to %v at %s: %s", peer.id, peer.connectTo, err)
			time.Sleep(time.Second)
			continue
		}
		err = peer.dn.peerConnected(conn)
		if err != nil {
			log.Printf("handshake with %v: %s", peer.id, err)
			time.Sleep(time.Second)
			continue
		}
		break
	}
}

func (dn *Dename) peerConnected(conn net.Conn) (err error) {
	var our_challenge, peer_challenge [32]byte
	if _, err := rand.Read(our_challenge[:]); err != nil {
		panic(err)
	}

	if err = binary.Write(conn, binary.LittleEndian, dn.us.id); err != nil {
		return
	}
	if _, err = conn.Write(our_challenge[:]); err != nil {
		return
	}
	var peer_id int64
	if err = binary.Read(conn, binary.LittleEndian, &peer_id); err != nil {
		return
	}
	peer, ok := dn.peers[peer_id]
	if !ok {
		return errors.New("Unknown peer id")
	}
	if _, err = io.ReadFull(conn, peer_challenge[:]); err != nil {
		return
	}

	shared, err := dn.our_sk.KeyAgreement(&peer.PublicKey)
	if err != nil {
		return err
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

	if _, err = readAuth(conn, read_cipher, 0); err != nil {
		return // if they did not have the shared key, this will return
	}

	go peer.receiveLoop(conn, read_cipher, dn.dispatch)

	peer.Lock()
	needWriteConn := peer.writeConn == nil
	peer.Unlock()
	if !needWriteConn {
		return nil
	}

	write_nonce := uint64(1) // 0 has been used for handshake
	err = dn.c.ResendRecentTo(peer_id, func(msg []byte) error {
		err := writeAuth(conn, write_cipher, write_nonce, append(msg, 0))
		write_nonce++
		return err
	})
	if err != nil {
		return err
	}

	peer.Lock()
	if peer.writeConn == nil {
		peer.writeConn = conn
		peer.writeCipher = write_cipher
		peer.writeNonce = write_nonce
	}
	peer.Unlock()
	return nil
}

func writeAuth(conn net.Conn, cipher cipher.AEAD, nonce uint64, msg []byte) (
	err error) {
	if len(msg)+cipher.Overhead() > 65535 {
		panic("sendMessage: message too long")
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

func (peer *Peer) lostConnection(conn net.Conn) {
	peer.Lock()
	if peer.writeConn == conn {
		peer.writeConn.Close()
		peer.writeConn = nil
		go peer.spawnConnection()
	}
	peer.Unlock()
}

func (peer *Peer) receiveLoop(conn net.Conn, cipher cipher.AEAD,
	handleFunc func(int64, []byte)) {
	defer peer.lostConnection(conn)
	for nonce := uint64(1); nonce != 0; nonce++ {
		msg, err := readAuth(conn, cipher, nonce)
		if err != nil {
			return
		}
		handleFunc(peer.id, msg)
	}
}

func (peer *Peer) send(tag uint8, msg []byte) error {
	peer.Lock()
	conn := peer.writeConn
	cipher := peer.writeCipher
	nonce := peer.writeNonce
	peer.writeNonce++
	peer.Unlock()
	if conn == nil {
		return errors.New(fmt.Sprintf("SendToPeer: No connection to %d", peer.id))
	}
	err := writeAuth(conn, cipher, nonce, append(msg, tag))
	if err != nil {
		peer.lostConnection(conn)
	}
	return err
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
