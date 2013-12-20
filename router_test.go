package main

import (
	"github.com/andres-erbsen/dename/protocol"
	"testing"
	"time"
)

func TestBasicRouting(t *testing.T) {
	rt := newRouter()

	x0s := rt.Receive(0, S2S_PUSH)
	y0s := rt.Receive(0, S2S_ROUNDKEY)
	x1s := rt.Receive(1, S2S_PUSH)
	y1s := rt.Receive(1, S2S_ROUNDKEY)

	zero := int64(0)
	one := int64(1)
	sendstuff := func() {
		rt.Send(&protocol.S2SMessage{Round: &zero, PushQueue: []byte("x0")})
		rt.Send(&protocol.S2SMessage{Round: &one, PushQueue: []byte("x1")})
		rt.Send(&protocol.S2SMessage{Round: &zero, RoundKey: []byte("y0")})
		rt.Send(&protocol.S2SMessage{Round: &one, RoundKey: []byte("y1")})
	}
	go sendstuff()

	if string((<-x0s).PushQueue) != "x0" {
		t.Errorf("")
	}
	if string((<-x1s).PushQueue) != "x1" {
		t.Errorf("")
	}
	if string((<-y0s).RoundKey) != "y0" {
		t.Errorf("")
	}
	if string((<-y1s).RoundKey) != "y1" {
		t.Errorf("")
	}

	select {
	case <-x0s:
		t.Errorf("From empty channel")
	case <-x1s:
		t.Errorf("From empty channel")
	case <-y0s:
		t.Errorf("From empty channel")
	case <-y1s:
		t.Errorf("From empty channel")
	case <-time.After(100):
	}

	go rt.Send(&protocol.S2SMessage{Round: &zero, PushQueue: []byte("x0")})
	go rt.Send(&protocol.S2SMessage{Round: &zero, PushQueue: []byte("x0")})
	i := 0
	for x0 := range x0s {
		if string(x0.PushQueue) != "x0" {
			t.Error("Send two things: wrong content")
		}
		i++
		if i == 2 {
			rt.Close(x0s)
		}
	}
	if i != 2 {
		t.Error("Send two things")
	}

	_, okx0 := <-x0s
	rt.Close(x1s)
	_, okx1 := <-x1s
	rt.Close(y0s)
	_, oky0 := <-y0s
	rt.Close(y1s)
	_, oky1 := <-y1s

	if okx0 || okx1 || oky0 || oky1 {
		t.Errorf("Close failed")
	}

	go sendstuff()

	_, okx0 = <-x0s
	_, okx1 = <-x1s
	_, oky0 = <-y0s
	_, oky1 = <-y1s

	if okx0 || okx1 || oky0 || oky1 {
		t.Errorf("Send after close")
	}
}
