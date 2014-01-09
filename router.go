package main

import (
	"errors"
	"github.com/andres-erbsen/dename/protocol"
	"log"
	"sync"
)

const (
	S2S_PUSH = iota
	S2S_COMMITMENT
	S2S_ACKNOWLEDGEMENT
	S2S_ROUNDKEY
	S2S_PUBLISH
)

func msgtype(msg *protocol.S2SMessage) int {
	switch {
	case msg.PushQueue != nil:
		return S2S_PUSH
	case msg.Commitment != nil:
		return S2S_COMMITMENT
	case msg.Ack != nil:
		return S2S_ACKNOWLEDGEMENT
	case msg.RoundKey != nil:
		return S2S_ROUNDKEY
	case msg.Publish != nil:
		return S2S_PUBLISH
	default:
		log.Fatal("Unknown message type ", msg)
	}
	return -1
}

var errNoRoute = errors.New("Router: no route for message")

type Router struct {
	routes map[router_match]router_dst
	sync.RWMutex
}

func newRouter() (rt *Router) {
	rt = new(Router)
	rt.routes = make(map[router_match]router_dst)
	return rt
}

type router_match struct {
	round int64
	tp    int
}

type router_dst struct {
	closer chan struct{}
	closed bool
	f      router_handler
	sync.Mutex
}

// handle a message and return whether it was the last one
type router_handler func(msg *protocol.S2SMessage) bool

func (rt *Router) Receive(round int64, tp int, f router_handler) {
	closer := make(chan struct{})
	k := router_match{round, tp}
	dst := router_dst{closer: closer, f: f}
	func() {
		rt.Lock()
		defer rt.Unlock()
		if _, already := rt.routes[k]; !already {
			rt.routes[k] = dst
		} else {
			log.Fatalf("Router: ambiguity for %v", k)
		}
	}()
	<-closer
}

func (rt *Router) Send(msg *protocol.S2SMessage) error {
	k := router_match{*msg.Round, msgtype(msg)}
	rt.RLock()
	defer rt.RUnlock()
	if dst, ok := rt.routes[k]; ok {
		dst.Lock()
		defer dst.Unlock()
		if !dst.closed {
			if dst.closed = dst.f(msg); dst.closed {
				close(dst.closer)
			}
			return nil
		}
	}
	return errNoRoute
}
