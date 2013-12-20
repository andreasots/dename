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
var errRouterClose = errors.New("Router: unexpected close")

type Router struct {
	ruleof map[chan *protocol.S2SMessage]router_match
	routes map[router_match]chan *protocol.S2SMessage
	sync.RWMutex
}

func newRouter() (rt *Router) {
	rt = new(Router)
	rt.ruleof = make(map[chan *protocol.S2SMessage]router_match)
	rt.routes = make(map[router_match]chan *protocol.S2SMessage)
	return rt
}

type router_match struct {
	round int64
	tp    int
}

func (rt *Router) Receive(round int64, tp int) chan *protocol.S2SMessage {
	ch := make(chan *protocol.S2SMessage)
	k := router_match{round, tp}
	rt.Lock()
	defer rt.Unlock()
	if _, already := rt.routes[k]; !already {
		rt.routes[k] = ch
		rt.ruleof[ch] = k
	} else {
		log.Fatalf("Router: ambiguity for %v", k)
	}
	return ch
}

func (rt *Router) Close(ch chan *protocol.S2SMessage) error {
	rt.Lock()
	defer rt.Unlock()
	if k, ok := rt.ruleof[ch]; ok {
		delete(rt.routes, k)
		delete(rt.ruleof, ch)
		close(ch)
		return nil
	} else {
		return errRouterClose
	}
}

func (rt *Router) Send(msg *protocol.S2SMessage) error {
	k := router_match{*msg.Round, msgtype(msg)}
	rt.RLock()
	defer rt.RUnlock()
	ch, ok := rt.routes[k]

	if ok {
		ch <- msg
		return nil
	} else {
		return errNoRoute
	}
}
