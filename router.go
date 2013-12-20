package main

import (
	"errors"
	"github.com/andres-erbsen/dename/protocol"
	"log"
)

const (
	S2S_PUSH = iota
	S2S_COMMITMENT
	S2S_ACKNOWLEDGEMENT
	S2S_ROUNDKEY
	S2S_PUBLISH
)

var errNoRoute = errors.New("Router: no route for message")

type router_rule struct {
	round int64
	tp    int
}

type Router struct {
	ruleof map[chan *protocol.S2SMessage]router_rule
	routes map[router_rule]chan *protocol.S2SMessage

	msgs     chan *protocol.S2SMessage
	msg_errs chan error
	receives chan struct {
		k  router_rule
		ch chan *protocol.S2SMessage
	}
	closech  chan chan *protocol.S2SMessage
	shutdown chan struct{}
}

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

func (rt *Router) Run(round int64, tp int) {
	for {
		select {
		case msg := <-rt.msgs:
			k := router_rule{*msg.Round, msgtype(msg)}
			if ch, ok := rt.routes[k]; ok {
				ch <- msg
				rt.msg_errs <- nil
			} else {
				rt.msg_errs <- errNoRoute
			}
		case rec := <-rt.receives:
			if _, already := rt.routes[rec.k]; !already {
				rt.routes[rec.k] = rec.ch
			} else {
				log.Fatalf("Router: ambiguity for %v", rec.k)
			}
		case ch := <-rt.closech:
			if k, ok := rt.ruleof[ch]; ok {
				delete(rt.routes, k)
				delete(rt.ruleof, ch)
			} else {
				log.Fatal("Router: unexpected close %v", ch)
			}
		case <-rt.shutdown:
			break
		}
	}
}

func (rt *Router) Receive(round int64, tp int) chan *protocol.S2SMessage {
	ch := make(chan *protocol.S2SMessage)
	rt.receives <- struct {
		k  router_rule
		ch chan *protocol.S2SMessage
	}{router_rule{round, tp}, ch}
	return ch
}

func (rt *Router) Close(ch chan *protocol.S2SMessage) {
	rt.closech <- ch
}

func (rt *Router) Send(msg *protocol.S2SMessage) error {
	rt.msgs <- msg
	return <-rt.msg_errs
}

func (rt *Router) Stop(round, tp int64) {
	rt.shutdown <- struct{}{}
}
