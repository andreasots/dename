package consensus

import (
	"errors"
	"github.com/andres-erbsen/dename/protocol"
	"log"
	"sync"
	"time"
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
	routes map[router_match]router_handler
	sync.RWMutex
}

func newRouter() (rt *Router) {
	rt = new(Router)
	rt.routes = make(map[router_match]router_handler)
	return rt
}

type router_match struct {
	round int64
	tp    int // message type
}

// handle a message and return whether it was the last one
type router_handler func(msg *protocol.S2SMessage) bool

func (rt *Router) Receive(round int64, tp int, f router_handler) {
	k := router_match{round, tp}
	func() {
		rt.Lock()
		defer rt.Unlock()
		if _, already := rt.routes[k]; !already {
			rt.routes[k] = f
		} else {
			log.Fatalf("Router: ambiguity for %v", k)
		}
	}()

	rt.Lock()
	defer rt.Unlock()
}

func (rt *Router) Send(msg *protocol.S2SMessage) error {
	k := router_match{*msg.Round, msgtype(msg)}
	rt.RLock()
	f, ok := rt.routes[k]
	rt.RUnlock()
	if ok {
		closing := f(msg)
		if closing {
			rt.Lock()
			delete(rt.routes, k)
			rt.Unlock()
		}
		return nil
	}
	return errNoRoute
}

func (rt *Router) SendWait(msg *protocol.S2SMessage) {
	for rt.Send(msg) != nil {
		time.Sleep(time.Millisecond * 50)
	}
}

func (rt *Router) Close(round int64, tp int) {
	k := router_match{round, tp}
	rt.Lock()
	defer rt.Unlock()
	_, ok := rt.routes[k]
	if ok {
		delete(rt.routes, k)
	} else {
		log.Fatal("Router: unexpected close")
	}
}
