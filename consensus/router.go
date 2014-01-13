package consensus

import (
	"errors"
	"log"
	"sync"
	"time"
)

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
type router_handler func(msg *ConsensusMSG) bool

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

func (rt *Router) Send(msg *ConsensusMSG) error {
	k := router_match{*msg.Round, msgtype(msg)}
	rt.RLock()
	f, ok := rt.routes[k]
	rt.RUnlock()
	if ok {
		// log.Printf("%v %v %v", *msg.Round, msgtypeName[msgtype(msg)], *msg.Server)
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

func (rt *Router) SendWait(msg *ConsensusMSG) {
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
