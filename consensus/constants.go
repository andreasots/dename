package consensus

import (
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
