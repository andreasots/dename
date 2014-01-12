package consensus

import (
	"log"
)

const (
	PUSH = iota
	COMMITMENT
	ACKNOWLEDGEMENT
	ROUNDKEY
	PUBLISH
)

var msgtypeName = map[int]string{
	PUSH:            "PUSH",
	COMMITMENT:      "COMMITMENT",
	ACKNOWLEDGEMENT: "ACKNOWLEDGEMENT",
	ROUNDKEY:        "ROUNDKEY",
	PUBLISH:         "PUBLISH",
}

func msgtype(msg *ConsensusMSG) int {
	switch {
	case msg.PushQueue != nil:
		return PUSH
	case msg.Commitment != nil:
		return COMMITMENT
	case msg.Ack != nil:
		return ACKNOWLEDGEMENT
	case msg.RoundKey != nil:
		return ROUNDKEY
	case msg.Publish != nil:
		return PUBLISH
	default:
		log.Fatal("Unknown message type ", msg)
	}
	return -1
}
