package main

import (
	"bytes"
	"errors"
	"sort"
	"time"
)

const TICK_INTERVAL = 4 * time.Second
const S2S_PORT = "6362"

var errPeer = errors.New("Peer id mismatch")

type ByteSlices [][]byte

func (p ByteSlices) Len() int           { return len(p) }
func (p ByteSlices) Less(i, j int) bool { return bytes.Compare(p[i], p[j]) < 0 }
func (p ByteSlices) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p ByteSlices) Sort()              { sort.Sort(p) }
