package prng

import (
	"code.google.com/p/go.crypto/salsa20/salsa"
	"sync"
	// FIXME: go.crypto/salsa20/salsa.core is not exported, workaround:
	"github.com/dchest/nacl/salsa20"
)

const BLOCKSIZE = 64

// PRNG implements a cryptographically secure random number generator that
// exposes both io.Reader and math/rand.Source API. At the moment, salsa20
// keystream is used. It is safe to use concurrently from multiple goroutines.
type PRNG struct {
	key       [32]byte
	counter   [16]byte
	block     [64]byte
	remaining int
	sync.Mutex
}

func NewPRNG(key *[32]byte) *PRNG {
	ret := new(PRNG)
	copy(ret.key[:], key[:])
	return ret
}

func (s *PRNG) Read(b []byte) (int, error) {
	s.Lock()
	defer s.Unlock()
	n := len(b)
	for len(b) > 0 {
		c := s.remaining
		if len(b) < c {
			c = len(b)
		}
		copy(b[:c], s.block[BLOCKSIZE-s.remaining:])
		b = b[c:]
		s.remaining -= c
		if s.remaining <= 0 {
			salsa20.Core(&s.block, &s.counter, &s.key, &salsa.Sigma)
			s.remaining = BLOCKSIZE
			// Add one to the little-endian 16-byte counter
			u := uint32(1)
			for i := 8; i < 16; i++ {
				u += uint32(s.counter[i])
				s.counter[i] = byte(u)
				u >>= 8
			}
		}
	}
	return n, nil
}

// Int63 returns a non-negative pseudo-random 63-bit integer as an int64
func (s *PRNG) Int63() int64 {
	var bs [8]byte
	s.Read(bs[:])
	ret := int64(bs[0]&0x7f) << (8 * 7)
	ret |= int64(bs[1]) << (8 * 6)
	ret |= int64(bs[2]) << (8 * 5)
	ret |= int64(bs[3]) << (8 * 4)
	ret |= int64(bs[4]) << (8 * 3)
	ret |= int64(bs[5]) << (8 * 2)
	ret |= int64(bs[6]) << (8 * 1)
	ret |= int64(bs[7])
	return ret
}

func (s *PRNG) Seed(int64) {
	panic("Cannot seed a cryptographic PRNG with an int")
}
