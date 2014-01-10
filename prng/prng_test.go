package prng

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"testing"
)

func fromHex(s string) []byte {
	ret, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return ret
}

// from https://github.com/AlexWebr/salsa20/blob/master/test_vectors.256
var testVectors = []struct {
	key  []byte
	out  []byte // bytes 0..63
	out2 []byte // bytes 192..255
}{
	{
		fromHex("8000000000000000000000000000000000000000000000000000000000000000"),
		fromHex("E3BE8FDD8BECA2E3EA8EF9475B29A6E7003951E1097A5C38D23B7A5FAD9F6844B22C97559E2723C7CBBD3FE4FC8D9A0744652A83E72A9C461876AF4D7EF1A117"),
		fromHex("57BE81F47B17D9AE7C4FF15429A73E10ACF250ED3A90A93C711308A74C6216A9ED84CD126DA7F28E8ABF8BB63517E1CA98E712F4FB2E1A6AED9FDC73291FAA17"),
	},
	{
		fromHex("0040000000000000000000000000000000000000000000000000000000000000"),
		fromHex("01F191C3A1F2CC6EBED78095A05E062E1228154AF6BAE80A0E1A61DF2AE15FBCC37286440F66780761413F23B0C2C9E4678C628C5E7FB48C6EC1D82D47117D9F"),
		fromHex("86D6F824D58012A14A19858CFE137D768E77597B96A4285D6B65D88A7F1A87784BF1A3E44FC9D3525DDC784F5D99BA222712420181CABAB00C4B91AAEDFF521C"),
	},
	{
		fromHex("0000200000000000000000000000000000000000000000000000000000000000"),
		fromHex("C29BA0DA9EBEBFACDEBBDD1D16E5F5987E1CB12E9083D437EAAAA4BA0CDC909E53D052AC387D86ACDA8D956BA9E6F6543065F6912A7DF710B4B57F27809BAFE3"),
		fromHex("77DE29C19136852CC5DF78B5903CAC7B8C91345350CF97529D90F18055ECB75AC86A922B2BD3BD1DE3E2FB6DF915316609BDBAB298B37EA0C5ECD917788E2216"),
	},
}

func TestSalsa20PRNGTestVectors(t *testing.T) {
	var key [32]byte
	for i, test := range testVectors {
		copy(key[:], test.key)
		out := make([]byte, len(test.out))
		s := NewPRNG(&key)
		s.Read(out)
		if !bytes.Equal(out, test.out) {
			t.Errorf("#%d: bad result", i)
		}
		s.Read(out)
		s.Read(out)
		s.Read(out)
		if !bytes.Equal(out, test.out2) {
			t.Errorf("#%d: bad result", i)
		}
	}
}

func TestSalsa20PRNGInt63(t *testing.T) {
	var key [32]byte
	for i, test := range testVectors {
		copy(key[:], test.key)
		var correct int64
		binary.Read(bytes.NewBuffer(test.out[:8]), binary.BigEndian, &correct)
		if correct >= 0 {
			if NewPRNG(&key).Int63() != correct {
				t.Errorf("#%d: bad result", i)
			}
		}
	}
}

func TestSalsa20PRNGMathRand(t *testing.T) {
	var key [32]byte
	for i, test := range testVectors {
		copy(key[:], test.key)
		r := rand.New(NewPRNG(&key))
		x := r.Float64()
		if x < 0 || x >= 1 {
			t.Errorf("#%d: bad result", i)
		}
	}
}
