package protocol

import (
	"bytes"
	"crypto/rand"
	"github.com/agl/ed25519"
	"testing"
)

func TestSign(t *testing.T) {
	signpk, signsk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	sk := (*Ed25519Secret)(signsk)
	pk := &PublicKey{Ed25519: signpk[:]}
	msg := []byte("I was here")
	msg2, err := pk.Verify(sk.Sign(msg, 123), 123)
	if err != nil {
		t.Error("Sign-Verify roundtrip failed:", err)
	} else if !bytes.Equal(msg, msg2) {
		t.Error("Sign-Verify roundtrip failed to reproduce original message")
	}
}
