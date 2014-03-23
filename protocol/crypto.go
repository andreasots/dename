package protocol

import (
	"code.google.com/p/go.crypto/nacl/box"
	"code.google.com/p/goprotobuf/proto"
	"errors"
	"github.com/agl/ed25519"
)

type Curve25519Secret [32]byte
type Ed25519Secret [ed25519.PrivateKeySize]byte

func (pk *PublicKey) Verify(signed_msg []byte, tag uint64) (msg []byte, err error) {
	if len(signed_msg) < ed25519.SignatureSize {
		return nil, errors.New("Verify: Signed message shorter than signature")
	}
	msg = signed_msg[ed25519.SignatureSize:]
	err = pk.VerifyDetached(msg, signed_msg[:ed25519.SignatureSize], tag)
	if err != nil {
		msg = nil
	}
	return
}

func (pk *PublicKey) VerifyDetached(msg, sig_bs []byte, tag uint64) error {
	if pk.GetEd25519() == nil || len(pk.Ed25519) != ed25519.PublicKeySize {
		return errors.New("VerifyDetached: ed25519 pubkey missing or incorrect length")
	}
	if len(sig_bs) != ed25519.SignatureSize {
		return errors.New("VerifyDetached: incrrect signature size")
	}
	sig := new([ed25519.SignatureSize]byte)
	edpk := new([ed25519.PublicKeySize]byte)
	copy(sig[:], sig_bs)
	copy(edpk[:], pk.Ed25519)
	tagged_msg := append(proto.EncodeVarint(tag), msg...)
	if !ed25519.Verify(edpk, tagged_msg, sig) {
		return errors.New("Signature verification failed")
	}
	return nil
}

func (sk *Ed25519Secret) Sign(msg []byte, tag uint64) []byte {
	return append(sk.SignDetached(msg, tag), msg...)
}

func (sk *Ed25519Secret) SignDetached(msg []byte, tag uint64) []byte {
	tagged_msg := append(proto.EncodeVarint(tag), msg...)
	sig := ed25519.Sign((*[ed25519.PrivateKeySize]byte)(sk), tagged_msg)
	return sig[:]
}

func (sk *Curve25519Secret) KeyAgreement(pk *PublicKey) ([]byte, error) {
	if pk.GetCurve25519() == nil || len(pk.Curve25519) != 32 {
		return nil, errors.New("KeyAgreement: curve25519 pubkey missing or incorrect length")
	}
	var cpk, ret [32]byte
	copy(cpk[:], pk.Curve25519)
	box.Precompute(&ret, &cpk, (*[32]byte)(sk))
	return ret[:], nil
}
