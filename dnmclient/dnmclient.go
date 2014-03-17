package dnmclient

import (
	"bytes"
	"code.google.com/p/gcfg"
	"code.google.com/p/go.net/proxy"
	"code.google.com/p/goprotobuf/proto"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/andres-erbsen/dename/consensus"
	"github.com/andres-erbsen/dename/protocol"
	"github.com/daniel-ziegler/merklemap"
	"io/ioutil"
	"time"
)

var ErrRejected = errors.New("Server refused to transfer the name")

type Cfg struct {
	Peer map[string]*struct {
		PublicKey string
		ConnectTo string
	}
}

type DenameClient struct {
	verifiers map[int64]*protocol.PublicKey
	server    string
	dialer    proxy.Dialer
}

const DefaultHostname = "dename.xvm.mit.edu"
const PilotVerifier_b64 = `Cl0KKAgBEAAYAiIgPG0f8Z363+bqSk1VfzDAaQbD7ggPM2MvAo8P6o8Xm7gKJggGGAEiIBYgQcQMqQlL6/IH0GL0PHdRjCu1oV+M4hb7Hdxa/+YLEPCa1pYFGICangEiQGQ2D0X+BPOX4XNyOco6BbksfBUF2DfegUaKYXnXxGnvyoh7AoAn7YeeSRxcqtMMhSJatwBG3hO+61u7LX5p9wk==`

var PilotVerifier *protocol.PublicKey
var DefaultVerifiers map[int64]*protocol.PublicKey

func init() {
	var err error
	PilotVerifier = new(protocol.PublicKey)
	pk_bs, err := base64.StdEncoding.DecodeString(PilotVerifier_b64)
	if err != nil {
		panic(err)
	}
	proto.Unmarshal(pk_bs, PilotVerifier)
	DefaultVerifiers = make(map[int64]*protocol.PublicKey)
	DefaultVerifiers[1] = PilotVerifier
}

func NewFromFile(cfgfile string, proxy_dialer proxy.Dialer) (dnmc *DenameClient, err error) {
	var cfg Cfg
	err = gcfg.ReadFileInto(&cfg, cfgfile)
	if err != nil {
		return nil, err
	}
	verifiers := make(map[int64]*protocol.PublicKey)
	var server string
	for id_str, peer := range cfg.Peer {
		var id int64
		if _, err = fmt.Sscan(id_str, &id); err != nil {
			return
		}
		if server == "" {
			server = peer.ConnectTo
		}
		pk_bytes, err := base64.StdEncoding.DecodeString(peer.PublicKey)
		if err != nil {
			return nil, err
		}
		pk := new(protocol.PublicKey)
		if err := proto.Unmarshal(pk_bytes, pk); err != nil {
			return nil, err
		}
		verifiers[id] = pk
	}
	return New(verifiers, server, proxy_dialer), nil
}

func New(verifiers map[int64]*protocol.PublicKey, server string, proxy_dialer proxy.Dialer) *DenameClient {
	dnmc := new(DenameClient)
	if verifiers != nil {
		dnmc.verifiers = verifiers
	} else {
		dnmc.verifiers = DefaultVerifiers
	}
	if server != "" {
		dnmc.server = server
	} else {
		dnmc.server = DefaultHostname
	}
	if proxy_dialer != nil {
		dnmc.dialer = proxy_dialer
	} else {
		dnmc.dialer = proxy.FromEnvironment()
	}
	return dnmc
}

func (dnmc *DenameClient) roundTrip(msg *protocol.C2SMessage) (
	ret *protocol.S2CMessage, err error) {
	query_bs, err := proto.Marshal(msg)
	if err != nil {
		return
	}

	conn, err := dnmc.dialer.Dial("tcp", dnmc.server)
	if err != nil {
		return
	}
	defer conn.Close()

	err = binary.Write(conn, binary.LittleEndian, uint16(len(query_bs)))
	if err != nil {
		return
	}

	if _, err = conn.Write(query_bs); err != nil {
		return
	}
	ret_bs, err := ioutil.ReadAll(conn)
	if err != nil {
		return
	}

	ret = new(protocol.S2CMessage)
	return ret, proto.Unmarshal(ret_bs, ret)
}

func (dnmc *DenameClient) VerifyConsensusResult(root_crs_bs []byte) (
	rawRoot []byte, err error) {
	crs := new(consensus.SignedConsensusResult)
	if err = proto.Unmarshal(root_crs_bs, crs); err != nil {
		return
	}

	if len(crs.Signatures) != len(crs.Signers) {
		return nil, errors.New("len(crs.Signatures) != len(crs.Signers)")
	}

next_verifier:
	for verifier_id, pk := range dnmc.verifiers {
		for i, signature := range crs.Signatures {
			signer_id := crs.Signers[i]
			if signer_id == verifier_id {
				if err := pk.VerifyDetached(crs.ConsensusResult, signature,
					protocol.SIGN_TAG_PUBLISH); err == nil {
					continue next_verifier
				}
			}
		}
		return nil, errors.New(fmt.Sprintf("Missing valid signature from %d", verifier_id))
	}
	cr := new(consensus.ConsensusResult)
	if err = proto.Unmarshal(crs.ConsensusResult, cr); err != nil {
		return
	}
	return cr.Result, nil
}

func (dnmc *DenameClient) CheckFreshness(rawRoot []byte, sfas []*protocol.SignedFreshnessAssertion) error {
	freshnessTimes := make(map[int64]time.Time, len(dnmc.verifiers))
	freshness := new(protocol.FreshnessAssertion)
next_verifier:
	for verifier_id, pk := range dnmc.verifiers {
		for _, sfa := range sfas {
			if *sfa.Server == verifier_id {
				if err := pk.VerifyDetached(sfa.Assertion, sfa.Signature,
					protocol.SIGN_TAG_FRESHNESS); err != nil {
					continue
				}
				if err := proto.Unmarshal(sfa.Assertion, freshness); err != nil {
					return errors.New("Malformed freshness assertion")
				}
				if !bytes.Equal(freshness.Root, rawRoot) {
					return errors.New("freshness root mismatch")
				}
				freshnessTimes[verifier_id] = time.Unix(*freshness.Time, 0)
				continue next_verifier
			}
		}
		return errors.New(fmt.Sprintf("Missing valid freshness from %d", verifier_id))
	}
	// TODO: how strong freshness should we require? For now, none
	return nil
}

func (dnmc *DenameClient) Lookup(name string) (iden *protocol.Identity, err error) {
	_true := true
	response, err := dnmc.roundTrip(&protocol.C2SMessage{Lookup: []byte(name),
		GetRoot: &_true, GetFreshness: &_true})
	if err != nil {
		return
	}

	var root []byte
	if root, err = dnmc.VerifyConsensusResult(response.RootConsensus); err != nil {
		return
	}

	if err = dnmc.CheckFreshness(root, response.Freshness); err != nil {
		return nil, err
	}

	path := new(merklemap.MerklePath)
	if err = proto.Unmarshal(response.LookupResponse.Path, path); err != nil {
		return
	}

	pk_hash := merklemap.Hash(response.LookupResponse.PublicKey)
	name_hash := merklemap.Hash([]byte(name))
	perceived_root := path.ComputeRootHash(name_hash, pk_hash)
	if !bytes.Equal(root, perceived_root) {
		return nil, errors.New("Failed to reproduce root hash")
	}

	iden = new(protocol.Identity)
	err = proto.Unmarshal(response.LookupResponse.PublicKey, iden)
	return
}

func Lookup(name string) (*protocol.Identity, error) {
	return New(nil, "", nil).Lookup(name)
}

func (dnmc *DenameClient) Transfer(sk *protocol.Ed25519Secret, name string, iden *protocol.Identity) (xfer, sig []byte) {
	transfer := &protocol.TransferName{Name: []byte(name), NewIdentity: iden}
	transfer_bs, err := proto.Marshal(transfer)
	if err != nil {
		panic(err)
	}
	return transfer_bs, sk.SignDetached(transfer_bs, protocol.SIGN_TAG_TRANSFER)
}

func Transfer(sk *protocol.Ed25519Secret, name string, pk *protocol.Identity) (
	xfer, sig []byte) {
	return New(nil, "", nil).Transfer(sk, name, pk)
}

func (dnmc *DenameClient) GetFreshnessToken() (ret []byte, err error) {
	_true := true
	response, err := dnmc.roundTrip(&protocol.C2SMessage{GetRoot: &_true})
	if err != nil {
		return
	}
	return dnmc.VerifyConsensusResult(response.RootConsensus)
}

func (dnmc *DenameClient) Accept(sk *protocol.Ed25519Secret, xfer []byte) (err error) {
	freshRoot, err := dnmc.GetFreshnessToken()
	if err != nil {
		return
	}
	accept := &protocol.AcceptTransfer{Transfer: xfer, FreshRoot: freshRoot}
	accept_bs, err := proto.Marshal(accept)
	if err != nil {
		panic(err)
	}
	sig := sk.SignDetached(accept_bs, protocol.SIGN_TAG_ACCEPT)
	response, err := dnmc.roundTrip(&protocol.C2SMessage{Transfer: &protocol.SignedAcceptedTransfer{Accept: accept_bs, Signature: sig}})
	if err != nil {
		return
	}
	if !response.GetTransferLooksGood() {
		return ErrRejected
	}
	return nil
}

func Accept(sk *protocol.Ed25519Secret, signed_transfer []byte) error {
	return New(nil, "", nil).Accept(sk, signed_transfer)
}

func (dnmc *DenameClient) Register(sk *protocol.Ed25519Secret, iden *protocol.Identity, name, regtoken_b64 string) error {
	regtoken, err := base64.StdEncoding.DecodeString(regtoken_b64)
	if err != nil {
		return err
	}
	freshRoot, err := dnmc.GetFreshnessToken()
	if err != nil {
		return err
	}
	xfer, xfer_sig := dnmc.Transfer(sk, name, iden)
	accept := &protocol.AcceptTransfer{Transfer: xfer,
		TransferSignature: xfer_sig, FreshRoot: freshRoot}
	accept_bs, err := proto.Marshal(accept)
	if err != nil {
		panic(err)
	}
	sig := sk.SignDetached(accept_bs, protocol.SIGN_TAG_ACCEPT)
	response, err := dnmc.roundTrip(
		&protocol.C2SMessage{
			Transfer: &protocol.SignedAcceptedTransfer{
				Accept:    accept_bs,
				Signature: sig},
			RegToken: regtoken})
	if err != nil {
		return err
	}
	if !response.GetTransferLooksGood() {
		return ErrRejected
	}
	return nil
}

func Register(sk *protocol.Ed25519Secret, iden *protocol.Identity, name, regtoken string) error {
	return New(nil, "", nil).Register(sk, iden, name, regtoken)
}
