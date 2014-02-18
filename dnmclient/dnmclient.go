package dnmclient

import (
	"bytes"
	"code.google.com/p/gcfg"
	"code.google.com/p/go.net/proxy"
	"code.google.com/p/goprotobuf/proto"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"github.com/andres-erbsen/dename/consensus"
	"github.com/andres-erbsen/dename/protocol"
	"github.com/andres-erbsen/sgp"
	"github.com/daniel-ziegler/merklemap"
	"io/ioutil"
	"log"
	"time"
)

var ErrRejected = errors.New("Server refused to transfer the name")

type Cfg struct {
	Peer map[string]*struct {
		PublicKey string
		Host      string
	}
}

type DenameClient struct {
	verifiers []*sgp.Entity
	server    string
	dialer    proxy.Dialer
}

const DefaultHostname = "dename.xvm.mit.edu"
const PilotVerifier_b64 = `Cl0KKAgBEAAYAiIgPG0f8Z363+bqSk1VfzDAaQbD7ggPM2MvAo8P6o8Xm7gKJggGGAEiIBYgQcQMqQlL6/IH0GL0PHdRjCu1oV+M4hb7Hdxa/+YLEPCa1pYFGICangEiQGQ2D0X+BPOX4XNyOco6BbksfBUF2DfegUaKYXnXxGnvyoh7AoAn7YeeSRxcqtMMhSJatwBG3hO+61u7LX5p9wk==`

var PilotVerifier *sgp.Entity
var DefaultVerifiers []*sgp.Entity

func init() {
	PilotVerifier := new(sgp.Entity)
	pk_bs, err := base64.StdEncoding.DecodeString(PilotVerifier_b64)
	if err != nil {
		panic(err)
	}
	PilotVerifier.Parse(pk_bs)
	DefaultVerifiers = []*sgp.Entity{PilotVerifier}
}

func NewFromFile(cfgfile string, proxy_dialer proxy.Dialer) (dnmc *DenameClient, err error) {
	var cfg Cfg
	err = gcfg.ReadFileInto(&cfg, cfgfile)
	if err != nil {
		return nil, err
	}
	verifiers := make([]*sgp.Entity, 0, len(cfg.Peer))
	var server string
	for _, peer := range cfg.Peer {
		if server == "" {
			server = peer.Host
		}
		pk_bytes, err := base64.StdEncoding.DecodeString(peer.PublicKey)
		if err != nil {
			return nil, err
		}
		e := new(sgp.Entity)
		err = e.Parse(pk_bytes)
		if err != nil {
			return nil, err
		}
		verifiers = append(verifiers, e)
	}
	return New(verifiers, server, proxy_dialer), nil
}

func New(pks []*sgp.Entity, server string, proxy_dialer proxy.Dialer) *DenameClient {
	dnmc := new(DenameClient)
	if pks != nil {
		dnmc.verifiers = pks
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

	conn, err := dnmc.dialer.Dial("tcp", dnmc.server+":6263")
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

func (dnmc *DenameClient) Lookup(name string) (entity *sgp.Entity, err error) {
	_true := true
	response, err := dnmc.roundTrip(&protocol.C2SMessage{Lookup: []byte(name),
		GetRoot: &_true, GetFreshness: &_true})
	if err != nil {
		return
	}

	var verified_result_bs []byte
	for _, pk := range dnmc.verifiers {
		verified_result_bs, err = pk.Verify(response.Root, protocol.SIGN_TAG_PUBLISH)
		if err != nil {
			return
		}
	}
	verified_result := new(consensus.ConsensusResult)
	if err = proto.Unmarshal(verified_result_bs, verified_result); err != nil {
		return
	}

	path := new(merklemap.MerklePath)
	if err = proto.Unmarshal(response.LookupResponse.Path, path); err != nil {
		return
	}

	pk_hash := merklemap.Hash(response.LookupResponse.PublicKey)
	name_hash := merklemap.Hash([]byte(name))
	perceived_root := path.ComputeRootHash(name_hash, pk_hash)
	if !bytes.Equal(verified_result.Result, perceived_root) {
		return nil, errors.New("Failed to reproduce root hash")
	}

	entity = new(sgp.Entity)
	err = entity.Parse(response.LookupResponse.PublicKey)

	freshness_times := make([]*time.Time, len(dnmc.verifiers))
	freshness := new(protocol.FreshnessAssertion)
	vrfs := sgp.OneOf(dnmc.verifiers)
	for _, frs_s_bs := range response.FreshnessAssertions {
		freshness_bs, i, err := vrfs.Verify(frs_s_bs, protocol.SIGN_TAG_FRESHNESS)
		if err != nil {
			continue
		}
		if err = proto.Unmarshal(freshness_bs, freshness); err != nil {
			continue
		}
		if !bytes.Equal(freshness.Root, verified_result.Result) {
			return nil, errors.New("freshness root mismatch")
		}
		t_i := time.Unix(*freshness.Time, 0)
		freshness_times[i] = &t_i
	}

	log.Print(freshness_times)
	// TODO: how strong freshness should we require? For now, none

	return
}

func Lookup(name string) (*sgp.Entity, error) {
	return New(nil, "", nil).Lookup(name)
}

func (dnmc *DenameClient) Transfer(sk *sgp.SecretKey, name string, pk *sgp.Entity) []byte {
	transfer := &protocol.TransferName{Name: []byte(name), PublicKey: pk.Bytes}
	transfer_bs, err := proto.Marshal(transfer)
	if err != nil {
		panic(err)
	}
	ret := sk.Sign(transfer_bs, protocol.SIGN_TAG_TRANSFER)
	return ret
}

func Transfer(sk *sgp.SecretKey, name string, pk *sgp.Entity) []byte {
	return New(nil, "", nil).Transfer(sk, name, pk)
}

func (dnmc *DenameClient) GetFreshnessToken() (ret []byte, err error) {
	_true := true
	response, err := dnmc.roundTrip(&protocol.C2SMessage{GetRoot: &_true})
	if err != nil {
		return
	}

	var verified_result_bs []byte
	for _, pk := range dnmc.verifiers {
		verified_result_bs, err = pk.Verify(response.Root, protocol.SIGN_TAG_PUBLISH)
		if err != nil {
			return
		}
	}
	verified_result := new(consensus.ConsensusResult)
	if err = proto.Unmarshal(verified_result_bs, verified_result); err != nil {
		return
	}
	return verified_result.Result, nil
}

func (dnmc *DenameClient) Accept(sk *sgp.SecretKey, xfer []byte) (err error) {
	freshRoot, err := dnmc.GetFreshnessToken()
	if err != nil {
		return
	}
	accept := &protocol.AcceptTransfer{Transfer: xfer, FreshRoot: freshRoot}
	accept_bs, err := proto.Marshal(accept)
	if err != nil {
		panic(err)
	}
	signed_accept_bs := sk.Sign(accept_bs, protocol.SIGN_TAG_ACCEPT)
	response, err := dnmc.roundTrip(&protocol.C2SMessage{Transfer: signed_accept_bs})
	if err != nil {
		return
	}
	if !response.GetTransferLooksGood() {
		return ErrRejected
	}
	return nil
}

func Accept(sk *sgp.SecretKey, signed_transfer []byte) error {
	return New(nil, "", nil).Accept(sk, signed_transfer)
}

func (dnmc *DenameClient) Register(sk *sgp.SecretKey, name, regtoken_b64 string) error {
	regtoken, err := base64.StdEncoding.DecodeString(regtoken_b64)
	if err != nil {
		return err
	}
	freshRoot, err := dnmc.GetFreshnessToken()
	if err != nil {
		return err
	}
	accept := &protocol.AcceptTransfer{
		Transfer: dnmc.Transfer(sk, name, sk.Entity), FreshRoot: freshRoot}
	accept_bs, err := proto.Marshal(accept)
	if err != nil {
		panic(err)
	}
	response, err := dnmc.roundTrip(&protocol.C2SMessage{
		Transfer: sk.Sign(accept_bs, protocol.SIGN_TAG_ACCEPT),
		RegToken: regtoken})
	if err != nil {
		return err
	}
	if !response.GetTransferLooksGood() {
		return ErrRejected
	}
	return nil
}

func Register(sk *sgp.SecretKey, name, regtoken string) error {
	return New(nil, "", nil).Register(sk, name, regtoken)
}
