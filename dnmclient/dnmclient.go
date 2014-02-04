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
)

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

func (dnmc *DenameClient) roundTrip(msg *protocol.C2SMessage) (response []byte, err error) {
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
	return ioutil.ReadAll(conn)
}

func (dnmc *DenameClient) Lookup(name string) (entity *sgp.Entity, err error) {
	response_bs, err := dnmc.roundTrip(&protocol.C2SMessage{Lookup: []byte(name)})
	if err != nil {
		return
	}
	response := new(protocol.LookupResponse)
	if err = proto.Unmarshal(response_bs, response); err != nil {
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
	if err = proto.Unmarshal(response.Path, path); err != nil {
		return
	}

	pk_hash := merklemap.Hash(response.PublicKey)
	name_hash := merklemap.Hash([]byte(name))
	perceived_root := path.ComputeRootHash(name_hash, pk_hash)
	if !bytes.Equal(verified_result.Result, perceived_root) {
		return nil, errors.New("Failed to reproduce root hash")
	}

	entity = new(sgp.Entity)
	err = entity.Parse(response.PublicKey)
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

func (dnmc *DenameClient) Accept(sk *sgp.SecretKey, signed_transfer []byte) (err error) {
	// get a fresh root to use as proof of freshness of the signed_transfer
	response_bs, err := dnmc.roundTrip(&protocol.C2SMessage{Lookup: []byte("")})
	if err != nil {
		return
	}
	response := new(protocol.LookupResponse)
	if err = proto.Unmarshal(response_bs, response); err != nil {
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

	accept := &protocol.AcceptTransfer{Transfer: signed_transfer, FreshRoot: verified_result.Result}
	accept_bs, err := proto.Marshal(accept)
	if err != nil {
		panic(err)
	}
	signed_accept_bs := sk.Sign(accept_bs, protocol.SIGN_TAG_ACCEPT)
	_, err = dnmc.roundTrip(&protocol.C2SMessage{Transfer: signed_accept_bs})
	return
}

func Accept(sk *sgp.SecretKey, signed_transfer []byte) error {
	return New(nil, "", nil).Accept(sk, signed_transfer)
}

func (dnmc *DenameClient) Register(sk *sgp.SecretKey, name string) error {
	return dnmc.Accept(sk, dnmc.Transfer(sk, name, sk.Entity))
}

func Register(sk *sgp.SecretKey, name string) error {
	return New(nil, "", nil).Register(sk, name)
}
