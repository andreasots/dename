package dnmclient

import (
	"code.google.com/p/goprotobuf/proto"
	"github.com/andres-erbsen/dename/protocol"
	"github.com/andres-erbsen/sgp"
	"github.com/daniel-ziegler/merklemap"
	// "github.com/andres-erbsen/sgp"
	"bytes"
	"code.google.com/p/gcfg"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"net"
)

type Cfg struct {
	Peer map[string]*struct {
		Host string
	}
}

type DenameClient struct {
	cfg      Cfg
	peer_pks []*sgp.Entity
	server   string
}

func New(cfgfile string) (dnmc *DenameClient, err error) {
	dnmc = new(DenameClient)
	err = gcfg.ReadFileInto(&dnmc.cfg, cfgfile)
	if err != nil {
		return nil, err
	}
	dnmc.peer_pks = make([]*sgp.Entity, len(dnmc.cfg.Peer))
	i := 0
	for pk_b64, peer := range dnmc.cfg.Peer {
		if dnmc.server == "" {
			dnmc.server = peer.Host
		}
		pk_bytes, err := base64.StdEncoding.DecodeString(pk_b64)
		if err != nil {
			return nil, err
		}
		dnmc.peer_pks[i] = new(sgp.Entity)
		err = dnmc.peer_pks[i].Parse(pk_bytes)
		if err != nil {
			return nil, err
		}
		i++
	}
	return dnmc, nil
}

func (dnmc *DenameClient) Lookup(name string) (entity *sgp.Entity, err error) {
	for _, peer := range dnmc.cfg.Peer {
		entity, err = dnmc.LookupFrom(peer.Host, name)
		if err == nil {
			if entity == nil {
				panic(entity)
			}
			return
		}
	}
	return nil, errors.New("Lookup failed")
}

func (dnmc *DenameClient) LookupFrom(host, name string) (entity *sgp.Entity, err error) {
	query_bs, err := proto.Marshal(&protocol.C2SMessage{Lookup: &name})
	if err != nil {
		return
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", host+":6263")
	if err != nil {
		return
	}
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return
	}
	defer conn.Close()

	_, err = conn.Write(query_bs)
	if err != nil {
		return
	}
	conn.CloseWrite()

	response_bs, err := ioutil.ReadAll(conn)
	if err != nil {
		return
	}
	response := new(protocol.LookupResponse)
	err = proto.Unmarshal(response_bs, response)
	if err != nil {
		return
	}

	root_signed := new(sgp.Signed)
	err = proto.Unmarshal(response.Root, root_signed)
	if err != nil {
		return
	}
	for _, pk := range dnmc.peer_pks {
		if !pk.VerifyPb(root_signed, protocol.SIGN_TAG_PUBLISH) {
			return nil, errors.New("Cannot verify signature")
		}
	}

	path := new(merklemap.MerklePath)
	err = proto.Unmarshal(response.Path, path)
	if err != nil {
		return
	}

	rootdata := new(protocol.MappingRoot)
	err = proto.Unmarshal(root_signed.Message, rootdata)
	if err != nil {
		return
	}

	pk_hash := merklemap.Hash(response.PublicKey)
	name_hash := merklemap.Hash([]byte(name))
	perceived_root_hash := path.ComputeRootHash(name_hash, pk_hash)
	if !bytes.Equal(rootdata.Root, perceived_root_hash) {
		return nil, errors.New("Failed to reproduce root hash")
	}

	entity = new(sgp.Entity)
	err = entity.Parse(response.PublicKey)
	return
}

func (dnmc *DenameClient) Transfer(sk *sgp.SecretKey, name string, pk *sgp.Entity) (err error) {
	details := &protocol.TransferName{Name: []byte(name), PublicKey: pk.Bytes}
	details_bs, err := proto.Marshal(details)
	if err != nil {
		return
	}

	request := sk.Sign(details_bs, protocol.SIGN_TAG_TRANSFER)
	request_bs, err := proto.Marshal(&protocol.C2SMessage{TransferName: request})
	if err != nil {
		return
	}

	conn, err := net.Dial("tcp", dnmc.server+":6263")
	if err != nil {
		return
	}
	defer conn.Close()
	_, err = conn.Write(request_bs)
	return
}

func (dnmc *DenameClient) Register(sk *sgp.SecretKey, name string) (err error) {
	return dnmc.Transfer(sk, name, sk.Entity)
}
