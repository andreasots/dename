// Code generated by protoc-gen-go.
// source: dename.proto
// DO NOT EDIT!

package protocol

import proto "code.google.com/p/goprotobuf/proto"
import json "encoding/json"
import math "math"

// Reference proto, json, and math imports to suppress error if they are not otherwise used.
var _ = proto.Marshal
var _ = &json.SyntaxError{}
var _ = math.Inf

type TransferName struct {
	Pubkey           []byte `protobuf:"bytes,1,req,name=pubkey" json:"pubkey,omitempty"`
	Name             []byte `protobuf:"bytes,2,req,name=name" json:"name,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (m *TransferName) Reset()         { *m = TransferName{} }
func (m *TransferName) String() string { return proto.CompactTextString(m) }
func (*TransferName) ProtoMessage()    {}

func (m *TransferName) GetPubkey() []byte {
	if m != nil {
		return m.Pubkey
	}
	return nil
}

func (m *TransferName) GetName() []byte {
	if m != nil {
		return m.Name
	}
	return nil
}

type C2SMessage struct {
	TransferName     []byte `protobuf:"bytes,1,opt,name=transfer_name" json:"transfer_name,omitempty"`
	Lookup           []byte `protobuf:"bytes,2,opt,name=lookup" json:"lookup,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (m *C2SMessage) Reset()         { *m = C2SMessage{} }
func (m *C2SMessage) String() string { return proto.CompactTextString(m) }
func (*C2SMessage) ProtoMessage()    {}

func (m *C2SMessage) GetTransferName() []byte {
	if m != nil {
		return m.TransferName
	}
	return nil
}

func (m *C2SMessage) GetLookup() []byte {
	if m != nil {
		return m.Lookup
	}
	return nil
}

type S2SMessage struct {
	Round  *int64 `protobuf:"varint,1,req,name=round" json:"round,omitempty"`
	Server *int64 `protobuf:"varint,2,req,name=server" json:"server,omitempty"`
	// one of the following:
	PushQueue        []byte `protobuf:"bytes,3,opt,name=push_queue" json:"push_queue,omitempty"`
	Commitment       []byte `protobuf:"bytes,4,opt,name=commitment" json:"commitment,omitempty"`
	Ack              []byte `protobuf:"bytes,5,opt,name=ack" json:"ack,omitempty"`
	RoundKey         []byte `protobuf:"bytes,6,opt,name=round_key" json:"round_key,omitempty"`
	Publish          []byte `protobuf:"bytes,7,opt,name=publish" json:"publish,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (m *S2SMessage) Reset()         { *m = S2SMessage{} }
func (m *S2SMessage) String() string { return proto.CompactTextString(m) }
func (*S2SMessage) ProtoMessage()    {}

func (m *S2SMessage) GetRound() int64 {
	if m != nil && m.Round != nil {
		return *m.Round
	}
	return 0
}

func (m *S2SMessage) GetServer() int64 {
	if m != nil && m.Server != nil {
		return *m.Server
	}
	return 0
}

func (m *S2SMessage) GetPushQueue() []byte {
	if m != nil {
		return m.PushQueue
	}
	return nil
}

func (m *S2SMessage) GetCommitment() []byte {
	if m != nil {
		return m.Commitment
	}
	return nil
}

func (m *S2SMessage) GetAck() []byte {
	if m != nil {
		return m.Ack
	}
	return nil
}

func (m *S2SMessage) GetRoundKey() []byte {
	if m != nil {
		return m.RoundKey
	}
	return nil
}

func (m *S2SMessage) GetPublish() []byte {
	if m != nil {
		return m.Publish
	}
	return nil
}

type CommitData struct {
	Round            *int64   `protobuf:"varint,1,req,name=round" json:"round,omitempty"`
	Server           *int64   `protobuf:"varint,2,req,name=server" json:"server,omitempty"`
	RoundKey         []byte   `protobuf:"bytes,3,req,name=round_key" json:"round_key,omitempty"`
	TransactionQueue [][]byte `protobuf:"bytes,4,rep,name=transaction_queue" json:"transaction_queue,omitempty"`
	XXX_unrecognized []byte   `json:"-"`
}

func (m *CommitData) Reset()         { *m = CommitData{} }
func (m *CommitData) String() string { return proto.CompactTextString(m) }
func (*CommitData) ProtoMessage()    {}

func (m *CommitData) GetRound() int64 {
	if m != nil && m.Round != nil {
		return *m.Round
	}
	return 0
}

func (m *CommitData) GetServer() int64 {
	if m != nil && m.Server != nil {
		return *m.Server
	}
	return 0
}

func (m *CommitData) GetRoundKey() []byte {
	if m != nil {
		return m.RoundKey
	}
	return nil
}

func (m *CommitData) GetTransactionQueue() [][]byte {
	if m != nil {
		return m.TransactionQueue
	}
	return nil
}

type Commitment struct {
	Round            *int64 `protobuf:"varint,1,req,name=round" json:"round,omitempty"`
	Server           *int64 `protobuf:"varint,2,req,name=server" json:"server,omitempty"`
	Hash             []byte `protobuf:"bytes,4,req,name=hash" json:"hash,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (m *Commitment) Reset()         { *m = Commitment{} }
func (m *Commitment) String() string { return proto.CompactTextString(m) }
func (*Commitment) ProtoMessage()    {}

func (m *Commitment) GetRound() int64 {
	if m != nil && m.Round != nil {
		return *m.Round
	}
	return 0
}

func (m *Commitment) GetServer() int64 {
	if m != nil && m.Server != nil {
		return *m.Server
	}
	return 0
}

func (m *Commitment) GetHash() []byte {
	if m != nil {
		return m.Hash
	}
	return nil
}

type Acknowledgement struct {
	Commiter         *int64 `protobuf:"varint,1,req,name=commiter" json:"commiter,omitempty"`
	Acker            *int64 `protobuf:"varint,2,req,name=acker" json:"acker,omitempty"`
	Commitment       []byte `protobuf:"bytes,3,req,name=commitment" json:"commitment,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (m *Acknowledgement) Reset()         { *m = Acknowledgement{} }
func (m *Acknowledgement) String() string { return proto.CompactTextString(m) }
func (*Acknowledgement) ProtoMessage()    {}

func (m *Acknowledgement) GetCommiter() int64 {
	if m != nil && m.Commiter != nil {
		return *m.Commiter
	}
	return 0
}

func (m *Acknowledgement) GetAcker() int64 {
	if m != nil && m.Acker != nil {
		return *m.Acker
	}
	return 0
}

func (m *Acknowledgement) GetCommitment() []byte {
	if m != nil {
		return m.Commitment
	}
	return nil
}

type MappingRoot struct {
	Round            *int64 `protobuf:"varint,1,req,name=round" json:"round,omitempty"`
	Root             []byte `protobuf:"bytes,2,req,name=root" json:"root,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (m *MappingRoot) Reset()         { *m = MappingRoot{} }
func (m *MappingRoot) String() string { return proto.CompactTextString(m) }
func (*MappingRoot) ProtoMessage()    {}

func (m *MappingRoot) GetRound() int64 {
	if m != nil && m.Round != nil {
		return *m.Round
	}
	return 0
}

func (m *MappingRoot) GetRoot() []byte {
	if m != nil {
		return m.Root
	}
	return nil
}

func init() {
}
