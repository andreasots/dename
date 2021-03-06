// Code generated by protoc-gen-go.
// source: consensus.proto
// DO NOT EDIT!

/*
Package consensus is a generated protocol buffer package.

It is generated from these files:
	consensus.proto

It has these top-level messages:
	ConsensusMSG
	CommitData
	Commitment
	Acknowledgement
	Result
	ConsensusResult
	SignedConsensusResult
*/
package consensus

import proto "code.google.com/p/goprotobuf/proto"
import json "encoding/json"
import math "math"

// Reference proto, json, and math imports to suppress error if they are not otherwise used.
var _ = proto.Marshal
var _ = &json.SyntaxError{}
var _ = math.Inf

type ConsensusMSG struct {
	Round  *int64 `protobuf:"varint,1,req,name=round" json:"round,omitempty"`
	Server *int64 `protobuf:"varint,2,req,name=server" json:"server,omitempty"`
	// one of the following:
	PushQueue        []byte  `protobuf:"bytes,3,opt,name=push_queue" json:"push_queue,omitempty"`
	Commitment       []byte  `protobuf:"bytes,4,opt,name=commitment" json:"commitment,omitempty"`
	Ack              []byte  `protobuf:"bytes,5,opt,name=ack" json:"ack,omitempty"`
	RoundKey         []byte  `protobuf:"bytes,6,opt,name=round_key" json:"round_key,omitempty"`
	Publish          *Result `protobuf:"bytes,7,opt" json:"Publish,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func (m *ConsensusMSG) Reset()         { *m = ConsensusMSG{} }
func (m *ConsensusMSG) String() string { return proto.CompactTextString(m) }
func (*ConsensusMSG) ProtoMessage()    {}

func (m *ConsensusMSG) GetRound() int64 {
	if m != nil && m.Round != nil {
		return *m.Round
	}
	return 0
}

func (m *ConsensusMSG) GetServer() int64 {
	if m != nil && m.Server != nil {
		return *m.Server
	}
	return 0
}

func (m *ConsensusMSG) GetPushQueue() []byte {
	if m != nil {
		return m.PushQueue
	}
	return nil
}

func (m *ConsensusMSG) GetCommitment() []byte {
	if m != nil {
		return m.Commitment
	}
	return nil
}

func (m *ConsensusMSG) GetAck() []byte {
	if m != nil {
		return m.Ack
	}
	return nil
}

func (m *ConsensusMSG) GetRoundKey() []byte {
	if m != nil {
		return m.RoundKey
	}
	return nil
}

func (m *ConsensusMSG) GetPublish() *Result {
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
	Server            *int64 `protobuf:"varint,1,req,name=server" json:"server,omitempty"`
	Round             *int64 `protobuf:"varint,2,req,name=round" json:"round,omitempty"`
	HashOfCommitments []byte `protobuf:"bytes,3,req,name=hash_of_commitments" json:"hash_of_commitments,omitempty"`
	XXX_unrecognized  []byte `json:"-"`
}

func (m *Acknowledgement) Reset()         { *m = Acknowledgement{} }
func (m *Acknowledgement) String() string { return proto.CompactTextString(m) }
func (*Acknowledgement) ProtoMessage()    {}

func (m *Acknowledgement) GetServer() int64 {
	if m != nil && m.Server != nil {
		return *m.Server
	}
	return 0
}

func (m *Acknowledgement) GetRound() int64 {
	if m != nil && m.Round != nil {
		return *m.Round
	}
	return 0
}

func (m *Acknowledgement) GetHashOfCommitments() []byte {
	if m != nil {
		return m.HashOfCommitments
	}
	return nil
}

type Result struct {
	Canonical        *SignedConsensusResult `protobuf:"bytes,1,req,name=canonical" json:"canonical,omitempty"`
	Aux              []byte                 `protobuf:"bytes,2,req,name=aux" json:"aux,omitempty"`
	XXX_unrecognized []byte                 `json:"-"`
}

func (m *Result) Reset()         { *m = Result{} }
func (m *Result) String() string { return proto.CompactTextString(m) }
func (*Result) ProtoMessage()    {}

func (m *Result) GetCanonical() *SignedConsensusResult {
	if m != nil {
		return m.Canonical
	}
	return nil
}

func (m *Result) GetAux() []byte {
	if m != nil {
		return m.Aux
	}
	return nil
}

type ConsensusResult struct {
	Round            *int64 `protobuf:"varint,1,req,name=round" json:"round,omitempty"`
	Result           []byte `protobuf:"bytes,2,req,name=result" json:"result,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (m *ConsensusResult) Reset()         { *m = ConsensusResult{} }
func (m *ConsensusResult) String() string { return proto.CompactTextString(m) }
func (*ConsensusResult) ProtoMessage()    {}

func (m *ConsensusResult) GetRound() int64 {
	if m != nil && m.Round != nil {
		return *m.Round
	}
	return 0
}

func (m *ConsensusResult) GetResult() []byte {
	if m != nil {
		return m.Result
	}
	return nil
}

type SignedConsensusResult struct {
	ConsensusResult  []byte   `protobuf:"bytes,1,req" json:"ConsensusResult,omitempty"`
	Signatures       [][]byte `protobuf:"bytes,2,rep" json:"Signatures,omitempty"`
	Signers          []int64  `protobuf:"varint,3,rep" json:"Signers,omitempty"`
	XXX_unrecognized []byte   `json:"-"`
}

func (m *SignedConsensusResult) Reset()         { *m = SignedConsensusResult{} }
func (m *SignedConsensusResult) String() string { return proto.CompactTextString(m) }
func (*SignedConsensusResult) ProtoMessage()    {}

func (m *SignedConsensusResult) GetConsensusResult() []byte {
	if m != nil {
		return m.ConsensusResult
	}
	return nil
}

func (m *SignedConsensusResult) GetSignatures() [][]byte {
	if m != nil {
		return m.Signatures
	}
	return nil
}

func (m *SignedConsensusResult) GetSigners() []int64 {
	if m != nil {
		return m.Signers
	}
	return nil
}

func init() {
}
