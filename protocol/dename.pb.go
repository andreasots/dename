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
	PublicKey        []byte `protobuf:"bytes,1,req,name=public_key" json:"public_key,omitempty"`
	Name             []byte `protobuf:"bytes,2,req,name=name" json:"name,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (m *TransferName) Reset()         { *m = TransferName{} }
func (m *TransferName) String() string { return proto.CompactTextString(m) }
func (*TransferName) ProtoMessage()    {}

func (m *TransferName) GetPublicKey() []byte {
	if m != nil {
		return m.PublicKey
	}
	return nil
}

func (m *TransferName) GetName() []byte {
	if m != nil {
		return m.Name
	}
	return nil
}

type AcceptTransfer struct {
	Transfer         []byte `protobuf:"bytes,1,req,name=transfer" json:"transfer,omitempty"`
	FreshRoot        []byte `protobuf:"bytes,2,req,name=fresh_root" json:"fresh_root,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (m *AcceptTransfer) Reset()         { *m = AcceptTransfer{} }
func (m *AcceptTransfer) String() string { return proto.CompactTextString(m) }
func (*AcceptTransfer) ProtoMessage()    {}

func (m *AcceptTransfer) GetTransfer() []byte {
	if m != nil {
		return m.Transfer
	}
	return nil
}

func (m *AcceptTransfer) GetFreshRoot() []byte {
	if m != nil {
		return m.FreshRoot
	}
	return nil
}

type C2SMessage struct {
	GetRoot          *bool  `protobuf:"varint,1,opt,name=get_root" json:"get_root,omitempty"`
	Transfer         []byte `protobuf:"bytes,2,opt,name=transfer" json:"transfer,omitempty"`
	Lookup           []byte `protobuf:"bytes,3,opt,name=lookup" json:"lookup,omitempty"`
	GetFreshness     *bool  `protobuf:"varint,4,opt,name=get_freshness" json:"get_freshness,omitempty"`
	RegToken         []byte `protobuf:"bytes,5,opt,name=reg_token" json:"reg_token,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (m *C2SMessage) Reset()         { *m = C2SMessage{} }
func (m *C2SMessage) String() string { return proto.CompactTextString(m) }
func (*C2SMessage) ProtoMessage()    {}

func (m *C2SMessage) GetGetRoot() bool {
	if m != nil && m.GetRoot != nil {
		return *m.GetRoot
	}
	return false
}

func (m *C2SMessage) GetTransfer() []byte {
	if m != nil {
		return m.Transfer
	}
	return nil
}

func (m *C2SMessage) GetLookup() []byte {
	if m != nil {
		return m.Lookup
	}
	return nil
}

func (m *C2SMessage) GetGetFreshness() bool {
	if m != nil && m.GetFreshness != nil {
		return *m.GetFreshness
	}
	return false
}

func (m *C2SMessage) GetRegToken() []byte {
	if m != nil {
		return m.RegToken
	}
	return nil
}

type S2CMessage struct {
	Root                []byte          `protobuf:"bytes,1,opt,name=root" json:"root,omitempty"`
	LookupResponse      *LookupResponse `protobuf:"bytes,3,opt,name=lookup_response" json:"lookup_response,omitempty"`
	FreshnessAssertions [][]byte        `protobuf:"bytes,4,rep,name=freshness_assertions" json:"freshness_assertions,omitempty"`
	XXX_unrecognized    []byte          `json:"-"`
}

func (m *S2CMessage) Reset()         { *m = S2CMessage{} }
func (m *S2CMessage) String() string { return proto.CompactTextString(m) }
func (*S2CMessage) ProtoMessage()    {}

func (m *S2CMessage) GetRoot() []byte {
	if m != nil {
		return m.Root
	}
	return nil
}

func (m *S2CMessage) GetLookupResponse() *LookupResponse {
	if m != nil {
		return m.LookupResponse
	}
	return nil
}

func (m *S2CMessage) GetFreshnessAssertions() [][]byte {
	if m != nil {
		return m.FreshnessAssertions
	}
	return nil
}

type LookupResponse struct {
	Path             []byte `protobuf:"bytes,2,opt,name=path" json:"path,omitempty"`
	PublicKey        []byte `protobuf:"bytes,3,opt,name=public_key" json:"public_key,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (m *LookupResponse) Reset()         { *m = LookupResponse{} }
func (m *LookupResponse) String() string { return proto.CompactTextString(m) }
func (*LookupResponse) ProtoMessage()    {}

func (m *LookupResponse) GetPath() []byte {
	if m != nil {
		return m.Path
	}
	return nil
}

func (m *LookupResponse) GetPublicKey() []byte {
	if m != nil {
		return m.PublicKey
	}
	return nil
}

type FreshnessAssertion struct {
	Time             *int64 `protobuf:"varint,1,req,name=time" json:"time,omitempty"`
	Root             []byte `protobuf:"bytes,2,req,name=root" json:"root,omitempty"`
	Finalized        *bool  `protobuf:"varint,3,opt,name=finalized" json:"finalized,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (m *FreshnessAssertion) Reset()         { *m = FreshnessAssertion{} }
func (m *FreshnessAssertion) String() string { return proto.CompactTextString(m) }
func (*FreshnessAssertion) ProtoMessage()    {}

func (m *FreshnessAssertion) GetTime() int64 {
	if m != nil && m.Time != nil {
		return *m.Time
	}
	return 0
}

func (m *FreshnessAssertion) GetRoot() []byte {
	if m != nil {
		return m.Root
	}
	return nil
}

func (m *FreshnessAssertion) GetFinalized() bool {
	if m != nil && m.Finalized != nil {
		return *m.Finalized
	}
	return false
}

func init() {
}
