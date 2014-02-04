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
	Transfer         []byte `protobuf:"bytes,1,opt,name=transfer" json:"transfer,omitempty"`
	Lookup           []byte `protobuf:"bytes,2,opt,name=lookup" json:"lookup,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (m *C2SMessage) Reset()         { *m = C2SMessage{} }
func (m *C2SMessage) String() string { return proto.CompactTextString(m) }
func (*C2SMessage) ProtoMessage()    {}

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

type LookupResponse struct {
	Root             []byte `protobuf:"bytes,1,req,name=root" json:"root,omitempty"`
	Path             []byte `protobuf:"bytes,2,opt,name=path" json:"path,omitempty"`
	PublicKey        []byte `protobuf:"bytes,3,opt,name=public_key" json:"public_key,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (m *LookupResponse) Reset()         { *m = LookupResponse{} }
func (m *LookupResponse) String() string { return proto.CompactTextString(m) }
func (*LookupResponse) ProtoMessage()    {}

func (m *LookupResponse) GetRoot() []byte {
	if m != nil {
		return m.Root
	}
	return nil
}

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

func init() {
}
