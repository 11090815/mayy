// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v4.24.4
// source: configuration.proto

package ppeer

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// AnchorPeers 用于存储多个锚节点的信息。
type AnchorPeers struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AnchorPeers []*AnchorPeer `protobuf:"bytes,1,rep,name=anchor_peers,json=anchorPeers,proto3" json:"anchor_peers,omitempty"`
}

func (x *AnchorPeers) Reset() {
	*x = AnchorPeers{}
	if protoimpl.UnsafeEnabled {
		mi := &file_configuration_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AnchorPeers) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AnchorPeers) ProtoMessage() {}

func (x *AnchorPeers) ProtoReflect() protoreflect.Message {
	mi := &file_configuration_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AnchorPeers.ProtoReflect.Descriptor instead.
func (*AnchorPeers) Descriptor() ([]byte, []int) {
	return file_configuration_proto_rawDescGZIP(), []int{0}
}

func (x *AnchorPeers) GetAnchorPeers() []*AnchorPeer {
	if x != nil {
		return x.AnchorPeers
	}
	return nil
}

// AnchorPeer 结构体表示一个锚节点的详细信息，包括 host（锚节点的 DNS 主机名）和 port（端口号）。
type AnchorPeer struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Host 锚节点的 DNS 主机名。
	Host string `protobuf:"bytes,1,opt,name=host,proto3" json:"host,omitempty"`
	// Port 锚节点的端口号。
	Port int32 `protobuf:"varint,2,opt,name=port,proto3" json:"port,omitempty"`
}

func (x *AnchorPeer) Reset() {
	*x = AnchorPeer{}
	if protoimpl.UnsafeEnabled {
		mi := &file_configuration_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AnchorPeer) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AnchorPeer) ProtoMessage() {}

func (x *AnchorPeer) ProtoReflect() protoreflect.Message {
	mi := &file_configuration_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AnchorPeer.ProtoReflect.Descriptor instead.
func (*AnchorPeer) Descriptor() ([]byte, []int) {
	return file_configuration_proto_rawDescGZIP(), []int{1}
}

func (x *AnchorPeer) GetHost() string {
	if x != nil {
		return x.Host
	}
	return ""
}

func (x *AnchorPeer) GetPort() int32 {
	if x != nil {
		return x.Port
	}
	return 0
}

// APIResource 表示一个 API 资源，其中包含一个 PolicyRef 字段，用于指定该 API 资源
// 的访问控制策略的名称。
type APIResource struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PolicyRef string `protobuf:"bytes,1,opt,name=policy_ref,json=policyRef,proto3" json:"policy_ref,omitempty"`
}

func (x *APIResource) Reset() {
	*x = APIResource{}
	if protoimpl.UnsafeEnabled {
		mi := &file_configuration_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *APIResource) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*APIResource) ProtoMessage() {}

func (x *APIResource) ProtoReflect() protoreflect.Message {
	mi := &file_configuration_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use APIResource.ProtoReflect.Descriptor instead.
func (*APIResource) Descriptor() ([]byte, []int) {
	return file_configuration_proto_rawDescGZIP(), []int{2}
}

func (x *APIResource) GetPolicyRef() string {
	if x != nil {
		return x.PolicyRef
	}
	return ""
}

// ACLs 结构体表示通道中资源的 ACL 映射，它包含一个 Acls 字段，是一个字符串到 APIResource
// 的映射。这个映射可以用于指定每个资源对应的访问控制策略。
type ACLs struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Acls map[string]*APIResource `protobuf:"bytes,1,rep,name=acls,proto3" json:"acls,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *ACLs) Reset() {
	*x = ACLs{}
	if protoimpl.UnsafeEnabled {
		mi := &file_configuration_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ACLs) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ACLs) ProtoMessage() {}

func (x *ACLs) ProtoReflect() protoreflect.Message {
	mi := &file_configuration_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ACLs.ProtoReflect.Descriptor instead.
func (*ACLs) Descriptor() ([]byte, []int) {
	return file_configuration_proto_rawDescGZIP(), []int{3}
}

func (x *ACLs) GetAcls() map[string]*APIResource {
	if x != nil {
		return x.Acls
	}
	return nil
}

var File_configuration_proto protoreflect.FileDescriptor

var file_configuration_proto_rawDesc = []byte{
	0x0a, 0x13, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x05, 0x70, 0x70, 0x65, 0x65, 0x72, 0x22, 0x43, 0x0a, 0x0b,
	0x41, 0x6e, 0x63, 0x68, 0x6f, 0x72, 0x50, 0x65, 0x65, 0x72, 0x73, 0x12, 0x34, 0x0a, 0x0c, 0x61,
	0x6e, 0x63, 0x68, 0x6f, 0x72, 0x5f, 0x70, 0x65, 0x65, 0x72, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x11, 0x2e, 0x70, 0x70, 0x65, 0x65, 0x72, 0x2e, 0x41, 0x6e, 0x63, 0x68, 0x6f, 0x72,
	0x50, 0x65, 0x65, 0x72, 0x52, 0x0b, 0x61, 0x6e, 0x63, 0x68, 0x6f, 0x72, 0x50, 0x65, 0x65, 0x72,
	0x73, 0x22, 0x34, 0x0a, 0x0a, 0x41, 0x6e, 0x63, 0x68, 0x6f, 0x72, 0x50, 0x65, 0x65, 0x72, 0x12,
	0x12, 0x0a, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x68,
	0x6f, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x05, 0x52, 0x04, 0x70, 0x6f, 0x72, 0x74, 0x22, 0x2c, 0x0a, 0x0b, 0x41, 0x50, 0x49, 0x52, 0x65,
	0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79,
	0x5f, 0x72, 0x65, 0x66, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x70, 0x6f, 0x6c, 0x69,
	0x63, 0x79, 0x52, 0x65, 0x66, 0x22, 0x7e, 0x0a, 0x04, 0x41, 0x43, 0x4c, 0x73, 0x12, 0x29, 0x0a,
	0x04, 0x61, 0x63, 0x6c, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x70, 0x70,
	0x65, 0x65, 0x72, 0x2e, 0x41, 0x43, 0x4c, 0x73, 0x2e, 0x41, 0x63, 0x6c, 0x73, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x52, 0x04, 0x61, 0x63, 0x6c, 0x73, 0x1a, 0x4b, 0x0a, 0x09, 0x41, 0x63, 0x6c, 0x73,
	0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x28, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x70, 0x70, 0x65, 0x65, 0x72, 0x2e, 0x41,
	0x50, 0x49, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x3a, 0x02, 0x38, 0x01, 0x42, 0x29, 0x5a, 0x27, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e,
	0x63, 0x6f, 0x6d, 0x2f, 0x31, 0x31, 0x30, 0x39, 0x30, 0x38, 0x31, 0x35, 0x2f, 0x6d, 0x61, 0x79,
	0x79, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x70, 0x70, 0x65, 0x65, 0x72,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_configuration_proto_rawDescOnce sync.Once
	file_configuration_proto_rawDescData = file_configuration_proto_rawDesc
)

func file_configuration_proto_rawDescGZIP() []byte {
	file_configuration_proto_rawDescOnce.Do(func() {
		file_configuration_proto_rawDescData = protoimpl.X.CompressGZIP(file_configuration_proto_rawDescData)
	})
	return file_configuration_proto_rawDescData
}

var file_configuration_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_configuration_proto_goTypes = []interface{}{
	(*AnchorPeers)(nil), // 0: ppeer.AnchorPeers
	(*AnchorPeer)(nil),  // 1: ppeer.AnchorPeer
	(*APIResource)(nil), // 2: ppeer.APIResource
	(*ACLs)(nil),        // 3: ppeer.ACLs
	nil,                 // 4: ppeer.ACLs.AclsEntry
}
var file_configuration_proto_depIdxs = []int32{
	1, // 0: ppeer.AnchorPeers.anchor_peers:type_name -> ppeer.AnchorPeer
	4, // 1: ppeer.ACLs.acls:type_name -> ppeer.ACLs.AclsEntry
	2, // 2: ppeer.ACLs.AclsEntry.value:type_name -> ppeer.APIResource
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_configuration_proto_init() }
func file_configuration_proto_init() {
	if File_configuration_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_configuration_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AnchorPeers); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_configuration_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AnchorPeer); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_configuration_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*APIResource); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_configuration_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ACLs); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_configuration_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_configuration_proto_goTypes,
		DependencyIndexes: file_configuration_proto_depIdxs,
		MessageInfos:      file_configuration_proto_msgTypes,
	}.Build()
	File_configuration_proto = out.File
	file_configuration_proto_rawDesc = nil
	file_configuration_proto_goTypes = nil
	file_configuration_proto_depIdxs = nil
}