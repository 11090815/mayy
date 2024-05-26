// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v4.24.4
// source: kv_query_result.proto

package queryresult

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// KV 结构体是一个用于表示键值对的数据结构。
type KV struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Namespace 用于标识键值对所属的命名空间，命名空间可以理解为对键值对进行分类或分组的方式，
	// 类似于目录结构中的文件夹，通过命名空间可以方便地对键值对进行管理和查找。
	Namespace string `protobuf:"bytes,1,opt,name=namespace,proto3" json:"namespace,omitempty"`
	// Key 用于唯一标识一个键值对的键，在同一个命名空间中，每个键必须是唯一的。
	Key string `protobuf:"bytes,2,opt,name=key,proto3" json:"key,omitempty"`
	// Value 与键对应的值，值可以是任意数据，是一个字节数组，具体的值解析方式需要根据具体的应用
	// 场景进行定义和处理。
	Value []byte `protobuf:"bytes,3,opt,name=value,proto3" json:"value,omitempty"`
}

func (x *KV) Reset() {
	*x = KV{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kv_query_result_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KV) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KV) ProtoMessage() {}

func (x *KV) ProtoReflect() protoreflect.Message {
	mi := &file_kv_query_result_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KV.ProtoReflect.Descriptor instead.
func (*KV) Descriptor() ([]byte, []int) {
	return file_kv_query_result_proto_rawDescGZIP(), []int{0}
}

func (x *KV) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}

func (x *KV) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *KV) GetValue() []byte {
	if x != nil {
		return x.Value
	}
	return nil
}

// KeyModification 结构体用于表示对键的修改操作。
type KeyModification struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// TxId 用于标识进行该键修改操作的事务的唯一 ID，事务 ID 可以用于追踪和记录事务的执行情况，
	// 以及确保操作的一致性和可靠性。
	TxId string `protobuf:"bytes,1,opt,name=tx_id,json=txId,proto3" json:"tx_id,omitempty"`
	// Value 表示对键进行修改后的新值，值可以是任意数据，是一个字节数组，具体的值解析方式需要根
	// 据具体的应用场景进行定义和处理。
	Value []byte `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
	// Timestamp 用于记录对键进行修改操作的时间，时间戳可以用于排序或追踪键的修改历史，以及进行
	// 与时间相关的查询和分析。
	Timestamp *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	// IsDelete 表示该操作是否是删除操作，当 IsDelete 为 true 时，表示对键进行了删除操作，当
	// IsDelete 为 false 时，表示对键进行了修改操作。
	IsDelete bool `protobuf:"varint,4,opt,name=is_delete,json=isDelete,proto3" json:"is_delete,omitempty"`
}

func (x *KeyModification) Reset() {
	*x = KeyModification{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kv_query_result_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KeyModification) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KeyModification) ProtoMessage() {}

func (x *KeyModification) ProtoReflect() protoreflect.Message {
	mi := &file_kv_query_result_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KeyModification.ProtoReflect.Descriptor instead.
func (*KeyModification) Descriptor() ([]byte, []int) {
	return file_kv_query_result_proto_rawDescGZIP(), []int{1}
}

func (x *KeyModification) GetTxId() string {
	if x != nil {
		return x.TxId
	}
	return ""
}

func (x *KeyModification) GetValue() []byte {
	if x != nil {
		return x.Value
	}
	return nil
}

func (x *KeyModification) GetTimestamp() *timestamppb.Timestamp {
	if x != nil {
		return x.Timestamp
	}
	return nil
}

func (x *KeyModification) GetIsDelete() bool {
	if x != nil {
		return x.IsDelete
	}
	return false
}

var File_kv_query_result_proto protoreflect.FileDescriptor

var file_kv_query_result_proto_rawDesc = []byte{
	0x0a, 0x15, 0x6b, 0x76, 0x5f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x5f, 0x72, 0x65, 0x73, 0x75, 0x6c,
	0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0b, 0x71, 0x75, 0x65, 0x72, 0x79, 0x72, 0x65,
	0x73, 0x75, 0x6c, 0x74, 0x1a, 0x2a, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0x4a, 0x0a, 0x02, 0x4b, 0x56, 0x12, 0x1c, 0x0a, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70,
	0x61, 0x63, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73,
	0x70, 0x61, 0x63, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x22, 0x93, 0x01, 0x0a,
	0x0f, 0x4b, 0x65, 0x79, 0x4d, 0x6f, 0x64, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x12, 0x13, 0x0a, 0x05, 0x74, 0x78, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x74, 0x78, 0x49, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x38, 0x0a, 0x09, 0x74,
	0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x74, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x12, 0x1b, 0x0a, 0x09, 0x69, 0x73, 0x5f, 0x64, 0x65, 0x6c, 0x65,
	0x74, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x08, 0x52, 0x08, 0x69, 0x73, 0x44, 0x65, 0x6c, 0x65,
	0x74, 0x65, 0x42, 0x37, 0x5a, 0x35, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x31, 0x31, 0x30, 0x39, 0x30, 0x38, 0x31, 0x35, 0x2f, 0x6d, 0x61, 0x79, 0x79, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x70, 0x6c, 0x65, 0x64, 0x67, 0x65, 0x72, 0x2f,
	0x71, 0x75, 0x65, 0x72, 0x79, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_kv_query_result_proto_rawDescOnce sync.Once
	file_kv_query_result_proto_rawDescData = file_kv_query_result_proto_rawDesc
)

func file_kv_query_result_proto_rawDescGZIP() []byte {
	file_kv_query_result_proto_rawDescOnce.Do(func() {
		file_kv_query_result_proto_rawDescData = protoimpl.X.CompressGZIP(file_kv_query_result_proto_rawDescData)
	})
	return file_kv_query_result_proto_rawDescData
}

var file_kv_query_result_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_kv_query_result_proto_goTypes = []interface{}{
	(*KV)(nil),                    // 0: queryresult.KV
	(*KeyModification)(nil),       // 1: queryresult.KeyModification
	(*timestamppb.Timestamp)(nil), // 2: google.protobuf.Timestamp
}
var file_kv_query_result_proto_depIdxs = []int32{
	2, // 0: queryresult.KeyModification.timestamp:type_name -> google.protobuf.Timestamp
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_kv_query_result_proto_init() }
func file_kv_query_result_proto_init() {
	if File_kv_query_result_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_kv_query_result_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KV); i {
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
		file_kv_query_result_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KeyModification); i {
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
			RawDescriptor: file_kv_query_result_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_kv_query_result_proto_goTypes,
		DependencyIndexes: file_kv_query_result_proto_depIdxs,
		MessageInfos:      file_kv_query_result_proto_msgTypes,
	}.Build()
	File_kv_query_result_proto = out.File
	file_kv_query_result_proto_rawDesc = nil
	file_kv_query_result_proto_goTypes = nil
	file_kv_query_result_proto_depIdxs = nil
}