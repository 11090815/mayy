// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v4.24.4
// source: configtx.proto

package pcommon

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

// ConfigEnvelope 消息包含了一条链的所有配置，不依赖于先前的配置事务。
type ConfigEnvelope struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Config 序列化后的 Config 结构，表示配置信息。
	Config *Config `protobuf:"bytes,1,opt,name=config,proto3" json:"config,omitempty"`
	// LastUpdate 最后一个生成当前配置的 CONFIG_UPDATE 消息，它的 Payload.Data 是一个序列化的
	// ConfigUpdate。
	LastUpdate *Envelope `protobuf:"bytes,2,opt,name=last_update,json=lastUpdate,proto3" json:"last_update,omitempty"`
}

func (x *ConfigEnvelope) Reset() {
	*x = ConfigEnvelope{}
	if protoimpl.UnsafeEnabled {
		mi := &file_configtx_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConfigEnvelope) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConfigEnvelope) ProtoMessage() {}

func (x *ConfigEnvelope) ProtoReflect() protoreflect.Message {
	mi := &file_configtx_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConfigEnvelope.ProtoReflect.Descriptor instead.
func (*ConfigEnvelope) Descriptor() ([]byte, []int) {
	return file_configtx_proto_rawDescGZIP(), []int{0}
}

func (x *ConfigEnvelope) GetConfig() *Config {
	if x != nil {
		return x.Config
	}
	return nil
}

func (x *ConfigEnvelope) GetLastUpdate() *Envelope {
	if x != nil {
		return x.LastUpdate
	}
	return nil
}

// Config 消息表示特定通道的配置。
type Config struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Sequence 配置的序列号。
	Sequence uint64 `protobuf:"varint,1,opt,name=sequence,proto3" json:"sequence,omitempty"`
	// ChannelGroup 通道的配置组，当允许 API 破坏时，应将其更改为 root。
	ChannelGroup *ConfigGroup `protobuf:"bytes,2,opt,name=channel_group,json=channelGroup,proto3" json:"channel_group,omitempty"`
}

func (x *Config) Reset() {
	*x = Config{}
	if protoimpl.UnsafeEnabled {
		mi := &file_configtx_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Config) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Config) ProtoMessage() {}

func (x *Config) ProtoReflect() protoreflect.Message {
	mi := &file_configtx_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Config.ProtoReflect.Descriptor instead.
func (*Config) Descriptor() ([]byte, []int) {
	return file_configtx_proto_rawDescGZIP(), []int{1}
}

func (x *Config) GetSequence() uint64 {
	if x != nil {
		return x.Sequence
	}
	return 0
}

func (x *Config) GetChannelGroup() *ConfigGroup {
	if x != nil {
		return x.ChannelGroup
	}
	return nil
}

type ConfigUpdateEnvelope struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// ConfigUpdate 用于存储序列化的 ConfigUpdate 结构。
	ConfigUpdate []byte `protobuf:"bytes,1,opt,name=config_update,json=configUpdate,proto3" json:"config_update,omitempty"`
	// Signatures 用于存储对 ConfigUpdate 的多个签名。
	Signatures []*ConfigSignature `protobuf:"bytes,2,rep,name=signatures,proto3" json:"signatures,omitempty"`
}

func (x *ConfigUpdateEnvelope) Reset() {
	*x = ConfigUpdateEnvelope{}
	if protoimpl.UnsafeEnabled {
		mi := &file_configtx_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConfigUpdateEnvelope) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConfigUpdateEnvelope) ProtoMessage() {}

func (x *ConfigUpdateEnvelope) ProtoReflect() protoreflect.Message {
	mi := &file_configtx_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConfigUpdateEnvelope.ProtoReflect.Descriptor instead.
func (*ConfigUpdateEnvelope) Descriptor() ([]byte, []int) {
	return file_configtx_proto_rawDescGZIP(), []int{2}
}

func (x *ConfigUpdateEnvelope) GetConfigUpdate() []byte {
	if x != nil {
		return x.ConfigUpdate
	}
	return nil
}

func (x *ConfigUpdateEnvelope) GetSignatures() []*ConfigSignature {
	if x != nil {
		return x.Signatures
	}
	return nil
}

// ConfigUpdate 结构用于提交配置的子集，并要求排序节点应用此配置，它始终在 ConfigUpdateEnvelope 中
// 提交，允许添加签名，从而生成新的配置。配置更新按照以下方式应用：
//  1. 从 ReadSet 中的所有元素的版本与现有配置中的版本进行验证，如果读取版本不匹配，则配置更新失败。
//  2. 忽略 WriteSet 中与 ReadSet 具有相同版本的任何元素。
//  3. 收集 WriteSet 中每个剩余元素的相应 ModPolicy。
//  4. 检查每个策略与 ConfigUpdateEnvelope 中的签名，任何无法验证的策略都会被拒绝。
//  5. WriteSet 应用到 Config 中，并通过 ConfigGroupSchema 验证更新是否合法。
type ConfigUpdate struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// ChannelId 表示此配置更新应适用于哪个通道。
	ChannelId string `protobuf:"bytes,1,opt,name=channel_id,json=channelId,proto3" json:"channel_id,omitempty"`
	// ReadSet 明确列出了已读取的配置部分，其中应该只设置了 Version。
	ReadSet *ConfigGroup `protobuf:"bytes,2,opt,name=read_set,json=readSet,proto3" json:"read_set,omitempty"`
	// WriteSet 列出了已写入的配置部分，其中应包括已更新的 Version。
	WriteSet *ConfigGroup `protobuf:"bytes,3,opt,name=write_set,json=writeSet,proto3" json:"write_set,omitempty"`
	// IsolatedData 是一个映射，用于存储不会反映在结果配置中但仍需要用于其他目的的数据，例如 RsccSeedData。
	IsolatedData map[string][]byte `protobuf:"bytes,5,rep,name=isolated_data,json=isolatedData,proto3" json:"isolated_data,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *ConfigUpdate) Reset() {
	*x = ConfigUpdate{}
	if protoimpl.UnsafeEnabled {
		mi := &file_configtx_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConfigUpdate) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConfigUpdate) ProtoMessage() {}

func (x *ConfigUpdate) ProtoReflect() protoreflect.Message {
	mi := &file_configtx_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConfigUpdate.ProtoReflect.Descriptor instead.
func (*ConfigUpdate) Descriptor() ([]byte, []int) {
	return file_configtx_proto_rawDescGZIP(), []int{3}
}

func (x *ConfigUpdate) GetChannelId() string {
	if x != nil {
		return x.ChannelId
	}
	return ""
}

func (x *ConfigUpdate) GetReadSet() *ConfigGroup {
	if x != nil {
		return x.ReadSet
	}
	return nil
}

func (x *ConfigUpdate) GetWriteSet() *ConfigGroup {
	if x != nil {
		return x.WriteSet
	}
	return nil
}

func (x *ConfigUpdate) GetIsolatedData() map[string][]byte {
	if x != nil {
		return x.IsolatedData
	}
	return nil
}

// ConfigGroup 是一个层次化的数据结构，用于存储配置信息。
type ConfigGroup struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Version 表示配置组的版本。
	Version uint64 `protobuf:"varint,1,opt,name=version,proto3" json:"version,omitempty"`
	// Groups 是一个映射，存储了子配置组，键是子配置组的名称，值是对应的 ConfigGroup 对象。
	Groups map[string]*ConfigGroup `protobuf:"bytes,2,rep,name=groups,proto3" json:"groups,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	// Values 是一个映射，用于存储配置值，键是配置值的名称，值是对应的 ConfigValue。
	Values map[string]*ConfigValue `protobuf:"bytes,3,rep,name=values,proto3" json:"values,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	// Policies 是一个映射，用于存储配置策略，键是策略的名称，值是对应的 ConfigPolicy 对象。
	Policies map[string]*ConfigPolicy `protobuf:"bytes,4,rep,name=policies,proto3" json:"policies,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	// ModPolicy 是一个字符串，表示配置组的修改策略。
	ModPolicy string `protobuf:"bytes,5,opt,name=mod_policy,json=modPolicy,proto3" json:"mod_policy,omitempty"`
}

func (x *ConfigGroup) Reset() {
	*x = ConfigGroup{}
	if protoimpl.UnsafeEnabled {
		mi := &file_configtx_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConfigGroup) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConfigGroup) ProtoMessage() {}

func (x *ConfigGroup) ProtoReflect() protoreflect.Message {
	mi := &file_configtx_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConfigGroup.ProtoReflect.Descriptor instead.
func (*ConfigGroup) Descriptor() ([]byte, []int) {
	return file_configtx_proto_rawDescGZIP(), []int{4}
}

func (x *ConfigGroup) GetVersion() uint64 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *ConfigGroup) GetGroups() map[string]*ConfigGroup {
	if x != nil {
		return x.Groups
	}
	return nil
}

func (x *ConfigGroup) GetValues() map[string]*ConfigValue {
	if x != nil {
		return x.Values
	}
	return nil
}

func (x *ConfigGroup) GetPolicies() map[string]*ConfigPolicy {
	if x != nil {
		return x.Policies
	}
	return nil
}

func (x *ConfigGroup) GetModPolicy() string {
	if x != nil {
		return x.ModPolicy
	}
	return ""
}

// ConfigValue 表示单个配置数据。
type ConfigValue struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Version 表示配置值的版本。
	Version uint64 `protobuf:"varint,1,opt,name=version,proto3" json:"version,omitempty"`
	// Value 字段是一个字节数组，存储配置数据的值。
	Value []byte `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
	// ModPolicy 字段是一个字符串，表示配置值的修改策略。
	ModPolicy string `protobuf:"bytes,3,opt,name=mod_policy,json=modPolicy,proto3" json:"mod_policy,omitempty"`
}

func (x *ConfigValue) Reset() {
	*x = ConfigValue{}
	if protoimpl.UnsafeEnabled {
		mi := &file_configtx_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConfigValue) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConfigValue) ProtoMessage() {}

func (x *ConfigValue) ProtoReflect() protoreflect.Message {
	mi := &file_configtx_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConfigValue.ProtoReflect.Descriptor instead.
func (*ConfigValue) Descriptor() ([]byte, []int) {
	return file_configtx_proto_rawDescGZIP(), []int{5}
}

func (x *ConfigValue) GetVersion() uint64 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *ConfigValue) GetValue() []byte {
	if x != nil {
		return x.Value
	}
	return nil
}

func (x *ConfigValue) GetModPolicy() string {
	if x != nil {
		return x.ModPolicy
	}
	return ""
}

// ConfigPolicy 表示配置策略。
type ConfigPolicy struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Version 表示配置策略的版本。
	Version uint64 `protobuf:"varint,1,opt,name=version,proto3" json:"version,omitempty"`
	// Policy 是一个 Policy 类型的消息，表示配置策略的详细信息。
	Policy *Policy `protobuf:"bytes,2,opt,name=policy,proto3" json:"policy,omitempty"`
	// ModPolicy 字段是一个字符串，表示配置策略的修改策略。
	ModPolicy string `protobuf:"bytes,3,opt,name=mod_policy,json=modPolicy,proto3" json:"mod_policy,omitempty"`
}

func (x *ConfigPolicy) Reset() {
	*x = ConfigPolicy{}
	if protoimpl.UnsafeEnabled {
		mi := &file_configtx_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConfigPolicy) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConfigPolicy) ProtoMessage() {}

func (x *ConfigPolicy) ProtoReflect() protoreflect.Message {
	mi := &file_configtx_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConfigPolicy.ProtoReflect.Descriptor instead.
func (*ConfigPolicy) Descriptor() ([]byte, []int) {
	return file_configtx_proto_rawDescGZIP(), []int{6}
}

func (x *ConfigPolicy) GetVersion() uint64 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *ConfigPolicy) GetPolicy() *Policy {
	if x != nil {
		return x.Policy
	}
	return nil
}

func (x *ConfigPolicy) GetModPolicy() string {
	if x != nil {
		return x.ModPolicy
	}
	return ""
}

// ConfigSignature 表示配置的签名信息。
type ConfigSignature struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// SignatureHeader 是一个字节数组，存储对 SignatureHeader 结构的序列化字节数组。
	SignatureHeader []byte `protobuf:"bytes,1,opt,name=signature_header,json=signatureHeader,proto3" json:"signature_header,omitempty"`
	// Signature 字段是一个字节数组，存储对 SignatureHeader 字节和配置字节的签名。
	Signature []byte `protobuf:"bytes,2,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *ConfigSignature) Reset() {
	*x = ConfigSignature{}
	if protoimpl.UnsafeEnabled {
		mi := &file_configtx_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConfigSignature) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConfigSignature) ProtoMessage() {}

func (x *ConfigSignature) ProtoReflect() protoreflect.Message {
	mi := &file_configtx_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConfigSignature.ProtoReflect.Descriptor instead.
func (*ConfigSignature) Descriptor() ([]byte, []int) {
	return file_configtx_proto_rawDescGZIP(), []int{7}
}

func (x *ConfigSignature) GetSignatureHeader() []byte {
	if x != nil {
		return x.SignatureHeader
	}
	return nil
}

func (x *ConfigSignature) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

var File_configtx_proto protoreflect.FileDescriptor

var file_configtx_proto_rawDesc = []byte{
	0x0a, 0x0e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x74, 0x78, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x07, 0x70, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x1a, 0x0c, 0x63, 0x6f, 0x6d, 0x6d, 0x6f,
	0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0e, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x69, 0x65,
	0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x6d, 0x0a, 0x0e, 0x43, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x45, 0x6e, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65, 0x12, 0x27, 0x0a, 0x06, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x70, 0x63, 0x6f, 0x6d,
	0x6d, 0x6f, 0x6e, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52, 0x06, 0x63, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x12, 0x32, 0x0a, 0x0b, 0x6c, 0x61, 0x73, 0x74, 0x5f, 0x75, 0x70, 0x64, 0x61, 0x74,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x11, 0x2e, 0x70, 0x63, 0x6f, 0x6d, 0x6d, 0x6f,
	0x6e, 0x2e, 0x45, 0x6e, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65, 0x52, 0x0a, 0x6c, 0x61, 0x73, 0x74,
	0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x22, 0x5f, 0x0a, 0x06, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x12, 0x1a, 0x0a, 0x08, 0x73, 0x65, 0x71, 0x75, 0x65, 0x6e, 0x63, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x04, 0x52, 0x08, 0x73, 0x65, 0x71, 0x75, 0x65, 0x6e, 0x63, 0x65, 0x12, 0x39, 0x0a, 0x0d,
	0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x5f, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x70, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x43, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x52, 0x0c, 0x63, 0x68, 0x61, 0x6e, 0x6e,
	0x65, 0x6c, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x22, 0x75, 0x0a, 0x14, 0x43, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x45, 0x6e, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65, 0x12,
	0x23, 0x0a, 0x0d, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x5f, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0c, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x55, 0x70,
	0x64, 0x61, 0x74, 0x65, 0x12, 0x38, 0x0a, 0x0a, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72,
	0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x70, 0x63, 0x6f, 0x6d, 0x6d,
	0x6f, 0x6e, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75,
	0x72, 0x65, 0x52, 0x0a, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x22, 0xa0,
	0x02, 0x0a, 0x0c, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x12,
	0x1d, 0x0a, 0x0a, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x09, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x49, 0x64, 0x12, 0x2f,
	0x0a, 0x08, 0x72, 0x65, 0x61, 0x64, 0x5f, 0x73, 0x65, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x14, 0x2e, 0x70, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x52, 0x07, 0x72, 0x65, 0x61, 0x64, 0x53, 0x65, 0x74, 0x12,
	0x31, 0x0a, 0x09, 0x77, 0x72, 0x69, 0x74, 0x65, 0x5f, 0x73, 0x65, 0x74, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x14, 0x2e, 0x70, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x43, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x52, 0x08, 0x77, 0x72, 0x69, 0x74, 0x65, 0x53,
	0x65, 0x74, 0x12, 0x4c, 0x0a, 0x0d, 0x69, 0x73, 0x6f, 0x6c, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x64,
	0x61, 0x74, 0x61, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x27, 0x2e, 0x70, 0x63, 0x6f, 0x6d,
	0x6d, 0x6f, 0x6e, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65,
	0x2e, 0x49, 0x73, 0x6f, 0x6c, 0x61, 0x74, 0x65, 0x64, 0x44, 0x61, 0x74, 0x61, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x52, 0x0c, 0x69, 0x73, 0x6f, 0x6c, 0x61, 0x74, 0x65, 0x64, 0x44, 0x61, 0x74, 0x61,
	0x1a, 0x3f, 0x0a, 0x11, 0x49, 0x73, 0x6f, 0x6c, 0x61, 0x74, 0x65, 0x64, 0x44, 0x61, 0x74, 0x61,
	0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38,
	0x01, 0x22, 0xf0, 0x03, 0x0a, 0x0b, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x47, 0x72, 0x6f, 0x75,
	0x70, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x04, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x38, 0x0a, 0x06, 0x67,
	0x72, 0x6f, 0x75, 0x70, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x70, 0x63,
	0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x47, 0x72, 0x6f, 0x75,
	0x70, 0x2e, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x06, 0x67,
	0x72, 0x6f, 0x75, 0x70, 0x73, 0x12, 0x38, 0x0a, 0x06, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x18,
	0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x70, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e,
	0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x2e, 0x56, 0x61, 0x6c, 0x75,
	0x65, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x06, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x12,
	0x3e, 0x0a, 0x08, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x69, 0x65, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x22, 0x2e, 0x70, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x43, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x2e, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x69, 0x65, 0x73,
	0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x08, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x69, 0x65, 0x73, 0x12,
	0x1d, 0x0a, 0x0a, 0x6d, 0x6f, 0x64, 0x5f, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x18, 0x05, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x09, 0x6d, 0x6f, 0x64, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x1a, 0x4f,
	0x0a, 0x0b, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a,
	0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12,
	0x2a, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14,
	0x2e, 0x70, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x47,
	0x72, 0x6f, 0x75, 0x70, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x1a,
	0x4f, 0x0a, 0x0b, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10,
	0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79,
	0x12, 0x2a, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x14, 0x2e, 0x70, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01,
	0x1a, 0x52, 0x0a, 0x0d, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x69, 0x65, 0x73, 0x45, 0x6e, 0x74, 0x72,
	0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03,
	0x6b, 0x65, 0x79, 0x12, 0x2b, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x15, 0x2e, 0x70, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x43, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x3a, 0x02, 0x38, 0x01, 0x22, 0x5c, 0x0a, 0x0b, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x56, 0x61,
	0x6c, 0x75, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x04, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x14, 0x0a,
	0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x76, 0x61,
	0x6c, 0x75, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x6d, 0x6f, 0x64, 0x5f, 0x70, 0x6f, 0x6c, 0x69, 0x63,
	0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x6d, 0x6f, 0x64, 0x50, 0x6f, 0x6c, 0x69,
	0x63, 0x79, 0x22, 0x70, 0x0a, 0x0c, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x50, 0x6f, 0x6c, 0x69,
	0x63, 0x79, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x04, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x27, 0x0a, 0x06,
	0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x70,
	0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x06, 0x70,
	0x6f, 0x6c, 0x69, 0x63, 0x79, 0x12, 0x1d, 0x0a, 0x0a, 0x6d, 0x6f, 0x64, 0x5f, 0x70, 0x6f, 0x6c,
	0x69, 0x63, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x6d, 0x6f, 0x64, 0x50, 0x6f,
	0x6c, 0x69, 0x63, 0x79, 0x22, 0x5a, 0x0a, 0x0f, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x53, 0x69,
	0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x12, 0x29, 0x0a, 0x10, 0x73, 0x69, 0x67, 0x6e, 0x61,
	0x74, 0x75, 0x72, 0x65, 0x5f, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x0f, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x48, 0x65, 0x61, 0x64,
	0x65, 0x72, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65,
	0x42, 0x2b, 0x5a, 0x29, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x31,
	0x31, 0x30, 0x39, 0x30, 0x38, 0x31, 0x35, 0x2f, 0x6d, 0x61, 0x79, 0x79, 0x2f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x70, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_configtx_proto_rawDescOnce sync.Once
	file_configtx_proto_rawDescData = file_configtx_proto_rawDesc
)

func file_configtx_proto_rawDescGZIP() []byte {
	file_configtx_proto_rawDescOnce.Do(func() {
		file_configtx_proto_rawDescData = protoimpl.X.CompressGZIP(file_configtx_proto_rawDescData)
	})
	return file_configtx_proto_rawDescData
}

var file_configtx_proto_msgTypes = make([]protoimpl.MessageInfo, 12)
var file_configtx_proto_goTypes = []interface{}{
	(*ConfigEnvelope)(nil),       // 0: pcommon.ConfigEnvelope
	(*Config)(nil),               // 1: pcommon.Config
	(*ConfigUpdateEnvelope)(nil), // 2: pcommon.ConfigUpdateEnvelope
	(*ConfigUpdate)(nil),         // 3: pcommon.ConfigUpdate
	(*ConfigGroup)(nil),          // 4: pcommon.ConfigGroup
	(*ConfigValue)(nil),          // 5: pcommon.ConfigValue
	(*ConfigPolicy)(nil),         // 6: pcommon.ConfigPolicy
	(*ConfigSignature)(nil),      // 7: pcommon.ConfigSignature
	nil,                          // 8: pcommon.ConfigUpdate.IsolatedDataEntry
	nil,                          // 9: pcommon.ConfigGroup.GroupsEntry
	nil,                          // 10: pcommon.ConfigGroup.ValuesEntry
	nil,                          // 11: pcommon.ConfigGroup.PoliciesEntry
	(*Envelope)(nil),             // 12: pcommon.Envelope
	(*Policy)(nil),               // 13: pcommon.Policy
}
var file_configtx_proto_depIdxs = []int32{
	1,  // 0: pcommon.ConfigEnvelope.config:type_name -> pcommon.Config
	12, // 1: pcommon.ConfigEnvelope.last_update:type_name -> pcommon.Envelope
	4,  // 2: pcommon.Config.channel_group:type_name -> pcommon.ConfigGroup
	7,  // 3: pcommon.ConfigUpdateEnvelope.signatures:type_name -> pcommon.ConfigSignature
	4,  // 4: pcommon.ConfigUpdate.read_set:type_name -> pcommon.ConfigGroup
	4,  // 5: pcommon.ConfigUpdate.write_set:type_name -> pcommon.ConfigGroup
	8,  // 6: pcommon.ConfigUpdate.isolated_data:type_name -> pcommon.ConfigUpdate.IsolatedDataEntry
	9,  // 7: pcommon.ConfigGroup.groups:type_name -> pcommon.ConfigGroup.GroupsEntry
	10, // 8: pcommon.ConfigGroup.values:type_name -> pcommon.ConfigGroup.ValuesEntry
	11, // 9: pcommon.ConfigGroup.policies:type_name -> pcommon.ConfigGroup.PoliciesEntry
	13, // 10: pcommon.ConfigPolicy.policy:type_name -> pcommon.Policy
	4,  // 11: pcommon.ConfigGroup.GroupsEntry.value:type_name -> pcommon.ConfigGroup
	5,  // 12: pcommon.ConfigGroup.ValuesEntry.value:type_name -> pcommon.ConfigValue
	6,  // 13: pcommon.ConfigGroup.PoliciesEntry.value:type_name -> pcommon.ConfigPolicy
	14, // [14:14] is the sub-list for method output_type
	14, // [14:14] is the sub-list for method input_type
	14, // [14:14] is the sub-list for extension type_name
	14, // [14:14] is the sub-list for extension extendee
	0,  // [0:14] is the sub-list for field type_name
}

func init() { file_configtx_proto_init() }
func file_configtx_proto_init() {
	if File_configtx_proto != nil {
		return
	}
	file_common_proto_init()
	file_policies_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_configtx_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConfigEnvelope); i {
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
		file_configtx_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Config); i {
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
		file_configtx_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConfigUpdateEnvelope); i {
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
		file_configtx_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConfigUpdate); i {
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
		file_configtx_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConfigGroup); i {
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
		file_configtx_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConfigValue); i {
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
		file_configtx_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConfigPolicy); i {
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
		file_configtx_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConfigSignature); i {
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
			RawDescriptor: file_configtx_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   12,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_configtx_proto_goTypes,
		DependencyIndexes: file_configtx_proto_depIdxs,
		MessageInfos:      file_configtx_proto_msgTypes,
	}.Build()
	File_configtx_proto = out.File
	file_configtx_proto_rawDesc = nil
	file_configtx_proto_goTypes = nil
	file_configtx_proto_depIdxs = nil
}
