package protoutil

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/11090815/mayy/errors"
	"github.com/11090815/mayy/protobuf/pcommon"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CreateNonce 产生一个 24 字节长度伪随机字节数组，当产生的数组长度不为 24 时，或者产生其他错误时，该方法会返回一个错误。
func CreateNonce() ([]byte, error) {
	nonce := make([]byte, 24)
	n, err := rand.Read(nonce)
	if err != nil {
		return nil, errors.NewErrorf("failed getting random nonce, the error is \"%s\"", err.Error())
	}
	if n != 24 {
		return nil, errors.NewErrorf("failed getting random nonce with 24 bytes, actually getted %d bytes", n)
	}
	return nonce, nil
}

// CreateNonceOrPanic 产生一个 24 字节长度伪随机字节数组，当产生的数组长度不为 24 时，或者产生其他错误时，
// 该方法会 panic。
func CreateNonceOrPanic() []byte {
	nonce, err := CreateNonce()
	if err != nil {
		panic(err)
	}
	return nonce
}

// Marshal 此方法直接调用 google.golang.org/protobuf/proto 包的 Marshal 方法，对 proto.Message 类型的消息结构体
// 进行序列化，得到一串字节数组，如果序列化失败，则会返回错误。
func Marshal(message proto.Message) ([]byte, error) {
	return proto.Marshal(message)
}

// MarshalOrPanic 此方法直接调用 google.golang.org/protobuf/proto 包的 Marshal 方法，对 proto.Message 类型的消
// 息结构体进行序列化，得到一串字节数组，如果序列化失败，则会 panic。
func MarshalOrPanic(message proto.Message) []byte {
	if marshaled, err := proto.Marshal(message); err != nil {
		panic(err)
	} else {
		return marshaled
	}
}

// Unmarshal 此方法直接调用 google.golang.org/protobuf/proto 包的 Unmarshal 方法，对给定的经过序列化后的字节数组
// 进行反序列化，得到一个结构体消息，如果反序列化失败，则会返回错误。
func Unmarshal(encoded []byte, message proto.Message) error {
	return proto.Unmarshal(encoded, message)
}

// ExtractEnvelope 给定一个区块和某个交易数据的索引，将交易数据的原始字节数组反编译成 Envelope 结构体并返回。
// 交易数据在区块中的索引号必须是合法的，不然会返回错误。
func ExtractEnvelope(block *pcommon.Block, index int) (*pcommon.Envelope, error) {
	if block.Data == nil {
		return nil, errors.NewError("block data is empty")
	}

	if index < 0 || index >= len(block.Data.Data) {
		return nil, errors.NewErrorf("invalid index, out of bounds, the given index should be >= 0 and < %d", len(block.Data.Data))
	}

	return UnmarshalEnvelope(block.Data.Data[index])
}

// ExtractEnvelopeOrPanic 给定一个区块和某个交易数据的索引，将交易数据的原始字节数组反编译成 Envelope 结构体并返回，
// 如果反序列化失败，则会直接 panic。
func ExtractEnvelopeOrPanic(block *pcommon.Block, index int) *pcommon.Envelope {
	envelope, err := ExtractEnvelope(block, index)
	if err != nil {
		panic(err)
	}
	return envelope
}

// MakeChannelHeader 创建一个通道头。
func MakeChannelHeader(headerType pcommon.HeaderType, version int32, chainID string, epoch uint64) *pcommon.ChannelHeader {
	return &pcommon.ChannelHeader{
		Type:    int32(headerType),
		Version: version,
		Timestamp: &timestamppb.Timestamp{
			Seconds: time.Now().Unix(),
			Nanos:   0,
		},
		ChannelId: chainID,
		Epoch:     epoch,
	}
}

// MakeSignatureHeader 创建一个签名头。
func MakeSignatureHeader(serializedCreatorCertChain []byte, nonce []byte) *pcommon.SignatureHeader {
	return &pcommon.SignatureHeader{
		Creator: serializedCreatorCertChain,
		Nonce:   nonce,
	}
}

// MakePayloadHeader 创建负载 Payload 的头，负载的头由两部分组成，一个是通道头 ChannelHeader，另一个是签名头 SignatureHeader，
// 通道头与签名头分别是 ChannelHeader 和 SignatureHeader 两个结构体消息序列化后产生的字节数组。
func MakePayloadHeader(channelHeader *pcommon.ChannelHeader, signatureHeader *pcommon.SignatureHeader) *pcommon.Header {
	return &pcommon.Header{
		ChannelHeader:   MarshalOrPanic(channelHeader),
		SignatureHeader: MarshalOrPanic(signatureHeader),
	}
}

// NewSignatureHeader 此方法以一个能够代表“身份”信息的结构体消息序列化后产生的字节数组作为参数，然后
// 随机产生一个随机值 nonce，之后将身份结构体消息序列化后得到的字节数组和 nonce 组装成 SignatureHeader
// 结构体消息。
func NewSignatureHeader(serializedIdentity []byte) (*pcommon.SignatureHeader, error) {
	nonce, err := CreateNonce()
	if err != nil {
		return nil, errors.NewErrorf("failed creating a new signature header, the error is \"%s\"", err.Error())
	}

	return &pcommon.SignatureHeader{
		Creator: serializedIdentity,
		Nonce:   nonce,
	}, nil
}

// NewSignatureHeaderOrPanic 此方法以一个能够代表“身份”信息的结构体消息序列化后产生的字节数组作为参数，然后
// 随机产生一个随机值 nonce，之后将身份结构体消息序列化后得到的字节数组和 nonce 组装成 SignatureHeader 结构
// 体消息。如果在产生随机值的时候出错了，则此方法会 panic。
func NewSignatureHeaderOrPanic(serializedIdentity []byte) *pcommon.SignatureHeader {
	if serializedIdentity == nil {
		panic("creator must be provided")
	}
	nonce, err := CreateNonce()
	if err != nil {
		panic(err)
	}

	return &pcommon.SignatureHeader{
		Creator: serializedIdentity,
		Nonce:   nonce,
	}
}

// NewConfigGroup 创建一个配置组。
func NewConfigGroup() *pcommon.ConfigGroup {
	return &pcommon.ConfigGroup{
		Groups:   make(map[string]*pcommon.ConfigGroup),
		Values:   make(map[string]*pcommon.ConfigValue),
		Policies: make(map[string]*pcommon.ConfigPolicy),
	}
}

// SetTxID 根据给定的签名头中的随机值 nonce 和创造者 creator 计算交易的哈希值，并将其作为
// 通道头中的交易 id。
func SetTxID(channelHeader *pcommon.ChannelHeader, signatureHeader *pcommon.SignatureHeader) {
	channelHeader.TxId = ComputeTxID(signatureHeader.Nonce, signatureHeader.Creator)
}

// ComputeTxID 根据给定的随机 nonce 值以及创造者的身份 creator 计算 txID。
func ComputeTxID(nonce, creator []byte) string {
	hasher := sha256.New()
	hasher.Write(nonce)
	hasher.Write(creator)
	return hex.EncodeToString(hasher.Sum(nil))
}

// IsConfigBlock 判断给定的区块是否是用来存储系统配置信息的区块。判断规则如下：
//  1. 如果区块的数据内容是空的，则不是配置块；
//  2. 如果区块中包含的交易条数不等于 1，则不是配置块；
//  3. 如果区块中唯一的那条交易的负载的头部信息是空的，则不是配置块；
//  4. 判断交易头中通道头的类型是否等于 HeaderType_CONFIG，如果等于，则是配置块，否则不是。
func IsConfigBlock(block *pcommon.Block) bool {
	if block.Data == nil {
		return false
	}

	if len(block.Data.Data) != 1 {
		return false
	}

	envalope, err := UnmarshalEnvelope(block.Data.Data[0])
	if err != nil {
		return false
	}

	payload, err := UnmarshalPayload(envalope.Payload)
	if err != nil {
		return false
	}

	if payload.Header == nil {
		return false
	}

	channelHeader, err := UnmarshalChannelHeader(payload.Header.ChannelHeader)
	if err != nil {
		return false
	}

	return channelHeader.Type == int32(pcommon.HeaderType_CONFIG)
}

// IsConfigTransaction 判断给定的交易是否是用来存储系统配置信息的交易。判断规则如下：
//  1. 如果交易的负载的头部信息是空的，则不是配置块；
//  2. 判断交易头中通道头的类型是否等于 HeaderType_CONFIG 或 HeaderType_ORDERER_TRANSACTION，如果等于，则是配置块，否则不是。
func IsConfigTransaction(envelope *pcommon.Envelope) bool {
	payload, err := UnmarshalPayload(envelope.Payload)
	if err != nil {
		return false
	}

	if payload.Header == nil {
		return false
	}

	channelHeader, err := UnmarshalChannelHeader(payload.Header.ChannelHeader)
	if err != nil {
		return false
	}

	return channelHeader.Type == int32(pcommon.HeaderType_CONFIG) || channelHeader.Type == int32(pcommon.HeaderType_ORDERER_TRANSACTION)
}

// ExtractChannelHeaderFromEnvelope 从 Envelope 的负载 Payload 的头部中提取出 ChannelHeader。
func ExtractChannelHeaderFromEnvelope(envelope *pcommon.Envelope) (*pcommon.ChannelHeader, error) {
	if envelope == nil {
		return nil, errors.NewError("the given envelope is nil")
	}

	payload, err := UnmarshalPayload(envelope.Payload)
	if err != nil {
		return nil, err
	}

	if payload.Header == nil {
		return nil, errors.NewError("failed extracting channel header from envelope, because the header of the envelope's payload is nil")
	}

	if len(payload.Header.ChannelHeader) == 0 {
		return nil, errors.NewError("failed extracting channel header from envelope, because the channel header of the envelope's payload is empty")
	}

	return UnmarshalChannelHeader(payload.Header.ChannelHeader)
}

// ExtractChannelIDFromEnvelope 从 Envelope 的负载 Payload 的头部中提取出链 ID。
func ExtractChannelIDFromEnvelope(envelope *pcommon.Envelope) (string, error) {
	channelHeader, err := ExtractChannelHeaderFromEnvelope(envelope)
	if err != nil {
		return "", err
	}

	return channelHeader.ChannelId, nil
}

// EnvelopeToConfigUpdate 将 Envelope 中的负载 Payload 反序列化得到 ConfigUpdateEnvelope 结构体消息。
func EnvelopeToConfigUpdate(configtx *pcommon.Envelope) (*pcommon.ConfigUpdateEnvelope, error) {
	configUpdateEnv := &pcommon.ConfigUpdateEnvelope{}
	_, err := UnmarshalEnvelopeOfType(configtx, pcommon.HeaderType_CONFIG_UPDATE, configUpdateEnv)
	if err != nil {
		return nil, err
	}
	return configUpdateEnv, nil
}

func SignOrPanic(signer Signer, msg []byte) []byte {
	if signer == nil {
		panic("invalid signer, nil pointer")
	}

	signature, err := signer.Sign(msg)
	if err != nil {
		panic(err)
	}
	return signature
}
