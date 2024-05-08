package protoutil

import (
	"bytes"
	"crypto/sha256"

	"github.com/11090815/mayy/errors"
	"github.com/11090815/mayy/protobuf/pcommon"
	"github.com/11090815/mayy/protobuf/pmsp"
	"google.golang.org/protobuf/proto"
)

// NewBlock 组装一个新区块，除了指定该区块的区块号和上一个区块的哈希值外，其余字段皆为空。
func NewBlock(seqNum uint64, previousHash []byte) *pcommon.Block {
	block := &pcommon.Block{
		Header: &pcommon.BlockHeader{
			Number:       seqNum,
			PreviousHash: previousHash,
			DataHash:     []byte{},
		},
		Data: &pcommon.BlockData{},
	}

	var metadataContents [][]byte
	// 第一条元数据是：签名信息，第二条元数据是：交易过滤条件；第三条元数据是：commit_hash。
	for i := 0; i < len(pcommon.BlockMetadataIndex_name); i++ {
		metadataContents = append(metadataContents, []byte{})
	}
	block.Metadata = &pcommon.BlockMetadata{Metadata: metadataContents}

	return block
}

// BlockHeaderBytes
//
// fabric 将区块头中区块编号、区块交易哈希和上一个区块的哈希值组装到 asn1Header 结构体中，
// 然后对其进行 asn.1 编码，编码后得到的字节数组作为区块头的字节表示形式。
//
// mayy 直接计算区块头的 protobuf 编码值，弃用 fabric 的做法。
func BlockHeaderBytes(blockHeader *pcommon.BlockHeader) []byte {
	result, err := proto.Marshal(blockHeader)
	if err != nil {
		panic(err)
	}
	return result
}

// BlockHeaderHash 计算区块头的 sha256 哈希值。
func BlockHeaderHash(blockHeader *pcommon.BlockHeader) []byte {
	sum := sha256.Sum256(BlockHeaderBytes(blockHeader))
	return sum[:]
}

// BlockDataHash 计算区块内每个交易的哈希值。
func BlockDataHash(data *pcommon.BlockData) []byte {
	sum := sha256.Sum256(bytes.Join(data.Data, nil))
	return sum[:]
}

// GetChannelIDFromBlockBytes 提取给定的区块中的第一条交易数据，交易数据中含有通道信息，
// 进而可以提取出通道 ID。
func GetChannelIDFromBlockBytes(encoded []byte) (string, error) {
	block, err := UnmarshalBlock(encoded)
	if err != nil {
		return "", errors.NewErrorf("failed getting channel id from block bytes, the error is \"%s\"", err.Error())
	}
	return GetChannelIDFromBlock(block)
}

// GetChannelIDFromBlock 提取给定的区块中的第一条交易数据，交易数据中含有通道信息，
// 进而可以提取出通道 ID。
func GetChannelIDFromBlock(block *pcommon.Block) (string, error) {
	if block == nil || block.Data == nil || block.Data.Data == nil || len(block.Data.Data) == 0 {
		return "", errors.NewError("failed getting channel id from block, because the given block is empty")
	}

	envelope, err := UnmarshalEnvelope(block.Data.Data[0])
	if err != nil {
		return "", errors.NewErrorf("failed getting channel id from block, the error is \"%s\"", err.Error())
	}

	payload, err := UnmarshalPayload(envelope.Payload)
	if err != nil {
		return "", errors.NewErrorf("failed getting channel id from block, the error is \"%s\"", err.Error())
	}

	if payload.Header == nil {
		return "", errors.NewError("failed getting channel id from block, payload header is nil")
	}

	channelHeader, err := UnmarshalChannelHeader(payload.Header.ChannelHeader)
	if err != nil {
		return "", errors.NewErrorf("failed getting channel id from block, the error is \"%s\"", err.Error())
	}

	return channelHeader.ChannelId, nil
}

// GetMetadataFromBlock 根据给定的元数据索引位置，从给定的区块中获取对应的元数据。
func GetMetadataFromBlock(block *pcommon.Block, index pcommon.BlockMetadataIndex) (*pcommon.Metadata, error) {
	if block.Metadata == nil {
		return nil, errors.NewError("no metadata in the given block")
	}

	if len(block.Metadata.Metadata) <= int(index) {
		return nil, errors.NewErrorf("no metadata at index [%d:%s]", index, index.String())
	}

	metadata := &pcommon.Metadata{}
	if err := proto.Unmarshal(block.Metadata.Metadata[index], metadata); err != nil {
		return nil, errors.NewErrorf("failed getting metadata at index [%d:%s], the error is \"%s\"", index, index.String(), err.Error())
	}

	return metadata, nil
}

// GetMetadataFromBlockOrPanic 根据给定的元数据索引位置，从给定的区块中获取对应的元数据，如果出错，则会 panic。
func GetMetadataFromBlockOrPanic(block *pcommon.Block, index pcommon.BlockMetadataIndex) *pcommon.Metadata {
	if metadata, err := GetMetadataFromBlock(block, index); err != nil {
		panic(err)
	} else {
		return metadata
	}
}

// GetConsenterMetadataFromBlock 区块元数据中的第一条元数据，即签名背书数据中含有共识者的元数据。
//
//  1. Block.Metadata.Metadata[0] -> Metadata;
//  2. Metadata.Value -> OrdererBlockMetadata;
//  3. OrdererMetadata.ConsenterMetadata -> Metadata
func GetConsenterMetadataFromBlock(block *pcommon.Block) (*pcommon.Metadata, error) {
	metadata, err := GetMetadataFromBlock(block, pcommon.BlockMetadataIndex_SIGNATURES)
	if err != nil {
		return nil, errors.NewErrorf("failed getting consenter metadata from block, the error is \"%s\"", err.Error())
	}

	ordererBlockMetadata := &pcommon.OrdererBlockMetadata{}
	// metadata.value 存储 OrdererBlockMetadata 经过 protobuf 序列化后的字节数组
	if err := proto.Unmarshal(metadata.Value, ordererBlockMetadata); err != nil {
		return nil, errors.NewErrorf("failed getting consenter metadata from block, the error is \"%s\"", err.Error())
	}

	rtn := &pcommon.Metadata{}
	if err := proto.Unmarshal(ordererBlockMetadata.ConsenterMetadata, rtn); err != nil {
		return nil, errors.NewErrorf("failed getting consenter metadata from block, the error is \"%s\"", err.Error())
	}

	return rtn, nil
}

// GetLastConfigIndexFromBlock 区块元数据中的第一条数据，即签名背书数据中含有排序节点的元数据，
// 在此元数据中存有最后一个配置区块的索引位置。
//
//  1. Block.Metadata.Metadata[0] -> Metadata;
//  2. Metadata.Value -> OrdererBlockMetadata.LastConfig.Index
//
// LastConfig block 是指最新产生的配置区块，它记录了最近一次的网络配置更改。网络配置包括了参与
// 网络的组织、节点、通道和链代码等信息。当网络的配置发生变化时（例如添加或删除组织、节点或通道），
// 会生成一个配置交易，该交易被打包成一个 config 区块并广播到网络中。网络的参与者可以通过查询
// LastConfig block 获取最新的网络配置信息，从而了解网络的状态和拓扑结构。当新的节点加入网络或
// 者网络配置发生变化时，其他节点可以通过检查 LastConfig block 来同步最新的配置信息，确保网络的
// 一致性和正确性。
func GetLastConfigIndexFromBlock(block *pcommon.Block) (uint64, error) {
	metadata, err := GetMetadataFromBlock(block, pcommon.BlockMetadataIndex_SIGNATURES)
	if err != nil {
		return 0, errors.NewErrorf("failed getting last config index from block, the error is \"%s\"", err.Error())
	}

	ordererBlockMetadata := &pcommon.OrdererBlockMetadata{}
	if err := proto.Unmarshal(metadata.Value, ordererBlockMetadata); err != nil {
		return 0, errors.NewErrorf("failed getting last config index from block, the error is \"%s\"", err.Error())
	}

	return ordererBlockMetadata.LastConfig.Index, nil
}

// GetLastConfigIndexFromBlockOrPanic 区块元数据中的第一条数据，即签名背书数据中含有排序节点的元数据，
// 在此元数据中存有最后一个配置区块的索引位置。
//
//  1. Block.Metadata.Metadata[0] -> Metadata;
//  2. Metadata.Value -> OrdererBlockMetadata.LastConfig.Index
//
// LastConfig block 是指最新产生的配置区块，它记录了最近一次的网络配置更改。网络配置包括了参与
// 网络的组织、节点、通道和链代码等信息。当网络的配置发生变化时（例如添加或删除组织、节点或通道），
// 会生成一个配置交易，该交易被打包成一个 config 区块并广播到网络中。网络的参与者可以通过查询
// LastConfig block 获取最新的网络配置信息，从而了解网络的状态和拓扑结构。当新的节点加入网络或
// 者网络配置发生变化时，其他节点可以通过检查 LastConfig block 来同步最新的配置信息，确保网络的
// 一致性和正确性。
func GetLastConfigIndexFromBlockOrPanic(block *pcommon.Block) uint64 {
	if index, err := GetLastConfigIndexFromBlock(block); err != nil {
		panic(err)
	} else {
		return index
	}
}

// CopyBlockMetadata 将区块中的元数据拷贝到目标区块中。
func CopyBlockMetadata(src *pcommon.Block, dst *pcommon.Block) {
	dst.Metadata = src.Metadata
	InitBlockMetadata(dst)
}

// InitBlockMetadata 初始化区块的元数据字段，确保每种类型的元数据不为 nil，为 nil 的用 []byte{} 赋值。
//
// 包括以下类型的元数据：
//  1. SIGNATURES
//  2. TRANSACTIONS_FILTER
//  3. COMMIT_HASH
func InitBlockMetadata(block *pcommon.Block) {
	if block.Metadata == nil {
		block.Metadata = &pcommon.BlockMetadata{Metadata: [][]byte{{}, {}, {}}}
	} else if len(block.Metadata.Metadata) < int(pcommon.BlockMetadataIndex_COMMIT_HASH+1) {
		for i := len(block.Metadata.Metadata); i <= int(pcommon.BlockMetadataIndex_COMMIT_HASH); i++ {
			block.Metadata.Metadata = append(block.Metadata.Metadata, []byte{})
		}
	}
}

type VerifierBuilder func(block *pcommon.Block) BlockVerifierFunc

type BlockVerifierFunc func(header *pcommon.BlockHeader, metadata *pcommon.BlockMetadata) error

// policy 内仅定义了一个方法：EvaluateSignedData，该方法用于验证签名的合法性，以及签名者的
// 身份是否满足既定策略。
type policy interface {
	EvaluateSignedData(signatureSet []*SignedData) error
}

// BlockSignatureVerifier 构造验证区块中签名的方法。
//
//	TODO：为什么要有这么一句判断：if bftEnabled && len(mdSignature.SignatureHeader) == 0 && len(mdSignature.IdentifierHeader) > 0 {...}
func BlockSignatureVerifier(bftEnabled bool, consenters []*pcommon.Consenter, policy policy) BlockVerifierFunc {
	return func(header *pcommon.BlockHeader, metadata *pcommon.BlockMetadata) error {
		if len(metadata.Metadata) < int(pcommon.BlockMetadataIndex_SIGNATURES)+1 {
			return errors.NewError("no signatures in block")
		}

		md := &pcommon.Metadata{}
		if err := proto.Unmarshal(metadata.Metadata[pcommon.BlockMetadataIndex_SIGNATURES], md); err != nil {
			return errors.NewErrorf("failed verifying block signatures, the error is \"%s\"", err.Error())
		}

		var signatureSet []*SignedData
		for _, mdSignature := range md.Signatures {
			var signerIdentity []byte
			var signedPayload []byte

			if bftEnabled && len(mdSignature.SignatureHeader) == 0 && len(mdSignature.IdentifierHeader) > 0 {
				identifierHeader, err := UnmarshalIdentifierHeader(mdSignature.IdentifierHeader)
				if err != nil {
					return errors.NewErrorf("failed verifying block signatures, the error is \"%s\"", err.Error())
				}
				// 根据身份标识头内的签名者编号，从共识节点中找到共识节点的身份
				signerIdentity = searchConsenterIdentityByID(consenters, identifierHeader.Identifier)
				if len(signerIdentity) == 0 {
					continue
					// 所给的共识节点中，没有节点生成了此签名
				}
				signedPayload = bytes.Join([][]byte{md.Value, mdSignature.IdentifierHeader, BlockHeaderBytes(header)}, nil)
			} else {
				signatureHeader, err := UnmarshalSignatureHeader(mdSignature.SignatureHeader)
				if err != nil {
					return errors.NewErrorf("failed verifying block signatures, the error is \"%s\"", err.Error())
				}
				signedPayload = bytes.Join([][]byte{md.Value, mdSignature.SignatureHeader, BlockHeaderBytes(header)}, nil)
				signerIdentity = signatureHeader.Creator
			}

			signatureSet = append(signatureSet, &SignedData{
				Data:      signedPayload,
				Signature: mdSignature.Signature,
				Identity:  signerIdentity,
			})
		}

		return policy.EvaluateSignedData(signatureSet)
	}
}

func searchConsenterIdentityByID(consenters []*pcommon.Consenter, identifier uint32) []byte {
	for _, consenter := range consenters {
		if consenter.Id == identifier {
			return MarshalOrPanic(&pmsp.SerializedIdentity{
				Mspid:   consenter.MspId,
				IdBytes: consenter.Identity,
			})
		}
	}
	return nil
}
