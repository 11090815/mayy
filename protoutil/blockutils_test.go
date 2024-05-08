package protoutil_test

import (
	"fmt"
	"testing"

	"github.com/11090815/mayy/csp/softimpl/utils"
	"github.com/11090815/mayy/errors"
	"github.com/11090815/mayy/protobuf/pcommon"
	"github.com/11090815/mayy/protobuf/pmsp"
	"github.com/11090815/mayy/protoutil"
	"github.com/11090815/mayy/protoutil/mocks"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

var testChannelID = "myuniquetestchainid"

func TestCompareProtobufToASN1(t *testing.T) {
	digest, err := utils.GetRandomBytes(64)
	require.NoError(t, err)
	blockHeader := &pcommon.BlockHeader{
		Number:       233,
		DataHash:     digest,
		PreviousHash: digest,
	}

	asn1Bytes := protoutil.BlockHeaderBytes(blockHeader)
	protoBytes, err := proto.Marshal(blockHeader)
	require.NoError(t, err)

	if len(asn1Bytes) > len(protoBytes) {
		t.Log("protobuf")
	} else {
		t.Log("asn.1")
	}

	fmt.Println(asn1Bytes)
	fmt.Println("========================================")
	fmt.Println(protoBytes)
}

func TestBlockSignatureVerifierEmptyMetadata(t *testing.T) {
	policy := &mocks.Policy{}
	verifier := protoutil.BlockSignatureVerifier(true, nil, policy)
	metadata := &pcommon.BlockMetadata{}

	err := verifier(nil, metadata)
	require.ErrorContains(t, err, "no signatures in block")
}

func TestNewBlock(t *testing.T) {
	var block *pcommon.Block
	require.Nil(t, block.GetHeader())
	require.Nil(t, block.GetData())
	require.Nil(t, block.GetMetadata())

	blockData := &pcommon.BlockData{
		Data: [][]byte{{0, 1, 2}},
	}
	block = protoutil.NewBlock(0, []byte("datahash"))
	require.Equal(t, []byte("datahash"), block.Header.PreviousHash)
	require.NotNil(t, block.GetData())
	require.NotNil(t, block.GetMetadata())

	block.GetHeader().DataHash = protoutil.BlockDataHash(blockData)
	blockHeaderHash := protoutil.BlockHeaderHash(block.GetHeader())
	require.Len(t, blockHeaderHash, 32)
}

func TestBlockSignatureVerifierByIdentifier(t *testing.T) {
	consenters := []*pcommon.Consenter{
		{
			Id:       1,
			Host:     "host1",
			Port:     8001,
			MspId:    "msp1",
			Identity: []byte("identity1"),
		},
		{
			Id:       2,
			Host:     "host2",
			Port:     8002,
			MspId:    "msp2",
			Identity: []byte("identity2"),
		},
		{
			Id:       3,
			Host:     "host3",
			Port:     8003,
			MspId:    "msp3",
			Identity: []byte("identity3"),
		},
	}

	policies := &mocks.Policy{}
	verify := protoutil.BlockSignatureVerifier(true, consenters, policies)

	header := &pcommon.BlockHeader{}
	md := &pcommon.BlockMetadata{
		Metadata: [][]byte{
			protoutil.MarshalOrPanic(&pcommon.Metadata{
				Signatures: []*pcommon.MetadataSignature{
					{
						Signature:        []byte{},
						IdentifierHeader: protoutil.MarshalOrPanic(&pcommon.IdentifierHeader{Identifier: 1}),
					},
					{
						Signature:        []byte{},
						IdentifierHeader: protoutil.MarshalOrPanic(&pcommon.IdentifierHeader{Identifier: 2}),
					},
				},
			}),
		},
	}

	err := verify(header, md)
	require.NoError(t, err)
	signatureSet := policies.EvaluateSignedDataArgsForCall(0)
	require.Len(t, signatureSet, 2)
	require.Equal(t, protoutil.MarshalOrPanic(&pmsp.SerializedIdentity{Mspid: "msp1", IdBytes: []byte("identity1")}), signatureSet[0].Identity)
	require.Equal(t, protoutil.MarshalOrPanic(&pmsp.SerializedIdentity{Mspid: "msp2", IdBytes: []byte("identity2")}), signatureSet[1].Identity)
}

func TestBlockSignatureVerifierByCreator(t *testing.T) {
	consenters := []*pcommon.Consenter{
		{
			Id:       1,
			Host:     "host1",
			Port:     8001,
			MspId:    "msp1",
			Identity: []byte("identity1"),
		},
		{
			Id:       2,
			Host:     "host2",
			Port:     8002,
			MspId:    "msp2",
			Identity: []byte("identity2"),
		},
		{
			Id:       3,
			Host:     "host3",
			Port:     8003,
			MspId:    "msp3",
			Identity: []byte("identity3"),
		},
	}

	policies := &mocks.Policy{}
	verify := protoutil.BlockSignatureVerifier(true, consenters, policies)

	header := &pcommon.BlockHeader{}
	md := &pcommon.BlockMetadata{
		Metadata: [][]byte{
			protoutil.MarshalOrPanic(&pcommon.Metadata{
				Signatures: []*pcommon.MetadataSignature{
					{
						Signature:       []byte{},
						SignatureHeader: protoutil.MarshalOrPanic(&pcommon.SignatureHeader{Creator: []byte("creator1")}),
					},
				},
			}),
		},
	}

	err := verify(header, md)
	require.NoError(t, err)
	signatureSet := policies.EvaluateSignedDataArgsForCall(0)
	require.Len(t, signatureSet, 1)
	require.Equal(t, []byte("creator1"), signatureSet[0].Identity)
}

func TestUnmarshalNil(t *testing.T) {
	src := []byte{}
	channelHeader, err := protoutil.UnmarshalChannelHeader(src)
	require.NoError(t, err)
	require.NotNil(t, channelHeader)
}

func TestGetLastConfigIndexFromBlock(t *testing.T) {
	errors.SetTrace()
	index := uint64(2)
	block := protoutil.NewBlock(0, nil)

	t.Run("block with last config metadata in signatures field", func(t *testing.T) {
		block.Metadata.Metadata[pcommon.BlockMetadataIndex_SIGNATURES] = protoutil.MarshalOrPanic(&pcommon.Metadata{
			Value: protoutil.MarshalOrPanic(&pcommon.OrdererBlockMetadata{
				LastConfig: &pcommon.LastConfig{Index: 2},
			}),
		})
		result, err := protoutil.GetLastConfigIndexFromBlock(block)
		require.NoError(t, err, "Unexpected error returning last config index")
		require.Equal(t, index, result, "Unexpected last config index returned from block")
		result = protoutil.GetLastConfigIndexFromBlockOrPanic(block)
		require.Equal(t, index, result, "Unexpected last config index returned from block")
	})

	t.Run("block with malformed signatures", func(t *testing.T) {
		block.Metadata.Metadata[pcommon.BlockMetadataIndex_SIGNATURES] = []byte("apple")
		_, err := protoutil.GetLastConfigIndexFromBlock(block)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed getting last config index from block")
		t.Logf("error1 [%s]", err)
	})

	t.Run("block with malformed orderer block metadata", func(t *testing.T) {
		block.Metadata.Metadata[pcommon.BlockMetadataIndex_SIGNATURES] = protoutil.MarshalOrPanic(&pcommon.Metadata{Value: []byte("banana")})
		_, err := protoutil.GetLastConfigIndexFromBlock(block)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed getting last config index from block")
		t.Logf("error2 [%s]", err)
	})
}
