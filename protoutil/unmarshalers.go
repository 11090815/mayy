package protoutil

import (
	"github.com/11090815/mayy/errors"
	"github.com/11090815/mayy/protobuf/pcommon"
	"github.com/11090815/mayy/protobuf/pmsp"
	"github.com/11090815/mayy/protobuf/ppeer"
	"google.golang.org/protobuf/proto"
)

func UnmarshalBlock(encoded []byte) (*pcommon.Block, error) {
	block := &pcommon.Block{}
	if err := proto.Unmarshal(encoded, block); err != nil {
		return nil, errors.NewError(err.Error())
	}
	return block, nil
}

func UnmarshalBlockOrPanic(encoded []byte) *pcommon.Block {
	if block, err := UnmarshalBlock(encoded); err != nil {
		panic(err)
	} else {
		return block
	}
}

/* ------------------------------------------------------------------------------------------ */

func UnmarshalPayload(encoded []byte) (*pcommon.Payload, error) {
	payload := &pcommon.Payload{}
	if err := proto.Unmarshal(encoded, payload); err != nil {
		return nil, errors.NewError(err.Error())
	}
	return payload, nil
}

func UnmarshalPayloadOrPanic(encoded []byte) *pcommon.Payload {
	if payload, err := UnmarshalPayload(encoded); err != nil {
		panic(err)
	} else {
		return payload
	}
}

/* ------------------------------------------------------------------------------------------ */

func UnmarshalChannelHeader(encoded []byte) (*pcommon.ChannelHeader, error) {
	channelHeader := &pcommon.ChannelHeader{}
	if err := proto.Unmarshal(encoded, channelHeader); err != nil {
		return nil, errors.NewError(err.Error())
	}
	return channelHeader, nil
}

func UnmarshalIdentifierHeader(encoded []byte) (*pcommon.IdentifierHeader, error) {
	identifierHeader := &pcommon.IdentifierHeader{}
	if err := proto.Unmarshal(encoded, identifierHeader); err != nil {
		return nil, errors.NewError(err.Error())
	}
	return identifierHeader, nil
}

func UnmarshalSignatureHeader(encoded []byte) (*pcommon.SignatureHeader, error) {
	signatureHeader := &pcommon.SignatureHeader{}
	if err := proto.Unmarshal(encoded, signatureHeader); err != nil {
		return nil, errors.NewError(err.Error())
	}
	return signatureHeader, nil
}

func UnmarshalSignatureHeaderOrPanic(encoded []byte) *pcommon.SignatureHeader {
	if signatureHeader, err := UnmarshalSignatureHeader(encoded); err != nil {
		panic(err)
	} else {
		return signatureHeader
	}
}

func UnmarshalTransaction(encoded []byte) (*ppeer.Transaction, error) {
	transaction := &ppeer.Transaction{}
	if err := proto.Unmarshal(encoded, transaction); err != nil {
		return nil, errors.NewError(err.Error())
	}
	return transaction, nil
}

func UnmarshalChaincodeActionPayload(encoded []byte) (*ppeer.ChaincodeActionPayload, error) {
	chaincodeActionPayload := &ppeer.ChaincodeActionPayload{}
	if err := proto.Unmarshal(encoded, chaincodeActionPayload); err != nil {
		return nil, errors.NewError(err.Error())
	}
	return chaincodeActionPayload, nil
}

func UnmarshalProposalResponsePayload(encoded []byte) (*ppeer.ProposalResponsePayload, error) {
	proposalResponsePayload := &ppeer.ProposalResponsePayload{}
	if err := proto.Unmarshal(encoded, proposalResponsePayload); err != nil {
		return nil, errors.NewError(err.Error())
	}
	return proposalResponsePayload, nil
}

func UnmarshalChaincodeAction(encoded []byte) (*ppeer.ChaincodeAction, error) {
	chaincodeAction := &ppeer.ChaincodeAction{}
	if err := proto.Unmarshal(encoded, chaincodeAction); err != nil {
		return nil, errors.NewError(err.Error())
	}
	return chaincodeAction, nil
}

func UnmarshalEnvelope(encoded []byte) (*pcommon.Envelope, error) {
	envelope := &pcommon.Envelope{}
	if err := proto.Unmarshal(encoded, envelope); err != nil {
		return nil, errors.NewError(err.Error())
	}
	return envelope, nil
}

func UnmarshalEnvelopeOrPanic(encoded []byte) *pcommon.Envelope {
	if envelope, err := UnmarshalEnvelope(encoded); err != nil {
		panic(err)
	} else {
		return envelope
	}
}

func UnmarshalSerializedIdentity(encoded []byte) (*pmsp.SerializedIdentity, error) {
	serializedIdentity := &pmsp.SerializedIdentity{}
	if err := proto.Unmarshal(encoded, serializedIdentity); err != nil {
		return nil, errors.NewError(err.Error())
	}
	return serializedIdentity, nil
}

func UnmarshalHeader(encoded []byte) (*pcommon.Header, error) {
	header := &pcommon.Header{}
	if err := proto.Unmarshal(encoded, header); err != nil {
		return nil, errors.NewError(err.Error())
	}
	return header, nil
}

func UnmarshalChaincodeProposalPayload(encoded []byte) (*ppeer.ChaincodeProposalPayload, error) {
	chaincodeProposalPayload := &ppeer.ChaincodeProposalPayload{}
	if err := proto.Unmarshal(encoded, chaincodeProposalPayload); err != nil {
		return nil, errors.NewError(err.Error())
	}
	return chaincodeProposalPayload, nil
}

func UnmarshalChaincodeDeploymentSpec(encoded []byte) (*ppeer.ChaincodeDeploymentSpec, error) {
	chaincodeDeploymentSpec := &ppeer.ChaincodeDeploymentSpec{}
	if err := proto.Unmarshal(encoded, chaincodeDeploymentSpec); err != nil {
		return nil, errors.NewError(err.Error())
	}
	return chaincodeDeploymentSpec, nil
}

func UnmarshalChaincodeInvocationSpec(encoded []byte) (*ppeer.ChaincodeInvocationSpec, error) {
	chaincodeInvocationSpec := &ppeer.ChaincodeInvocationSpec{}
	if err := proto.Unmarshal(encoded, chaincodeInvocationSpec); err != nil {
		return nil, errors.NewError(err.Error())
	}
	return chaincodeInvocationSpec, nil
}

func UnmarshalChaincodeHeaderExtension(encoded []byte) (*ppeer.ChaincodeHeaderExtension, error) {
	chaincodeHeaderExtension := &ppeer.ChaincodeHeaderExtension{}
	if err := proto.Unmarshal(encoded, chaincodeHeaderExtension); err != nil {
		return nil, errors.NewError(err.Error())
	}
	return chaincodeHeaderExtension, nil
}

func UnmarshalProposal(encoded []byte) (*ppeer.Proposal, error) {
	proposal := &ppeer.Proposal{}
	if err := proto.Unmarshal(encoded, proposal); err != nil {
		return nil, errors.NewError(err.Error())
	}
	return proposal, nil
}

func UnmarshalProposalResponse(encoded []byte) (*ppeer.ProposalResponse, error) {
	proposalResponse := &ppeer.ProposalResponse{}
	if err := proto.Unmarshal(encoded, proposalResponse); err != nil {
		return nil, errors.NewError(err.Error())
	}
	return proposalResponse, nil
}

func UnmarshalChaincodeEvent(encoded []byte) (*ppeer.ChaincodeEvent, error) {
	chaincodeEvent := &ppeer.ChaincodeEvent{}
	if err := proto.Unmarshal(encoded, chaincodeEvent); err != nil {
		return nil, errors.NewError(err.Error())
	}
	return chaincodeEvent, nil
}

func UnmarshalResponse(encoded []byte) (*ppeer.Response, error) {
	response := &ppeer.Response{}
	if err := proto.Unmarshal(encoded, response); err != nil {
		return nil, errors.NewError(err.Error())
	}
	return response, nil
}

func UnmarshalChaincodeID(encoded []byte) (*ppeer.ChaincodeID, error) {
	chaincodeId := &ppeer.ChaincodeID{}
	if err := proto.Unmarshal(encoded, chaincodeId); err != nil {
		return nil, errors.NewError(err.Error())
	}
	return chaincodeId, nil
}

// UnmarshalEnvelopeOfType 给定一个 Envelope，将其中的 Payload 字节数组反序列化成 Payload 结构体，如果得到的负载的通道头
// ChannelHeader 的类型与给定的头类型（第二个参数）不一样，则返回错误，不然继续将 Payload 中的数据部分 Data 反序列化成另一
// 个结构体，并返回通道头的结构体消息。
func UnmarshalEnvelopeOfType(envelope *pcommon.Envelope, headerType pcommon.HeaderType, message proto.Message) (*pcommon.ChannelHeader, error) {
	payload, err := UnmarshalPayload(envelope.Payload)
	if err != nil {
		return nil, err
	}

	if payload.Header == nil {
		return nil, errors.NewError("payload must have a header")
	}

	channelHeader, err := UnmarshalChannelHeader(payload.Header.ChannelHeader)
	if err != nil {
		return nil, err
	}

	if channelHeader.Type != int32(headerType) {
		return nil, errors.NewErrorf("invalid type of channel header, expected \"%s\", but got \"%s\"", headerType.String(), pcommon.HeaderType(channelHeader.Type).String())
	}

	return channelHeader, Unmarshal(payload.Data, message)
}
