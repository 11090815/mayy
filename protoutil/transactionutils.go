package protoutil

import (
	"bytes"
	"crypto/sha256"

	"github.com/11090815/mayy/errors"
	"github.com/11090815/mayy/protobuf/pcommon"
	"github.com/11090815/mayy/protobuf/ppeer"
	"google.golang.org/protobuf/proto"
)

type Signer interface {
	Sign(msg []byte) ([]byte, error)
	// Serialize 将 x509 证书编码成 PEM 格式的字节数组。
	Serialize() ([]byte, error)
}

func GetPayloads(transactionAction *ppeer.TransactionAction) (*ppeer.ChaincodeActionPayload, *ppeer.ChaincodeAction, error) {
	chaincodeActionPayload, err := UnmarshalChaincodeActionPayload(transactionAction.Payload)
	if err != nil {
		return nil, nil, err
	}

	if chaincodeActionPayload.Action == nil || chaincodeActionPayload.Action.ProposalResponsePayload == nil {
		return nil, nil, errors.NewError("no payload in chaincode action")
	}

	proposalResponsePayload, err := UnmarshalProposalResponsePayload(chaincodeActionPayload.Action.ProposalResponsePayload)
	if err != nil {
		return nil, nil, err
	}

	if proposalResponsePayload.Extension == nil {
		return nil, nil, errors.NewError("no extension in proposal response payload")
	}

	chaincodeAction, err := UnmarshalChaincodeAction(proposalResponsePayload.Extension)
	if err != nil {
		return chaincodeActionPayload, nil, err
	}

	return chaincodeActionPayload, chaincodeAction, nil
}

func CreateSignedEnvelope(headerType pcommon.HeaderType, channelID string, signer Signer,
	message proto.Message, version int32, epoch uint64) (*pcommon.Envelope, error) {
	return CreateSignedEnvelopeWithTLSBinding(headerType, channelID, signer, message, version, epoch, nil)
}

func CreateSignedEnvelopeWithTLSBinding(headerType pcommon.HeaderType, channelID string, signer Signer,
	message proto.Message, version int32, epoch uint64, tlsCertHash []byte) (*pcommon.Envelope, error) {
	channelHeader := MakeChannelHeader(headerType, version, channelID, epoch)
	channelHeader.TlsCertHash = tlsCertHash

	var signatureHeader *pcommon.SignatureHeader

	if signer != nil {
		serializedIdentity, err := signer.Serialize()
		if err != nil {
			return nil, err
		}
		signatureHeader, err = NewSignatureHeader(serializedIdentity)
		if err != nil {
			return nil, err
		}
	}

	data, err := Marshal(message)
	if err != nil {
		return nil, err
	}

	encodedPayload := MarshalOrPanic(&pcommon.Payload{
		Data:   data,
		Header: MakePayloadHeader(channelHeader, signatureHeader),
	})

	var signature []byte
	if signer != nil {
		signature, err = signer.Sign(encodedPayload)
		if err != nil {
			return nil, err
		}
	}

	return &pcommon.Envelope{
		Payload:   encodedPayload,
		Signature: signature,
	}, nil
}

func CreateSignedTx(proposal *ppeer.Proposal, signer Signer, proposalResponses ...*ppeer.ProposalResponse) (*pcommon.Envelope, error) {
	if len(proposalResponses) == 0 {
		return nil, errors.NewError("at least 1 proposal response is required")
	}

	if signer == nil {
		return nil, errors.NewError("signer is required when creating a signed transaction")
	}

	header, err := UnmarshalHeader(proposal.Header)
	if err != nil {
		return nil, err
	}

	chaincodeProposalPayload, err := UnmarshalChaincodeProposalPayload(proposal.Payload)
	if err != nil {
		return nil, err
	}

	serializedIdentity, err := signer.Serialize()
	if err != nil {
		return nil, err
	}

	signatureHeader, err := UnmarshalSignatureHeader(header.SignatureHeader)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(serializedIdentity, signatureHeader.Creator) {
		return nil, errors.NewError("signer must be the same as the one referenced in the proposal header")
	}

	// 确保所有提案的响应都是一样的，避免有的同意有的不同意情况的出现
	var proposalResponsePayload []byte
	for i, proposalResponse := range proposalResponses {
		if proposalResponse.Response.Status < 200 || proposalResponse.Response.Status >= 400 {
			return nil, errors.NewErrorf("proposal response was not successful, error code is \"%d\", error message is \"%s\"", proposalResponse.Response.Status, proposalResponse.Response.Message)
		}

		if i == 0 {
			proposalResponsePayload = proposalResponse.Payload
			continue
		}

		if !bytes.Equal(proposalResponsePayload, proposalResponse.Payload) {
			return nil, errors.NewErrorf("proposal response payloads do not match: \"%x\" vs \"%x\"", proposalResponsePayload, proposalResponse.Payload)
		}
	}

	// 确保每个背书者只产生了一份签名，避免多签
	endorserUsed := make(map[string]struct{})
	var endorsements []*ppeer.Endorsement
	for _, proposalResponse := range proposalResponses {
		if proposalResponse.Endorsement == nil {
			continue
		}
		endorser := string(proposalResponse.Endorsement.Endorser)
		if _, used := endorserUsed[endorser]; used {
			continue
		}
		endorsements = append(endorsements, proposalResponse.Endorsement)
		endorserUsed[endorser] = struct{}{}
	}

	if len(endorsements) == 0 {
		return nil, errors.NewErrorf("no endorsements for proposal response")
	}

	chaincodeEndorsedAction := &ppeer.ChaincodeEndorsedAction{ProposalResponsePayload: proposalResponsePayload, Endorsements: endorsements}
	chaincodeProposalPayloadBytes, err := GetBytesProposalPayloadForTx(chaincodeProposalPayload)
	if err != nil {
		return nil, err
	}

	chaincodeActionPayload := &ppeer.ChaincodeActionPayload{ChaincodeProposalPayload: chaincodeProposalPayloadBytes, Action: chaincodeEndorsedAction}
	chaincodeActionPayloadBytes, err := Marshal(chaincodeActionPayload)
	if err != nil {
		return nil, err
	}

	transactionAction := &ppeer.TransactionAction{Header: header.SignatureHeader, Payload: chaincodeActionPayloadBytes}
	transaction := &ppeer.Transaction{Actions: []*ppeer.TransactionAction{transactionAction}}
	transactionBytes, err := Marshal(transaction)
	if err != nil {
		return nil, err
	}

	payload := &pcommon.Payload{Header: header, Data: transactionBytes}
	payloadBytes, err := Marshal(payload)
	if err != nil {
		return nil, err
	}

	signature, err := signer.Sign(payloadBytes)
	if err != nil {
		return nil, err
	}

	return &pcommon.Envelope{Payload: payloadBytes, Signature: signature}, nil
}

func CreateProposalResponse(headerBytes, chaincodeProposalBytes, result, event []byte,
	response *ppeer.Response, chaincodeId *ppeer.ChaincodeID, signer Signer) (*ppeer.ProposalResponse, error) {
	header, err := UnmarshalHeader(headerBytes)
	if err != nil {
		return nil, err
	}

	proposalHash, err := GetProposalHash1(header, chaincodeProposalBytes)
	if err != nil {
		return nil, errors.NewError("failed computing proposal hash")
	}

	proposalResponsePayloadBytes, err := GetBytesProposalResponsePayload(proposalHash, result, event, response, chaincodeId)
	if err != nil {
		return nil, err
	}

	endorser, err := signer.Serialize()
	if err != nil {
		return nil, err
	}

	signature, err := signer.Sign(append(proposalResponsePayloadBytes, endorser...))
	if err != nil {
		return nil, err
	}

	proposalResponse := &ppeer.ProposalResponse{
		Version: 1,
		Endorsement: &ppeer.Endorsement{
			Signature: signature,
			Endorser:  endorser,
		},
		Payload: proposalResponsePayloadBytes,
		Response: &ppeer.Response{
			Status:  200,
			Message: "OK",
		},
	}

	return proposalResponse, nil
}

func CreateProposalResponseFailure(headerBytes, chaincodeProposalBytes, result, event []byte, chaincodeName string, response *ppeer.Response) (*ppeer.ProposalResponse, error) {
	header, err := UnmarshalHeader(headerBytes)
	if err != nil {
		return nil, err
	}

	proposalHash, err := GetProposalHash1(header, chaincodeProposalBytes)
	if err != nil {
		return nil, errors.NewError("failed computing proposal hash")
	}

	proposalResponsePayloadBytes, err := GetBytesProposalResponsePayload(proposalHash, result, event, response, &ppeer.ChaincodeID{Name: chaincodeName})
	if err != nil {
		return nil, err
	}

	proposalResponse := &ppeer.ProposalResponse{
		Payload:  proposalResponsePayloadBytes,
		Response: response,
	}

	return proposalResponse, nil
}

func GetSignedProposal(proposal *ppeer.Proposal, signer Signer) (*ppeer.SignedProposal, error) {
	if proposal == nil {
		return nil, errors.NewError("nil proposal")
	}

	if signer == nil {
		return nil, errors.NewError("nil signer")
	}

	proposalBytes, err := Marshal(proposal)
	if err != nil {
		return nil, err
	}

	signature, err := signer.Sign(proposalBytes)
	if err != nil {
		return nil, err
	}

	return &ppeer.SignedProposal{Signature: signature, ProposalBytes: proposalBytes}, nil
}

// GetBytesProposalPayloadForTx 方法将 ChaincodeProposalPayload 消息结构体中的 TransientMap 设置成空，
// 然后对其进行序列化，将序列化结果进行返回。
func GetBytesProposalPayloadForTx(chaincodeProposalPayload *ppeer.ChaincodeProposalPayload) ([]byte, error) {
	if chaincodeProposalPayload == nil {
		return nil, errors.NewError("nil chaincode proposal payload")
	}

	chaincodeProposalPayloadNoTransient := &ppeer.ChaincodeProposalPayload{Input: chaincodeProposalPayload.Input, TransientMap: nil}
	return Marshal(chaincodeProposalPayloadNoTransient)
}

func GetProposalHash1(header *pcommon.Header, chaincodeProposalPayloadBytes []byte) ([]byte, error) {
	if header == nil {
		return nil, errors.NewError("header is nil")
	}

	if header.ChannelHeader == nil {
		return nil, errors.NewError("channel header is nil")
	}

	if header.SignatureHeader == nil {
		return nil, errors.NewError("signature header is nil")
	}

	if chaincodeProposalPayloadBytes == nil {
		return nil, errors.NewError("chaincode proposal payload is nil")
	}

	chaincodeProposalPayload, err := UnmarshalChaincodeProposalPayload(chaincodeProposalPayloadBytes)
	if err != nil {
		return nil, err
	}

	chaincodeProposalPayloadForTx, err := GetBytesProposalPayloadForTx(chaincodeProposalPayload)
	if err != nil {
		return nil, err
	}

	function := sha256.New()
	function.Write(header.ChannelHeader)
	function.Write(header.SignatureHeader)
	function.Write(chaincodeProposalPayloadForTx)
	return function.Sum(nil), nil
}

func GetProposalHash2(header *pcommon.Header, chaincodeProposalPayloadBytes []byte) ([]byte, error) {
	if header == nil {
		return nil, errors.NewError("header is nil")
	}

	if header.ChannelHeader == nil {
		return nil, errors.NewError("channel header is nil")
	}

	if header.SignatureHeader == nil {
		return nil, errors.NewError("signature header is nil")
	}

	if chaincodeProposalPayloadBytes == nil {
		return nil, errors.NewError("chaincode proposal payload is nil")
	}

	function := sha256.New()
	function.Write(header.ChannelHeader)
	function.Write(header.SignatureHeader)
	function.Write(chaincodeProposalPayloadBytes)
	return function.Sum(nil), nil
}

func GetOrComputeTxIDFromEnvelope(envelopeBytes []byte) (string, error) {
	envelope, err := UnmarshalEnvelope(envelopeBytes)
	if err != nil {
		return "", nil
	}

	payload, err := UnmarshalPayload(envelope.Payload)
	if err != nil {
		return "", err
	}

	if payload.Header == nil {
		return "", errors.NewError("payload header is nil")
	}

	channelHeader, err := UnmarshalChannelHeader(payload.Header.ChannelHeader)
	if err != nil {
		return "", err
	}

	if channelHeader.TxId != "" {
		return channelHeader.TxId, nil
	}

	signatureHeader, err := UnmarshalSignatureHeader(payload.Header.SignatureHeader)
	if err != nil {
		return "", err
	}

	txid := ComputeTxID(signatureHeader.Nonce, signatureHeader.Creator)

	return txid, nil
}

/* ------------------------------------------------------------------------------------------ */

func MockSignedEndorserProposal1OrPanic(channelID string, chaincodeSpec *ppeer.ChaincodeSpec, creator, signature []byte) (*ppeer.SignedProposal, *ppeer.Proposal) {
	chaincodeProposal, _, err := CreateChaincodeProposal(pcommon.HeaderType_ENDORSER_TRANSACTION, channelID, &ppeer.ChaincodeInvocationSpec{ChaincodeSpec: chaincodeSpec}, creator)
	if err != nil {
		panic(err)
	}

	proposalBytes, err := Marshal(chaincodeProposal)
	if err != nil {
		panic(err)
	}

	return &ppeer.SignedProposal{ProposalBytes: proposalBytes, Signature: signature}, chaincodeProposal
}

func MockSignedEndorserProposal2OrPanic(channelID string, chaincodeSpec *ppeer.ChaincodeSpec, signer Signer) (*ppeer.SignedProposal, *ppeer.Proposal) {
	endorser, err := signer.Serialize()
	if err != nil {
		panic(err)
	}

	chaincodeProposal, _, err := CreateChaincodeProposal(pcommon.HeaderType_ENDORSER_TRANSACTION, channelID, &ppeer.ChaincodeInvocationSpec{ChaincodeSpec: &ppeer.ChaincodeSpec{}}, endorser)
	if err != nil {
		panic(err)
	}

	signedProposal, err := GetSignedProposal(chaincodeProposal, signer)
	if err != nil {
		panic(err)
	}

	return signedProposal, chaincodeProposal
}
