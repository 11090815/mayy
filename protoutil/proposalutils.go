package protoutil

import (
	"github.com/11090815/mayy/errors"
	"github.com/11090815/mayy/protobuf/pcommon"
	"github.com/11090815/mayy/protobuf/ppeer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func CreateProposalFromChaincodeInvocationSpec(headerType pcommon.HeaderType, channelID string,
	chaincodeInvocationSpec *ppeer.ChaincodeInvocationSpec, creator []byte) (*ppeer.Proposal, string, error) {
	return CreateChaincodeProposal(headerType, channelID, chaincodeInvocationSpec, creator)
}

func CreateProposalFromChaincodeInvocationSpecAndTxid(txid, channelID string, headerType pcommon.HeaderType,
	chaincodeInvocationSpec *ppeer.ChaincodeInvocationSpec, creator []byte) (*ppeer.Proposal, string, error) {
	return CreateChaincodeProposalWithTxIDAndTransient(headerType, channelID, txid, chaincodeInvocationSpec, creator, nil)
}

func CreateChaincodeProposal(headerType pcommon.HeaderType, channelID string,
	chaincodeInvocationSpec *ppeer.ChaincodeInvocationSpec, creator []byte) (*ppeer.Proposal, string, error) {
	return CreateChaincodeProposalWithTransient(headerType, channelID, chaincodeInvocationSpec, creator, nil)
}

func CreateChaincodeProposalWithTransient(headerType pcommon.HeaderType, channelID string, chaincodeInvocationSpec *ppeer.ChaincodeInvocationSpec,
	creator []byte, transientMap map[string][]byte) (*ppeer.Proposal, string, error) {
	nonce, err := CreateNonce()
	if err != nil {
		return nil, "", errors.NewErrorf("failed creating chaincode proposal, the error is \"%s\"", err.Error())
	}

	txid := ComputeTxID(nonce, creator)

	return CreateChaincodeProposalWithTxIDNonceAndTransient(txid, headerType, channelID, chaincodeInvocationSpec, nonce, creator, transientMap)
}

func CreateChaincodeProposalWithTxIDAndTransient(headerType pcommon.HeaderType, channelID, txid string,
	chaincodeInvocationSpec *ppeer.ChaincodeInvocationSpec, creator []byte, transientMap map[string][]byte) (*ppeer.Proposal, string, error) {
	nonce, err := CreateNonce()
	if err != nil {
		return nil, "", errors.NewErrorf("failed creating chaincode proposal, the error is \"%s\"", err.Error())
	}

	if txid == "" {
		txid = ComputeTxID(nonce, creator)
	}

	return CreateChaincodeProposalWithTxIDNonceAndTransient(txid, headerType, channelID, chaincodeInvocationSpec, nonce, creator, transientMap)
}

func CreateChaincodeProposalWithTxIDNonceAndTransient(txid string, headerType pcommon.HeaderType, channelID string,
	chaincodeInvocationSpec *ppeer.ChaincodeInvocationSpec, nonce, creator []byte, transientMap map[string][]byte) (*ppeer.Proposal, string, error) {
	chaincodeHeaderExtension := &ppeer.ChaincodeHeaderExtension{
		ChaincodeId: chaincodeInvocationSpec.ChaincodeSpec.ChaincodeId,
	}

	encodedChaincodeHeaderExtension, err := Marshal(chaincodeHeaderExtension)
	if err != nil {
		return nil, "", errors.NewErrorf("failed creating chaincode proposal, the error is \"%s\"", err.Error())
	}

	encodedChaincodeInvocationSpec, err := Marshal(chaincodeInvocationSpec)
	if err != nil {
		return nil, "", errors.NewErrorf("failed creating chaincode proposal, the error is \"%s\"", err.Error())
	}

	chaincodeProposalPayload := &ppeer.ChaincodeProposalPayload{
		Input:        encodedChaincodeInvocationSpec,
		TransientMap: transientMap,
	}
	encodedChaincodeProposalPayload, err := Marshal(chaincodeProposalPayload)
	if err != nil {
		return nil, "", errors.NewErrorf("failed creating chaincode proposal, the error is \"%s\"", err.Error())
	}

	header := &pcommon.Header{
		ChannelHeader: MarshalOrPanic(&pcommon.ChannelHeader{
			Type:      int32(headerType),
			TxId:      txid,
			Timestamp: timestamppb.Now(),
			ChannelId: channelID,
			Extension: encodedChaincodeHeaderExtension,
			Epoch:     0, // 目前 epoch 的默认值是 0
		}),
		SignatureHeader: MarshalOrPanic(
			&pcommon.SignatureHeader{
				Nonce:   nonce,
				Creator: creator,
			},
		),
	}

	encodedHeader, err := Marshal(header)
	if err != nil {
		return nil, "", errors.NewErrorf("failed creating chaincode proposal, the error is \"%s\"", err.Error())
	}

	proposal := &ppeer.Proposal{
		Header:  encodedHeader,
		Payload: encodedChaincodeProposalPayload,
	}

	return proposal, txid, nil
}

func CreateGetChaincodesProposal(channelID string, creator []byte) (*ppeer.Proposal, string, error) {
	chaincodeInput := &ppeer.ChaincodeInput{Args: [][]byte{[]byte("getchaincodes")}}
	chaincodeInvocationSpec := &ppeer.ChaincodeInvocationSpec{
		ChaincodeSpec: &ppeer.ChaincodeSpec{
			Type:        ppeer.ChaincodeSpec_GOLANG,
			ChaincodeId: &ppeer.ChaincodeID{Name: "lscc"},
			Input:       chaincodeInput,
		},
	}
	return CreateProposalFromChaincodeInvocationSpec(pcommon.HeaderType_ENDORSER_TRANSACTION, channelID, chaincodeInvocationSpec, creator)
}

func CreateGetInstalledChaincodesProposal(creator []byte) (*ppeer.Proposal, string, error) {
	chaincodeInput := &ppeer.ChaincodeInput{
		Args: [][]byte{[]byte("getinstalledchaincodes")},
	}
	chaincodeInvocationSpec := &ppeer.ChaincodeInvocationSpec{
		ChaincodeSpec: &ppeer.ChaincodeSpec{
			Type:        ppeer.ChaincodeSpec_GOLANG,
			ChaincodeId: &ppeer.ChaincodeID{Name: "lscc"},
			Input:       chaincodeInput,
		},
	}
	return CreateProposalFromChaincodeInvocationSpec(pcommon.HeaderType_ENDORSER_TRANSACTION, "", chaincodeInvocationSpec, creator)
}

func CreateInstallProposalFromChaincodeDeploymentSpec(chaincodePackage proto.Message, creator []byte) (*ppeer.Proposal, string, error) {
	return createProposalFromChaincodeDeploymentSpec("", "install", chaincodePackage, creator)
}

func CreateDeployProposalFromChaincodeDeploymentSpec(channelID string, chaincodeDeploymentSpec *ppeer.ChaincodeDeploymentSpec,
	creator, policy, escc, vscc, collectionConfig []byte) (*ppeer.Proposal, string, error) {
	if collectionConfig == nil {
		return createProposalFromChaincodeDeploymentSpec(channelID, "deploy", chaincodeDeploymentSpec, creator, policy, escc, vscc)
	}
	return createProposalFromChaincodeDeploymentSpec(channelID, "deploy", chaincodeDeploymentSpec, creator, policy, escc, vscc, collectionConfig)
}

func CreateUpgradeProposalFromChaincodeDeploymentSpec(channelID string, chaincodeDeploymentSpec *ppeer.ChaincodeDeploymentSpec,
	creator, policy, escc, vscc, collectionConfig []byte) (*ppeer.Proposal, string, error) {
	if collectionConfig == nil {
		return createProposalFromChaincodeDeploymentSpec(channelID, "upgrade", chaincodeDeploymentSpec, creator, policy, escc, vscc)
	}
	return createProposalFromChaincodeDeploymentSpec(channelID, "upgrade", chaincodeDeploymentSpec, creator, policy, escc, vscc, collectionConfig)
}

func createProposalFromChaincodeDeploymentSpec(channelID, propType string, msg proto.Message, creator []byte, args ...[]byte) (*ppeer.Proposal, string, error) {
	var chaincodeInput *ppeer.ChaincodeInput
	var encoded []byte
	var err error
	if msg != nil {
		encoded, err = Marshal(msg)
		if err != nil {
			return nil, "", err
		}
	}

	switch propType {
	case "deploy":
		fallthrough
	case "upgrade": // "upgrade" + "channelID" + deployment spec + args
		chaincodeDeploymentSpec, ok := msg.(*ppeer.ChaincodeDeploymentSpec)
		if !ok || chaincodeDeploymentSpec == nil {
			return nil, "", errors.NewErrorf("failed creating lifecycle chaincode proposal, expected \"%T\", but got \"%T\"", &ppeer.ChaincodeDeploymentSpec{}, msg)
		}
		args_ := [][]byte{[]byte(propType), []byte(channelID), encoded}
		args_ = append(args_, args...)
		chaincodeInput = &ppeer.ChaincodeInput{Args: args_}
	case "install": // "install" + deployment spec
		chaincodeInput = &ppeer.ChaincodeInput{Args: [][]byte{[]byte(propType), encoded}}
	}

	chaincodeInvocationSpec := &ppeer.ChaincodeInvocationSpec{
		ChaincodeSpec: &ppeer.ChaincodeSpec{
			Type:        ppeer.ChaincodeSpec_GOLANG,
			ChaincodeId: &ppeer.ChaincodeID{Name: "lscc"},
			Input:       chaincodeInput,
		},
	}

	return CreateProposalFromChaincodeInvocationSpec(pcommon.HeaderType_ENDORSER_TRANSACTION, channelID, chaincodeInvocationSpec, creator)
}

/* ------------------------------------------------------------------------------------------ */

func GetActionFromEnvelope(encodedEnvelope []byte) (*ppeer.ChaincodeAction, error) {
	envelope, err := UnmarshalEnvelope(encodedEnvelope)
	if err != nil {
		return nil, err
	}
	return GetActionFromEnvelopeMsg(envelope)
}

func GetActionFromEnvelopeMsg(envelope *pcommon.Envelope) (*ppeer.ChaincodeAction, error) {
	payload, err := UnmarshalPayload(envelope.Payload)
	if err != nil {
		return nil, err
	}

	transaction, err := UnmarshalTransaction(payload.Data)
	if err != nil {
		return nil, err
	}

	if len(transaction.Actions) == 0 {
		return nil, errors.NewError("at least 1 TransactionAction required")
	}

	_, responsePayload, err := GetPayloads(transaction.Actions[0])
	return responsePayload, err
}

/* ------------------------------------------------------------------------------------------ */

// GetBytesProposalResponsePayload 给定链码执行结果 result、 事件 event、响应 response 和 链码 id，组装出一个
// ChaincodeAction 结构体消息，并对它进行序列化，得到字节数组，然后随给定的哈希值 hash，组装出一个 ProposalResponsePayload
// 结构体消息，最后返回对此结构体消息进行序列化后的 protobuf 字节数组。
func GetBytesProposalResponsePayload(hash, result, event []byte, response *ppeer.Response, chaincodeId *ppeer.ChaincodeID) ([]byte, error) {
	chaincodeAction := &ppeer.ChaincodeAction{
		Events:      event,
		Results:     result,
		Response:    response,
		ChaincodeId: chaincodeId,
	}
	encodedChaincodeAction, err := Marshal(chaincodeAction)
	if err != nil {
		return nil, errors.NewErrorf("failed getting bytes of proposal response payload, the error is \"%s\"", err.Error())
	}

	proposalResponsePayload := &ppeer.ProposalResponsePayload{
		ProposalHash: hash, // proposal 的哈希值放在这里应该是用来确认此响应与提案是否对应。
		Extension:    encodedChaincodeAction,
	}

	return Marshal(proposalResponsePayload)
}

// GetBytesChaincodeProposalPayload 计算给定的 ChaincodeProposalPayload 结构体消息经序列化后的 protobuf 字节数组。
func GetBytesChaincodeProposalPayload(chaincodeProposalPayload *ppeer.ChaincodeProposalPayload) ([]byte, error) {
	return Marshal(chaincodeProposalPayload)
}

// GetBytesResponse 计算给定的 Response 结构体消息经序列化后的 protobuf 字节数组。
func GetBytesResponse(response *ppeer.Response) ([]byte, error) {
	return Marshal(response)
}

// GetBytesChaincodeEvent 计算给定的 ChaincodeEvent 结构体消息经序列化后的 protobuf 字节数组。
func GetBytesChaincodeEvent(chaincodeEvent *ppeer.ChaincodeEvent) ([]byte, error) {
	return Marshal(chaincodeEvent)
}

// GetBytesChaincodeActionPayload 计算给定的 ChaincodeActionPayload 结构体消息经序列化后的 protobuf 字节数组。
func GetBytesChaincodeActionPayload(chaincodeActionPayload *ppeer.ChaincodeActionPayload) ([]byte, error) {
	return Marshal(chaincodeActionPayload)
}

// GetBytesProposalResponse 计算给定的 ProposalResponse 结构体消息经序列化后的 protobuf 字节数组。
func GetBytesProposalResponse(proposalResponse *ppeer.ProposalResponse) ([]byte, error) {
	return Marshal(proposalResponse)
}

// GetBytesEnvelope 计算给定的 Envelope 结构体消息经序列化后的 protobuf 字节数组。
func GetBytesEnvelope(envelope *pcommon.Envelope) ([]byte, error) {
	return Marshal(envelope)
}

// GetBytesPayload 计算给定的 Payload 结构体消息经序列化后的 protobuf 字节数组。
func GetBytesPayload(payload *pcommon.Payload) ([]byte, error) {
	return Marshal(payload)
}

// GetBytesTransaction 计算给定的 Transaction 结构体消息经序列化后的 protobuf 字节数组。
func GetBytesTransaction(transaction *ppeer.Transaction) ([]byte, error) {
	return Marshal(transaction)
}

// GetBytesSignatureHeader 计算给定的 SignatureHeader 结构体消息经序列化后的 protobuf 字节数组。
func GetBytesSignatureHeader(signatureHeader *pcommon.SignatureHeader) ([]byte, error) {
	return Marshal(signatureHeader)
}

// GetBytesHeader 计算给定的 Header 结构体消息经序列化后的 protobuf 字节数组。
func GetBytesHeader(header *pcommon.Header) ([]byte, error) {
	return Marshal(header)
}

/* ------------------------------------------------------------------------------------------ */

func CheckTxID(txid string, nonce, creator []byte) error {
	computedTxID := ComputeTxID(nonce, creator)
	if txid != computedTxID {
		return errors.NewErrorf("invalid txid, expected \"%s\", but got \"%s\"", computedTxID, txid)
	}
	return nil
}

// InvokedChaincodeName 给定一个提案的 protobuf 序列化字节数组，对其进行反序列化，提取调用的链码名。
func InvokedChaincodeName(proposalBytes []byte) (string, error) {
	proposal := &ppeer.Proposal{} // 创建一个容器
	if err := Unmarshal(proposalBytes, proposal); err != nil {
		return "", errors.NewErrorf("failed retriving chaincode name from proposal, the error is \"%s\"", err.Error())
	}

	chaincodeProposalPayload := &ppeer.ChaincodeProposalPayload{}
	if err := Unmarshal(proposal.Payload, chaincodeProposalPayload); err != nil {
		return "", errors.NewErrorf("failed retriving chaincode name from chaincode proposal payload, the error is \"%s\"", err.Error())
	}

	chaincodeInvocationSpec := &ppeer.ChaincodeInvocationSpec{}
	if err := Unmarshal(chaincodeProposalPayload.Input, chaincodeInvocationSpec); err != nil {
		return "", errors.NewErrorf("failed retriving chaincode name from chaincode invocation spec, the error is \"%s\"", err.Error())
	}

	if chaincodeInvocationSpec.ChaincodeSpec == nil {
		return "", errors.NewError("failed retriving chaincode name, because the chaincode invocation spec is nil")
	}

	if chaincodeInvocationSpec.ChaincodeSpec.ChaincodeId == nil {
		return "", errors.NewError("failed retriving chaincode name, because the chaincode id is nil")
	}

	return chaincodeInvocationSpec.ChaincodeSpec.ChaincodeId.Name, nil
}
