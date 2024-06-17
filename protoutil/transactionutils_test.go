package protoutil_test

import (
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/11090815/mayy/common/errors"
	"github.com/11090815/mayy/protobuf/pcommon"
	"github.com/11090815/mayy/protobuf/ppeer"
	"github.com/11090815/mayy/protoutil"
	"github.com/11090815/mayy/protoutil/mocks"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestGetPayloads(t *testing.T) {
	var transactionAction *ppeer.TransactionAction
	var err error

	chaincodeActionBytes, _ := protoutil.Marshal(&ppeer.ChaincodeAction{Results: []byte("results")})
	proposalResponsePayloadBytes, _ := protoutil.Marshal(&ppeer.ProposalResponsePayload{Extension: chaincodeActionBytes})
	chaincodeActionPayload := &ppeer.ChaincodeActionPayload{
		Action: &ppeer.ChaincodeEndorsedAction{
			ProposalResponsePayload: proposalResponsePayloadBytes,
		},
	}
	chaincodeActionPayloadBytes, _ := protoutil.Marshal(chaincodeActionPayload)
	transactionAction = &ppeer.TransactionAction{
		Payload: chaincodeActionPayloadBytes,
	}
	_, _, err = protoutil.GetPayloads(transactionAction)
	require.NoError(t, err)
	t.Logf("error1 [%s]", err)

	proposalResponsePayloadBytes, err = protoutil.Marshal(&ppeer.ProposalResponsePayload{Extension: nil})
	require.NoError(t, err)
	chaincodeActionPayload = &ppeer.ChaincodeActionPayload{
		Action: &ppeer.ChaincodeEndorsedAction{
			ProposalResponsePayload: proposalResponsePayloadBytes,
		},
	}
	chaincodeActionPayloadBytes, _ = protoutil.Marshal(chaincodeActionPayload)
	transactionAction = &ppeer.TransactionAction{
		Payload: chaincodeActionPayloadBytes,
	}
	_, _, err = protoutil.GetPayloads(transactionAction)
	require.Error(t, err)
	t.Logf("error2 [%s]", err)

	chaincodeActionPayload = &ppeer.ChaincodeActionPayload{
		Action: &ppeer.ChaincodeEndorsedAction{
			ProposalResponsePayload: []byte("invalid payload"),
		},
	}
	chaincodeActionPayloadBytes, _ = protoutil.Marshal(chaincodeActionPayload)
	transactionAction = &ppeer.TransactionAction{Payload: chaincodeActionPayloadBytes}
	_, _, err = protoutil.GetPayloads(transactionAction)
	require.Error(t, err)
	t.Logf("error3 [%s]", err)

	proposalResponsePayloadBytes, _ = protoutil.Marshal(&ppeer.ProposalResponsePayload{
		Extension: []byte("invalid extension"),
	})
	chaincodeActionPayload = &ppeer.ChaincodeActionPayload{
		Action: &ppeer.ChaincodeEndorsedAction{
			ProposalResponsePayload: proposalResponsePayloadBytes,
		},
	}
	chaincodeActionPayloadBytes, _ = protoutil.Marshal(chaincodeActionPayload)
	transactionAction = &ppeer.TransactionAction{Payload: chaincodeActionPayloadBytes}
	_, _, err = protoutil.GetPayloads(transactionAction)
	require.Error(t, err)
	t.Logf("error4 [%s]", err)

	proposalResponsePayloadBytes, _ = protoutil.Marshal(&ppeer.ProposalResponsePayload{
		ProposalHash: []byte("proposal hash"),
	})
	chaincodeActionPayload = &ppeer.ChaincodeActionPayload{
		Action: &ppeer.ChaincodeEndorsedAction{
			ProposalResponsePayload: proposalResponsePayloadBytes,
		},
	}
	chaincodeActionPayloadBytes, _ = protoutil.Marshal(chaincodeActionPayload)
	transactionAction = &ppeer.TransactionAction{Payload: chaincodeActionPayloadBytes}
	_, _, err = protoutil.GetPayloads(transactionAction)
	require.Error(t, err)
	t.Logf("error5 [%s]", err)

	transactionAction = &ppeer.TransactionAction{
		Payload: []byte("invalid payload"),
	}
	_, _, err = protoutil.GetPayloads(transactionAction)
	require.Error(t, err)
	t.Logf("error6 [%s]", err)
}

func TestDuplicateEndorsement(t *testing.T) {
	signer := &mocks.Signer{}
	// signer.SetSerializeReturns([]byte("mock signer"), nil)
	creator, err := signer.Serialize()
	require.NoError(t, err)
	// require.Equal(t, creator, []byte("mock signer"))

	proposal := &ppeer.Proposal{
		Header: protoutil.MarshalOrPanic(&pcommon.Header{
			ChannelHeader: protoutil.MarshalOrPanic(&pcommon.ChannelHeader{
				Extension: protoutil.MarshalOrPanic(&ppeer.ChaincodeHeaderExtension{}),
			}),
			SignatureHeader: protoutil.MarshalOrPanic(&pcommon.SignatureHeader{
				Creator: creator,
			}),
		}),
	}
	responses := []*ppeer.ProposalResponse{
		{Payload: []byte("payload"), Endorsement: &ppeer.Endorsement{Endorser: []byte("endorser")}, Response: &ppeer.Response{Status: 200}},
		{Payload: []byte("payload"), Endorsement: &ppeer.Endorsement{Endorser: []byte("endorser")}, Response: &ppeer.Response{Status: 200}},
	}

	envelope, err := protoutil.CreateSignedTx(proposal, signer, responses...)
	require.NoError(t, err)

	payload := protoutil.UnmarshalPayloadOrPanic(envelope.Payload)
	transaction, err := protoutil.UnmarshalTransaction(payload.Data)
	require.NoError(t, err)
	chaincodeActionPayload, err := protoutil.UnmarshalChaincodeActionPayload(transaction.Actions[0].Payload)
	require.NoError(t, err)
	require.Len(t, chaincodeActionPayload.Action.Endorsements, 1)
	require.Equal(t, []byte("endorser"), chaincodeActionPayload.Action.Endorsements[0].Endorser)
}

func TestCreateSignedTx(t *testing.T) {
	var proposal = &ppeer.Proposal{}

	signer := &mocks.Signer{}
	signer.SetSerializeReturns([]byte("creator"), nil)
	creator, err := signer.Serialize()
	require.NoError(t, err)

	chaincodeHeaderExtensionBytes := protoutil.MarshalOrPanic(&ppeer.ChaincodeHeaderExtension{})
	channelHeaderBytes := protoutil.MarshalOrPanic(&pcommon.ChannelHeader{
		Extension: chaincodeHeaderExtensionBytes,
	})
	signatureHeaderBytes := protoutil.MarshalOrPanic(&pcommon.SignatureHeader{
		Creator: creator,
	})

	responses := []*ppeer.ProposalResponse{{}}
	headerBytes := protoutil.MarshalOrPanic(&pcommon.Header{
		SignatureHeader: []byte("invalid signature header"),
	})

	proposal.Header = headerBytes
	_, err = protoutil.CreateSignedTx(proposal, signer, responses...)
	t.Logf("error1 [%s]", err)

	headerBytes = protoutil.MarshalOrPanic(&pcommon.Header{
		SignatureHeader: signatureHeaderBytes,
		ChannelHeader:   channelHeaderBytes,
	})
	proposal.Header = headerBytes

	nonMatchingTests := []struct {
		responses     []*ppeer.ProposalResponse
		expectedError string
	}{
		{
			[]*ppeer.ProposalResponse{
				{Payload: []byte("payload"), Response: &ppeer.Response{Status: 200}},
				{Payload: []byte{}, Response: &ppeer.Response{Status: 500, Message: "failed to endorse"}},
			},
			"proposal response was not successful, error code is 500, msg failed to endorse",
		},
		{
			[]*ppeer.ProposalResponse{
				{Payload: []byte{}, Response: &ppeer.Response{Status: 500, Message: "failed to endorse"}},
				{Payload: []byte("payload"), Response: &ppeer.Response{Status: 200}},
			},
			"proposal response was not successful, error code is 500, msg failed to endorse",
		},
	}

	for i, nonMatchingTest := range nonMatchingTests {
		_, err = protoutil.CreateSignedTx(proposal, signer, nonMatchingTest.responses...)
		if nonMatchingTest.expectedError != "" {
			require.Error(t, err)
			t.Logf("error%d [%s]", i+2, err)
		}
	}

	responses = []*ppeer.ProposalResponse{
		{Payload: []byte("payload1"), Response: &ppeer.Response{Status: 200}},
		{Payload: []byte("payload2"), Response: &ppeer.Response{Status: 200}},
	}
	_, err = protoutil.CreateSignedTx(proposal, signer, responses...)
	require.ErrorContains(t, err, "proposal response payloads do not match")
	t.Logf("error4 [%s]", err)

	responses = []*ppeer.ProposalResponse{
		{Payload: []byte("payload"), Response: &ppeer.Response{Status: 200}},
	}
	_, err = protoutil.CreateSignedTx(proposal, signer, responses...)
	require.ErrorContains(t, err, "no endorsements for proposal response")
	t.Logf("error5 [%s]", err)

	responses = []*ppeer.ProposalResponse{
		{Payload: []byte("payload"), Response: &ppeer.Response{Status: 200}, Endorsement: &ppeer.Endorsement{}},
	}
	_, err = protoutil.CreateSignedTx(proposal, signer, responses...)
	require.NoError(t, err)

	proposal = &ppeer.Proposal{}
	responses = []*ppeer.ProposalResponse{}
	_, err = protoutil.CreateSignedTx(proposal, signer, responses...)
	require.ErrorContains(t, err, "at least 1 proposal response is required")
	t.Logf("error6 [%s]", err)

	responses = append(responses, &ppeer.ProposalResponse{})
	_, err = protoutil.CreateSignedTx(proposal, signer, responses...)
	require.Error(t, err)
	t.Logf("error7 [%s]", err)

	proposal.Payload = []byte("invalid payload")
	_, err = protoutil.CreateSignedTx(proposal, signer, responses...)
	require.Error(t, err)
	t.Logf("error8 [%s]", err)

	proposal.Header = []byte("invalid header")
	_, err = protoutil.CreateSignedTx(proposal, signer, responses...)
	require.Error(t, err)
	t.Logf("error9 [%s]", err)

	_, err = protoutil.CreateSignedTx(nil, nil, responses...)
	require.Error(t, err)
	t.Logf("error10 [%s]", err)
}

func TestCreateSignedTxStatus(t *testing.T) {
	serializedExtension, err := proto.Marshal(&ppeer.ChaincodeHeaderExtension{})
	require.NoError(t, err)
	serializedChannelHeader, err := proto.Marshal(&pcommon.ChannelHeader{
		Extension: serializedExtension,
	})
	require.NoError(t, err)

	signingID := &mocks.Signer{}
	signingID.SetSerializeReturns([]byte("signer"), nil)
	serializedSigningID, err := signingID.Serialize()
	require.NoError(t, err)
	serializedSignatureHeader, err := proto.Marshal(&pcommon.SignatureHeader{
		Creator: serializedSigningID,
	})
	require.NoError(t, err)

	header := &pcommon.Header{
		ChannelHeader:   serializedChannelHeader,
		SignatureHeader: serializedSignatureHeader,
	}

	serializedHeader, err := proto.Marshal(header)
	require.NoError(t, err)

	proposal := &ppeer.Proposal{
		Header: serializedHeader,
	}

	tests := []struct {
		status      int32
		expectedErr string
	}{
		{status: 0, expectedErr: "proposal response was not successful, error code 0, msg response-message"},
		{status: 199, expectedErr: "proposal response was not successful, error code 199, msg response-message"},
		{status: 200, expectedErr: ""},
		{status: 201, expectedErr: ""},
		{status: 399, expectedErr: ""},
		{status: 400, expectedErr: "proposal response was not successful, error code 400, msg response-message"},
	}
	for i, tc := range tests {
		t.Run(strconv.Itoa(int(tc.status)), func(t *testing.T) {
			response := &ppeer.ProposalResponse{
				Payload:     []byte("payload"),
				Endorsement: &ppeer.Endorsement{},
				Response: &ppeer.Response{
					Status:  tc.status,
					Message: "response-message",
				},
			}

			_, err := protoutil.CreateSignedTx(proposal, signingID, response)
			if tc.expectedErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err, tc.expectedErr)
				t.Logf("error%d [%s]", i, err)
			}
		})
	}
}

func TestCreateSignedEnvelope(t *testing.T) {
	var env *pcommon.Envelope
	channelID := "mychannelID"
	msg := &pcommon.ConfigEnvelope{}

	id := &mocks.Signer{}
	id.SetSignReturnsOnCall(0, []byte("goodsig"), nil)
	id.SetSignReturnsOnCall(1, nil, errors.NewError("bad signature"))
	env, err := protoutil.CreateSignedEnvelope(pcommon.HeaderType_CONFIG, channelID,
		id, msg, int32(1), uint64(1))
	require.NoError(t, err, "Unexpected error creating signed envelope")
	require.NotNil(t, env, "Envelope should not be nil")
	// mock sign returns the bytes to be signed
	require.Equal(t, []byte("goodsig"), env.Signature, "Unexpected signature returned")
	payload := &pcommon.Payload{}
	err = proto.Unmarshal(env.Payload, payload)
	require.NoError(t, err, "Failed to unmarshal payload")
	data := &pcommon.ConfigEnvelope{}
	err = proto.Unmarshal(payload.Data, data)
	require.NoError(t, err, "Expected payload data to be a config envelope")
	require.Equal(t, msg, data, "Payload data does not match expected value")

	_, err = protoutil.CreateSignedEnvelope(pcommon.HeaderType_CONFIG, channelID,
		id, &pcommon.ConfigEnvelope{}, int32(1), uint64(1))
	require.Error(t, err, "Expected sign error")
}

func TestCreateSignedEnvelopeNilSigner(t *testing.T) {
	var env *pcommon.Envelope
	channelID := "mychannelID"
	msg := &pcommon.ConfigEnvelope{}

	env, err := protoutil.CreateSignedEnvelope(pcommon.HeaderType_CONFIG, channelID,
		nil, msg, int32(1), uint64(1))
	require.NoError(t, err, "Unexpected error creating signed envelope")
	require.NotNil(t, env, "Envelope should not be nil")
	require.Empty(t, env.Signature, "Signature should have been empty")
	payload := &pcommon.Payload{}
	err = proto.Unmarshal(env.Payload, payload)
	require.NoError(t, err, "Failed to unmarshal payload")
	data := &pcommon.ConfigEnvelope{}
	err = proto.Unmarshal(payload.Data, data)
	require.NoError(t, err, "Expected payload data to be a config envelope")
	require.Equal(t, msg, data, "Payload data does not match expected value")
}

func TestGetSignedProposal(t *testing.T) {
	var signedProp *ppeer.SignedProposal
	var err error

	sig := []byte("signature")

	signID := &mocks.Signer{}
	signID.SetSignReturns(sig, nil)

	prop := &ppeer.Proposal{}
	propBytes, _ := proto.Marshal(prop)
	signedProp, err = protoutil.GetSignedProposal(prop, signID)
	require.NoError(t, err, "Unexpected error getting signed proposal")
	require.Equal(t, propBytes, signedProp.ProposalBytes,
		"Proposal bytes did not match expected value")
	require.Equal(t, sig, signedProp.Signature,
		"Signature did not match expected value")

	_, err = protoutil.GetSignedProposal(nil, signID)
	require.Error(t, err, "Expected error with nil proposal")
	_, err = protoutil.GetSignedProposal(prop, nil)
	require.Error(t, err, "Expected error with nil signing identity")
}

func TestMockSignedEndorserProposal1OrPanic(t *testing.T) {
	var prop *ppeer.Proposal
	var signedProp *ppeer.SignedProposal

	ccProposal := &ppeer.ChaincodeProposalPayload{}
	cis := &ppeer.ChaincodeInvocationSpec{}
	chainID := "testchannelid"
	sig := []byte("signature")
	creator := []byte("creator")
	cs := &ppeer.ChaincodeSpec{
		ChaincodeId: &ppeer.ChaincodeID{
			Name: "mychaincode",
		},
	}

	signedProp, prop = protoutil.MockSignedEndorserProposal1OrPanic(chainID, cs,
		creator, sig)
	require.Equal(t, sig, signedProp.Signature,
		"Signature did not match expected result")
	propBytes, _ := proto.Marshal(prop)
	require.Equal(t, propBytes, signedProp.ProposalBytes,
		"Proposal bytes do not match expected value")
	err := proto.Unmarshal(prop.Payload, ccProposal)
	require.NoError(t, err, "Expected ChaincodeProposalPayload")
	err = proto.Unmarshal(ccProposal.Input, cis)
	require.NoError(t, err, "Expected ChaincodeInvocationSpec")
	require.Equal(t, cs.ChaincodeId.Name, cis.ChaincodeSpec.ChaincodeId.Name,
		"Chaincode name did not match expected value")
}

func TestMockSignedEndorserProposal2OrPanic(t *testing.T) {
	var prop *ppeer.Proposal
	var signedProp *ppeer.SignedProposal

	ccProposal := &ppeer.ChaincodeProposalPayload{}
	cis := &ppeer.ChaincodeInvocationSpec{}
	chainID := "testchannelid"
	sig := []byte("signature")
	signID := &mocks.Signer{}
	signID.SetSignReturns(sig, nil)

	signedProp, prop = protoutil.MockSignedEndorserProposal2OrPanic(chainID,
		&ppeer.ChaincodeSpec{}, signID)
	require.Equal(t, sig, signedProp.Signature,
		"Signature did not match expected result")
	propBytes, _ := proto.Marshal(prop)
	require.Equal(t, propBytes, signedProp.ProposalBytes,
		"Proposal bytes do not match expected value")
	err := proto.Unmarshal(prop.Payload, ccProposal)
	require.NoError(t, err, "Expected ChaincodeProposalPayload")
	err = proto.Unmarshal(ccProposal.Input, cis)
	require.NoError(t, err, "Expected ChaincodeInvocationSpec")
}

func TestGetBytesProposalPayloadForTx(t *testing.T) {
	input := &ppeer.ChaincodeProposalPayload{
		Input:        []byte("input"),
		TransientMap: make(map[string][]byte),
	}
	expected, _ := proto.Marshal(&ppeer.ChaincodeProposalPayload{
		Input: []byte("input"),
	})

	result, err := protoutil.GetBytesProposalPayloadForTx(input)
	require.NoError(t, err, "Unexpected error getting proposal payload")
	require.Equal(t, expected, result, "Payload does not match expected value")

	_, err = protoutil.GetBytesProposalPayloadForTx(nil)
	require.Error(t, err, "Expected error with nil proposal payload")
}

func TestGetProposalHash1(t *testing.T) {
	expectedHashHex := "d4c1e3cac2105da5fddc2cfe776d6ec28e4598cf1e6fa51122c7f70d8076437b"
	expectedHash, _ := hex.DecodeString(expectedHashHex)
	hdr := &pcommon.Header{
		ChannelHeader:   []byte("chdr"),
		SignatureHeader: []byte("shdr"),
	}

	ccProposal, _ := proto.Marshal(&ppeer.ChaincodeProposalPayload{})

	propHash, err := protoutil.GetProposalHash1(hdr, ccProposal)
	require.NoError(t, err, "Unexpected error getting hash for proposal")
	require.Equal(t, expectedHash, propHash, "Proposal hash did not match expected hash")

	_, err = protoutil.GetProposalHash1(hdr, []byte("ccproppayload"))
	require.Error(t, err, "Expected error with malformed chaincode proposal payload")

	_, err = protoutil.GetProposalHash1(&pcommon.Header{}, []byte("ccproppayload"))
	require.Error(t, err, "Expected error with nil arguments")
}

func TestGetProposalHash2(t *testing.T) {
	expectedHashHex := "7b622ef4e1ab9b7093ec3bbfbca17d5d6f14a437914a6839319978a7034f7960"
	expectedHash, _ := hex.DecodeString(expectedHashHex)
	hdr := &pcommon.Header{
		ChannelHeader:   []byte("chdr"),
		SignatureHeader: []byte("shdr"),
	}
	propHash, err := protoutil.GetProposalHash2(hdr, []byte("ccproppayload"))
	require.NoError(t, err, "Unexpected error getting hash2 for proposal")
	require.Equal(t, expectedHash, propHash, "Proposal hash did not match expected hash")

	_, err = protoutil.GetProposalHash2(&pcommon.Header{}, []byte("ccproppayload"))
	require.Error(t, err, "Expected error with nil arguments")
}

func TestCreateProposalResponseFailure(t *testing.T) {
	var testChannelID = "myuniquetestchainid"
	prop, _, err := protoutil.CreateChaincodeProposal(pcommon.HeaderType_ENDORSER_TRANSACTION, testChannelID, createCIS(), signerSerialized)
	if err != nil {
		t.Fatalf("Could not create chaincode proposal, err %s\n", err)
		return
	}

	response := &ppeer.Response{Status: 502, Payload: []byte("Invalid function name")}
	result := []byte("res")

	prespFailure, err := protoutil.CreateProposalResponseFailure(prop.Header, prop.Payload, result, nil, "foo", response)
	if err != nil {
		t.Fatalf("Could not create proposal response failure, err %s\n", err)
		return
	}

	require.Equal(t, int32(502), prespFailure.Response.Status)
	// drilldown into the response to find the chaincode response
	pRespPayload, err := protoutil.UnmarshalProposalResponsePayload(prespFailure.Payload)
	require.NoError(t, err, "Error while unmarshalling proposal response payload: %s", err)
	ca, err := protoutil.UnmarshalChaincodeAction(pRespPayload.Extension)
	require.NoError(t, err, "Error while unmarshalling chaincode action: %s", err)

	require.Equal(t, int32(502), ca.Response.Status)
	require.Equal(t, "Invalid function name", string(ca.Response.Payload))
}

func TestGetorComputeTxIDFromEnvelope(t *testing.T) {
	t.Run("txID is present in the envelope", func(t *testing.T) {
		envelopeBytes := createSampleTxEnvelopeBytes()
		actualTxID, err := protoutil.GetOrComputeTxIDFromEnvelope(envelopeBytes)
		require.Nil(t, err)
		require.Equal(t, "709184f9d24f6ade8fcd4d6521a6eef295fef6c2e67216c58b68ac15e8946492", actualTxID)
	})

	t.Run("txID is not present in the envelope", func(t *testing.T) {
		envelopeBytes := createSampleTxEnvelopeBytes()
		actualTxID, err := protoutil.GetOrComputeTxIDFromEnvelope(envelopeBytes)
		require.Nil(t, err)
		require.Equal(t, "709184f9d24f6ade8fcd4d6521a6eef295fef6c2e67216c58b68ac15e8946492", actualTxID)
	})
}

func createSampleTxEnvelopeBytes() []byte {
	chdr := &pcommon.ChannelHeader{
		TxId: "709184f9d24f6ade8fcd4d6521a6eef295fef6c2e67216c58b68ac15e8946492",
	}
	chdrBytes := protoutil.MarshalOrPanic(chdr)

	shdr := &pcommon.SignatureHeader{
		Nonce:   []byte("nonce"),
		Creator: []byte("creator"),
	}
	shdrBytes := protoutil.MarshalOrPanic(shdr)

	hdr := &pcommon.Header{
		ChannelHeader:   chdrBytes,
		SignatureHeader: shdrBytes,
	}

	payload := &pcommon.Payload{
		Header: hdr,
	}
	payloadBytes := protoutil.MarshalOrPanic(payload)

	envelope := &pcommon.Envelope{
		Payload: payloadBytes,
	}
	return protoutil.MarshalOrPanic(envelope)
}
