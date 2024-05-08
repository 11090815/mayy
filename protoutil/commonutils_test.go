package protoutil_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/11090815/mayy/protoutil/mocks"
	"github.com/11090815/mayy/protobuf/pcommon"
	"github.com/11090815/mayy/protobuf/ppeer"
	"github.com/11090815/mayy/protoutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestNonceRandomness(t *testing.T) {
	n1, err := protoutil.CreateNonce()
	if err != nil {
		t.Fatal(err)
	}
	n2, err := protoutil.CreateNonce()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(n1, n2) {
		t.Fatalf("Expected nonces to be different, got %x and %x", n1, n2)
	}
}

func TestNonceLength(t *testing.T) {
	n, err := protoutil.CreateNonce()
	if err != nil {
		t.Fatal(err)
	}
	actual := len(n)
	expected := 24
	if actual != expected {
		t.Fatalf("Expected nonce to be of size %d, got %d instead", expected, actual)
	}
}

func TestUnmarshalPayload(t *testing.T) {
	var payload *pcommon.Payload
	good, _ := proto.Marshal(&pcommon.Payload{
		Data: []byte("payload"),
	})
	payload, err := protoutil.UnmarshalPayload(good)
	require.NoError(t, err, "Unexpected error unmarshalling payload")
	require.NotNil(t, payload, "Payload should not be nil")
	payload = protoutil.UnmarshalPayloadOrPanic(good)
	require.NotNil(t, payload, "Payload should not be nil")

	bad := []byte("bad payload")
	require.Panics(t, func() {
		_ = protoutil.UnmarshalPayloadOrPanic(bad)
	}, "Expected panic unmarshalling malformed payload")
}

func TestUnmarshalSignatureHeader(t *testing.T) {
	t.Run("invalid header", func(t *testing.T) {
		sighdrBytes := []byte("invalid signature header")
		_, err := protoutil.UnmarshalSignatureHeader(sighdrBytes)
		require.Error(t, err, "Expected unmarshalling error")
	})

	t.Run("valid empty header", func(t *testing.T) {
		sighdr := &pcommon.SignatureHeader{}
		sighdrBytes := protoutil.MarshalOrPanic(sighdr)
		sighdr, err := protoutil.UnmarshalSignatureHeader(sighdrBytes)
		require.NoError(t, err, "Unexpected error unmarshalling signature header")
		require.Nil(t, sighdr.Creator)
		require.Nil(t, sighdr.Nonce)
	})

	t.Run("valid header", func(t *testing.T) {
		sighdr := &pcommon.SignatureHeader{
			Creator: []byte("creator"),
			Nonce:   []byte("nonce"),
		}
		sighdrBytes := protoutil.MarshalOrPanic(sighdr)
		sighdr, err := protoutil.UnmarshalSignatureHeader(sighdrBytes)
		require.NoError(t, err, "Unexpected error unmarshalling signature header")
		require.Equal(t, []byte("creator"), sighdr.Creator)
		require.Equal(t, []byte("nonce"), sighdr.Nonce)
	})
}

func TestUnmarshalSignatureHeaderOrPanic(t *testing.T) {
	t.Run("panic due to invalid header", func(t *testing.T) {
		sighdrBytes := []byte("invalid signature header")
		require.Panics(t, func() {
			protoutil.UnmarshalSignatureHeaderOrPanic(sighdrBytes)
		}, "Expected panic with invalid header")
	})

	t.Run("no panic as the header is valid", func(t *testing.T) {
		sighdr := &pcommon.SignatureHeader{}
		sighdrBytes := protoutil.MarshalOrPanic(sighdr)
		sighdr = protoutil.UnmarshalSignatureHeaderOrPanic(sighdrBytes)
		require.Nil(t, sighdr.Creator)
		require.Nil(t, sighdr.Nonce)
	})
}

func TestUnmarshalEnvelope(t *testing.T) {
	var env *pcommon.Envelope
	good, _ := proto.Marshal(&pcommon.Envelope{})
	env, err := protoutil.UnmarshalEnvelope(good)
	require.NoError(t, err, "Unexpected error unmarshalling envelope")
	require.NotNil(t, env, "Envelope should not be nil")
	env = protoutil.UnmarshalEnvelopeOrPanic(good)
	require.NotNil(t, env, "Envelope should not be nil")

	bad := []byte("bad envelope")
	require.Panics(t, func() {
		_ = protoutil.UnmarshalEnvelopeOrPanic(bad)
	}, "Expected panic unmarshalling malformed envelope")
}

func TestUnmarshalBlock(t *testing.T) {
	var env *pcommon.Block
	good, _ := proto.Marshal(&pcommon.Block{})
	env, err := protoutil.UnmarshalBlock(good)
	require.NoError(t, err, "Unexpected error unmarshalling block")
	require.NotNil(t, env, "Block should not be nil")
	env = protoutil.UnmarshalBlockOrPanic(good)
	require.NotNil(t, env, "Block should not be nil")

	bad := []byte("bad block")
	require.Panics(t, func() {
		_ = protoutil.UnmarshalBlockOrPanic(bad)
	}, "Expected panic unmarshalling malformed block")
}

func TestUnmarshalEnvelopeOfType(t *testing.T) {
	env := &pcommon.Envelope{}

	env.Payload = []byte("bad payload")
	_, err := protoutil.UnmarshalEnvelopeOfType(env, pcommon.HeaderType_CONFIG, nil)
	require.Error(t, err, "Expected error unmarshalling malformed envelope")

	payload, _ := proto.Marshal(&pcommon.Payload{
		Header: nil,
	})
	env.Payload = payload
	_, err = protoutil.UnmarshalEnvelopeOfType(env, pcommon.HeaderType_CONFIG, nil)
	require.Error(t, err, "Expected error with missing payload header")

	payload, _ = proto.Marshal(&pcommon.Payload{
		Header: &pcommon.Header{
			ChannelHeader: []byte("bad header"),
		},
	})
	env.Payload = payload
	_, err = protoutil.UnmarshalEnvelopeOfType(env, pcommon.HeaderType_CONFIG, nil)
	require.Error(t, err, "Expected error for malformed channel header")

	chdr, _ := proto.Marshal(&pcommon.ChannelHeader{
		Type: int32(pcommon.HeaderType_CHAINCODE_PACKAGE),
	})
	payload, _ = proto.Marshal(&pcommon.Payload{
		Header: &pcommon.Header{
			ChannelHeader: chdr,
		},
	})
	env.Payload = payload
	_, err = protoutil.UnmarshalEnvelopeOfType(env, pcommon.HeaderType_CONFIG, nil)
	require.Error(t, err, "Expected error for wrong channel header type")

	chdr, _ = proto.Marshal(&pcommon.ChannelHeader{
		Type: int32(pcommon.HeaderType_CONFIG),
	})
	payload, _ = proto.Marshal(&pcommon.Payload{
		Header: &pcommon.Header{
			ChannelHeader: chdr,
		},
		Data: []byte("bad data"),
	})
	env.Payload = payload
	_, err = protoutil.UnmarshalEnvelopeOfType(env, pcommon.HeaderType_CONFIG, &pcommon.ConfigEnvelope{})
	require.Error(t, err, "Expected error for malformed payload data")

	chdr, _ = proto.Marshal(&pcommon.ChannelHeader{
		Type: int32(pcommon.HeaderType_CONFIG),
	})
	configEnv, _ := proto.Marshal(&pcommon.ConfigEnvelope{})
	payload, _ = proto.Marshal(&pcommon.Payload{
		Header: &pcommon.Header{
			ChannelHeader: chdr,
		},
		Data: configEnv,
	})
	env.Payload = payload
	_, err = protoutil.UnmarshalEnvelopeOfType(env, pcommon.HeaderType_CONFIG, &pcommon.ConfigEnvelope{})
	require.NoError(t, err, "Unexpected error unmarshalling envelope")
}

func TestExtractEnvelopeNilData(t *testing.T) {
	block := &pcommon.Block{}
	_, err := protoutil.ExtractEnvelope(block, 0)
	require.Error(t, err, "Nil data")
}

func TestExtractEnvelopeWrongIndex(t *testing.T) {
	block := testBlock()
	if _, err := protoutil.ExtractEnvelope(block, len(block.GetData().Data)); err == nil {
		t.Fatal("Expected envelope extraction to fail (wrong index)")
	}
}

func TestExtractEnvelopeWrongIndexOrPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Expected envelope extraction to panic (wrong index)")
		}
	}()

	block := testBlock()
	protoutil.ExtractEnvelopeOrPanic(block, len(block.GetData().Data))
}

func TestExtractEnvelope(t *testing.T) {
	if envelope, err := protoutil.ExtractEnvelope(testBlock(), 0); err != nil {
		t.Fatalf("Expected envelop extraction to succeed: %s", err)
	} else if !proto.Equal(envelope, testEnvelope()) {
		t.Fatal("Expected extracted envelope to match test envelope")
	}
}

func TestExtractEnvelopeOrPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatal("Expected envelope extraction to succeed")
		}
	}()

	if !proto.Equal(protoutil.ExtractEnvelopeOrPanic(testBlock(), 0), testEnvelope()) {
		t.Fatal("Expected extracted envelope to match test envelope")
	}
}

func TestExtractPayload(t *testing.T) {
	if payload, err := protoutil.UnmarshalPayload(testEnvelope().Payload); err != nil {
		t.Fatalf("Expected payload extraction to succeed: %s", err)
	} else if !proto.Equal(payload, testPayload()) {
		t.Fatal("Expected extracted payload to match test payload")
	}
}

func TestExtractPayloadOrPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatal("Expected payload extraction to succeed")
		}
	}()

	if !proto.Equal(protoutil.UnmarshalPayloadOrPanic(testEnvelope().Payload), testPayload()) {
		t.Fatal("Expected extracted payload to match test payload")
	}
}

func TestUnmarshalChaincodeID(t *testing.T) {
	ccname := "mychaincode"
	ccversion := "myversion"
	ccidbytes, _ := proto.Marshal(&ppeer.ChaincodeID{
		Name:    ccname,
		Version: ccversion,
	})
	ccid, err := protoutil.UnmarshalChaincodeID(ccidbytes)
	require.NoError(t, err)
	require.Equal(t, ccname, ccid.Name, "Expected ccid names to match")
	require.Equal(t, ccversion, ccid.Version, "Expected ccid versions to match")

	_, err = protoutil.UnmarshalChaincodeID([]byte("bad chaincodeID"))
	require.Error(t, err, "Expected error marshaling malformed chaincode ID")
}

func TestNewSignatureHeaderOrPanic(t *testing.T) {
	var sigHeader *pcommon.SignatureHeader

	id := &mocks.Signer{}
	id.SetSerializeReturnsOnCall(0, []byte("serialized"), nil)
	id.SetSerializeReturnsOnCall(1, nil, errors.New("serialize failed"))
	creator, _ := id.Serialize()
	sigHeader = protoutil.NewSignatureHeaderOrPanic(creator)
	require.NotNil(t, sigHeader, "Signature header should not be nil")

	require.Panics(t, func() {
		_ = protoutil.NewSignatureHeaderOrPanic(nil)
	}, "Expected panic with nil signer")
}

func TestSignOrPanic(t *testing.T) {
	msg := []byte("sign me")
	signer := &mocks.Signer{}
	signer.SetSignReturnsOnCall(0, msg, nil)
	signer.SetSignReturnsOnCall(1, nil, errors.New("bad signature"))
	sig := protoutil.SignOrPanic(signer, msg)
	// mock signer returns message to be signed
	require.Equal(t, msg, sig, "Signature does not match expected value")

	require.Panics(t, func() {
		_ = protoutil.SignOrPanic(nil, []byte("sign me"))
	}, "Expected panic with nil signer")

	require.Panics(t, func() {
		_ = protoutil.SignOrPanic(signer, []byte("sign me"))
	}, "Expected panic with sign error")
}

// Helper functions

func testPayload() *pcommon.Payload {
	return &pcommon.Payload{
		Header: protoutil.MakePayloadHeader(
			protoutil.MakeChannelHeader(pcommon.HeaderType_MESSAGE, int32(1), "test", 0),
			protoutil.MakeSignatureHeader([]byte("creator"), []byte("nonce"))),
		Data: []byte("test"),
	}
}

func testEnvelope() *pcommon.Envelope {
	// No need to set the signature
	return &pcommon.Envelope{Payload: protoutil.MarshalOrPanic(testPayload())}
}

func testBlock() *pcommon.Block {
	// No need to set the block's Header, or Metadata
	return &pcommon.Block{
		Data: &pcommon.BlockData{
			Data: [][]byte{protoutil.MarshalOrPanic(testEnvelope())},
		},
	}
}

func TestChannelHeader(t *testing.T) {
	makeEnvelope := func(payload *pcommon.Payload) *pcommon.Envelope {
		return &pcommon.Envelope{
			Payload: protoutil.MarshalOrPanic(payload),
		}
	}

	_, err := protoutil.ExtractChannelHeaderFromEnvelope(makeEnvelope(&pcommon.Payload{
		Header: &pcommon.Header{
			ChannelHeader: protoutil.MarshalOrPanic(&pcommon.ChannelHeader{
				ChannelId: "foo",
			}),
		},
	}))
	require.NoError(t, err, "Channel header was present")

	_, err = protoutil.ExtractChannelHeaderFromEnvelope(makeEnvelope(&pcommon.Payload{
		Header: &pcommon.Header{},
	}))
	require.Error(t, err, "ChannelHeader was missing")

	_, err = protoutil.ExtractChannelHeaderFromEnvelope(makeEnvelope(&pcommon.Payload{}))
	require.Error(t, err, "Header was missing")

	_, err = protoutil.ExtractChannelHeaderFromEnvelope(&pcommon.Envelope{})
	require.Error(t, err, "Payload was missing")
}

func TestIsConfigBlock(t *testing.T) {
	newBlock := func(env *pcommon.Envelope) *pcommon.Block {
		return &pcommon.Block{
			Data: &pcommon.BlockData{
				Data: [][]byte{protoutil.MarshalOrPanic(env)},
			},
		}
	}

	newConfigEnv := func(envType int32) *pcommon.Envelope {
		return &pcommon.Envelope{
			Payload: protoutil.MarshalOrPanic(&pcommon.Payload{
				Header: &pcommon.Header{
					ChannelHeader: protoutil.MarshalOrPanic(&pcommon.ChannelHeader{
						Type:      envType,
						ChannelId: "test-chain",
					}),
				},
				Data: []byte("test bytes"),
			}), // common.Payload
		} // LastUpdate
	}

	// scenario 1: CONFIG envelope
	envType := int32(pcommon.HeaderType_CONFIG)
	env := newConfigEnv(envType)
	block := newBlock(env)

	result := protoutil.IsConfigBlock(block)
	require.True(t, result, "IsConfigBlock returns true for blocks with CONFIG envelope")

	// scenario 2: ORDERER_TRANSACTION envelope
	envType = int32(pcommon.HeaderType_ORDERER_TRANSACTION)
	env = newConfigEnv(envType)
	block = newBlock(env)

	result = protoutil.IsConfigBlock(block)
	require.False(t, result, "IsConfigBlock returns false for blocks with ORDERER_TRANSACTION envelope since it is no longer supported")

	// scenario 3: MESSAGE envelope
	envType = int32(pcommon.HeaderType_MESSAGE)
	env = newConfigEnv(envType)
	block = newBlock(env)

	result = protoutil.IsConfigBlock(block)
	require.False(t, result, "IsConfigBlock returns false for blocks with MESSAGE envelope")

	// scenario 4: Data with more than one tx
	result = protoutil.IsConfigBlock(&pcommon.Block{
		Header:   nil,
		Data:     &pcommon.BlockData{Data: [][]byte{{1, 2, 3, 4}, {1, 2, 3, 4}}},
		Metadata: nil,
	})
	require.False(t, result, "IsConfigBlock returns false for blocks with more than one transaction")

	// scenario 5: nil data
	result = protoutil.IsConfigBlock(&pcommon.Block{
		Header:   nil,
		Data:     nil,
		Metadata: nil,
	})
	require.False(t, result, "IsConfigBlock returns false for blocks with no data")
}

func TestEnvelopeToConfigUpdate(t *testing.T) {
	makeEnv := func(data []byte) *pcommon.Envelope {
		return &pcommon.Envelope{
			Payload: protoutil.MarshalOrPanic(&pcommon.Payload{
				Header: &pcommon.Header{
					ChannelHeader: protoutil.MarshalOrPanic(&pcommon.ChannelHeader{
						Type:      int32(pcommon.HeaderType_CONFIG_UPDATE),
						ChannelId: "test-chain",
					}),
				},
				Data: data,
			}), // common.Payload
		} // LastUpdate
	}

	// scenario 1: for valid envelopes
	configUpdateEnv := &pcommon.ConfigUpdateEnvelope{}
	env := makeEnv(protoutil.MarshalOrPanic(configUpdateEnv))
	result, err := protoutil.EnvelopeToConfigUpdate(env)

	require.NoError(t, err, "EnvelopeToConfigUpdate runs without error for valid CONFIG_UPDATE envelope")
	require.Equal(t, configUpdateEnv, result, "Correct configUpdateEnvelope returned")

	// scenario 2: for invalid envelopes
	env = makeEnv([]byte("test bytes"))
	_, err = protoutil.EnvelopeToConfigUpdate(env)

	require.Error(t, err, "EnvelopeToConfigUpdate fails with error for invalid CONFIG_UPDATE envelope")
}

func TestGetRandomNonce(t *testing.T) {
	key1, err := protoutil.CreateNonce()
	require.NoErrorf(t, err, "error getting random bytes")
	require.Len(t, key1, 24)
}
