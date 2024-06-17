package protoutil_test

import (
	"bytes"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/11090815/mayy/common/errors"
	"github.com/11090815/mayy/protobuf/pcommon"
	"github.com/11090815/mayy/protobuf/pmsp"
	"github.com/11090815/mayy/protoutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func marshalOrPanic(msg proto.Message) []byte {
	data, err := proto.Marshal(msg)
	if err != nil {
		panic("Error marshaling")
	}
	return data
}

func TestNilConfigEnvelopeAsSignedData(t *testing.T) {
	var ce *pcommon.ConfigUpdateEnvelope
	_, err := protoutil.ConfigUpdateEnvelopeAsSignedData(ce)
	if err == nil {
		t.Fatalf("Should have errored trying to convert a nil signed config item to signed data")
	}
}

func TestConfigEnvelopeAsSignedData(t *testing.T) {
	configBytes := []byte("Foo")
	signatures := [][]byte{[]byte("Signature1"), []byte("Signature2")}
	identities := [][]byte{[]byte("Identity1"), []byte("Identity2")}

	configSignatures := make([]*pcommon.ConfigSignature, len(signatures))
	for i := range configSignatures {
		configSignatures[i] = &pcommon.ConfigSignature{
			SignatureHeader: marshalOrPanic(&pcommon.SignatureHeader{
				Creator: identities[i],
			}),
			Signature: signatures[i],
		}
	}

	ce := &pcommon.ConfigUpdateEnvelope{
		ConfigUpdate: configBytes,
		Signatures:   configSignatures,
	}

	signedData, err := protoutil.ConfigUpdateEnvelopeAsSignedData(ce)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	for i, sigData := range signedData {
		if !bytes.Equal(sigData.Identity, identities[i]) {
			t.Errorf("Expected identity to match at index %d", i)
		}
		if !bytes.Equal(sigData.Data, append(configSignatures[i].SignatureHeader, configBytes...)) {
			t.Errorf("Expected signature over concatenation of config item bytes and signature header")
		}
		if !bytes.Equal(sigData.Signature, signatures[i]) {
			t.Errorf("Expected signature to match at index %d", i)
		}
	}
}

func TestNilEnvelopeAsSignedData(t *testing.T) {
	var env *pcommon.Envelope
	_, err := protoutil.EnvelopeAsSignedData(env)
	if err == nil {
		t.Fatalf("Should have errored trying to convert a nil envelope")
	}
}

func TestEnvelopeAsSignedData(t *testing.T) {
	identity := []byte("Foo")
	sig := []byte("Bar")

	shdrbytes, err := proto.Marshal(&pcommon.SignatureHeader{Creator: identity})
	if err != nil {
		t.Fatalf("%s", err)
	}

	env := &pcommon.Envelope{
		Payload: marshalOrPanic(&pcommon.Payload{
			Header: &pcommon.Header{
				SignatureHeader: shdrbytes,
			},
		}),
		Signature: sig,
	}

	signedData, err := protoutil.EnvelopeAsSignedData(env)
	if err != nil {
		t.Fatalf("Unexpected error converting envelope to SignedData: %s", err)
	}

	if len(signedData) != 1 {
		t.Fatalf("Expected 1 entry of signed data, but got %d", len(signedData))
	}

	if !bytes.Equal(signedData[0].Identity, identity) {
		t.Errorf("Wrong identity bytes")
	}
	if !bytes.Equal(signedData[0].Data, env.Payload) {
		t.Errorf("Wrong data bytes")
	}
	if !bytes.Equal(signedData[0].Signature, sig) {
		t.Errorf("Wrong data bytes")
	}
}

func TestLogMessageForSerializedIdentity(t *testing.T) {
	pem, err := readPemFile(filepath.Join("testdata", "peer-expired.pem"))
	require.NoError(t, err, "Unexpected error reading pem file")

	serializedIdentity := &pmsp.SerializedIdentity{
		Mspid:   "MyMSP",
		IdBytes: pem,
	}

	serializedIdentityBytes, err := proto.Marshal(serializedIdentity)
	require.NoError(t, err, "Unexpected error marshaling")

	identityLogMessage := protoutil.LogMessageForSerializedIdentity(serializedIdentityBytes)

	expected := "(mspid=MyMSP subject=CN=peer0.org1.example.com,L=San Francisco,ST=California,C=US issuer=CN=ca.org1.example.com,O=org1.example.com,L=San Francisco,ST=California,C=US serialnumber=216422593083731187380743188920914963441)"
	require.Equal(t, expected, identityLogMessage)

	signedDatas := []*protoutil.SignedData{
		{
			Data:      nil,
			Identity:  serializedIdentityBytes,
			Signature: nil,
		},
		{
			Data:      nil,
			Identity:  serializedIdentityBytes,
			Signature: nil,
		},
	}

	identitiesLogMessage := protoutil.LogMessageForSerializedIdentities(signedDatas)

	expected =
		"(mspid=MyMSP subject=CN=peer0.org1.example.com,L=San Francisco,ST=California,C=US issuer=CN=ca.org1.example.com,O=org1.example.com,L=San Francisco,ST=California,C=US serialnumber=216422593083731187380743188920914963441), " +
			"(mspid=MyMSP subject=CN=peer0.org1.example.com,L=San Francisco,ST=California,C=US issuer=CN=ca.org1.example.com,O=org1.example.com,L=San Francisco,ST=California,C=US serialnumber=216422593083731187380743188920914963441)"
	require.Equal(t, expected, identitiesLogMessage)
}

func readFile(file string) ([]byte, error) {
	fileCont, err := os.ReadFile(file)
	if err != nil {
		return nil, errors.NewErrorf("could not read file \"%s\", the error is \"%s\"", file, err.Error())
	}
	return fileCont, nil
}

func readPemFile(file string) ([]byte, error) {
	bytes, err := readFile(file)
	if err != nil {
		return nil, errors.NewErrorf("reading from file \"%s\" failed, the error is \"%s\"", file, err.Error())
	}

	b, _ := pem.Decode(bytes)
	if b == nil {
		return nil, errors.NewErrorf("no pem content for file \"%s\"", file)
	}

	return bytes, nil
}
