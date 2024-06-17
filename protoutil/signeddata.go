package protoutil

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/11090815/mayy/common/errors"
	"github.com/11090815/mayy/protobuf/pcommon"
)

// SignedData 结构体封装了用于验证签名的三元组：数据（Data）、身份（Identity）和签名（Signature）。
// 在大多数密码方案中，Data 通常包含签名者的身份和一个随机数。
type SignedData struct {
	Data      []byte
	Identity  []byte
	Signature []byte
}

func ConfigUpdateEnvelopeAsSignedData(configUpdateEnvelope *pcommon.ConfigUpdateEnvelope) ([]*SignedData, error) {
	if configUpdateEnvelope == nil {
		return nil, errors.NewError("the given config update envelope is nil")
	}

	signedDatas := make([]*SignedData, len(configUpdateEnvelope.Signatures))
	for i, signature := range configUpdateEnvelope.Signatures {
		signatureHeader, err := UnmarshalSignatureHeader(signature.SignatureHeader)
		if err != nil {
			return nil, err
		}
		signedDatas[i] = &SignedData{
			Data:      bytes.Join([][]byte{signature.SignatureHeader, configUpdateEnvelope.ConfigUpdate}, nil),
			Identity:  signatureHeader.Creator,
			Signature: signature.Signature,
		}
	}

	return signedDatas, nil
}

func EnvelopeAsSignedData(envelope *pcommon.Envelope) ([]*SignedData, error) {
	if envelope == nil {
		return nil, errors.NewError("the given envelope is nil")
	}

	payload, err := UnmarshalPayload(envelope.Payload)
	if err != nil {
		return nil, err
	}

	if payload.Header == nil {
		return nil, errors.NewError("missing header")
	}

	signatureHeader, err := UnmarshalSignatureHeader(payload.Header.SignatureHeader)
	if err != nil {
		return nil, err
	}

	return []*SignedData{
		{
			Data:      envelope.Payload,
			Identity:  signatureHeader.Creator,
			Signature: envelope.Signature,
		},
	}, nil
}

func LogMessageForSerializedIdentity(encodedSerializedIdentity []byte) string {
	serializedIdentity, err := UnmarshalSerializedIdentity(encodedSerializedIdentity)
	if err != nil {
		return err.Error()
	}

	pemBlock, _ := pem.Decode(serializedIdentity.IdBytes)
	if pemBlock == nil {
		if len(encodedSerializedIdentity) > 32 {
			return fmt.Sprintf("cannot parse identity \"%x...\"", encodedSerializedIdentity[:32])
		} else {
			return fmt.Sprintf("cannot parse identity \"%x\"", encodedSerializedIdentity)
		}
	}

	x509Certificate, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return fmt.Sprintf("failed parsing x509 certificate, the error is \"%s\"", err.Error())
	}

	return fmt.Sprintf("(mspid=%s subject=%s issuer=%s serialnumber=%d)", serializedIdentity.Mspid, x509Certificate.Subject, x509Certificate.Issuer, x509Certificate.SerialNumber)
}

func LogMessageForSerializedIdentities(signedData []*SignedData) string {
	var identityMessages []string
	for _, sd := range signedData {
		identityMessages = append(identityMessages, LogMessageForSerializedIdentity(sd.Identity))
	}
	return strings.Join(identityMessages, ", ")
}
