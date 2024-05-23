package msp

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	goecdsa "crypto/ecdsa"

	"github.com/11090815/mayy/csp/softimpl/ecdsa"
	"github.com/11090815/mayy/errors"
)

type validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type certificate struct {
	Raw                asn1.RawContent
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          publicKeyInfo
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

func isECDSASignedCert(cert *x509.Certificate) bool {
	return cert.SignatureAlgorithm == x509.ECDSAWithSHA1 ||
		cert.SignatureAlgorithm == x509.ECDSAWithSHA256 ||
		cert.SignatureAlgorithm == x509.ECDSAWithSHA384 ||
		cert.SignatureAlgorithm == x509.ECDSAWithSHA512
}

func sanitizeECDSASignedCert(cert *x509.Certificate, parentCert *x509.Certificate) (*x509.Certificate, error) {
	if cert == nil {
		return nil, errors.NewError("certificate must not be nil")
	}
	if parentCert == nil {
		return nil, errors.NewError("parent certificate must not be nil")
	}

	expectedSig, err := ecdsa.SignatureToLowS(parentCert.PublicKey.(*goecdsa.PublicKey), cert.Signature)
	if err != nil {
		return nil, err
	}

	// 净化后的签名如果没有变化，那么直接返回原始签名
	if bytes.Equal(cert.Signature, expectedSig) {
		return cert, nil
	}

	newCert, err := certFromX509Cert(cert)
	if err != nil {
		return nil, errors.NewErrorf("failed sanitizing ECDSA signed certificate, the error is \"%s\"", err.Error())
	}

	newCert.SignatureValue = asn1.BitString{Bytes: expectedSig, BitLength: len(expectedSig) * 8}
	newCert.Raw = nil

	newCertRaw, err := asn1.Marshal(newCert)
	if err != nil {
		return nil, errors.NewErrorf("failed sanitizing ECDSA signed certificate, the error is \"%s\"", err.Error())
	}

	return x509.ParseCertificate(newCertRaw)
}

func certFromX509Cert(cert *x509.Certificate) (certificate, error) {
	var newCert = &certificate{}
	if _, err := asn1.Unmarshal(cert.Raw, newCert); err != nil {
		return certificate{}, err
	}
	return *newCert, nil
}

func (c certificate) String() string {
	b, err := asn1.Marshal(c)
	if err != nil {
		return fmt.Sprintf("Failed marshaling certificate: %s", err.Error())
	}
	block := &pem.Block{
		Bytes: b,
		Type:  "CERTIFICATE",
	}
	b = pem.EncodeToMemory(block)
	return string(b)
}

func certificateToPEM(cert *x509.Certificate) string {
	newCert, err := certFromX509Cert(cert)
	if err != nil {
		return ""
	}
	return newCert.String()
}
