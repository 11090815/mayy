package msp

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"

	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/csp/softimpl/ecdsa"
	"github.com/11090815/mayy/common/errors"
	"github.com/11090815/mayy/protobuf/pmsp"
	"google.golang.org/protobuf/proto"
)

var (
	subjectKeyIdentifier   = asn1.ObjectIdentifier{2, 5, 29, 14} // 在证书的扩展字段，subjectKeyIdentifier 用来标识证书的唯一标识符。
	authorityKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 35} // 在证书的扩展字段，authorityKeyIdentifier 代表签发此证书的权威机构的标识符，一般是权威机构证书公钥的哈希值。

	mspLogger = mlog.GetLogger("msp", mlog.DebugLevel, true)
)

type authority struct {
	AuthorityKeyIdentifier    []byte  `asn1:"optional,tag:0"`
	AuthorityCertIssuer       []byte  `asn1:"optional,tag:1"`
	AuthorityCertSerialNumber big.Int `asn1:"optional,tag:2"`
}

func getAuthorityKeyIdentifierFromCrl(crl *x509.RevocationList) ([]byte, error) {
	for _, ext := range crl.Extensions {
		if ext.Id.Equal(authorityKeyIdentifier) {
			var auth authority
			if _, err := asn1.Unmarshal(ext.Value, &auth); err != nil {
				return nil, errors.NewErrorf("failed getting authority key identifier from x509 revocation list %s, the error is \"%s\"", crl.Number.String(), err)
			} else {
				return auth.AuthorityKeyIdentifier, nil
			}
		}
	}

	return nil, errors.NewErrorf("cannot find authority key identifier from x509 certificate %s", crl.Number.String())
}

func getSubjectKeyIdentifierFromCert(cert *x509.Certificate) ([]byte, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(subjectKeyIdentifier) {
			var ski []byte
			if _, err := asn1.Unmarshal(ext.Value, &ski); err != nil {
				return nil, errors.NewErrorf("failed getting subject key identifier from x509 certificate %s, the error is \"%s\"", cert.SerialNumber.String(), err)
			} else {
				return ski, nil
			}
			// return ext.Value, nil
		}
	}

	return nil, errors.NewErrorf("cannot find subject key identifier from x509 certificate %s", cert.SerialNumber.String())
}

// collectPrinciples 将 combined principle 内含有的所有 principle 放入到一个数组中。
func collectPrinciples(principle *pmsp.MSPPrinciple, mspVersion MSPVersion) ([]*pmsp.MSPPrinciple, error) {
	switch principle.PrincipleClassification {
	case pmsp.MSPPrinciple_COMBINED:
		if mspVersion != MSPv1_0 {
			return nil, errors.NewErrorf("combined principles are not supported in msp v%d", mspVersion)
		}
		combinedPrinciple := &pmsp.CombinedPrinciple{}
		if err := proto.Unmarshal(principle.Principle, combinedPrinciple); err != nil {
			return nil, errors.NewErrorf("failed collecting principles, the error is \"%s\"", err.Error())
		}
		if len(combinedPrinciple.Principles) == 0 {
			return nil, errors.NewError("failed collecting principles, no principles in combined principle")
		}
		var principles []*pmsp.MSPPrinciple
		for _, p := range combinedPrinciple.Principles {
			internalPrinciples, err := collectPrinciples(p, mspVersion)
			if err != nil {
				return nil, err
			}
			principles = append(principles, internalPrinciples...)
		}
		return principles, nil
	default:
		return []*pmsp.MSPPrinciple{principle}, nil
	}
}

func oidInExtensions(oid asn1.ObjectIdentifier, exts []pkix.Extension) bool {
	for _, ext := range exts {
		if ext.Id.Equal(oid) {
			return true
		}
	}
	return false
}

func isIdentitySignedInCanonicalForm(sig []byte, mspID string, pemEncodedIdentity []byte) error {
	r, s, err := ecdsa.UnmarshalECDSASignature(sig)
	if err != nil {
		return err
	}

	expectedSig, err := ecdsa.MarshalECDSASignature(r, s)
	if err != nil {
		return err
	}

	if !bytes.Equal(expectedSig, sig) {
		return errors.NewErrorf("identity %s for msp %s has a non canonical signature", string(pemEncodedIdentity), mspID)
	}

	return nil
}
