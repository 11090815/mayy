package msp

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"time"

	"github.com/11090815/mayy/errors"
)

var (
	oidExtensionSubjectAltName  = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtensionNameConstraints = asn1.ObjectIdentifier{2, 5, 29, 30}
)

type msp struct {
	version MSPVersion

	// opts 提供用于验证 msp 成员的 x509 证书的选项。
	opts *x509.VerifyOptions
}

func (msp *msp) sanitizeCert(cert *x509.Certificate) (*x509.Certificate, error) {
	var err error

	if isECDSASignedCert(cert) {
		isRootCACert := false
		validityOpts := msp.getValidityOptsForCert(cert)
		if cert.IsCA && cert.CheckSignatureFrom(cert) == nil {
			cert, err = sanitizeECDSASignedCert(cert, cert) // 净化签名
			if err != nil {
				return nil, err
			}
			isRootCACert = true
			validityOpts.Roots = x509.NewCertPool()
			validityOpts.Roots.AddCert(cert)
		}

		chain, err := msp.getUniqueValidationChain(cert, validityOpts)
		if err != nil {
			return nil, err
		}

		if isRootCACert {
			return cert, nil
		}

		if len(chain) <= 1 {
			return nil, errors.NewErrorf("failed to traverse certificate verification chain for leaf or intermediate certificate, with subject %s", cert.Subject)
		}
		return sanitizeECDSASignedCert(cert, chain[1])
	}
	return cert, nil
}

func (msp *msp) getUniqueValidationChain(cert *x509.Certificate, opts x509.VerifyOptions) ([]*x509.Certificate, error) {
	validationChains, err := cert.Verify(opts) // Verify 的用法可以参考 certificate_test.go 中的测试案例 TestCertificateVerify
	if err != nil {
		return nil, errors.NewErrorf("failed verifying the given certificate against verify options %v, the error is \"%s\"", opts, err.Error())
	}

	if err = verifyLegacyNameConstraints(validationChains[0]); err != nil {
		return nil, errors.NewErrorf("failed verifying legacy name constraints, the error is \"%s\"", err.Error())
	}

	return validationChains[0], nil
}

func verifyLegacyNameConstraints(chain []*x509.Certificate) error {
	if len(chain) < 2 { // CA 证书
		return nil
	}

	if oidInExtensions(oidExtensionSubjectAltName, chain[0].Extensions) {
		return nil
	}

	return nil
}

func oidInExtensions(oid asn1.ObjectIdentifier, exts []pkix.Extension) bool {
	for _, ext := range exts {
		if ext.Id.Equal(oid) {
			return true
		}
	}
	return false
}

func (msp *msp) getValidityOptsForCert(cert *x509.Certificate) x509.VerifyOptions {
	return x509.VerifyOptions{
		Roots:         msp.opts.Roots,
		DNSName:       msp.opts.DNSName,
		Intermediates: msp.opts.Intermediates,
		KeyUsages:     msp.opts.KeyUsages,
		CurrentTime:   cert.NotBefore.Add(time.Second),
	}
}
