package msp

import (
	"crypto/x509"
	"time"
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
			cert, err = sanitizeECDSASignedCert(cert, cert)
			if err != nil {
				return nil, err
			}
			isRootCACert = true
			validityOpts.Roots = x509.NewCertPool()
			validityOpts.Roots.AddCert(cert)
		}
	}
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
