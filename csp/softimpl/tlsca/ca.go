package tlsca

import (
	"crypto"

	"github.com/11090815/mayy/csp"
	"github.com/11090815/mayy/errors"
)

type ca struct {
	keyPair       csp.CertKeyPair
	securityLevel int
}

func newCA(level int) (*ca, error) {
	c := &ca{securityLevel: level}
	var err error
	c.keyPair, err = newCertKeyPair(level, true, false, nil, nil)
	if err != nil {
		return nil, errors.NewErrorf("failed generating tls CA, the error is \"%s\"", err.Error())
	}
	return c, nil
}

func (c *ca) NewIntermediateCA() (csp.CA, error) {
	intermediateCA := &ca{securityLevel: c.securityLevel}
	var err error
	intermediateCA.keyPair, err = newCertKeyPair(c.securityLevel, true, false, c.keyPair.Signer(), c.keyPair.X509Cert())
	if err != nil {
		return nil, errors.NewErrorf("failed generating intermediate tls CA, the error is \"%s\"", err.Error())
	}

	return intermediateCA, nil
}

func (c *ca) CertBytes() []byte {
	return c.keyPair.Cert()
}

func (c *ca) KeyBytes() []byte {
	return c.keyPair.Key()
}

func (c *ca) NewClientCertKeyPair() (csp.CertKeyPair, error) {
	return newCertKeyPair(c.securityLevel, false, false, c.keyPair.Signer(), c.keyPair.X509Cert())
}

func (c *ca) NewServerCertKeyPair(hosts ...string) (csp.CertKeyPair, error) {
	return newCertKeyPair(c.securityLevel, false, true, c.keyPair.Signer(), c.keyPair.X509Cert(), hosts...)
}

func (c *ca) Signer() crypto.Signer {
	return c.keyPair.Signer()
}
