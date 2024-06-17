package signer

import (
	"crypto"
	"io"

	"github.com/11090815/mayy/csp"
	"github.com/11090815/mayy/common/errors"
)

type signer struct {
	csp csp.CSP
	sk  csp.Key
	pk  csp.Key
}

func NewSigner(csp csp.CSP, key csp.Key) (crypto.Signer, error) {
	if csp == nil {
		return nil, errors.NewError("csp instance must be specified")
	}

	if key == nil {
		return nil, errors.NewError("the private key of the signer must be specified")
	}

	pk, err := key.PublicKey()
	if err != nil {
		return nil, err
	}

	return &signer{csp: csp, sk: key, pk: pk}, nil
}

func (s *signer) Public() crypto.PublicKey {
	return s.pk
}

func (s *signer) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.csp.Sign(s.sk, digest, opts)
}
