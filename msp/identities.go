package msp

import (
	"crypto/x509"
	"sync"

	"github.com/11090815/mayy/csp"
)

type identity struct {
	// identityIdentifier 简单的表示身份的身份标识符。
	identityIdentifier *IdentityIdentifier

	// cert 此身份的 x509 证书。
	cert *x509.Certificate

	// publicKey 此身份的公钥。
	publicKey csp.Key

	// msp 是一个索引，该 msp 管理此身份。
	msp *msp

	validationMutex sync.Mutex

	validated bool

	validationErr error
}

func newIdentity()
