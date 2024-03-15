package utils_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/11090815/mayy/csp/softimpl/utils"
	"github.com/stretchr/testify/require"
)

func TestPrivateKeyTransfer(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	p, err := utils.PrivateKeyToPEM(privateKey)
	require.NoError(t, err)

	sk, err := utils.PEMToPrivateKey(p)
	require.NoError(t, err)

	require.IsType(t, &ecdsa.PrivateKey{}, sk)

	d, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	p2 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: d})
	require.Equal(t, p, p2)
}

func TestInterfaceCast(t *testing.T) {
	var pk *ecdsa.PublicKey

	testFunc := func(k interface{}) {
		if k== nil {
			t.Log("invalid param, nil interface{}")
			return
		}

		switch tk := k.(type) {
		case *ecdsa.PublicKey:
			if tk == nil {
				t.Log("invalid param, nil ECDSA public key")
				return
			}
		default:
			t.Log("cannot catch here")
		}
	}

	testFunc(pk)
}
