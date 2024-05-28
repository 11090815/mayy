package msp

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/11090815/mayy/csp/softimpl/ecdsa"
	"github.com/11090815/mayy/csp/softimpl/tlsca"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalSignature(t *testing.T) {
	generator := tlsca.NewTLSCAGenerator()
	ca, err := generator.GenCA(&tlsca.TLSCAGenOpts{Level: 384})
	require.NoError(t, err)
	block, _ := pem.Decode(ca.CertBytes())
	caCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	caCert, err = sanitizeECDSASignedCert(caCert, caCert)
	require.NoError(t, err)

	server, err := ca.NewServerCertKeyPair()
	require.NoError(t, err)
	block, _ = pem.Decode(server.Cert())
	serverCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	require.True(t, isECDSASignedCert(serverCert))
	serverCert, err = sanitizeECDSASignedCert(serverCert, caCert)
	require.NoError(t, err)

	r, s, err := ecdsa.UnmarshalECDSASignature(serverCert.Signature)
	require.NoError(t, err)

	sig, err := ecdsa.MarshalECDSASignature(r, s)
	require.NoError(t, err)
	require.Equal(t, sig, serverCert.Signature)
}
