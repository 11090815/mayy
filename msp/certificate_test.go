package msp

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"github.com/11090815/mayy/csp/softimpl/tlsca"
	"github.com/stretchr/testify/require"
)

func TestCertificateVerify(t *testing.T) {
	generator := tlsca.NewTLSCAGenerator()
	ca, err := generator.GenCA(&tlsca.TLSCAGenOpts{Level: 384})
	require.NoError(t, err)

	// CA 证书
	block, _ := pem.Decode(ca.CertBytes())
	caCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	// 1 中级 CA 证书
	intermediateCA1, err := ca.NewIntermediateCA()
	require.NoError(t, err)
	block, _ = pem.Decode(intermediateCA1.CertBytes())
	intermediateCACert1, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	// 2 中级 CA 证书
	intermediateCA2, err := intermediateCA1.NewIntermediateCA()
	require.NoError(t, err)
	block, _ = pem.Decode(intermediateCA2.CertBytes())
	intermediateCACert2, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	// 2 中级 CA 产生的 client 证书
	client, err := intermediateCA2.NewClientCertKeyPair()
	require.NoError(t, err)
	block, _ = pem.Decode(client.Cert())
	clientCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	roots.AddCert(intermediateCACert1)
	roots.AddCert(intermediateCACert2)

	intermediates := x509.NewCertPool()
	intermediates.AddCert(caCert)
	intermediates.AddCert(intermediateCACert1)
	intermediates.AddCert(intermediateCACert2)
	// intermediates.AddCert(clientCert)

	verifyOpts := x509.VerifyOptions{
		CurrentTime:   clientCert.NotBefore.Add(time.Second),
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     clientCert.ExtKeyUsage,
	}

	validationChains, err := clientCert.Verify(verifyOpts)
	require.NoError(t, err)

	t.Logf("validation chains len [%d]", len(validationChains))
	t.Logf("validation chains[0] len [%d]", len(validationChains[0]))
	for i, chain := range validationChains {
		for j, cert := range chain {
			t.Logf("chain [%d] cert [%d] [%x]", i, j, cert.Raw[:64])
		}
	}

	t.Logf("ca [%x]", caCert.Raw[:64])
	t.Logf("intermediateCA1 [%x]", intermediateCACert1.Raw[:64])
	t.Logf("intermediateCA2 [%x]", intermediateCACert2.Raw[:64])
	t.Logf("clientCert [%x]", clientCert.Raw[:64])

	fmt.Println("===================== Verify CA =====================")

	validationChains, err = caCert.Verify(verifyOpts)
	require.NoError(t, err)
	t.Logf("validation chains len [%d]", len(validationChains))
	t.Logf("validation chains[0] len [%d]", len(validationChains[0]))
	for i, chain := range validationChains {
		for j, cert := range chain {
			t.Logf("chain [%d] cert [%d] [%x]", i, j, cert.Raw[:64])
		}
	}
}
