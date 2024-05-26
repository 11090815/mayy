package msp

import (
	goecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
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
	// roots.AddCert(intermediateCACert1)
	// roots.AddCert(intermediateCACert2)

	intermediates := x509.NewCertPool()
	// intermediates.AddCert(caCert)
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

	fmt.Println("===================== Verify Client Certificate =====================")

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

	fmt.Println("===================== Verify Intermediate CA =====================")

	validationChains, err = intermediateCACert1.Verify(verifyOpts)
	require.NoError(t, err)
	t.Logf("validation chains len [%d]", len(validationChains))
	t.Logf("validation chains[0] len [%d]", len(validationChains[0]))
	for i, chain := range validationChains {
		for j, cert := range chain {
			t.Logf("chain [%d] cert [%d] [%x]", i, j, cert.Raw[:64])
		}
	}
}

func TestFindAKIAndSKIFromCert(t *testing.T) {
	generator := tlsca.NewTLSCAGenerator()
	ca, err := generator.GenCA(&tlsca.TLSCAGenOpts{Level: 384})
	require.NoError(t, err)
	block, _ := pem.Decode(ca.CertBytes())
	caCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	caCertSki, err := getSubjectKeyIdentifierFromCert(caCert)
	require.NoError(t, err)
	t.Logf("ca cert ski [%x]", caCertSki)
	caPK, ok := caCert.PublicKey.(*goecdsa.PublicKey)
	if ok {
		raw := elliptic.Marshal(caPK.Curve, caPK.X, caPK.Y)
		digest := sha256.Sum256(raw)
		t.Logf("ca cert ski [%x]", digest)
	}

	server, err := ca.NewServerCertKeyPair("127.0.0.1")
	require.NoError(t, err)
	block, _ = pem.Decode(server.Cert())
	serverCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	for _, ext := range serverCert.Extensions {
		if ext.Id.Equal(authorityKeyIdentifier) {
			var auth = authority{}
			if _, err := asn1.Unmarshal(ext.Value, &auth); err != nil {
				t.Logf("error1 [%v]", err)
			} else {
				t.Logf("server cert aki [%x]", auth.AuthorityKeyIdentifier)
				t.Logf("server cert aci [%x]", auth.AuthorityCertIssuer)
				t.Logf("server cert acsn [%s]", auth.AuthorityCertSerialNumber.String())
			}
			break
		}
	}
}

func TestIsIntermediateCA(t *testing.T) {
	generator := tlsca.NewTLSCAGenerator()
	ca, err := generator.GenCA(&tlsca.TLSCAGenOpts{Level: 384})
	require.NoError(t, err)

	intermediate, err := ca.NewIntermediateCA()
	require.NoError(t, err)
	block, _ := pem.Decode(intermediate.CertBytes())
	intermediateCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	require.True(t, intermediateCert.IsCA, "intermediate certificate should also be ca")

	verifyOpts := x509.VerifyOptions{
		Roots: x509.NewCertPool(),
	}
	verifyOpts.Roots.AppendCertsFromPEM(ca.CertBytes())
	chains, err := intermediateCert.Verify(verifyOpts)
	require.NoError(t, err)
	require.Len(t, chains, 1)
	require.Len(t, chains[0], 2)
}
