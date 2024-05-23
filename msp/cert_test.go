package msp

import (
	goecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/11090815/mayy/csp/softimpl/ecdsa"
	"github.com/stretchr/testify/require"
)

func TestSanitizeCertWithRSA(t *testing.T) {
	cert := &x509.Certificate{
		SignatureAlgorithm: x509.SHA1WithRSA,
	}
	require.False(t, isECDSASignedCert(cert))

	cert.SignatureAlgorithm = x509.ECDSAWithSHA1
	require.True(t, isECDSASignedCert(cert))
}

func TestSanitizeCertInvalidInput(t *testing.T) {
	_, err := sanitizeECDSASignedCert(nil, nil)
	require.Error(t, err)
	t.Logf("error1 [%s]", err.Error())

	_, err = sanitizeECDSASignedCert(&x509.Certificate{}, nil)
	require.Error(t, err)
	t.Logf("error2 [%s]", err.Error())

	key, err := goecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := &x509.Certificate{}
	cert.PublicKey = &key.PublicKey
	sigma, err := ecdsa.MarshalECDSASignature(big.NewInt(1), elliptic.P256().Params().N)
	require.NoError(t, err)
	cert.Signature = sigma
	cert.PublicKeyAlgorithm = x509.ECDSA
	cert.Raw = []byte{1, 2}
	_, err = sanitizeECDSASignedCert(cert, cert)
	require.Error(t, err)
	t.Logf("error3 [%s]", err.Error())
}

func TestSanitizeCert(t *testing.T) {
	var key *goecdsa.PrivateKey
	var cert *x509.Certificate
	for {
		key, cert = generateSelfSignedCert(t, time.Now())
		_, s, err := ecdsa.UnmarshalECDSASignature(cert.Signature)
		require.NoError(t, err)
		lowS, err := ecdsa.IsLowS(&key.PublicKey, s)
		require.NoError(t, err)
		if !lowS {
			break
		}
	}

	sanitizedCert, err := sanitizeECDSASignedCert(cert, cert)
	require.NoError(t, err)
	require.NotEqual(t, cert.Signature, sanitizedCert.Signature)

	_, s, err := ecdsa.UnmarshalECDSASignature(sanitizedCert.Signature)
	require.NoError(t, err)

	lowS, err := ecdsa.IsLowS(&key.PublicKey, s)
	require.NoError(t, err)
	require.True(t, lowS)
}

func generateSelfSignedCert(t *testing.T, now time.Time) (*goecdsa.PrivateKey, *x509.Certificate) {
	key, err := goecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(7911),
		Subject: pkix.Name{
			CommonName:   "love.home",
			Organization: []string{"love.zone"},
			Country:      []string{"CN"},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(time.Hour),
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		SubjectKeyId:          []byte{7, 9, 11},
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certRaw, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certRaw)
	require.NoError(t, err)

	return key, cert
}
