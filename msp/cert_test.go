package msp

import (
	goecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/11090815/mayy/core/config/configtest"
	"github.com/11090815/mayy/csp/softimpl/ecdsa"
	"github.com/11090815/mayy/csp/softimpl/tlsca"
	"github.com/11090815/mayy/csp/softimpl/utils"
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

func TestGenerateSampleConfigMsp(t *testing.T) {
	writeFile := func(path string, content []byte) error {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_RDWR, os.FileMode(0600))
		if err != nil {
			return err
		}
		n, err := file.Write(content)
		if n != len(content) {
			return fmt.Errorf("should write %d bytes, but %d", len(content), n)
		}
		if err != nil {
			return err
		}
		if err = file.Sync(); err != nil {
			return err
		}
		return file.Close()
	}

	path := configtest.GetDevMspDir()

	generator := tlsca.NewTLSCAGenerator()
	ca, err := generator.GenCA(&tlsca.TLSCAGenOpts{Level: 384})
	require.NoError(t, err)
	err = writeFile(filepath.Join(path, "cacerts/cacert.pem"), ca.CertBytes())
	require.NoError(t, err)

	admin, err := ca.NewClientCertKeyPair()
	require.NoError(t, err)
	err = writeFile(filepath.Join(path, "admincerts/admincert.pem"), admin.Cert())
	require.NoError(t, err)

	signer, err := ca.NewClientCertKeyPair()
	require.NoError(t, err)
	err = writeFile(filepath.Join(path, "signcerts/peer.pem"), signer.Cert())
	require.NoError(t, err)
	sk, err := utils.PEMToPrivateKey(signer.Key())
	require.NoError(t, err)
	raw := elliptic.Marshal(sk.Curve, sk.PublicKey.X, sk.PublicKey.Y)
	hashFunc := sha256.New()
	hashFunc.Write(raw)
	ski := hex.EncodeToString(hashFunc.Sum(nil))
	err = writeFile(filepath.Join(path, fmt.Sprintf("keystore/%s_sk", ski)), signer.Key())
	require.NoError(t, err)

	tlsca, err := generator.GenCA(&tlsca.TLSCAGenOpts{Level: 384})
	require.NoError(t, err)
	err = writeFile(filepath.Join(path, "tlscacerts/tlsroot.pem"), tlsca.CertBytes())
	require.NoError(t, err)

	tlsIntermediate, err := tlsca.NewIntermediateCA()
	require.NoError(t, err)
	err = writeFile(filepath.Join(path, "tlsintermediatecerts/tlsintermediate.pem"), tlsIntermediate.CertBytes())
	require.NoError(t, err)
}
