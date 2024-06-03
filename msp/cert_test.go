package msp

import (
	goecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
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

func TestGenerateCRL(t *testing.T) {
	generator := tlsca.NewTLSCAGenerator()
	ca, err := generator.GenCA(&tlsca.TLSCAGenOpts{Level: 384})
	require.NoError(t, err)
	block, _ := pem.Decode(ca.CertBytes())
	caCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	sk, err := utils.PEMToPrivateKey(ca.KeyBytes())
	require.NoError(t, err)
	template := &x509.RevocationList{
		ThisUpdate: time.Now().Add(-1 * time.Hour),
		NextUpdate: caCert.NotAfter,
		Issuer:     caCert.Issuer,
		Number:     serialNumber,
	}
	rl, err := x509.CreateRevocationList(rand.Reader, template, caCert, sk)
	require.NoError(t, err)
	_, err = x509.ParseRevocationList(rl)
	require.NoError(t, err)
	pemFormatRL := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: rl})
	fmt.Println(string(pemFormatRL))
}

func generateSelfSignedCert(t *testing.T, now time.Time) (*goecdsa.PrivateKey, *x509.Certificate) {
	k, err := goecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Generate a self-signed certificate
	testExtKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")
	commonName := "test.example.com"
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"PLA"},
			Country:      []string{"CN"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "Gopher",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "NL",
				},
			},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(1 * time.Hour),
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		SubjectKeyId:          []byte{1, 2, 3, 4},
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           testExtKeyUsage,
		UnknownExtKeyUsage:    testUnknownExtKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  true,
		OCSPServer:            []string{"http://ocurrentCSP.example.com"},
		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},
		DNSNames:              []string{"test.example.com"},
		EmailAddresses:        []string{"gopher@golang.org"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
		PolicyIdentifiers:     []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		PermittedDNSDomains:   []string{".example.com", "example.com"},
		CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},
		ExtraExtensions: []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: extraExtensionData,
			},
		},
	}
	certRaw, err := x509.CreateCertificate(rand.Reader, &template, &template, &k.PublicKey, k)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certRaw)
	require.NoError(t, err)

	return k, cert
}
