package comm_test

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/11090815/mayy/csp/interfaces"
	"github.com/11090815/mayy/csp/softimpl/tlsca"
	"github.com/stretchr/testify/require"
)

func GenerateCertificatesForTest() {
	generator := tlsca.NewTLSCAGenerator()

	rootCA1, err := generator.CAGen(&tlsca.TLSCAGenOpts{Level: 384})
	if err != nil {
		panic(err)
	}
	rootCA2, err := generator.CAGen(&tlsca.TLSCAGenOpts{Level: 384})
	if err != nil {
		panic(err)
	}

	secondaryCA1_1, err := rootCA1.NewIntermediateCA()
	if err != nil {
		panic(err)
	}
	secondaryCA1_2, err := rootCA1.NewIntermediateCA()
	if err != nil {
		panic(err)
	}

	secondaryCA2_1, err := rootCA2.NewIntermediateCA()
	if err != nil {
		panic(err)
	}
	secondaryCA2_2, err := rootCA2.NewIntermediateCA()
	if err != nil {
		panic(err)
	}

	storeCA := func(ca interfaces.CA, name, path string) error {
		filename := filepath.Join(path, fmt.Sprintf("%s-cert.pem", name))
		file, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.FileMode(0666))
		if err != nil {
			return err
		}
		file.Write(ca.CertBytes())
		file.Sync()
		file.Close()

		filename = filepath.Join(path, fmt.Sprintf("%s-key.pem", name))
		file, err = os.OpenFile(filename, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.FileMode(0666))
		if err != nil {
			return err
		}
		file.Write(ca.KeyBytes())
		file.Sync()
		file.Close()
		return nil
	}

	storeCA(rootCA1, "root1", "testdata")
	storeCA(rootCA2, "root2", "testdata")
	storeCA(secondaryCA1_1, "root1-sec1", "testdata")
	storeCA(secondaryCA1_2, "root1-sec2", "testdata")
	storeCA(secondaryCA2_1, "root2-sec1", "testdata")
	storeCA(secondaryCA2_2, "root2-sec2", "testdata")

	generateClientAndServerCerts := func(ca interfaces.CA, name string, path string) error {
		method := func(isServer bool) error {
			var keyPair interfaces.CertKeyPair
			var kind string
			if isServer {
				kind = "server"
				keyPair, err = ca.NewServerCertKeyPair("localhost", "127.0.0.1", "192.168.189.128")
				if err != nil {
					return err
				}
			} else {
				kind = "client"
				keyPair, err = ca.NewClientCertKeyPair()
				if err != nil {
					return err
				}
			}

			filename := filepath.Join(path, fmt.Sprintf("%s-%s-cert.pem", name, kind))
			file, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.FileMode(0666))
			if err != nil {
				return err
			}
			_, err = file.Write(keyPair.Cert())
			if err != nil {
				return err
			}
			file.Sync()
			file.Close()

			filename = filepath.Join(path, fmt.Sprintf("%s-%s-key.pem", name, kind))
			file, err = os.OpenFile(filename, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.FileMode(0666))
			if err != nil {
				return err
			}
			_, err = file.Write(keyPair.Key())
			if err != nil {
				return err
			}
			file.Sync()
			file.Close()
			return nil
		}

		if err = method(true); err != nil {
			return err
		}
		if err = method(false); err != nil {
			return err
		}
		return nil
	}

	generateClientAndServerCerts(rootCA1, "root1", "testdata")
	generateClientAndServerCerts(rootCA2, "root2", "testdata")
	generateClientAndServerCerts(secondaryCA1_1, "root1-sec1", "testdata")
	generateClientAndServerCerts(secondaryCA1_2, "root1-sec2", "testdata")
	generateClientAndServerCerts(secondaryCA2_1, "root2-sec1", "testdata")
	generateClientAndServerCerts(secondaryCA2_2, "root2-sec2", "testdata")
}

func TestGenerateCertificates(t *testing.T) {
	GenerateCertificatesForTest()

	var (
		root1_sec1Cert []byte
		// root1_sec1Key         []byte
		root1_sec1_serverCert []byte
		// root1_sec1_serverKey  []byte
	)
	root1_sec1_certFilePath := filepath.Join("testdata", "root1-sec1-cert.pem")
	// root1_sec1_keyFilePath := filepath.Join("testdata", "root1-sec1-key.pem")
	root1_sec1_server_certFilePath := filepath.Join("testdata", "root1-sec1-server-cert.pem")
	// root1_sec1_server_keyFilePath := filepath.Join("testdata", "root1-sec1-server-key.pem")

	root1_sec1Cert, _ = os.ReadFile(root1_sec1_certFilePath)
	// root1_sec1Key, _ = os.ReadFile(root1_sec1_keyFilePath)
	root1_sec1_serverCert, _ = os.ReadFile(root1_sec1_server_certFilePath)
	// root1_sec1_serverKey, _ = os.ReadFile(root1_sec1_server_keyFilePath)

	block1, _ := pem.Decode(root1_sec1Cert)
	root1Sec1Cert, err := x509.ParseCertificate(block1.Bytes)
	require.NoError(t, err)

	block2, _ := pem.Decode(root1_sec1_serverCert)
	root1Sec1ServerCert, err := x509.ParseCertificate(block2.Bytes)
	require.NoError(t, err)

	certPool := x509.NewCertPool()
	certPool.AddCert(root1Sec1Cert)
	chains, _ := root1Sec1ServerCert.Verify(x509.VerifyOptions{Roots: certPool})
	require.NoError(t, err)
	t.Logf("len [%d]", len(chains))
}
