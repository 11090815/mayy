package comm_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/11090815/mayy/csp/interfaces"
	"github.com/11090815/mayy/csp/softimpl/tlsca"
)

type certificate struct {
	isCA      bool
	name      string
	cert      []byte
	key       []byte
	secondary *certificate
}

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
	storeCA(rootCA1, "root2", "testdata")
	storeCA(rootCA1, "root1-sec1", "testdata")
	storeCA(rootCA1, "root1-sec2", "testdata")
	storeCA(rootCA1, "root2-sec1", "testdata")
	storeCA(rootCA1, "root2-sec2", "testdata")

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
}
