package main

import (
	"os"
	"path/filepath"

	"github.com/11090815/mayy/csp/softimpl/tlsca"
)

func main() {
	genDir := func(dir string) {
		path := filepath.Join("msp", dir)
		if _, err := os.Stat(path); err != nil && os.IsNotExist(err) {
			os.MkdirAll(path, os.FileMode(0777))
		}
	}

	genDir("admincerts")
	genDir("cacerts")
	genDir("keystore")
	genDir("signcerts")
	genDir("tlscacerts")
	genDir("tlsintermediatecerts")

	generator := tlsca.NewTLSCAGenerator()
	ca, err := generator.GenCA(&tlsca.TLSCAGenOpts{Level: 384})
	if err != nil {
		panic(err)
	}

	genFile := func(dir, file string, content []byte) {
		path := filepath.Join(dir, file)
		if _, err := os.Stat(path); err != nil && os.IsNotExist(err) {
			f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_RDWR, os.FileMode(0666))
			if err != nil {
				panic(err)
			}
			f.Write(content)
		} else if err != nil {
			panic(err)
		} else {
			f, err := os.OpenFile(path, os.O_TRUNC|os.O_RDWR, os.FileMode(0666))
			if err != nil {
				panic(err)
			}
			f.Write(content)
		}
	}

	admin, err := ca.NewClientCertKeyPair()
	if err != nil {
		panic(err)
	}
	peer, err := ca.NewClientCertKeyPair()
	if err != nil {
		panic(err)
	}
	intermediate, err := ca.NewIntermediateCA()
	if err != nil {
		panic(err)
	}

	genFile("msp/cacerts", "cacert.pem", ca.CertBytes())
	genFile("msp/admincerts", "admincert.pem", admin.Cert())
	genFile("msp/signcerts", "peer.pem", peer.Cert())
	genFile("msp/keystore", "key.pem", peer.Key())
	genFile("msp/tlscacerts", "tlsroot.pem", ca.CertBytes())
	genFile("msp/tlsintermediatecerts", "tlsintermediate.pem", intermediate.CertBytes())
}
