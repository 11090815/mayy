package main

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/11090815/mayy/csp/softimpl/tlsca"
	"github.com/11090815/mayy/csp/softimpl/utils"
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
	genDir("intermediatecerts")
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

	peer, err := ca.NewClientCertKeyPair()
	if err != nil {
		panic(err)
	}

	intermediate, err := ca.NewIntermediateCA()
	if err != nil {
		panic(err)
	}

	admin, err := intermediate.NewClientCertKeyPair()
	if err != nil {
		panic(err)
	}

	tlsCA, err := generator.GenCA(&tlsca.TLSCAGenOpts{Level: 384})
	if err != nil {
		panic(err)
	}
	tlsIntermediate, err := tlsCA.NewIntermediateCA()
	if err != nil {
		panic(err)
	}
	key, err := utils.PEMToPrivateKey(peer.Key())
	if err != nil {
		panic(err)
	}
	ski := sha256.Sum256(elliptic.Marshal(key.Curve, key.X, key.Y))

	genFile("msp/cacerts", "cacert.pem", ca.CertBytes())
	genFile("msp/admincerts", "admincert.pem", admin.Cert())
	genFile("msp/signcerts", "peer.pem", peer.Cert())
	genFile("msp/keystore", fmt.Sprintf("%s.pem", hex.EncodeToString(ski[:])), peer.Key())
	genFile("msp/intermediatecerts", "intermediatecert.pem", intermediate.CertBytes())
	genFile("msp/tlscacerts", "tlsroot.pem", tlsCA.CertBytes())
	genFile("msp/tlsintermediatecerts", "tlsintermediate.pem", tlsIntermediate.CertBytes())
}
