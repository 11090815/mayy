package msp

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"testing"

	"github.com/11090815/mayy/core/config/configtest"
	"github.com/11090815/mayy/csp/factory"
	"github.com/11090815/mayy/csp/softimpl/ecdsa"
	"github.com/11090815/mayy/csp/softimpl/tlsca"
	"github.com/11090815/mayy/errors"
	"github.com/11090815/mayy/protobuf/pmsp"
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

var (
	conf *pmsp.MSPConfig
	msp  MSP
)

func TestMain(m *testing.M) {
	errors.SetTrace()
	var err error
	mspDir := configtest.GetDevMspDir()
	conf, err = GetLocalMspConfig(mspDir, nil, "SampleOrg")
	if err != nil {
		fmt.Printf("error1 [%s]\n", err.Error())
		os.Exit(-1)
	}

	csp, err := factory.GetCSP()
	if err != nil {
		fmt.Printf("error2 [%s]\n", err.Error())
		os.Exit(-1)
	}

	msp, err = newCspMsp(MSPv1_0, csp)
	if err != nil {
		fmt.Printf("error3 [%s]\n", err.Error())
		os.Exit(-1)
	}

	err = msp.Setup(conf)
	if err != nil {
		fmt.Printf("error4 [%s]\n", err.Error())
		os.Exit(-1)
	}

	res := m.Run()
	os.Exit(res)
}

func TestMSPParsers(t *testing.T) {
	_, _, err := msp.(*mspImpl).getIdentityFromCert(nil)
	require.Error(t, err)

}
