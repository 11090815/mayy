package msp

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/11090815/mayy/core/config/configtest"
	"github.com/11090815/mayy/csp/factory"
	"github.com/11090815/mayy/csp/mocks"
	"github.com/11090815/mayy/csp/softimpl"
	"github.com/11090815/mayy/common/errors"
	"github.com/11090815/mayy/protobuf/pmsp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

var notACert = `-----BEGIN X509 CRL-----
MIIBJjCBrgIBATAKBggqhkjOPQQDAzAyMTAwLgYDVQQFEycxMzczMDExMDc1OTIw
NDMxMTIxNTkxOTQ4MzQzOTM5NzE4OTU2NzUXDTI0MDUyOTIzMzQ1OFoXDTM0MDUy
ODAwMzQ1OFqgSzBJMCsGA1UdIwQkMCKAII+i645k4fNB8iWPy/IznUehgzLb3TS7
UhiN+srRHUyKMBoGA1UdFAQTAhEA9RUIidUYn/nLM9lrmjYYAjAKBggqhkjOPQQD
AwNnADBkAjAsjaPsDFLKQXQkzg8K3GGUjwXXh0ze/p21GagI0t86qe9Ed59sjdxI
EC4HoaNvPXUCMHL/rn1LXqDvGyjHICm3sxVdOl3U2dM+UfaeSOhU1rLW2TN+C5ZP
fHGKeM6hMQHkjw==
-----END X509 CRL-----`

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
	_, _, err = msp.(*mspImpl).getIdentityFromCert([]byte("lalalala"))
	require.Error(t, err)
	_, _, err = msp.(*mspImpl).getIdentityFromCert([]byte(notACert))
	require.Error(t, err)

	_, err = msp.(*mspImpl).getSigningIdentityFromConf(nil)
	require.Error(t, err)
	sid := &pmsp.SigningIdentityInfo{PublicSigner: []byte("lalala"), PrivateSigner: nil}
	_, err = msp.(*mspImpl).getSigningIdentityFromConf(sid)
	require.Error(t, err)
	keyInfo := &pmsp.KeyInfo{KeyIdentifier: "ski", KeyMaterial: nil}
	sid.PrivateSigner = keyInfo
	_, err = msp.(*mspImpl).getSigningIdentityFromConf(sid)
	require.Error(t, err)
}

func TestGetSigningIdentityFromConfWithWrongPrivateCert(t *testing.T) {
	oldRoots := msp.(*mspImpl).opts.Roots
	defer func() {
		msp.(*mspImpl).opts.Roots = oldRoots
	}()
	_, cert := generateSelfSignedCert(t, time.Now())
	msp.(*mspImpl).opts.Roots = x509.NewCertPool()
	msp.(*mspImpl).opts.Roots.AddCert(cert)

	pemFormatCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	keyInfo := &pmsp.KeyInfo{
		KeyIdentifier: "ski",
		KeyMaterial:   []byte("lalala"),
	}
	sid := &pmsp.SigningIdentityInfo{PublicSigner: pemFormatCert, PrivateSigner: keyInfo}
	_, err := msp.(*mspImpl).getSigningIdentityFromConf(sid)
	require.Error(t, err)
	t.Logf("error1 [%s]", err.Error())
}

func TestMSPSetupNoCryptoConf(t *testing.T) {
	mspDir := configtest.GetDevMspDir()
	conf, err := GetLocalMspConfig(mspDir, nil, "SampleOrg")
	require.NoError(t, err)
	require.NotNil(t, conf)
	mspConf := &pmsp.MayyMSPConfig{}
	err = proto.Unmarshal(conf.Config, mspConf)
	require.NoError(t, err)

	mspConf.CryptoConfig.IdentityIdentifierHashFunction = ""
	b, err := proto.Marshal(mspConf)
	require.NoError(t, err)
	conf.Config = b
	defaultCsp, err := factory.GetCSP()
	require.NoError(t, err)
	newMsp, err := newCspMsp(MSPv1_0, defaultCsp)
	require.NoError(t, err)
	err = newMsp.Setup(conf)
	require.NoError(t, err)

	mspConf.CryptoConfig.SignatureHashFunction = ""
	b, err = proto.Marshal(mspConf)
	require.NoError(t, err)
	conf.Config = b
	newMsp, err = newCspMsp(MSPv1_0, defaultCsp)
	require.NoError(t, err)
	err = newMsp.Setup(conf)
	require.NoError(t, err)

	mspConf.CryptoConfig = nil
	b, err = proto.Marshal(mspConf)
	require.NoError(t, err)
	conf.Config = b
	newMsp, err = newCspMsp(MSPv1_0, defaultCsp)
	require.NoError(t, err)
	err = newMsp.Setup(conf)
	require.NoError(t, err)
}

func TestGetIdentities(t *testing.T) {
	_, err := msp.GetDefaultSigningIdentity()
	require.NoError(t, err)
}

func getLocalMSP(t *testing.T, dir string) MSP {
	conf, err := GetLocalMspConfig(dir, nil, "SampleOrg")
	require.NoError(t, err)
	csp, err := softimpl.NewSoftCSPImpl(mocks.NewMockKeyStore())
	require.NoError(t, err)
	thisMsp, err := newCspMsp(MSPv1_0, csp)
	require.NoError(t, err)
	err = thisMsp.Setup(conf)
	require.NoError(t, err)
	return thisMsp
}

func TestMSPWithIntermediateCAs(t *testing.T) {
		
}
