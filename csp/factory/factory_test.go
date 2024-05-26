package factory_test

import (
	"testing"

	"github.com/11090815/mayy/csp/factory"
	"github.com/11090815/mayy/csp/softimpl/ecdsa"
	"github.com/11090815/mayy/csp/softimpl/hash"
	"github.com/stretchr/testify/require"
)

func TestCreatCSP(t *testing.T) {
	opts, err := factory.ReadConfig()
	require.NoError(t, err)

	factory.InitCSPFactoryWithOpts(opts)

	csp, err := factory.GetCSP()
	require.NoError(t, err)

	ecdsaSK256, err := csp.KeyGen(&ecdsa.ECDSAP256KeyGenOpts{Temporary: false})
	require.NoError(t, err)
	ecdsaPK256, err := ecdsaSK256.PublicKey()
	require.NoError(t, err)

	msg := []byte("权限系统")
	digest, err := csp.Hash(msg, &hash.SHA256Opts{})
	require.NoError(t, err)

	sig, err := csp.Sign(ecdsaSK256, digest, nil)
	require.NoError(t, err)

	isValid, err := csp.Verify(ecdsaPK256, sig, digest, nil)
	require.NoError(t, err)
	require.True(t, isValid)
}
