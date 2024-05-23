package msp

import (
	"testing"

	"github.com/11090815/mayy/core/config/configtest"
	"github.com/stretchr/testify/require"
)

func TestSetupCSPKeystoreConfig(t *testing.T) {
	keystoreDir := "/tmp"

	cfg := SetupCSPKeystoreConfig(nil, keystoreDir)
	require.Equal(t, cfg.KeyStorePath, keystoreDir)
}

func TestGetLocalMspConfig(t *testing.T) {
	mspDir := configtest.GetDevMspDir()
	_, err := GetLocalMspConfig(mspDir, nil, "SampleOrg")
	require.NoError(t, err)	
}
