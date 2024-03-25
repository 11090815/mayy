package factory_test

import (
	"testing"

	"github.com/11090815/mayy/csp/factory"
	"github.com/stretchr/testify/require"
)

func TestReadConfig(t *testing.T) {
	cfg, err := factory.ReadConfig()
	require.NoError(t, err)

	require.Equal(t, cfg.Kind, "sw")
	require.Equal(t, cfg.HashFamily, "SHA2")
	require.Equal(t, cfg.KeyStorePath, "xxx")
	require.Equal(t, cfg.SecurityLevel, 256)
	require.Equal(t, cfg.ReadOnly, false)
}
