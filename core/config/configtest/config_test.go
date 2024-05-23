package configtest

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGOPATHDevConfigDir(t *testing.T) {
	devPath, err := gopathDevConfigDir()
	require.NoError(t, err)
	t.Log(devPath)
}

func TestGOMODDevConfigDir(t *testing.T) {
	devPath, err := gomodDevConfigDir()
	require.NoError(t, err)
	t.Log(devPath)	
}
