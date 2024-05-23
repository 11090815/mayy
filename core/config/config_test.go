package config

import (
	"os"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestConfigDirExists(t *testing.T) {
	tmpF := os.TempDir()
	exists := dirExists(tmpF)
	require.True(t, exists)

	tmpF = "/blah-" + time.Now().Format(time.RFC3339)
	exists = dirExists(tmpF)
	require.False(t, exists)
}

func TestConfigInitViper(t *testing.T) {
	v := viper.New()
	err := InitViper(v, "")
	require.NoError(t, err)	

	err = InitViper(nil, "")
	require.NoError(t, err)
}

func TestConfigGetPath(t *testing.T) {
	path := GetPath("foo")
	require.Empty(t, path)

	viper.Set("testpath", "/test/config.yaml")
	path = GetPath("testpath")
	require.Equal(t, "/test/config.yaml", path)
}

func TestConfigTranslatePathInPlace(t *testing.T) {
	path := "bar"
	TranslatePathInPlace(OfficialPath, &path)
	require.Equal(t, OfficialPath + "/bar", path)

	path = "/bar"
	TranslatePathInPlace(OfficialPath, &path)
	require.Equal(t, "/bar", path)
}
