package config

import (
	"os"
	"path/filepath"

	"github.com/11090815/mayy/errors"
	"github.com/spf13/viper"
)

var _config *viper.Viper

func init() {
	path := os.Getenv("MAYY_HOME")
	viper.AddConfigPath(path + "/sampleconfig")
	viper.SetConfigName("config.yaml")
	viper.SetConfigType("yaml")
	err := viper.ReadInConfig()
	if err != nil {
		panic(err.Error())
	}
	_config = viper.GetViper()
}

func GetConfig() *viper.Viper {
	return _config
}

/* ------------------------------------------------------------------------------------------ */

func dirExists(path string) bool {
	stat, err := os.Stat(path)
	if err != nil {
		return false
	}
	return stat.IsDir()
}

func AddConfigPath(v *viper.Viper, path string) {
	if v != nil {
		v.AddConfigPath(path)
	} else {
		viper.AddConfigPath(path)
	}
}

// TranslatePath 判断给定的路径（第二个参数）是否是绝对路径，若是，直接返回此路径，否则返回
// base/path。
func TranslatePath(base, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}

// TranslatePathInPlace 判断给定的路径（第二个参数）是否是绝对路径，若是，不做任何处理，否则
// 让第二个参数 path = base/path。
func TranslatePathInPlace(base string, path *string) {
	*path = TranslatePath(base, *path)
}

func GetPath(key string) string {
	path := viper.GetString(key)
	if path == "" {
		return ""
	}

	return TranslatePath(filepath.Dir(viper.ConfigFileUsed()), path)
}

const OfficialPath = "/etc/11090815/mayy"

func InitViper(v *viper.Viper, configName string) error {
	altPath := os.Getenv("MAYY_CONFIG_PATH")
	if altPath != "" {
		if !dirExists(altPath) {
			return errors.NewErrorf("MAYY_CONFIG_PATH %s does not exist", altPath)
		}

		AddConfigPath(v, altPath)
	} else {
		AddConfigPath(v, "./")

		if dirExists(OfficialPath) {
			AddConfigPath(v, OfficialPath)
		}
	}

	if v != nil {
		v.SetConfigName(configName)
	} else {
		viper.SetConfigName(configName)
	}

	return nil
}
