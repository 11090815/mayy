package config

import (
	"os"

	"github.com/spf13/viper"
)

var _config *viper.Viper

func init() {
	path := os.Getenv("MAYY_HOME")
	viper.AddConfigPath(path)
	viper.SetConfigName("config.yml")
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
