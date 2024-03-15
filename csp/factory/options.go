package factory

import (
	"os"

	"github.com/11090815/mayy/errors"
	"github.com/spf13/viper"
)

type FactoryOpts struct {
	Kind          string `json:"kind" yaml:"Kind"`
	KeyStorePath  string `json:"key_store_path" yaml:"KeyStorePath"`
	SecurityLevel int    `json:"security_level" yaml:"SecurityLevel"`
	HashFamily    string `json:"hash_family" yaml:"HashFamily"`
	ReadOnly      bool   `json:"read_only" yaml:"ReadOnly"`
}

func ReadConfig(path string) (*FactoryOpts, error) {
	cfgFile, err := os.Open(path)
	if err != nil {
		return nil, errors.NewErrorf("cannot read config file, the error is \"%s\"", err.Error())
	}

	viper.SetConfigType("yaml")
	if err = viper.ReadConfig(cfgFile); err != nil {
		return nil, errors.NewErrorf("cannot read config file, the error is \"%s\"", err.Error())
	}

	opts := &FactoryOpts{}
	if err = viper.UnmarshalKey("csp", opts); err != nil {
		return nil, errors.NewErrorf("cannot read config file, the error is \"%s\"", err.Error())
	}

	return opts, nil
}
