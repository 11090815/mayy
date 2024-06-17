package factory

import (
	"os"
	"path/filepath"

	"github.com/11090815/mayy/core/config"
	"github.com/11090815/mayy/common/errors"
)

type FactoryOpts struct {
	// Kind 目前仅支持：sw，即通过软件实现的密码方案。
	Kind          string `json:"kind" yaml:"Kind"`
	KeyStorePath  string `json:"key_store_path" yaml:"KeyStorePath"`
	SecurityLevel int    `json:"security_level" yaml:"SecurityLevel"`
	HashFamily    string `json:"hash_family" yaml:"HashFamily"`
	ReadOnly      bool   `json:"read_only" yaml:"ReadOnly"`
}

func ReadConfig() (*FactoryOpts, error) {
	cfg := config.GetConfig()

	opts := &FactoryOpts{}
	if err := cfg.UnmarshalKey("csp", opts); err != nil {
		return nil, errors.NewErrorf("cannot read config file, the error is \"%s\"", err.Error())
	}
	opts.KeyStorePath = filepath.Join(os.Getenv("MAYY_HOME"), opts.KeyStorePath)
	return opts, nil
}
