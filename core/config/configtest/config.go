package configtest

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/11090815/mayy/common/errors"
	"github.com/spf13/viper"
)

// AddDevConfigPath 将存放项目的默认配置文件的路径添加到 viper 中。
func AddDevConfigPath(v *viper.Viper) {
	devPath := GetDevConfigDir()
	if v != nil {
		v.AddConfigPath(devPath)
	} else {
		viper.AddConfigPath(devPath)
	}
}

func GetDevConfigDir() string {
	path, err := gomodDevConfigDir()
	if err != nil {
		path, err = gopathDevConfigDir()
		if err != nil {
			panic(err)
		}
	}
	return path
}

func GetDevMspDir() string {
	devDir := GetDevConfigDir()
	return filepath.Join(devDir, "msp")
}

func SetDevMayyConfigPath(t *testing.T) {
	t.Helper()
	t.Setenv("MAYY_CONFIG_PATH", GetDevConfigDir())
}

/* ------------------------------------------------------------------------------------------ */

func gopathDevConfigDir() (string, error) {
	buf := bytes.NewBuffer(nil)
	cmd := exec.Command("go", "env", "GOPATH")
	cmd.Stdout = buf
	if err := cmd.Run(); err != nil {
		return "", err
	}

	gopath := strings.TrimSpace(buf.String())
	for _, path := range filepath.SplitList(gopath) { // 以 ':' 作为分隔符，分割路径字符串
		devPath := filepath.Join(path, "src/github.com/11090815/mayy/sampleconfig")
		if dirExists(devPath) {
			return devPath, nil
		}
	}

	return "", errors.NewErrorf("failed finding sampleconfig directory on GOPATH")
}

func gomodDevConfigDir() (string, error) {
	buf := bytes.NewBuffer(nil)
	cmd := exec.Command("go", "env", "GOMOD")
	cmd.Stdout = buf
	if err := cmd.Run(); err != nil {
		return "", err
	}

	modFile := strings.TrimSpace(buf.String())
	if modFile == "" {
		return "", errors.NewError("not a module or not in module mode")
	}

	devPath := filepath.Join(filepath.Dir(modFile), "sampleconfig")
	if !dirExists(devPath) {
		return "", errors.NewErrorf("%s does not exist", devPath)
	}

	return devPath, nil
}

func dirExists(path string) bool {
	stat, err := os.Stat(path)
	if err != nil {
		return false
	}
	return stat.IsDir()
}
