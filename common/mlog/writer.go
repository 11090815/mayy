package mlog

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"

	"github.com/11090815/mayy/core/config"
	"github.com/11090815/mayy/errors"
	"github.com/spf13/viper"
)

/* ------------------------------------------------------------------------------------------ */

// writer 定义了条目写入器接口。
type writer interface {
	// WriteEntry 利用写入器将日志条目写入到指定位置，返回写入内容的字节数量和可能出现的错误。
	WriteEntry(e *entry) error
	// Close 关闭写入日志的记录器。
	Close() error
}

/* ------------------------------------------------------------------------------------------ */

type terminalWriter struct{}

func NewTerminalWriter() writer {
	return &terminalWriter{}
}

func (*terminalWriter) WriteEntry(e *entry) error {
	_, err := os.Stdout.Write([]byte(e.ColorLevelString()))
	return err
}

func (*terminalWriter) Close() error {
	return nil
}

/* ------------------------------------------------------------------------------------------ */

type multiFileWriter struct {
	// cfgPath 配置文件的地址。
	cfg *viper.Viper
	// maxSize 定义一个日志文件所能存储的字节数。
	maxSize uint32
	// writers 多种级别日志记录器。
	writers map[string]*fileWriter
}

func NewMultiFileWriter() (writer, error) {
	cfg, _cfg, err := ReadConfig()
	if err != nil {
		return nil, err
	}
	if cfg.DirPath == "" {
		return nil, errors.NewError("invalid path, nil directory path")
	}

	mfw := &multiFileWriter{
		cfg:     _cfg,
		maxSize: uint32(cfg.SingleFileMaxSize),
		writers: make(map[string]*fileWriter),
	}

	if _, err := os.Stat(filepath.Join(cfg.DirPath, DebugLevel.String())); err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(filepath.Join(cfg.DirPath, DebugLevel.String()), os.FileMode(0775))
		}
	}

	if _, err := os.Stat(filepath.Join(cfg.DirPath, InfoLevel.String())); err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(filepath.Join(cfg.DirPath, InfoLevel.String()), os.FileMode(0775))
		}
	}

	if _, err := os.Stat(filepath.Join(cfg.DirPath, WarnLevel.String())); err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(filepath.Join(cfg.DirPath, WarnLevel.String()), os.FileMode(0775))
		}
	}

	if _, err := os.Stat(filepath.Join(cfg.DirPath, ErrorLevel.String())); err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(filepath.Join(cfg.DirPath, ErrorLevel.String()), os.FileMode(0775))
		}
	}

	if _, err := os.Stat(filepath.Join(cfg.DirPath, PanicLevel.String())); err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(filepath.Join(cfg.DirPath, PanicLevel.String()), os.FileMode(0775))
		}
	}
	if wr, err := newFileWriter(cfg.DirPath, DebugLevel); err == nil {
		mfw.writers[DebugLevel.String()] = wr
	} else {
		return nil, err
	}

	if wr, err := newFileWriter(cfg.DirPath, InfoLevel); err == nil {
		mfw.writers[InfoLevel.String()] = wr
	} else {
		return nil, err
	}

	if wr, err := newFileWriter(cfg.DirPath, WarnLevel); err == nil {
		mfw.writers[WarnLevel.String()] = wr
	} else {
		return nil, err
	}

	if wr, err := newFileWriter(cfg.DirPath, ErrorLevel); err == nil {
		mfw.writers[ErrorLevel.String()] = wr
	} else {
		return nil, err
	}

	if wr, err := newFileWriter(cfg.DirPath, PanicLevel); err == nil {
		mfw.writers[PanicLevel.String()] = wr
	} else {
		return nil, err
	}

	return mfw, nil
}

func (mfw *multiFileWriter) WriteEntry(e *entry) (err error) {
	return mfw.writers[e.level.String()].write(mfw.maxSize, e)
}

func (mfw *multiFileWriter) Close() error {
	errCh := make(chan error, len(mfw.writers))
	for name, wr := range mfw.writers {
		if err := wr.wr.Close(); err != nil {
			errCh <- errors.NewErrorf("failed closing %s log file, the error is \"%s\"", name, err.Error())
		}
	}
	close(errCh)
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

/* ------------------------------------------------------------------------------------------ */

type fileWriter struct {
	dirPath        string
	alreadyWritten uint32
	num            uint32
	wr             *os.File
	mutex          *sync.Mutex
}

func newFileWriter(dirPath string, lvl level) (*fileWriter, error) {
	files, err := os.ReadDir(filepath.Join(dirPath, lvl.String()))
	if err != nil {
		return nil, errors.NewErrorf("failed reading %s log directory \"%s\", the error is \"%s\"", lvl.String(), filepath.Join(dirPath, lvl.String()), err.Error())
	}
	var recordedLogFilesNum, latestAlreadyWritten int
	reg := regexp.MustCompile(fmt.Sprintf(`%s-\d+\.log`, lvl.String()))
	for _, file := range files {
		if reg.Match([]byte(file.Name())) {
			recordedLogFilesNum++
		}
	}
	if recordedLogFilesNum > 0 {
		filePath := filepath.Join(dirPath, lvl.String(), fmt.Sprintf("%s-%d.log", lvl.String(), recordedLogFilesNum))
		stat, err := os.Stat(filePath)
		if err != nil {
			return nil, errors.NewErrorf("cannot fetch the latest information of the %s log file \"%s\", the error is \"%s\"", lvl.String(), filePath, err.Error())
		}
		latestAlreadyWritten = int(stat.Size())
	} else {
		latestAlreadyWritten = 0
		recordedLogFilesNum = 1
	}

	return &fileWriter{
		num:            uint32(recordedLogFilesNum),
		alreadyWritten: uint32(latestAlreadyWritten),
		dirPath:        dirPath,
		mutex:          &sync.Mutex{},
	}, nil
}

func (fw *fileWriter) write(max uint32, e *entry) (err error) {
	if fw.wr == nil {
		fw.mutex.Lock()
		fw.wr, err = os.OpenFile(filepath.Join(fw.dirPath, e.level.String(), fmt.Sprintf("%s-%d.log", e.level.String(), fw.num)), os.O_CREATE|os.O_APPEND|os.O_RDWR, os.FileMode(0600))
		if err != nil {
			fw.mutex.Unlock()
			return errors.NewErrorf("failed opening the %s log file, the error is \"%s\"", e.level.String(), err.Error())
		}
		fw.mutex.Unlock()
	}
	var n int
	fw.mutex.Lock()
	n, err = fw.wr.Write([]byte(e.NormalLevelString()))
	if err != nil {
		fw.mutex.Unlock()
		return errors.NewErrorf("failed writing log entry to the %s file, the error is \"%s\"", e.level.String(), err.Error())
	}
	atomic.AddUint32(&fw.alreadyWritten, uint32(n))
	if err = fw.wr.Sync(); err != nil {
		fw.mutex.Unlock()
		return errors.NewErrorf("failed synchronizing log entry to the %s file, the error is \"%s\"", e.level.String(), err.Error())
	}
	fw.mutex.Unlock()

	if fw.alreadyWritten >= max {
		fw.mutex.Lock()
		defer fw.mutex.Unlock()
		fw.wr.Close()
		atomic.StoreUint32(&fw.alreadyWritten, 0)
		atomic.AddUint32(&fw.num, 1)
		fw.wr, err = os.OpenFile(filepath.Join(fw.dirPath, e.level.String(), fmt.Sprintf("%s-%d.log", e.level.String(), fw.num)), os.O_CREATE|os.O_APPEND|os.O_RDWR, os.FileMode(0600))
		if err != nil {
			return errors.NewErrorf("failed creating the new %s log file, the error is \"%s\"", e.level.String(), err.Error())
		}
	}
	return nil
}

/* ------------------------------------------------------------------------------------------ */

type fileWriterConfig struct {
	DirPath           string `json:"dir_path" yaml:"DirPath"`
	SingleFileMaxSize int    `json:"single_file_max_size" yaml:"SingleFileMaxSize"`
}

func ReadConfig() (*fileWriterConfig, *viper.Viper, error) {
	cfg := config.GetConfig()

	opts := &fileWriterConfig{}
	if err := cfg.UnmarshalKey("log", opts); err != nil {
		return nil, nil, errors.NewErrorf("cannot read config file, the error is \"%s\"", err.Error())
	}
	opts.DirPath = filepath.Join(os.Getenv("MAYY_HOME"), opts.DirPath)

	return opts, cfg, nil
}

/* ------------------------------------------------------------------------------------------ */

type mockWriter struct {}

func (mock *mockWriter) WriteEntry(*entry) error {
	return nil
}

func (mock *mockWriter) Close() error {
	return nil
}
