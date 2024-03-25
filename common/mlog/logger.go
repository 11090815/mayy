package mlog

import (
	"fmt"
	"sync"
	"time"
)

/* ------------------------------------------------------------------------------------------ */

type Logger interface {
	Debug(msg string)
	Debugf(format, msg string)
	Info(msg string)
	Infof(format, msg string)
	Warn(msg string)
	Warnf(format, msg string)
	Error(msg string)
	Errorf(format, msg string)
	Panic(msg string)
	Panicf(format, msg string)
	Stop() error
}

/* ------------------------------------------------------------------------------------------ */

var now = func() string {
	return time.Now().Format("2006-01-02 15:04:05.000")
}

var (
	loggerBus *logger
)

func init() {
	mfw, err := NewMultiFileWriter()
	if err != nil {
		panic(err)
	}
	loggerBus = &logger{
		lvl:       DebugLevel,
		printPath: true,
		module:    "MAYY",
		terminal:  NewTerminalWriter(),
		file:      mfw,
		isStopped: false,
		mutex:     &sync.RWMutex{},
	}
}

/* ------------------------------------------------------------------------------------------ */

type logger struct {
	// lvl 定义记录的日志等级。
	lvl level

	// printPath 字段控制是否在每条日志记录上增加 file:line 信息。
	printPath bool

	// ctx 定义日志输出器 logger 的上下文信息。
	module string

	// terminal 定义将日志输出到控制台的日志输出器，如果为空的话，则默认使用 os.Stderr。
	terminal writer

	// file 定义将日志输出到文件的日志输出器，如果为空的话，则不输出到文件中。
	file writer

	// isStopped 如果日志记录器被关闭，此字段会变成 true。
	isStopped bool

	mutex *sync.RWMutex
}

func GetLogger(module string, lvl level, printPath ...bool) Logger {
	l := &logger{
		lvl:       lvl,
		printPath: loggerBus.printPath,
		module:    module,
		terminal:  loggerBus.terminal,
		file:      loggerBus.file,
	}
	if len(printPath) > 0 {
		l.printPath = printPath[0]
	}
	return l
}

func (l *logger) Debug(msg string) {
	if l.silent(DebugLevel) {
		return
	}
	l.log(newEntry(now(), l.module, DebugLevel, msg, l.printPath))
}

func (l *logger) Debugf(format, msg string) {
	if l.silent(DebugLevel) {
		return
	}
	l.log(newEntry(now(), l.module, DebugLevel, fmt.Sprintf(format, msg), l.printPath))
}

func (l *logger) Info(msg string) {
	if l.silent(InfoLevel) {
		return
	}
	l.log(newEntry(now(), l.module, InfoLevel, msg, l.printPath))
}

func (l *logger) Infof(format, msg string) {
	if l.silent(InfoLevel) {
		return
	}
	l.log(newEntry(now(), l.module, InfoLevel, fmt.Sprintf(format, msg), l.printPath))
}

func (l *logger) Warn(msg string) {
	if l.silent(WarnLevel) {
		return
	}
	l.log(newEntry(now(), l.module, WarnLevel, msg, l.printPath))
}

func (l *logger) Warnf(format, msg string) {
	if l.silent(WarnLevel) {
		return
	}
	l.log(newEntry(now(), l.module, WarnLevel, fmt.Sprintf(format, msg), l.printPath))
}

func (l *logger) Error(msg string) {
	if l.silent(ErrorLevel) {
		return
	}
	l.log(newEntry(now(), l.module, ErrorLevel, msg, l.printPath))
}

func (l *logger) Errorf(format, msg string) {
	if l.silent(ErrorLevel) {
		return
	}
	l.log(newEntry(now(), l.module, ErrorLevel, fmt.Sprintf(format, msg), l.printPath))
}

func (l *logger) Panic(msg string) {
	if l.silent(PanicLevel) {
		return
	}
	l.log(newEntry(now(), l.module, PanicLevel, msg, l.printPath))
}

func (l *logger) Panicf(format, msg string) {
	if l.silent(PanicLevel) {
		return
	}
	l.log(newEntry(now(), l.module, PanicLevel, fmt.Sprintf(format, msg), l.printPath))
}

func (l *logger) Stop() error {
	loggerBus.mutex.Lock()
	loggerBus.isStopped = true
	loggerBus.mutex.Unlock()
	return loggerBus.file.Close()
}

func (l *logger) stopped() bool {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.isStopped
}

// silent 给定的日志等级如果小于 logger 设定的日志等级，则保持沉默，不输出日志信息。
func (l *logger) silent(lvl level) bool {
	return lvl < l.lvl
}

func (l *logger) log(e *entry) {
	if loggerBus.stopped() {
		return
	}
	// l.file.WriteEntry(e)
	l.terminal.WriteEntry(e)
}
