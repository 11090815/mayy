package mlog

import (
	"fmt"
	"sync"
	"time"
)

/* ------------------------------------------------------------------------------------------ */

type Logger interface {
	Debug(msg string)
	Debugf(format string, args ...interface{})
	Info(msg string)
	Infof(format string, args ...interface{})
	Warn(msg string)
	Warnf(format string, args ...interface{})
	Error(msg string)
	Errorf(format string, args ...interface{})
	Panic(msg string)
	Panicf(format string, args ...interface{})
	With(key, value string) Logger
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
		ctx:       make([]string, 0),
		mutex:     &sync.RWMutex{},
	}
}

/* ------------------------------------------------------------------------------------------ */

type logger struct {
	// lvl 定义记录的日志等级。
	lvl level

	// printPath 字段控制是否在每条日志记录上增加 file:line 信息。
	printPath bool

	// module 定义日志输出器 logger 属于项目的哪个模块。
	module string

	// ctx 定义日志输出器 logger 的上下文信息。
	ctx []string

	// terminal 定义将日志输出到控制台的日志输出器，如果为空的话，则默认使用 os.Stderr。
	terminal writer

	// file 定义将日志输出到文件的日志输出器，如果为空的话，则不输出到文件中。
	file writer

	// isStopped 如果日志记录器被关闭，此字段会变成 true。
	isStopped bool

	kvLoggers map[string]*logger

	mutex *sync.RWMutex
}

func GetLogger(module string, lvl level, printPath ...bool) Logger {
	l := &logger{
		lvl:       lvl,
		printPath: loggerBus.printPath,
		module:    module,
		terminal:  loggerBus.terminal,
		file:      loggerBus.file,
		kvLoggers: make(map[string]*logger),
		ctx:       make([]string, 0),
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
	l.log(newEntry(now(), l.module, DebugLevel, msg, l.ctxStr(), l.printPath))
}

func (l *logger) Debugf(format string, args ...interface{}) {
	if l.silent(DebugLevel) {
		return
	}
	l.log(newEntry(now(), l.module, DebugLevel, fmt.Sprintf(format, args...), l.ctxStr(), l.printPath))
}

func (l *logger) Info(msg string) {
	if l.silent(InfoLevel) {
		return
	}
	l.log(newEntry(now(), l.module, InfoLevel, msg, l.ctxStr(), l.printPath))
}

func (l *logger) Infof(format string, args ...interface{}) {
	if l.silent(InfoLevel) {
		return
	}
	l.log(newEntry(now(), l.module, InfoLevel, fmt.Sprintf(format, args...), l.ctxStr(), l.printPath))
}

func (l *logger) Warn(msg string) {
	if l.silent(WarnLevel) {
		return
	}
	l.log(newEntry(now(), l.module, WarnLevel, msg, l.ctxStr(), l.printPath))
}

func (l *logger) Warnf(format string, args ...interface{}) {
	if l.silent(WarnLevel) {
		return
	}
	l.log(newEntry(now(), l.module, WarnLevel, fmt.Sprintf(format, args...), l.ctxStr(), l.printPath))
}

func (l *logger) Error(msg string) {
	if l.silent(ErrorLevel) {
		return
	}
	l.log(newEntry(now(), l.module, ErrorLevel, msg, l.ctxStr(), l.printPath))
}

func (l *logger) Errorf(format string, args ...interface{}) {
	if l.silent(ErrorLevel) {
		return
	}
	l.log(newEntry(now(), l.module, ErrorLevel, fmt.Sprintf(format, args...), l.ctxStr(), l.printPath))
}

func (l *logger) Panic(msg string) {
	if l.silent(PanicLevel) {
		return
	}
	l.log(newEntry(now(), l.module, PanicLevel, msg, l.ctxStr(), l.printPath))
}

func (l *logger) Panicf(format string, args ...interface{}) {
	if l.silent(PanicLevel) {
		return
	}
	l.log(newEntry(now(), l.module, PanicLevel, fmt.Sprintf(format, args...), l.ctxStr(), l.printPath))
}

func (l *logger) With(key, value string) Logger {
	kv := fmt.Sprintf("%s=%v", key, value)
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	if last, ok := l.kvLoggers[kv]; ok {
		return last
	}

	l.mutex.Lock()
	l.ctx = append(l.ctx, []string{key, value}...)
	cpy := &logger{
		lvl:       l.lvl,
		printPath: l.printPath,
		module:    l.module,
		terminal:  l.terminal,
		file:      l.file,
		isStopped: l.isStopped,
		mutex:     &sync.RWMutex{},
		ctx:       make([]string, 0),
	}
	cpy.ctx = append(cpy.ctx, []string{key, value}...)
	l.kvLoggers[kv] = cpy
	l.mutex.Unlock()
	return cpy
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
	l.file.WriteEntry(e)
	l.terminal.WriteEntry(e)
}

func (l *logger) ctxStr() string {
	if len(l.ctx) == 0 {
		return ""
	}
	var ctx string
	for i := 0; i <= len(l.ctx)-2; i += 2 {
		key := l.ctx[i]
		value := l.ctx[i+1]

		if key == "" {
			key = "unknown"
		}

		if value == "" {
			value = "unknown"
		}

		if i == 0 {
			ctx = key + "=" + value
		}

		if i > 0 {
			ctx = ctx + ";" + key + "=" + value
		}
	}
	return ctx
}
