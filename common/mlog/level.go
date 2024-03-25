package mlog

import "fmt"

type level uint8

const (
	DebugLevel level = iota + 1
	InfoLevel
	WarnLevel
	ErrorLevel
	PanicLevel
	NaN
)

// String 返回描述日志等级的 Level 的小写字符串形式。
func (l level) String() (levelStr string) {
	switch l {
	case DebugLevel:
		levelStr = "debug"
	case InfoLevel:
		levelStr = "info"
	case WarnLevel:
		levelStr = "warn"
	case ErrorLevel:
		levelStr = "error"
	case PanicLevel:
		levelStr = "panic"
	}
	return levelStr
}

func (l level) ColorString() (levelStr string) {
	switch l {
	case DebugLevel:
		return fmt.Sprintf("\x1b[34m%s\x1b[0m", "debug")
	case InfoLevel:
		return fmt.Sprintf("\x1b[32m%s\x1b[0m", "info")
	case WarnLevel:
		return fmt.Sprintf("\x1b[33m%s\x1b[0m", "warn")
	case ErrorLevel:
		return fmt.Sprintf("\x1b[31m%s\x1b[0m", "error")
	case PanicLevel:
		return fmt.Sprintf("\x1b[35m%s\x1b[0m", "panic")
	default:
		return fmt.Sprintf("\x1b[36m%s\x1b[0m", "NaN")
	}
}

// ParseLevel 给定描述日志等级的字符串，返回其对应的 Level。
func ParseLevel(levelStr string) (lvl level) {
	switch levelStr {
	case "debug", "Debug", "DEBUG":
		lvl = DebugLevel
	case "info", "Info", "INFO":
		lvl = InfoLevel
	case "warn", "Warn", "WARN":
		lvl = WarnLevel
	case "error", "Error", "ERROR":
		lvl = ErrorLevel
	case "panic", "Panic", "PANIC":
		lvl = PanicLevel
	}
	return lvl
}
