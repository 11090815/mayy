package mlog

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/11090815/mayy/errors"
)

/* ------------------------------------------------------------------------------------------ */

type entry struct {
	timestamp string
	module    string
	msg       string
	level     level
}

func (e *entry) ColorLevelString() string {
	return fmt.Sprintf("%-20s | %-14s | %-16s | %s\n", e.timestamp, e.level.ColorString(), e.module, e.msg)
}

func (e *entry) NormalLevelString() string {
	return fmt.Sprintf("%-20s | %-5s | %-16s | %s\n", e.timestamp, e.level.String(), e.module, e.msg)
}

func newEntry(timestamp string, module string, level level, msg string, printPath bool) *entry {
	if printPath {
		pc, file, line, ok := runtime.Caller(2)
		if !ok {
			msg = "unknown path => " + msg
		} else {
			index := strings.Index(file, errors.PrefixPath)
			if index == -1 {
				file = "unknown file"
			} else {
				file = file[index+len(errors.PrefixPath):]
			}
			funcName := runtime.FuncForPC(pc).Name()
			index = strings.LastIndex(funcName, ".")
			if index == -1 {
				funcName = "unknown function"
			} else {
				funcName = funcName[index+1:]
			}
			msg = fmt.Sprintf("%s_%s:%d => %s", file, funcName, line, msg)
		}
	}

	return &entry{
		timestamp: timestamp,
		module:    module,
		level:     level,
		msg:       msg,
	}
}
