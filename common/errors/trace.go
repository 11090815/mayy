package errors

import (
	"fmt"
	"runtime"
	"strings"
)

const PrefixPath = "github.com/11090815/"

var trace = false

type Error struct {
	content string
	path    string
}

func (et *Error) Error() string {
	if trace {
		return fmt.Sprintf("[%s] => {%s}", et.path, et.content)
	}
	return et.content
}

func NewError(content string) *Error {
	var path string
	if trace {
		path = constructPath()
	}

	return &Error{
		content: content,
		path:    path,
	}
}

func NewErrorf(format string, args ...interface{}) *Error {
	var path string
	if trace {
		path = constructPath()
	}

	return &Error{
		content: fmt.Sprintf(format, args...),
		path:    path,
	}
}

func SetTrace() {
	trace = true
}

func constructPath() string {
	pc, file, line, ok := runtime.Caller(2)
	if !ok {
		return "unknown path"
	}

	index := strings.Index(file, PrefixPath)
	if index == -1 {
		file = "unknown file"
	} else {
		file = file[index+len(PrefixPath):]
	}

	funcName := runtime.FuncForPC(pc).Name()
	index = strings.LastIndex(funcName, ".")
	if index == -1 {
		funcName = "unknown function"
	} else {
		funcName = funcName[index+1:]
	}

	return fmt.Sprintf("%s_%s:%d", file, funcName, line)
}
