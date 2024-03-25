package mlog

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPrintColorLevel(t *testing.T) {
	t.Log(DebugLevel.ColorString())
	t.Log(InfoLevel.ColorString())
	t.Log(WarnLevel.ColorString())
	t.Log(ErrorLevel.ColorString())
	t.Log(PanicLevel.ColorString())
	f, err := os.OpenFile("log.log", os.O_CREATE|os.O_RDWR, os.FileMode(0600))
	require.NoError(t, err)
	f.WriteString(DebugLevel.String())
	f.Close()
}
