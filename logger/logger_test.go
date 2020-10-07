package logger

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	// [INFO]  2020/03/06 14:25:05 logger_test.go:16: test message
	infoMsgRegex = `^\[INFO\]  \d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2} logger_test\.go:\d+: test message`
	errMsgRegex  = `^\[ERROR\] \d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2} logger_test\.go:\d+: test error message`
)

func TestLog(t *testing.T) {

	stdOut, _, rollback := setLoggerOutput()
	defer func() { rollback() }()

	Log("test message")
	msg := stdOut.String()

	assert.Regexp(t, infoMsgRegex, msg)
}

func TestLogf(t *testing.T) {

	stdOut, _, rollback := setLoggerOutput()
	defer func() { rollback() }()

	Logf("test %s", "message")
	msg := stdOut.String()

	assert.Regexp(t, infoMsgRegex, msg)
}

func TestErrLog(t *testing.T) {

	_, stdErr, rollback := setLoggerOutput()
	defer func() { rollback() }()

	Error("test error message")
	msg := stdErr.String()

	assert.Regexp(t, errMsgRegex, msg)
}

func TestErrLogf(t *testing.T) {

	_, stdErr, rollback := setLoggerOutput()
	defer func() { rollback() }()

	Errorf("test error %s", "message")
	msg := stdErr.String()

	assert.Regexp(t, errMsgRegex, msg)
}

// --- helper functions ---

func setLoggerOutput() (out *bytes.Buffer, errOut *bytes.Buffer, rollback func()) {

	stdOutLogger, stdErrLogger := StdOutLogger, StdErrLogger
	rollback = func() {
		StdOutLogger, StdErrLogger = stdOutLogger, stdErrLogger
	}

	buf, errBuf := new(bytes.Buffer), new(bytes.Buffer)
	StdOutLogger, StdErrLogger = newStdOutLogger(buf), newStdErrLogger(errBuf)
	return buf, errBuf, rollback
}
