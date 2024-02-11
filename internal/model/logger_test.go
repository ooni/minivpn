package model

import "fmt"

type testLogger struct {
	lines []string
}

func (tl *testLogger) append(msg string) {
	tl.lines = append(tl.lines, msg)
}

func (tl *testLogger) Debug(msg string) {
	tl.append(msg)
}
func (tl *testLogger) Debugf(format string, v ...any) {
	tl.append(fmt.Sprintf(format, v...))
}
func (tl *testLogger) Info(msg string) {
	tl.append(msg)
}
func (tl *testLogger) Infof(format string, v ...any) {
	tl.append(fmt.Sprintf(format, v...))
}
func (tl *testLogger) Warn(msg string) {
	tl.append(msg)
}
func (tl *testLogger) Warnf(format string, v ...any) {
	tl.append(fmt.Sprintf(format, v...))
}

func newTestLogger() *testLogger {
	return &testLogger{
		lines: make([]string, 0),
	}
}
