package model

import "fmt"

type TestLogger struct {
	Lines []string
}

func (tl *TestLogger) append(msg string) {
	tl.Lines = append(tl.Lines, msg)
}

func (tl *TestLogger) Debug(msg string) {
	tl.append(msg)
}
func (tl *TestLogger) Debugf(format string, v ...any) {
	tl.append(fmt.Sprintf(format, v...))
}
func (tl *TestLogger) Info(msg string) {
	tl.append(msg)
}
func (tl *TestLogger) Infof(format string, v ...any) {
	tl.append(fmt.Sprintf(format, v...))
}
func (tl *TestLogger) Warn(msg string) {
	tl.append(msg)
}
func (tl *TestLogger) Warnf(format string, v ...any) {
	tl.append(fmt.Sprintf(format, v...))
}

func NewTestLogger() *TestLogger {
	return &TestLogger{
		Lines: make([]string, 0),
	}
}
