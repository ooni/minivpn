package model

import "fmt"

// TestLogger is a logger that can be used whenever a test needs a logger to be passed around.
type TestLogger struct {
	Lines []string
}

func (tl *TestLogger) append(msg string) {
	tl.Lines = append(tl.Lines, msg)
}

// Debug implements model.Logger
func (tl *TestLogger) Debug(msg string) {
	tl.append(msg)
}

// Debugf implements model.Logger
func (tl *TestLogger) Debugf(format string, v ...any) {
	tl.append(fmt.Sprintf(format, v...))
}

// Info implements model.Logger
func (tl *TestLogger) Info(msg string) {
	tl.append(msg)
}

// Infof implements model.Logger
func (tl *TestLogger) Infof(format string, v ...any) {
	tl.append(fmt.Sprintf(format, v...))
}

// Warn implements model.Logger
func (tl *TestLogger) Warn(msg string) {
	tl.append(msg)
}

// Warnf implements model.Logger
func (tl *TestLogger) Warnf(format string, v ...any) {
	tl.append(fmt.Sprintf(format, v...))
}

func NewTestLogger() *TestLogger {
	return &TestLogger{
		Lines: make([]string, 0),
	}
}
