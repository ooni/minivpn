package vpn

//
// Logging capabilities.
//

import (
	"log"
	"os"
)

// logger uses an implementation from the standard library in case the
// binary does not set its own.
var logger Logger = &defaultLogger{}

// Logger is compatible with github.com/apex/log
type Logger interface {
	// Debug emits a debug message.
	Debug(msg string)

	// Debugf formats and emits a debug message.
	Debugf(format string, v ...interface{})

	// Info emits an informational message.
	Info(msg string)

	// Infof formats and emits an informational message.
	Infof(format string, v ...interface{})

	// Warn emits a warning message.
	Warn(msg string)

	// Warnf formats and emits a warning message.
	Warnf(format string, v ...interface{})

	// Error emits an error message
	Error(msg string)

	// Errorf formats and emits an error message.
	Errorf(format string, v ...interface{})
}

// defaultLogger uses the standard log package for logs in case
// the user does not provide a custom Log implementation.

type defaultLogger struct{}

func (dl *defaultLogger) Debug(msg string) {
	if os.Getenv("EXTRA_DEBUG") == "1" {
		log.Println(msg)
	}
}

func (dl *defaultLogger) Debugf(format string, v ...interface{}) {
	if os.Getenv("EXTRA_DEBUG") == "1" {
		log.Printf(format, v...)
	}
}

func (dl *defaultLogger) Info(msg string) {
	log.Printf("info : %s\n", msg)
}

func (dl *defaultLogger) Infof(format string, v ...interface{}) {
	log.Printf("info : "+format, v...)
}

func (dl *defaultLogger) Warn(msg string) {
	log.Printf("warn: %s\n", msg)
}

func (dl *defaultLogger) Warnf(format string, v ...interface{}) {
	log.Printf("warn: "+format, v...)
}

func (dl *defaultLogger) Error(msg string) {
	log.Printf("error: %s\n", msg)
}

func (dl *defaultLogger) Errorf(format string, v ...interface{}) {
	log.Printf("error: "+format, v...)
}
