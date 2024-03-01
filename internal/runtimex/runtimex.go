// Package runtimex contains [runtime] extensions.
package runtimex

import (
	"errors"
	"fmt"
)

// PanicIfFalse calls panic with the given message if the given statement is false.
func PanicIfFalse(stmt bool, message string) {
	if !stmt {
		panic(errors.New(message))
	}
}

// PanicIfTrue calls panic with the given message if the given statement is true.
func PanicIfTrue(stmt bool, message string) {
	if stmt {
		panic(errors.New(message))
	}
}

// Assert calls panic with the given message if the given statement is false.
var Assert = PanicIfFalse

// PanicOnError calls panic() if err is not nil. The type passed to panic
// is an error type wrapping the original error.
func PanicOnError(err error, message string) {
	if err != nil {
		panic(fmt.Errorf("%s: %w", message, err))
	}
}
