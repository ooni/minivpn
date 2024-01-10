// Package runtimex contains [runtime] extensions.
package runtimex

// PanicIfFalse calls panic with the given message if the given statement is false.
func PanicIfFalse(stmt bool, message interface{}) {
	if !stmt {
		panic(message)
	}
}

// PanicIfTrue calls panic with the given message if the given statement is true.
func PanicIfTrue(stmt bool, message interface{}) {
	if stmt {
		panic(message)
	}
}

// Assert calls panic with the given message if the given statement is false.
var Assert = PanicIfFalse
