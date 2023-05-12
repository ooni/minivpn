// Package runtimex contains [runtime] extensions.
package runtimex

// Assert calls panic with the given message if the given statement is false.
func Assert(stmt bool, message interface{}) {
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
