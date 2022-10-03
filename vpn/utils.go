package vpn

//
// Utility functions
//

// panicIfFalse calls panic with the given message if the given statement is false.
func panicIfFalse(stmt bool, message interface{}) {
	if !stmt {
		panic(message)
	}
}

// panicIfTrue calls panic with the given message if the given statement is true.
func panicIfTrue(stmt bool, message interface{}) {
	if stmt {
		panic(message)
	}
}
