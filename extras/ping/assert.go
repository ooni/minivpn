package ping

func assert(assertion bool, message string) {
	if !assertion {
		panic(message)
	}
}
