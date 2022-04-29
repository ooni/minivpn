package vpn

import (
	"os"
)

var debug = os.Getenv("DEBUG")
var initialized = false

func isDebug() bool {
	return debug == "1"
}
