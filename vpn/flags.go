package vpn

import (
	"os"
)

var debug = os.Getenv("DEBUG")

func isDebug() bool {
	return debug == "1"
}

var debugOLD = os.Getenv("DEBUG_OLD")

func isDebugOLD() bool {
	return debugOLD == "1"
}
