package vpn

import (
	"golang.org/x/sync/semaphore"
)

// rcvSem is a semaphore that limits all reads on the client socket to exactly one concurrent reader
var rcvSem = semaphore.NewWeighted(int64(1))
