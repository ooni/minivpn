// Package reliabletransport implements the reliable transport.
// A note about terminology: in this package, "receiver" is the moveUpWorker in the [reliabletransport.Service] (since it receives incoming packets), and
// "sender" is the moveDownWorker in the same service. The corresponding data structures lack mutexes because they are intended to be confined to a single
// goroutine (one for each worker), and they SHOULD ONLY communicate via message passing.
package reliabletransport
