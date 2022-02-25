package vpn

type DataProducer interface {
	DataChannel() chan []byte
}
