package vpn

type DataProducer interface {
	GetDataChannel() chan []byte
}
