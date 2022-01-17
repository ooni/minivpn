package vpn

type Channel struct {
	// this is a channel
	queue []interface{}
}

func init() {
}

func NewChannel() (c *Channel) {
	c = new(Channel)
	c.queue = []interface{}{}
	return
}

func (c *Channel) pushPacket(packet interface{}) {
	c.queue = append(c.queue, packet)
}

func (c *Channel) send(packet interface{}) {
	c.send(packet)
}
