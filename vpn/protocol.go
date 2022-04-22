package vpn

const (
	stNothing = iota
	stControlChannelOpen
	stControlMessageSent
	stKeyExchanged
	stPullRequestSent
	stOptionsPushed
	stInitialized
	stDataReady
)

const (
	pControlHardResetClientV1 = iota + 1
	pControlHardResetServerV1
	pControlSoftResetV1
	pControlV1
	pACKV1
	pDataV1
	pControlHardResetClientV2
	pControlHardResetServerV2
	pDataV2
)

const (
	UDPMode = iota
	TCPMode
)

func isTCP(mode int) bool {
	return mode == TCPMode
}

func isControlOpcode(b byte) bool {
	switch b {
	case byte(pControlHardResetServerV2), byte(pControlV1):
		return true
	default:
		return false
	}
}

func isDataOpcode(b byte) bool {
	switch b {
	case byte(pDataV1):
		return true
	default:
		return false
	}
}
