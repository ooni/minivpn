package vpn

//
// Protocol-related constants and convenience functions.
//

// TODO: merge packet.go here

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
	pControlHardResetServerV1 // 2
	pControlSoftResetV1       // 3
	pControlV1                // 4
	pACKV1                    // 5
	pDataV1                   // 6
	pControlHardResetClientV2 // 7
	pControlHardResetServerV2 // 8
	pDataV2                   // 9
)

const (
	UDPMode = iota
	TCPMode
)

func isTCP(mode int) bool {
	return mode == TCPMode
}
