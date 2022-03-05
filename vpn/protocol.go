package vpn

var (
	stNothing            = 0
	stControlChannelOpen = 1
	stControlMessageSent = 2
	stKeyExchanged       = 3
	stPullRequestSent    = 4
	stOptionsPushed      = 5
	stInitialized        = 6
	stDataReady          = 7

	pControlHardResetClientV1 = 1
	pControlHardResetServerV1 = 2
	pControlSoftResetV1       = 3
	pControlV1                = 4
	pACKV1                    = 5
	pDataV1                   = 6
	pDataV2                   = 9
	pControlHardResetClientV2 = 7
	pControlHardResetServerV2 = 8
)

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
