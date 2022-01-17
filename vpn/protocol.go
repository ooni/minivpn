package vpn

var (
	ST_NOTHING              = 0
	ST_CONTROL_CHANNEL_OPEN = 1
	ST_CONTROL_MESSAGE_SENT = 2
	ST_KEY_EXCHANGED        = 3
	ST_PULL_REQUEST_SENT    = 4
	ST_OPTIONS_PUSHED       = 5
	ST_INITIALIZED          = 6

	P_CONTROL_HARD_RESET_CLIENT_V1 = 1
	P_CONTROL_HARD_RESET_SERVER_V1 = 2
	P_CONTROL_SOFT_RESET_V1        = 3
	P_CONTROL_V1                   = 4
	P_ACK_V1                       = 5
	P_DATA_V1                      = 6
	P_DATA_V2                      = 9
	P_CONTROL_HARD_RESET_CLIENT_V2 = 7
	P_CONTROL_HARD_RESET_SERVER_V2 = 8
)

func isControlOpcode(b byte) bool {
	switch b {
	case byte(P_CONTROL_HARD_RESET_SERVER_V2), byte(P_CONTROL_V1):
		return true
	default:
		return false
	}
}

func isDataOpcode(b byte) bool {
	switch b {
	case byte(P_DATA_V1):
		return true
	default:
		return false
	}
}
