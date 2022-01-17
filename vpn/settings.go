package vpn

var DEFAULT_SETTINGS = map[string]interface{}{
	"tls-client": true,
	"cipher":     "BF-CBC",
	"auth":       "SHA1",
	"dev-type":   "tun",
	"link-mtu":   "1542",
	"tun-mtu":    "1500",
	"proto":      "UDPv4",
	"comp-lzo":   false,
	"keysize":    "128",
	"key-method": "2",
}

const hardcodedOpts = "V1,dev-type tun,link-mtu 1542,tun-mtu 1500,proto UDPv4,cipher AES-128-CBC,auth SHA1,keysize 128,key-method 2,tls-client"

func getOptions() []byte {
	return []byte(hardcodedOpts)
}
