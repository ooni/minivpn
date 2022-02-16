# minivpn

A minimalistic implementation of OpenVPN in Go (client only).

## License

GPLv3

## OpenVPN Compatibility

* Mode: Only `tls-client`.
* Ciphers: `AES-128-CBC`, `AES-256-CBC`.
* Protocol: Only `UDPv4`.
* HMAC: Only `SHA1`.
* Compression: `none`.
* tls-auth: `TODO`.

## References

Big thanks to:

* https://git.packetimpact.net/lvpn/ppyopenvpn
* https://github.com/ibrahimnasson/pyopenvpn
* https://github.com/roburio/openvpn
