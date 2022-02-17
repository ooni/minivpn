# minivpn

A dumb implementation of OpenVPN in Go (client only).

This implementation has serious flaws, so do **not** use this for any other
purposes than your own learning and research.

This is not, and will never be, a working implementation with all the
properties that you need from software that can protect your privacy.

## License

GPLv3

## OpenVPN Compatibility

* Mode: Only `tls-client`.
* Protocol: Only `UDPv4`.
* Ciphers: `AES-128-CBC`, `AES-256-CBC`, `AES-128-GCM`.
* HMAC: `SHA1`, `SHA256`, `SHA512`.
* Compression: `none`.
* tls-auth: `TODO`.

## References

Big thanks to people that wrote other implementations, that made easier for
me to understand the protocol. This project started as a learning exercise
adapting `ppyopenvpn` to Go.

* https://git.packetimpact.net/lvpn/ppyopenvpn
* https://github.com/roburio/openvpn
