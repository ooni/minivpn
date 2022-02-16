# minivpn

A minimalistic implementation of OpenVPN in Go (client only).

## License

GPLv3

## OpenVPN Compatibility

* Mode: Only `tls-client`.
* Protocol: Only `UDPv4`.
* Ciphers: `AES-128-CBC`, `AES-256-CBC`.
* HMAC: `SHA1`, `SHA256`, `SHA512`.
* Compression: `none`.
* tls-auth: `TODO`.

## References

Big thanks to:

* https://git.packetimpact.net/lvpn/ppyopenvpn
* https://github.com/roburio/openvpn
