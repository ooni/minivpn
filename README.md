# minivpn

A dumb implementation of OpenVPN in pure Go (client only).

[![Go Documentation](https://godocs.io/github.com/ainghazal/minivpn/vpn?status.svg)](https://godocs.io/github.com/ainghazal/minivpn/vpn)

This implementation has serious flaws, so do **not** use this for any other
purposes than your own learning and research.

This is not, and will never be, a working implementation with all the
properties that you need from software that can protect your privacy. If you
arrived here looking for such a thing, please use
[misteriumnetwork/go-openvpn](https://github.com/mysteriumnetwork/go-openvpn) instead.

## License

GPLv3

## OpenVPN Compatibility

* Mode: Only `tls-client`.
* Protocol: Only `UDPv4`.
* Ciphers: `AES-128-CBC`, `AES-256-CBC`, `AES-128-GCM`, `AES-256-GCM`.
* HMAC: `SHA1`, `SHA256`, `SHA512`.
* Compression: `none`, `compress stub`, `comp-lzo no`.
* tls-auth: `TODO`.
* tls-crypt & [tls-crypt-v2](https://raw.githubusercontent.com/OpenVPN/openvpn/master/doc/tls-crypt-v2.txt): `TODO`.

## Pointers

* [Security Overview](https://community.openvpn.net/openvpn/wiki/SecurityOverview) in the OpenVPN wiki.
* [doc_procotocol_overview.h](https://github.com/OpenVPN/openvpn/blob/master/doc/doxygen/doc_protocol_overview.h) in OpenVPN source code.
* [OpenVPN page in Wireshark wiki](https://wiki.wireshark.org/OpenVPN), with some available `pcaps`.

## References

* https://github.com/OpenVPN/openvpn the reference implementation.
* https://github.com/OpenVPN/openvpn3 the c++ class library for the client, protocol-compatible with the OpenVPN 2.x branch.
* https://github.com/glacjay/govpn another go implementation
* https://github.com/roburio/openvpn an ocaml implementation of a minimal subset of the protocol.
* https://git.packetimpact.net/lvpn/ppyopenvpn a pure python implementation.

## Acknowledgements

Big thanks to people that wrote other implementations, that made easier for
me to understand the protocol. This project started as a learning exercise
adapting `ppyopenvpn` to Go, and wouldn't have been possible without it.

And to Jason Donenfeld for making gVisor more palatable :)


