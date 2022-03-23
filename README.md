# minivpn

A dumb implementation of OpenVPN in pure Go (client only).

[![Go Reference](https://pkg.go.dev/badge/github.com/ainghazal/gowl.svg)](https://pkg.go.dev/github.com/ainghazal/minivpn/vpn)
![Build Status](https://github.com/ainghazal/minivpn/workflows/build/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/ainghazal/minivpn)](https://goreportcard.com/report/github.com/ainghazal/minivpn)

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

## Tests

You can run a `connect+ping` test against a given provider (but be aware that
there's very limited support for ciphersuites and compression). Place a config
file in `data/provider/config`. The [bootstrap script](https://github.com/ainghazal/minivpn/blob/main/scripts/bootstrap-provider)
can be useful.

Then you can run:

```
make test-ping
```

### Unit tests

You can run the short tests:

```
go test -v --short ./...
```

### Integration tests

You will need `docker` installed to run the integration tests. They use a [fork
of docker-openvpn](https://github.com/ainghazal/docker-openvpn) that allows us
to configure some parameters at runtime (cipher and auth, for the time being). 

```
cd tests/integration && go test -v .
```

The `dockertest` package will take care of everything: it starts a container
that runs `openvpn`, binds it to port 1194, and exposes the config file for the
test client on `localhost:8080`.

However, for debugging sometimes is useful to run the container on one shell:

```
make integration-server
```

Now you can download the config file:

```
curl localhost:8080/ > config
```

That config file is valid to use it with the `openvpn` client. Pro tip: launch
it in a [separated namespace](https://github.com/slingamn/namespaced-openvpn)
so not to mess with your global routes. `make netns-shell` will drop you in
a shell in the new namespace.

To be able to use that config file with the `minivpn` client, you need to
[extract](https://github.com/ainghazal/minivpn/blob/main/tests/integration/extract.sh)
the different key blocks first. 

You can download the config file, split it and run integration tests with:

```
make test-local
```





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


