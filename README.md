# minivpn

A minimalistic implementation of the OpenVPN protocol in Go (client only).

[![Go Reference](https://pkg.go.dev/badge/github.com/ooni/gowl.svg)](https://pkg.go.dev/github.com/ooni/minivpn/vpn)
![Build Status](https://github.com/ooni/minivpn/workflows/build/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/ooni/minivpn)](https://goreportcard.com/report/github.com/ooni/minivpn)

This implementation is intended for research purposes only. It has serious
flaws, so please do **not** use it for any real-life situation where you need to
trust it with user data.

This is not a working implementation with all the properties that you need from
software that can effectively protect your privacy. If you arrived here looking
for such a thing, please use [misteriumnetwork/go-openvpn](https://github.com/mysteriumnetwork/go-openvpn) instead.


## License

```
SPDX-License-Identifier: GPL-3.0-or-later
```

## OpenVPN Compatibility

* Mode: Only `tls-client`.
* Protocol: `UDPv4`, `TCPv4`.
* Ciphers: `AES-128-CBC`, `AES-256-CBC`, `AES-128-GCM`, `AES-256-GCM`.
* HMAC: `SHA1`, `SHA256`, `SHA512`.
* Compression: `none`, `compress stub`, `comp-lzo no`.
* tls-auth: `TODO`.
* tls-crypt & [tls-crypt-v2](https://raw.githubusercontent.com/OpenVPN/openvpn/master/doc/tls-crypt-v2.txt): `TODO`.

## Additional features

### Obfuscation

`obfs4` is supported. Add an additional entry in the config file, in this format:

```
proxy-obfs4 obfs4://RHOST:RPORT?cert=BASE64ENCODED_CERT&iat-mode=0
```

## Configuration

The public constructor for `vpn.Client` allows you to instantiate a `Client` from a
correctly initialized `Options` object.

For convenience, `minivpn` also understands how to parse a minimal subset of the
configuration options that can be written in an openvpn config file.

### Inline file support

Following the configuration format in the reference implementation, `minivpn`
allows including files in the main configuration file, but only for the ` ca`,
`cert` and `key` options.

Each inline file is started by the line `<option>` and ended by the line
`</option>`.

Here is an example of an inline file usage:

```
<cert>
-----BEGIN CERTIFICATE-----
[...]
-----END CERTIFICATE-----
</cert>
```

## Tests

You can run a `connect+ping` test against a given provider (but be aware that
there's very limited support for ciphersuites and compression). Place a config
file in `data/provider/config`. The [bootstrap script](https://github.com/ooni/minivpn/blob/main/scripts/bootstrap-provider)
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
of docker-openvpn](https://github.com/ooni/docker-openvpn) that allows us
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
[extract](https://github.com/ooni/minivpn/blob/main/tests/integration/extract.sh)
the different key blocks first. 

You can download the config file, split it and run integration tests with:

```
make test-local
```

## Limitations

Many, but re-keying is maybe one of the first expected to limit the usefulness
in the current state.


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

Big thanks to people that wrote other implementations. This project started as
a learning exercise adapting `ppyopenvpn` to Go, and wouldn't have been
possible without it.

And to [Jason Donenfeld](https://www.jasondonenfeld.com/) for
making [gVisor's netstack](https://gvisor.dev/docs/user_guide/networking/) more palatable.
