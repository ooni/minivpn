module github.com/ooni/minivpn

go 1.20

// pinning for backwards-incompatible change
// replace gitlab.com/yawning/obfs4.git v0.0.0-20220204003609-77af0cba934d => gitlab.com/yawning/obfs4.git v0.0.0-20210511220700-e330d1b7024b

require (
	git.torproject.org/pluggable-transports/goptlib.git v1.3.0
	github.com/Doridian/water v1.6.1
	github.com/apex/log v1.9.0
	github.com/armon/go-socks5 v0.0.0-20160902184237-e75332964ef5
	github.com/google/go-cmp v0.5.9
	github.com/google/gopacket v1.1.19
	github.com/google/martian v2.1.0+incompatible
	github.com/google/uuid v1.3.0
	github.com/gorilla/websocket v1.5.0
	github.com/jackpal/gateway v1.0.13
	github.com/m-lab/ndt7-client-go v0.7.0
	github.com/ory/dockertest/v3 v3.9.1
	github.com/pborman/getopt/v2 v2.1.0
	github.com/refraction-networking/utls v1.3.1
	github.com/rogpeppe/go-internal v1.9.0
	gitlab.com/yawning/obfs4.git v0.0.0-20220904064028-336a71d6e4cf
	golang.org/x/net v0.17.0
	golang.org/x/sync v0.4.0
	golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173
)

require (
	filippo.io/edwards25519 v1.0.0-rc.1.0.20210721174708-390f27c3be20 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78 // indirect
	github.com/Doridian/gopacket v1.2.1 // indirect
	github.com/Microsoft/go-winio v0.6.0 // indirect
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/andybalholm/brotli v1.0.4 // indirect
	github.com/araddon/dateparse v0.0.0-20200409225146-d820a6159ab1 // indirect
	github.com/cenkalti/backoff/v4 v4.1.3 // indirect
	github.com/containerd/continuity v0.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dchest/siphash v1.2.1 // indirect
	github.com/docker/cli v20.10.14+incompatible // indirect
	github.com/docker/docker v20.10.7+incompatible // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/klauspost/compress v1.15.15 // indirect
	github.com/m-lab/go v0.1.43 // indirect
	github.com/m-lab/locate v0.4.1 // indirect
	github.com/m-lab/ndt-server v0.20.2 // indirect
	github.com/m-lab/tcp-info v1.5.2 // indirect
	github.com/mitchellh/mapstructure v1.4.1 // indirect
	github.com/moby/term v0.0.0-20201216013528-df9cb8a40635 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/opencontainers/runc v1.1.2 // indirect
	github.com/pkg/diff v0.0.0-20210226163009-20ebb0f2a09e // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/stretchr/objx v0.5.0 // indirect
	github.com/stretchr/testify v1.8.4 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20180127040702-4e3ac2762d5f // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	gitlab.com/yawning/edwards25519-extra.git v0.0.0-20211229043746-2f91fcc9fbdb // indirect
	golang.org/x/crypto v0.14.0 // indirect
	golang.org/x/mod v0.13.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	golang.org/x/tools v0.14.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	gvisor.dev/gvisor v0.0.0-20230927004350-cbd86285d259 // indirect
)
