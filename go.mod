module github.com/ooni/minivpn

go 1.17

// pinning for backwards-incompatible change
replace gitlab.com/yawning/obfs4.git v0.0.0-20220204003609-77af0cba934d => gitlab.com/yawning/obfs4.git v0.0.0-20210511220700-e330d1b7024b

require (
	git.torproject.org/pluggable-transports/goptlib.git v1.2.0
	github.com/apex/log v1.9.0
	github.com/armon/go-socks5 v0.0.0-20160902184237-e75332964ef5
	github.com/google/go-cmp v0.5.8
	github.com/google/gopacket v1.1.19
	github.com/google/martian v2.1.0+incompatible
	github.com/gorilla/websocket v1.4.2
	github.com/m-lab/ndt7-client-go v0.6.1
	github.com/ory/dockertest/v3 v3.8.1
	github.com/pborman/getopt/v2 v2.1.0
	github.com/refraction-networking/utls v1.1.0
	gitlab.com/yawning/obfs4.git v0.0.0-20220204003609-77af0cba934d
	golang.org/x/net v0.0.0-20211111083644-e5c967477495
	golang.zx2c4.com/go118/netip v0.0.0-20211105124833-002a02cb0e53
	golang.zx2c4.com/wireguard v0.0.0-20210424170727-c9db4b7aaa22
	golang.zx2c4.com/wireguard/tun/netstack v0.0.0-20220202223031-3b95c81cc178
)

require (
	github.com/Azure/go-ansiterm v0.0.0-20210617225240-d185dfc1b5a1 // indirect
	github.com/Microsoft/go-winio v0.5.2 // indirect
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/araddon/dateparse v0.0.0-20200409225146-d820a6159ab1 // indirect
	github.com/cenkalti/backoff/v4 v4.1.2 // indirect
	github.com/containerd/continuity v0.2.2 // indirect
	github.com/dchest/siphash v1.2.1 // indirect
	github.com/docker/cli v20.10.13+incompatible // indirect
	github.com/docker/docker v20.10.13+incompatible // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/btree v1.0.1 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/m-lab/go v0.1.43 // indirect
	github.com/m-lab/locate v0.4.1 // indirect
	github.com/m-lab/ndt-server v0.20.2 // indirect
	github.com/m-lab/tcp-info v1.5.2 // indirect
	github.com/mitchellh/mapstructure v1.4.3 // indirect
	github.com/moby/term v0.0.0-20210619224110-3f7ff695adc6 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/opencontainers/runc v1.1.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	golang.org/x/crypto v0.0.0-20210711020723-a769d52b0f97 // indirect
	golang.org/x/sys v0.0.0-20211116061358-0a5406a5449c // indirect
	golang.org/x/time v0.0.0-20210220033141-f8bda1e9f3ba // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gvisor.dev/gvisor v0.0.0-20211020211948-f76a604701b6 // indirect
)
