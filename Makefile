PROVIDER ?= calyx
TARGET ?= "1.1.1.1"
COUNT ?= 3
LOCAL_TARGET := $(shell ip -4 addr show docker0 | grep 'inet ' | awk '{print $$2}' | cut -f 1 -d /)

build:
	@go build

build-race:
	@go build -race

build-ping:
	@go build -v ./cmd/ping

bootstrap:
	@./scripts/bootstrap-provider ${PROVIDER}

test:
	./minivpn -c data/${PROVIDER}/config -t ${TARGET} -n ${COUNT} ping

integration-server:
	# this needs the container from https://github.com/ainghazal/docker-openvpn
	cd tests/integration && ./run-server.sh

test-local:
	# run the integration-server first
	mkdir -p data/tests && curl http://localhost:8080/ > data/tests/config
	cd data/tests && ../../tests/integration/extract.sh config
	./minivpn -c data/tests/config -t ${LOCAL_TARGET} -n ${COUNT} ping

proxy:
	./minivpn -c data/${PROVIDER}/config proxy

backup-data:
	@tar cvzf ../data-vpn-`date +'%F'`.tar.gz

netns-shell:
	# useful for development, if we're running the openvpn client in the protected namespace
	# see https://github.com/slingamn/namespaced-openvpn
	sudo ip netns exec protected sudo -u `whoami` -i

