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
	GOFLAGS='-count=1' go test -v ./...

test-coverage:
	go test -coverprofile=coverage.out ./vpn

test-short:
	go test -short -v ./...

test-ping:
	./minivpn -c data/${PROVIDER}/config -t ${TARGET} -n ${COUNT} ping

integration-server:
	# this needs the container from https://github.com/ainghazal/docker-openvpn
	cd tests/integration && ./run-server.sh

test-fetch-config:
	rm -rf data/tests
	mkdir -p data/tests && curl http://localhost:8080/ > data/tests/config
	cd data/tests && ../../tests/integration/extract.sh config

test-ping-local:
	# run the integration-server first
	./minivpn -c data/tests/config -t ${LOCAL_TARGET} -n ${COUNT} ping

test-local: test-fetch-config test-ping-local

coverage:
	go test -coverprofile=coverage.out ./vpn
	go tool cover -html=coverage.out

proxy:
	./minivpn -c data/${PROVIDER}/config proxy

backup-data:
	@tar cvzf ../data-vpn-`date +'%F'`.tar.gz

netns-shell:
	# useful for development, if we're running the openvpn client in the protected namespace
	# see https://github.com/slingamn/namespaced-openvpn
	sudo ip netns exec protected sudo -u `whoami` -i

clean:
	@rm -f coverage.out
