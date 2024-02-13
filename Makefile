PROVIDER ?= calyx
TARGET ?= "1.1.1.1"
COUNT ?= 5
TIMEOUT ?= 10
LOCAL_TARGET := $(shell ip -4 addr show docker0 | grep 'inet ' | awk '{print $$2}' | cut -f 1 -d /)
COVERAGE_THRESHOLD := 80
FLAGS=-ldflags="-w -s -buildid=none -linkmode=external" -buildmode=pie -buildvcs=false

build:
	@go build -o ./minivpn ${FLAGS} ./cmd/minivpn/

build-rel:
	@go build ${FLAGS} -o minivpn
	@upx --brute minivpn
	@GOOS=darwin go build -d ${FLAGS} -o minivpn-osx
	@GOOS=windows go build ${FLAGS} -o minivpn.exe

build-race:
	@go build -race

build-ping:
	@go build -v ./cmd/vpnping

build-ndt7:
	@go build -o ndt7 ./cmd/ndt7

bootstrap:
	@./scripts/bootstrap-provider ${PROVIDER}

test:
	GOFLAGS='-count=1' go test -v ./...

test-coverage:
	go test -coverprofile=coverage.out ./vpn

test-coverage-refactor:
	go test -coverprofile=coverage.out ./internal/...

test-coverage-threshold:
	go test --short -coverprofile=cov-threshold.out ./vpn
	./scripts/go-coverage-check.sh cov-threshold.out ${COVERAGE_THRESHOLD}

test-coverage-threshold-refactor:
	go test --short -coverprofile=cov-threshold-refactor.out ./internal/...
	./scripts/go-coverage-check.sh cov-threshold-refactor.out ${COVERAGE_THRESHOLD}

test-short:
	go test -race -short -v ./...

test-ping:
	./minivpn -c data/${PROVIDER}/config -t ${TARGET} -n ${COUNT} ping

integration-server:
	# this needs the container from https://github.com/ainghazal/docker-openvpn
	cd tests/integration && ./run-server.sh

test-fetch-config:
	rm -rf data/tests
	mkdir -p data/tests && curl 172.17.0.2:8080/ > data/tests/config

test-ping-local:
	# run the integration-server first
	./minivpn -c data/tests/config -t 172.17.0.1 -n ${COUNT} ping

test-local: test-fetch-config test-ping-local

qa:
	@# all the steps at once
	cd tests/integration && ./run-server.sh &
	sleep 5 # 5secs should be enough, increase this if not.
	@rm -rf data/tests
	@mkdir -p data/tests && curl 172.17.0.2:8080/ > data/tests/config
	@sleep 1
	./minivpn -c data/tests/config -t 172.17.0.1 -n ${COUNT} ping
	@docker stop ovpn1

integration:
	go run ./tests/integration

filternet-qa:
	cd tests/qa && ./run-filternet.sh remote-block-all

coverage:
	go test -coverprofile=coverage.out ./vpn
	go tool cover -html=coverage.out

coverage-ping:
	go test -coverprofile=coverage-ping.out ./extras/ping
	go tool cover -html=coverage-ping.out

proxy:
	./minivpn -c data/${PROVIDER}/config proxy

backup-data:
	@tar cvzf ../data-vpn-`date +'%F'`.tar.gz

netns-shell:
	# useful for development, if we're running the openvpn client in the protected namespace
	# see https://github.com/slingamn/namespaced-openvpn
	sudo ip netns exec protected sudo -u `whoami` -i

.PHONY: lint
lint: go-fmt go-vet go-sec go-revive

go-fmt:
	gofmt -s -l .

go-vet:
	go vet internal/...

go-sec:
	gosec internal/...

go-revive:
	revive internal/...

clean:
	@rm -f coverage.out
