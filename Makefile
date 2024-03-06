PROVIDER ?= calyx
TARGET ?= "1.1.1.1"
COUNT ?= 5
TIMEOUT ?= 10
LOCAL_TARGET := $(shell ip -4 addr show docker0 | grep 'inet ' | awk '{print $$2}' | cut -f 1 -d /)
COVERAGE_THRESHOLD := 75
FLAGS=-ldflags="-w -s -buildid=none -linkmode=external" -buildmode=pie -buildvcs=false

build:
	@go build -o ./minivpn ${FLAGS} ./cmd/minivpn/

build-rel:
	@go build ${FLAGS} -o minivpn
	@upx --brute minivpn
	@GOOS=darwin go build -d ${FLAGS} -o minivpn-osx
	@GOOS=windows go build ${FLAGS} -o minivpn.exe

build-race:
	@go build -race ./cmd/minivpn

bootstrap:
	@./scripts/bootstrap-provider ${PROVIDER}

test:
	GOFLAGS='-count=1' go test -v ./...

test-unit:
	mkdir -p ./coverage/unit
	go test -cover ./internal/... -args -test.gocoverdir="`pwd`/coverage/unit"

test-integration:
	cd tests/integration && ./wrap_integration_cover.sh

test-combined-coverage:
	go tool covdata percent -i=./coverage/unit,./coverage/int
	# convert to text profile and exclude extras/integration test itself
	go tool covdata textfmt -i=./coverage/unit,./coverage/int -o coverage/profile
	cat coverage/profile| grep -v "extras/ping" | grep -v "tests/integration" > coverage/profile.out
	scripts/go-coverage-check.sh ./coverage/profile.out ${COVERAGE_THRESHOLD}

test-coverage-threshold:
	go test --short -coverprofile=cov-threshold-refactor.out ./internal/...
	./scripts/go-coverage-check.sh cov-threshold-refactor.out ${COVERAGE_THRESHOLD}

test-short:
	go test -race -short -v ./...

test-ping:
	./minivpn -c data/${PROVIDER}/config -ping

integration-server:
	# this needs the container from https://github.com/ainghazal/docker-openvpn
	cd tests/integration && ./run-server.sh

test-fetch-config:
	rm -rf data/tests
	mkdir -p data/tests && curl 172.17.0.2:8080/ > data/tests/config

qa:
	@# all the steps at once
	cd tests/integration && ./run-server.sh &
	sleep 5 # 5secs should be enough, increase this if not.
	@rm -rf data/tests
	@mkdir -p data/tests && curl 172.17.0.2:8080/ > data/tests/config
	@sleep 1
	./minivpn -c data/tests/config -ping
	@docker stop ovpn1

integration:
	go run ./tests/integration

filternet-qa:
	cd tests/qa && ./run-filternet.sh remote-block-all

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

install-linters:
	go install github.com/mgechev/revive@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest

clean:
	@rm -f coverage.out
