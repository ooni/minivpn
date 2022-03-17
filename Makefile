PROVIDER ?= calyx
TARGET ?= "1.1.1.1"
COUNT ?= 3

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

proxy:
	./minivpn -c data/${PROVIDER}/config proxy

backup-data:
	@tar cvzf ../data-vpn-`date +'%F'`.tar.gz
