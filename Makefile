PROVIDER ?= calyx
TARGET ?= "1.1.1.1"
COUNT ?= 3

build:
	@go build

bootstrap:
	@./scripts/bootstrap-provider ${PROVIDER}

test:
	TLSv13=1 ./minivpn -c data/${PROVIDER}/config -t ${TARGET} -n ${COUNT} ping

backup-data:
	@tar cvzf ../data-vpn-`date +'%F'`.tar.gz
