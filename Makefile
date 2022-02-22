PROVIDER ?= calyx
TARGET ?= "1.1.1.1"

bootstrap:
	@./scripts/bootstrap-provider ${PROVIDER}

test:
	TLSv13=1 ./minivpn -c data/${PROVIDER}/config -t ${TARGET} ping

backup-data:
	@tar cvzf ../data-vpn-`date +'%F'`.tar.gz
