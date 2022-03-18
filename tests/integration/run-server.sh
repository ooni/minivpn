#!/usr/bin/env bash
docker run --cap-add=NET_ADMIN \
-p 1194:1194/udp -p 8080:8080/tcp \
--rm \
--env-file=env \
--name=ovpn1 \
alekslitvinenk/openvpn
