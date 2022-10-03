This folder has end to end tests to test minivpn against a real server.

# DOS

To inject bogus packets and test for handshake completion:

```
❯ sudo ./dos_exploit -i enxe04f438dea75 -t 0.2
[+] Intercepting requests to UDP port 1194 and injecting bogus response
[-] Interval: 0.2 seconds
```

```
❯ ./minivpn -c ../data/riseup/config -t "1.1.1.1" -n 5 ping
2022/10/06 23:34:59 info : Connecting to 51.158.144.32:1194 with proto UDP
2022/10/06 23:34:59 info : Cipher: AES-256-GCM
2022/10/06 23:34:59 info : Auth:   SHA512
2022/10/06 23:34:59 info : Remote session ID: 3794664e9ff21400
2022/10/06 23:34:59 info : Local session ID:  3edf430eff46640a
2022/10/06 23:34:59 info : TLS handshake done
2022/10/06 23:34:59 info : Key derivation OK
2022/10/06 23:34:59 warn: Packet too far: 0
2022/10/06 23:34:59 info : Server pushed options
2022/10/06 23:34:59 info : Tunnel IP: 10.42.0.205
2022/10/06 23:34:59 info : Gateway IP: 10.42.0.1
2022/10/06 23:34:59 info : VPN handshake done
2022/10/06 23:34:59 error: bad input: bad ack: EOF
2022/10/06 23:34:59 error: bad input: bad ack: EOF
2022/10/06 23:34:59 error: bad input: bad ack: EOF
2022/10/06 23:35:00 error: bad input: bad ack: EOF
2022/10/06 23:35:00 info : Got ACK
2022/10/06 23:35:00 error: bad input: bad ack: EOF
reply from 1.1.1.1: icmp_seq=0 ttl=57 time=60.0 ms
2022/10/06 23:35:00 error: bad input: bad ack: EOF
2022/10/06 23:35:00 error: bad input: bad ack: EOF
2022/10/06 23:35:01 error: bad input: bad ack: EOF
2022/10/06 23:35:01 error: bad input: bad ack: EOF
reply from 1.1.1.1: icmp_seq=1 ttl=57 time=66.7 ms
2022/10/06 23:35:01 error: bad input: bad ack: EOF
2022/10/06 23:35:01 error: bad input: bad ack: EOF
2022/10/06 23:35:02 error: bad input: bad ack: EOF
2022/10/06 23:35:02 info : Got ACK
2022/10/06 23:35:02 error: bad input: bad ack: EOF
reply from 1.1.1.1: icmp_seq=2 ttl=57 time=60.2 ms
2022/10/06 23:35:02 error: bad input: bad ack: EOF
2022/10/06 23:35:02 error: bad input: bad ack: EOF
2022/10/06 23:35:03 error: bad input: bad ack: EOF
reply from 1.1.1.1: icmp_seq=3 ttl=57 time=59.5 ms
2022/10/06 23:35:04 error: bad input: bad ack: EOF
reply from 1.1.1.1: icmp_seq=4 ttl=57 time=64.0 ms
--- 1.1.1.1 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss
rtt min/avg/max/stdev = 59.468628ms, 62.052388ms, 66.659817ms, 2.80082ms
```

