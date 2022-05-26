# ndt7 client

For testing purposes, you can build this ndt7 client.

Be sure to pass the `TLS_NOVERIFY` flag if your test server has a self-signed certificate.

```
DEBUG=1 EXTRA_DEBUG=0 TLS_NOVERIFY=1 NDT7_SERVER=IP:PORT PROVIDER=calyx ./ndt7 --count 1 --type all
```
