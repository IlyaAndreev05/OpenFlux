# Xray over an OpenFlux Yandex Docs pool

This example runs an Xray VLESS+TLS client through an OpenFlux SOCKS5 pool
client, across a Yandex Docs pool, then through the exit-side OpenFlux forward
route to a loopback Xray server. The Xray server receives each original UUID;
OpenFlux only forwards the TCP stream. The pool's per-client AES-GCM layer is
also enabled by the pool protocol.

The runner starts three Xray client processes with distinct UUIDs. Clients 1
and 2 share OpenFlux pool client `edge-a`; client 3 uses `edge-b`. The exit
pool uses `least-loaded`, so the two OpenFlux clients should be assigned to the
two distinct configured documents while two Xray users share one document.
The runner then checks separate Xray traffic counters, removes client 2 with
`HandlerService`, verifies new requests from that UUID fail while clients 1 and
3 continue, and re-adds client 2.

## Requirements

- Linux or macOS, Go, OpenSSL, Python 3, and curl.
- Xray v26.9.8 or newer, supplied with `XRAY_BIN` or available as `xray` on
  `PATH`.
- Both public Yandex Docs documents must be reachable by the OpenFlux process
  on this host. A local echo test does not establish this live requirement.

Run from any directory:

```sh
XRAY_BIN=/path/to/xray ./examples/xray/run-local.sh
```

By default the runner uses the two document URLs in the test plan. Override
`OPENFLUX_POOL_DOC1` and `OPENFLUX_POOL_DOC2` to use other documents. It builds
OpenFlux from the current checkout when `OPENFLUX_BIN` is unset. Random pool
keys, UUIDs, and a short-lived self-signed certificate are created under a
private temporary directory for each run; the Xray test clients trust that
certificate only for this local test. The script deletes the directory after a
successful run. Set `KEEP_TMP=1` to retain generated configs and logs for
inspection.

The exit Xray listens only on `127.0.0.1:18443`, and the OpenFlux exit config
allows only virtual destination `198.18.0.1:18443`, rewritten to that loopback
listener. The HTTP test service and Xray API also bind to loopback.

To validate the Xray TLS/VLESS, OpenFlux TCP relay, per-user counters, and
HandlerService locally while Yandex is unavailable, run the same scenario with
an in-memory transport pair:

```sh
XRAY_BIN=/path/to/xray OPENFLUX_TEST_TRANSPORT=memory KEEP_TMP=1 \
  ./examples/xray/run-local.sh
```

This checks the Xray-to-Xray behavior through OpenFlux's real SOCKS and L4
forwarding code, but skips Yandex Docs assignment, pool encryption, and live
failover. A passing smoke test does not satisfy the live document test.
