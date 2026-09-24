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

Live runs require `OPENFLUX_POOL_DOC1` and `OPENFLUX_POOL_DOC2` to be set
explicitly to documents you control. No document URLs are bundled. The
in-memory test does not require these variables. It builds
OpenFlux from the current checkout when `OPENFLUX_BIN` is unset. Random pool
keys, UUIDs, and a short-lived self-signed certificate are created under a
private temporary directory for each run; the Xray test clients trust that
certificate only for this local test. The script deletes the directory after a
successful run. Set `KEEP_TMP=1` to retain generated configs and logs for
inspection.

The test runner generates a virtual IPv4 endpoint and an available Xray listen
port for each run. Override `OPENFLUX_XRAY_VIRTUAL_ENDPOINT=IP:PORT` and
`OPENFLUX_XRAY_EXIT_PORT=PORT` to select them. The generated exit config maps
that endpoint to the local Xray listener and denies unmatched destinations.
The HTTP test service and Xray API also bind to loopback.

OpenFlux does not require Xray. For ordinary direct egress, omit `forward` from
the pool exit config; the L4 exit connects to the destination requested by
SOCKS5/TUN. To chain through an Xray or another local/remote TCP service,
configure exact routes on the exit. For example:

```json
"forward": {
  "routes": [
    { "virtual_endpoint": "192.0.2.10:443", "target": "127.0.0.1:443" },
    { "virtual_endpoint": "192.0.2.11:8443", "target": "xray.internal:8443" }
  ],
  "unmatched": "deny"
}
```

The address on the left is selected by the operator/client config and is only
a route key; it does not come from Yandex. `unmatched` can be `direct` when
unlisted destinations should use normal direct egress. Routes match exact
IPv4 TCP endpoints. The older single-route `forward.virtual_endpoint` /
`forward.target` format remains supported.

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

## Raw TCP ingress experiment

Set `OPENFLUX_CLIENT_INGRESS=tcp` to make each Xray VLESS+TLS outbound connect
directly to its local OpenFlux TCP listener. Xray keeps `serverName` set to
`xray.local`; OpenFlux sends each accepted byte stream to the `tcp_target` in
the client pool config (or the `--tcp-target=host:port` CLI override). The
runner sets this to the generated virtual endpoint used by the exit route. The
Xray outbound has no `sockopt.dialerProxy` and no SOCKS outbound:

```sh
XRAY_BIN=/path/to/xray OPENFLUX_TEST_TRANSPORT=memory \
  OPENFLUX_CLIENT_INGRESS=tcp ./examples/xray/run-local.sh
```

For the Yandex-backed run, omit `OPENFLUX_TEST_TRANSPORT=memory`. Each OpenFlux
client binds `127.0.0.1` at a generated port by default; use
`--tcp-listen=127.0.0.1:PORT` to choose a fixed port when launching it manually.

Raw TCP ingress cannot infer an arbitrary destination from a byte stream, so it requires one configured target. SOCKS5 and TUN preserve each connection’s requested destination and can use direct egress or exit routes without this option.
