# Test results: `experiment/xray-yandex-pool-tcp`

Date: 2026-09-23 (UTC)

- Xray: **26.9.8**, Linux amd64 (`go1.27.1`), obtained from the official GHCR image for this host test.
- `go test ./...`: passed.
- `bash -n examples/xray/run-local.sh`: passed.
- `OPENFLUX_TEST_TRANSPORT=memory OPENFLUX_CLIENT_INGRESS=tcp XRAY_BIN=/tmp/openflux-xray-26.9.8 ./examples/xray/run-local.sh`: passed. Three generated UUIDs used parallel VLESS+TLS sessions with no `dialerProxy`, through OpenFlux's raw TCP ingress and fixed L4 exit forward. Xray reported separate nonzero uplink/downlink counters; removing client 2 rejected its next connection while clients 1 and 3 continued; re-adding client 2 restored access.
- The inherited SOCKS+`dialerProxy` smoke test also passed with the same three UUID/API checks.
- Live test against both configured Yandex Docs URLs: **blocked on this host**. OpenFlux requests were redirected to Yandex `showcaptchafast` pages for both document IDs; neither pool client received document configuration. No real-document assignment, Xray traffic through the pool, or live failover can be claimed until access is restored.

The in-memory tests validate Xray and OpenFlux's TCP path only. They skip the Yandex Docs transport, pool AES-GCM layer, document assignment, and live failover.
