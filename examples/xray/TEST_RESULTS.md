# Xray/OpenFlux test results

Date: 2026-09-24 (UTC)

- Xray: **26.9.8**, Linux amd64.
- `go test ./...`: passed on this branch, including direct L4 TCP egress with no Xray route, configurable route validation, and TCP target config validation.
- `bash -n examples/xray/run-local.sh`: passed.
- `OPENFLUX_TEST_TRANSPORT=memory XRAY_BIN=/tmp/openflux-xray-26.9.8 ./examples/xray/run-local.sh`: passed. Three generated UUIDs sent parallel VLESS+TLS requests through OpenFlux SOCKS ingress; the Xray exit reported distinct user counters; removing client 2 rejected its new request while clients 1 and 3 continued; re-adding client 2 restored access. The route endpoint and local exit port were generated per run.
- `OPENFLUX_TEST_TRANSPORT=memory OPENFLUX_CLIENT_INGRESS=tcp XRAY_BIN=/tmp/openflux-xray-26.9.8 ./examples/xray/run-local.sh`: passed. The clients connected to OpenFlux raw TCP ingress without `dialerProxy`; the target came from each client pool config and the exit used the matching generated route. Per-user counters, API removal, and re-add checks passed.
- Live test against both configured Yandex Docs URLs: **blocked on this host**. OpenFlux requests were redirected to Yandex `showcaptchafast` pages for document IDs `[redacted-document-1]` and `[redacted-document-2]`; neither pool client received document configuration. Real-document assignment, Xray traffic through the pool, and live failover remain unverified until access from this host is restored.

The in-memory tests exercise the Xray/OpenFlux TCP path but skip the Yandex Docs WebSocket transport, pool AES-GCM layer, document assignment, and live failover. They do not count as a live-document pass. The runner generates UUIDs, pool keys, and a short-lived TLS certificate per run and does not write secrets into the repository.
