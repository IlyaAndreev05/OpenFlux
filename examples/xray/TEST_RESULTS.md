# Test results: `feature/xray-yandex-pool-socks`

Date: 2026-09-23 (UTC)

- Xray: **26.9.8**, Linux amd64 (`go1.27.1`), obtained from the official GHCR image for this host test.
- `go test ./...`: passed.
- `bash -n examples/xray/run-local.sh`: passed.
- `OPENFLUX_TEST_TRANSPORT=memory XRAY_BIN=/tmp/openflux-xray-26.9.8 ./examples/xray/run-local.sh`: passed. Three generated UUIDs sent parallel HTTP requests through Xray VLESS+TLS, OpenFlux SOCKS ingress and the fixed L4 pool-exit forward; each user had nonzero, separate Xray uplink/downlink counters; removing `xray-client-2` rejected its next request while clients 1 and 3 continued; adding it back restored access.
- Live test against both configured Yandex Docs URLs: **blocked on this host**. OpenFlux received HTTP 200 responses redirected to `https://docs.yandex.ru/showcaptchafast?...` for both `[redacted-document-1]` and `[redacted-document-2]`. Neither pool client could fetch document config, so neither document could be assigned. The required live pool/Xray test and active-flow failover over real documents remain unverified until OpenFlux has restored access from this host.

The smoke test uses an in-memory raw transport pair and deliberately skips Yandex Docs, its pool AES-GCM protocol, document assignment, and live failover. It does not count as a live-test pass. The runner creates all UUIDs, pool keys, and its short-lived TLS certificate at launch and does not write them into the repository.


## Configurable-route follow-up

Date: 2026-09-24 (UTC)

- `go test ./...`: passed, including multi-route policy validation and a direct TCP egress test with no Xray route.
- `bash -n examples/xray/run-local.sh`: passed.
- Xray **26.9.8** with the updated runner and in-memory OpenFlux transport: passed using a generated virtual endpoint and generated exit port. Three UUIDs made parallel requests with separate counters; removing client 2 rejected its new connection while clients 1 and 3 continued; adding client 2 back restored access.
- This follow-up did not use Yandex Docs. The live-document limitation above remains.
