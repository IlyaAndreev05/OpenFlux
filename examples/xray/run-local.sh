#!/usr/bin/env bash
# End-to-end Xray -> OpenFlux -> Yandex Docs pool -> OpenFlux -> Xray test.
# Xray, UUIDs, pool keys and TLS credentials are generated locally per run.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
DOC1="${OPENFLUX_POOL_DOC1:-}"
DOC2="${OPENFLUX_POOL_DOC2:-}"
if [[ "${OPENFLUX_TEST_TRANSPORT:-yandex}" != "memory" && ( -z "$DOC1" || -z "$DOC2" ) ]]; then
  echo "Set OPENFLUX_POOL_DOC1 and OPENFLUX_POOL_DOC2 explicitly for live tests." >&2
  exit 2
fi
XRAY_BIN="${XRAY_BIN:-$(command -v xray || true)}"
OPENFLUX_BIN="${OPENFLUX_BIN:-}"

if [[ -z "$XRAY_BIN" || ! -x "$XRAY_BIN" ]]; then
  echo "Set XRAY_BIN to an executable Xray v26.9.8+ binary." >&2
  exit 2
fi
for tool in go openssl python3 curl; do
  command -v "$tool" >/dev/null || { echo "Required command not found: $tool" >&2; exit 2; }
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/openflux-xray.XXXXXX")"
PIDS=()
cleanup() {
  local status=$?
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${PIDS[@]:-}"; do wait "$pid" 2>/dev/null || true; done
  if [[ "$status" -eq 0 && "${KEEP_TMP:-0}" != "1" ]]; then
    rm -rf "$WORK"
  else
    echo "Test files and process logs retained at: $WORK" >&2
  fi
}
trap cleanup EXIT INT TERM

if [[ -z "$OPENFLUX_BIN" ]]; then
  OPENFLUX_BIN="$WORK/openflux"
  (cd "$REPO_ROOT" && go build -o "$OPENFLUX_BIN" .)
fi

port_free() {
  python3 - "$1" <<'PY'
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("127.0.0.1", int(sys.argv[1])))
except OSError:
    raise SystemExit(1)
finally:
    s.close()
PY
}
free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}
wait_port() {
  python3 - "$1" "${2:-30}" <<'PY'
import socket, sys, time
port, timeout = int(sys.argv[1]), float(sys.argv[2])
deadline = time.monotonic() + timeout
while time.monotonic() < deadline:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.25):
            raise SystemExit(0)
    except OSError:
        time.sleep(0.1)
raise SystemExit(f"timed out waiting for 127.0.0.1:{port}")
PY
}

XRAY_VERSION="$("$XRAY_BIN" version | sed -n '1s/.*Xray \([^ ]*\).*/\1/p')"
echo "Xray version: ${XRAY_VERSION:-unknown}"
if [[ -z "$XRAY_VERSION" ]]; then
  echo "Could not read Xray version from $XRAY_BIN" >&2
  exit 2
fi

XRAY_EXIT_PORT="${OPENFLUX_XRAY_EXIT_PORT:-$(free_port)}"
if ! [[ "$XRAY_EXIT_PORT" =~ ^[0-9]+$ ]] || (( XRAY_EXIT_PORT < 1 || XRAY_EXIT_PORT > 65535 )); then
  echo "OPENFLUX_XRAY_EXIT_PORT must be between 1 and 65535" >&2
  exit 2
fi
port_free "$XRAY_EXIT_PORT" || { echo "Xray exit port 127.0.0.1:$XRAY_EXIT_PORT is already in use" >&2; exit 2; }
XRAY_VIRTUAL_ENDPOINT="${OPENFLUX_XRAY_VIRTUAL_ENDPOINT:-}"
if [[ -z "$XRAY_VIRTUAL_ENDPOINT" ]]; then
  XRAY_VIRTUAL_ENDPOINT="$(python3 -c 'import ipaddress, secrets, sys; base=int(ipaddress.IPv4Address("198.18.0.0")); print(f"{ipaddress.IPv4Address(base + secrets.randbelow(131070) + 1)}:{sys.argv[1]}")' "$XRAY_EXIT_PORT")"
fi
XRAY_VIRTUAL_PARTS="$(python3 -c '
import ipaddress, sys
host, sep, port = sys.argv[1].rpartition(":")
if not sep:
    raise SystemExit("virtual endpoint must be IPv4:port")
try:
    address = ipaddress.IPv4Address(host)
    number = int(port)
except ValueError as exc:
    raise SystemExit(f"invalid virtual endpoint: {exc}")
if not 1 <= number <= 65535:
    raise SystemExit("virtual endpoint port must be between 1 and 65535")
print(address, number)
' "$XRAY_VIRTUAL_ENDPOINT")"
read -r XRAY_VIRTUAL_IP XRAY_VIRTUAL_PORT <<< "$XRAY_VIRTUAL_PARTS"
HTTP_PORT="$(free_port)"
API_PORT="$(free_port)"
CLIENT_A_SOCKS="$(free_port)"
CLIENT_B_SOCKS="$(free_port)"
XRAY_CLIENT_1="$(free_port)"
XRAY_CLIENT_2="$(free_port)"
XRAY_CLIENT_3="$(free_port)"

openssl rand -hex 32 > "$WORK/edge-a.key"
openssl rand -hex 32 > "$WORK/edge-b.key"
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -subj '/CN=xray.local' -keyout "$WORK/xray.key" -out "$WORK/xray.crt" \
  > "$WORK/openssl.log" 2>&1
UUID1="$("$XRAY_BIN" uuid)"
UUID2="$("$XRAY_BIN" uuid)"
UUID3="$("$XRAY_BIN" uuid)"
POOL_ID="xray-e2e-$(openssl rand -hex 8)"

export WORK DOC1 DOC2 POOL_ID HTTP_PORT API_PORT CLIENT_A_SOCKS CLIENT_B_SOCKS
export XRAY_EXIT_PORT XRAY_VIRTUAL_ENDPOINT XRAY_VIRTUAL_IP XRAY_VIRTUAL_PORT
TLS_PIN="$(openssl x509 -noout -fingerprint -sha256 -in "$WORK/xray.crt" | sed 's/.*=//')"
export XRAY_CLIENT_1 XRAY_CLIENT_2 XRAY_CLIENT_3 UUID1 UUID2 UUID3 TLS_PIN
python3 - <<'PY'
import json, os
from pathlib import Path
w = Path(os.environ["WORK"])
docs = [
    {"id": "doc-1", "url": os.environ["DOC1"]},
    {"id": "doc-2", "url": os.environ["DOC2"]},
]
def write(name, value):
    (w / name).write_text(json.dumps(value, indent=2) + "\n")
write("exit-pool.json", {
    "pool_id": os.environ["POOL_ID"],
    "strategy": "least-loaded",
    "documents": docs,
    "forward": {
        "routes": [{
            "virtual_endpoint": os.environ["XRAY_VIRTUAL_ENDPOINT"],
            "target": f"127.0.0.1:{os.environ['XRAY_EXIT_PORT']}",
        }],
        "unmatched": "deny",
    },
    "clients": [
        {"id": "edge-a", "key_file": "edge-a.key"},
        {"id": "edge-b", "key_file": "edge-b.key"},
    ],
})
for edge, key in (("edge-a", "edge-a.key"), ("edge-b", "edge-b.key")):
    write(f"{edge}-pool.json", {
        "pool_id": os.environ["POOL_ID"], "documents": docs,
        "client_id": edge, "key_file": key,
    })
users = [
    {"id": os.environ[f"UUID{i}"], "email": f"xray-client-{i}", "level": 0}
    for i in (1, 2, 3)
]
write("xray-exit.json", {
    "log": {"loglevel": "debug"},
    "api": {"tag": "api", "services": ["HandlerService", "StatsService"]},
    "stats": {},
    "policy": {"levels": {"0": {
        "statsUserUplink": True, "statsUserDownlink": True,
        "statsUserOnline": True,
    }}},
    "inbounds": [
        {"listen": "127.0.0.1", "port": int(os.environ["XRAY_EXIT_PORT"]), "tag": "vless-in",
         "protocol": "vless", "settings": {"clients": users, "decryption": "none"},
         "streamSettings": {"network": "tcp", "security": "tls",
             "tlsSettings": {"certificates": [{"certificateFile": str(w / "xray.crt"),
                                                  "keyFile": str(w / "xray.key")}]}}},
        {"listen": "127.0.0.1", "port": int(os.environ["API_PORT"]), "tag": "api-in",
         "protocol": " dokodemo-door ".strip(), "settings": {"address": "127.0.0.1"}},
    ],
    "outbounds": [{"protocol": "freedom", "tag": "direct", "settings": {
                      "finalRules": [{"action": "allow", "network": "tcp",
                                      "port": str(os.environ["HTTP_PORT"]),
                                      "ip": ["127.0.0.1"]}] }},
                  {"protocol": "blackhole", "tag": "blocked"}],
    "routing": {"rules": [{"type": "field", "inboundTag": ["api-in"], "outboundTag": "api"}]},
})
for i, (listen, edge_port) in enumerate([
    (int(os.environ["XRAY_CLIENT_1"]), int(os.environ["CLIENT_A_SOCKS"])),
    (int(os.environ["XRAY_CLIENT_2"]), int(os.environ["CLIENT_A_SOCKS"])),
    (int(os.environ["XRAY_CLIENT_3"]), int(os.environ["CLIENT_B_SOCKS"])),
], 1):
    write(f"xray-client-{i}.json", {
        "log": {"loglevel": "debug"},
        "inbounds": [{"listen": "127.0.0.1", "port": listen, "tag": "local-socks",
                      "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [
            {"tag": "vless-out", "protocol": "vless", "settings": {"vnext": [{
                "address": os.environ["XRAY_VIRTUAL_IP"], "port": int(os.environ["XRAY_VIRTUAL_PORT"]),
                "users": [{"id": os.environ[f"UUID{i}"], "encryption": "none"}],
            }]}, "streamSettings": {"network": "tcp", "security": "tls",
                "tlsSettings": {"serverName": "xray.local",
                    "pinnedPeerCertSha256": os.environ["TLS_PIN"],
                    "verifyPeerCertByName": "xray.local"},
                "sockopt": {"dialerProxy": "openflux-socks"}}},
            {"tag": "openflux-socks", "protocol": "socks", "settings": {"servers": [{
                "address": "127.0.0.1", "port": edge_port,
            }]}}
        ],
        "routing": {"rules": [{"type": "field", "inboundTag": ["local-socks"],
                                  "outboundTag": "vless-out"}]},
    })
(w / "user-2.json").write_text(json.dumps({"inbounds": [{"tag": "vless-in",
    "listen": "127.0.0.1", "port": int(os.environ["XRAY_EXIT_PORT"]), "protocol": "vless",
    "settings": {"clients": [users[1]], "decryption": "none"}}]}, indent=2) + "\n")
PY

python3 -u - "$HTTP_PORT" <<'PY' > "$WORK/http.log" 2>&1 &
import http.server, sys
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        print("GET", self.path, flush=True)
        body = ("ok:" + self.path.lstrip("/") + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_): pass
http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY
PIDS+=("$!")
wait_port "$HTTP_PORT"
"$XRAY_BIN" run -c "$WORK/xray-exit.json" > "$WORK/xray-exit.log" 2>&1 & PIDS+=("$!")
wait_port "$XRAY_EXIT_PORT"
wait_port "$API_PORT"
if [[ "${OPENFLUX_TEST_TRANSPORT:-yandex}" == "memory" ]]; then
  (cd "$REPO_ROOT" && go build -o "$WORK/mockhub" ./examples/xray/mockhub)
  "$WORK/mockhub" --listen-a="127.0.0.1:$CLIENT_A_SOCKS" \
    --listen-b="127.0.0.1:$CLIENT_B_SOCKS" \
    --virtual="$XRAY_VIRTUAL_ENDPOINT" --target="127.0.0.1:$XRAY_EXIT_PORT" > "$WORK/openflux-mockhub.log" 2>&1 & PIDS+=("$!")
  wait_port "$CLIENT_A_SOCKS"
  wait_port "$CLIENT_B_SOCKS"
else
  "$OPENFLUX_BIN" --role=exit --transport=yandex --mode=l4 --codec=batched \
    --pool-config "$WORK/exit-pool.json" --debug > "$WORK/openflux-exit.log" 2>&1 & PIDS+=("$!")
  "$OPENFLUX_BIN" --role=client --transport=yandex --mode=l4 --codec=batched \
    --pool-config "$WORK/edge-a-pool.json" --inbound=socks5 --socks5="127.0.0.1:$CLIENT_A_SOCKS" \
    --debug > "$WORK/openflux-edge-a.log" 2>&1 & PIDS+=("$!")
  "$OPENFLUX_BIN" --role=client --transport=yandex --mode=l4 --codec=batched \
    --pool-config "$WORK/edge-b-pool.json" --inbound=socks5 --socks5="127.0.0.1:$CLIENT_B_SOCKS" \
    --debug > "$WORK/openflux-edge-b.log" 2>&1 & PIDS+=("$!")
  wait_port "$CLIENT_A_SOCKS"
  wait_port "$CLIENT_B_SOCKS"
fi
for i in 1 2 3; do
  "$XRAY_BIN" run -c "$WORK/xray-client-$i.json" > "$WORK/xray-client-$i.log" 2>&1 & PIDS+=("$!")
done
wait_port "$XRAY_CLIENT_1"
wait_port "$XRAY_CLIENT_2"
wait_port "$XRAY_CLIENT_3"

check_body() {
  local port=$1 path=$2 expected=$3 got
  got="$(curl --silent --show-error --fail --max-time 20 \
    --proxy "socks5h://127.0.0.1:$port" "http://127.0.0.1:$HTTP_PORT/$path")"
  [[ "$got" == "$expected" ]] || { echo "Unexpected response: $got" >&2; return 1; }
}
parallel_check_bodies() {
  check_body "$XRAY_CLIENT_1" client-1 ok:client-1 & local p1=$!
  check_body "$XRAY_CLIENT_2" client-2 ok:client-2 & local p2=$!
  check_body "$XRAY_CLIENT_3" client-3 ok:client-3 & local p3=$!
  wait "$p1"
  wait "$p2"
  wait "$p3"
}
wait_assigned_docs() {
  local deadline=$((SECONDS + ${OPENFLUX_POOL_WAIT_SECONDS:-150}))
  while (( SECONDS < deadline )); do
    if grep -q 'connected to document' "$WORK/openflux-edge-a.log" && \
       grep -q 'connected to document' "$WORK/openflux-edge-b.log"; then
      local doc_a doc_b
      doc_a="$(sed -n 's/.*connected to document \([^ ]*\).*/\1/p' "$WORK/openflux-edge-a.log" | tail -n1)"
      doc_b="$(sed -n 's/.*connected to document \([^ ]*\).*/\1/p' "$WORK/openflux-edge-b.log" | tail -n1)"
      if [[ -n "$doc_a" && -n "$doc_b" && "$doc_a" != "$doc_b" ]]; then
        echo "OpenFlux document assignments: edge-a=$doc_a edge-b=$doc_b"
        return 0
      fi
    fi
    sleep 1
  done
  echo "OpenFlux clients did not become connected to different documents." >&2
  return 1
}

case "${OPENFLUX_TEST_TRANSPORT:-yandex}" in
  memory)
    echo "OpenFlux transport: in-memory loopback (Yandex Docs pool bypassed)"
    ;;
  yandex)
    wait_assigned_docs
    ;;
  *)
    echo "OPENFLUX_TEST_TRANSPORT must be yandex or memory" >&2
    exit 2
    ;;
esac
# Run all three users simultaneously; clients 1 and 2 share edge-a's pool
# session/document while client 3 uses edge-b's independent session.
parallel_check_bodies

counter_value() {
  local raw
  raw="$("$XRAY_BIN" api stats --server="127.0.0.1:$API_PORT" \
    -name "user>>>xray-client-$1>>>traffic>>>$2" 2>&1 || true)"
  printf '%s\n' "$raw" >> "$WORK/api-stats.log"
  printf '%s\n' "$raw" | python3 -c 'import re,sys; s=sys.stdin.read(); n=re.findall(r"\"value\"\s*:\s*(\d+)",s); print(n[-1] if n else 0)'
}
for n in 1 2 3; do
  up="$(counter_value "$n" uplink)"
  down="$(counter_value "$n" downlink)"
  if (( up <= 0 || down <= 0 )); then
    echo "Missing per-user Xray counters for client-$n (uplink=$up downlink=$down)." >&2
    exit 1
  fi
  echo "Xray user client-$n traffic: uplink=$up downlink=$down"
done

"$XRAY_BIN" api rmu --server="127.0.0.1:$API_PORT" -tag=vless-in xray-client-2
if curl --silent --show-error --fail --max-time 10 --proxy "socks5h://127.0.0.1:$XRAY_CLIENT_2" \
  "http://127.0.0.1:$HTTP_PORT/blocked" > "$WORK/blocked.out" 2> "$WORK/blocked.err"; then
  echo "Removed Xray UUID unexpectedly accepted a new connection." >&2
  exit 1
fi
check_body "$XRAY_CLIENT_1" client-1 ok:client-1 & p1=$!
check_body "$XRAY_CLIENT_3" client-3 ok:client-3 & p3=$!
wait "$p1"
wait "$p3"
"$XRAY_BIN" api adu --server="127.0.0.1:$API_PORT" "$WORK/user-2.json"
check_body "$XRAY_CLIENT_2" restored ok:restored

if [[ "${OPENFLUX_TEST_TRANSPORT:-yandex}" == "memory" ]]; then
  echo "PASS: three Xray UUIDs, parallel TCP flows, per-user counters, API removal/re-add over OpenFlux L4."
  echo "Yandex Docs assignment, pool encryption, and live failover were skipped."
else
  echo "PASS: three Xray UUIDs, two OpenFlux pool clients assigned to two documents, shared-document traffic, per-user counters, API removal/re-add."
fi
echo "Xray version: $XRAY_VERSION"
