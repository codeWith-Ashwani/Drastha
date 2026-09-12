#!/usr/bin/env bash
set -euo pipefail

root="${1:-$(pwd)}"
raw="$root/data/raw/sih26145-gate2-tls-v1"
namespace="drastha-g2t"
host_link="d-g2t-host"
client_link="d-g2t-client"
if [[ -e "$raw" ]] || ip netns list | grep -q "^$namespace " || ip link show "$host_link" >/dev/null 2>&1; then
  printf 'Refusing to overwrite or reuse existing TLS lab state\n' >&2
  exit 1
fi
mkdir -p "$raw/zeek"
cleanup() {
  set +e
  [[ -n "${tcpdump_pid:-}" ]] && kill -INT "$tcpdump_pid" 2>/dev/null
  [[ -n "${server_pid:-}" ]] && kill "$server_pid" 2>/dev/null
  [[ "${created_namespace:-0}" == 1 ]] && ip netns del "$namespace" 2>/dev/null
  [[ "${created_link:-0}" == 1 ]] && ip link del "$host_link" 2>/dev/null
}
trap cleanup EXIT
ip netns add "$namespace"
created_namespace=1
ip link add "$host_link" type veth peer name "$client_link"
created_link=1
ip link set "$client_link" netns "$namespace"
ip address add 10.37.0.1/30 dev "$host_link"
ip link set "$host_link" up
ip netns exec "$namespace" ip address add 10.37.0.2/30 dev "$client_link"
ip netns exec "$namespace" ip link set "$client_link" up
ip netns exec "$namespace" ip link set lo up
if [[ -n "$(ip netns exec "$namespace" ip route show default)" ]]; then
  printf 'Isolated TLS lab unexpectedly has a default route\n' >&2
  exit 1
fi
ip netns exec "$namespace" ip route >"$raw/client-routes.txt"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=lab.test' \
  -keyout "$raw/lab.key" -out "$raw/lab.crt" >"$raw/openssl.stdout.txt" 2>"$raw/openssl.stderr.txt"
tcpdump -i "$host_link" -U -s 0 -w "$raw/traffic.pcap" 'tcp port 443' \
  >"$raw/tcpdump.stdout.txt" 2>"$raw/tcpdump.stderr.txt" &
tcpdump_pid=$!
sleep 1
python3 "$root/scripts/lab_tls_exchange.py" server --cert "$raw/lab.crt" --key "$raw/lab.key" \
  >"$raw/server.stdout.txt" 2>"$raw/server.stderr.txt" &
server_pid=$!
sleep 1
ip netns exec "$namespace" python3 "$root/scripts/lab_tls_exchange.py" client \
  >"$raw/client.csv" 2>"$raw/client.stderr.txt"
wait "$server_pid"
unset server_pid
sleep 2
kill -INT "$tcpdump_pid"
wait "$tcpdump_pid"
unset tcpdump_pid
(cd "$raw/zeek" && /opt/zeek/bin/zeek -C -r "$raw/traffic.pcap" LogAscii::use_json=T)
sha256sum "$raw/traffic.pcap" "$raw/zeek"/*.log >"$raw/SHA256SUMS"
printf 'Generated isolated measured TLS capture in %s\n' "$raw"
