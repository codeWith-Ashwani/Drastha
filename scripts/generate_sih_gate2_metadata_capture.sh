#!/usr/bin/env bash
set -euo pipefail

# Three PS-source behaviours on a fixed private /30, no default route.
root="${1:-$(pwd)}"
raw="$root/data/raw/sih26145-gate2-metadata-v1"
namespace="drastha-g2m"
host_link="d-g2m-host"
client_link="d-g2m-client"

if [[ -e "$raw" ]] || ip netns list | grep -q "^$namespace " || ip link show "$host_link" >/dev/null 2>&1; then
  printf 'Refusing to overwrite or reuse existing Gate 2 lab state\n' >&2
  exit 1
fi
mkdir -p "$raw/zeek"
cleanup() {
  set +e
  [[ -n "${tcpdump_pid:-}" ]] && kill -INT "$tcpdump_pid" 2>/dev/null
  [[ -n "${http_pid:-}" ]] && kill "$http_pid" 2>/dev/null
  [[ -n "${c2_pid:-}" ]] && kill "$c2_pid" 2>/dev/null
  [[ -n "${iodined_pid:-}" ]] && kill "$iodined_pid" 2>/dev/null
  [[ "${created_namespace:-0}" == 1 ]] && ip netns del "$namespace" 2>/dev/null
  [[ "${created_link:-0}" == 1 ]] && ip link del "$host_link" 2>/dev/null
}
trap cleanup EXIT

ip netns add "$namespace"
created_namespace=1
ip link add "$host_link" type veth peer name "$client_link"
created_link=1
ip link set "$client_link" netns "$namespace"
ip address add 10.34.0.1/30 dev "$host_link"
ip link set "$host_link" up
ip netns exec "$namespace" ip address add 10.34.0.2/30 dev "$client_link"
ip netns exec "$namespace" ip link set "$client_link" up
ip netns exec "$namespace" ip link set lo up
if [[ -n "$(ip netns exec "$namespace" ip route show default)" ]]; then
  printf 'Isolated Gate 2 lab unexpectedly has a default route\n' >&2
  exit 1
fi
ip netns exec "$namespace" ip route >"$raw/client-routes.txt"

tcpdump -i "$host_link" -U -s 0 -w "$raw/traffic.pcap" \
  'tcp port 18081 or tcp port 18443 or udp port 53' \
  >"$raw/tcpdump.stdout.txt" 2>"$raw/tcpdump.stderr.txt" &
tcpdump_pid=$!
sleep 1

python3 "$root/scripts/lab_http_sink.py" \
  >"$raw/http.stdout.txt" 2>"$raw/http.stderr.txt" &
http_pid=$!
sleep 1
ip netns exec "$namespace" slowhttptest -H -c 26 -i 60 -l 132 -r 26 \
  -x 2 -p 3 -u http://10.34.0.1:18081/ -g -o "$raw/slowhttptest" \
  >"$raw/slowhttptest.stdout.txt" 2>"$raw/slowhttptest.stderr.txt"
kill "$http_pid" 2>/dev/null || true
wait "$http_pid" 2>/dev/null || true
unset http_pid

python3 "$root/scripts/lab_c2_emulator.py" server --profile gate2 --count 13 --interval 2.5 \
  >"$raw/c2-server.stdout.txt" 2>"$raw/c2-server.stderr.txt" &
c2_pid=$!
sleep 1
ip netns exec "$namespace" python3 "$root/scripts/lab_c2_emulator.py" client \
  --profile gate2 --count 13 --interval 2.5 \
  >"$raw/c2-client.stdout.txt" 2>"$raw/c2-client.stderr.txt"
wait "$c2_pid"
unset c2_pid

iodined -f -c -l 10.34.0.1 -P drastha-lab 10.35.0.1/24 g2.test \
  >"$raw/iodined.stdout.txt" 2>"$raw/iodined.stderr.txt" &
iodined_pid=$!
sleep 2
ip netns exec "$namespace" timeout 25 iodine -f -r -T TXT -I 1 \
  -P drastha-lab 10.34.0.1 g2.test \
  >"$raw/iodine.stdout.txt" 2>"$raw/iodine.stderr.txt" &
iodine_pid=$!
sleep 7
ip netns exec "$namespace" ping -c 8 -i 0.25 10.35.0.1 \
  >"$raw/iodine-ping.txt" 2>&1 || true
wait "$iodine_pid" || test "$?" -eq 124
kill "$iodined_pid" 2>/dev/null || true
wait "$iodined_pid" 2>/dev/null || true
unset iodined_pid

sleep 2
kill -INT "$tcpdump_pid"
wait "$tcpdump_pid"
unset tcpdump_pid
(cd "$raw/zeek" && /opt/zeek/bin/zeek -C -r "$raw/traffic.pcap" LogAscii::use_json=T)
{
  /opt/zeek/bin/zeek --version
  slowhttptest -h 2>&1 | head -1 || true
  iodine -v 2>&1 | head -1 || true
  tcpdump --version | head -1 || true
} >"$raw/tool-versions.txt"
sha256sum "$raw/traffic.pcap" "$raw/zeek"/*.log >"$raw/SHA256SUMS"
printf 'Generated fresh isolated Gate 2 metadata capture in %s\n' "$raw"
