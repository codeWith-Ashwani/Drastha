#!/usr/bin/env bash
set -euo pipefail

# This script creates a network namespace with no default route and connects it
# only to a fixed private /30. It cannot reach the Internet or production hosts.
root="${1:-$(pwd)}"
raw="$root/data/raw/sih26145-real-tools-v1"
pcap="$raw/sprint34-isolated-tools.pcap"
zeek_out="$raw/zeek"
namespace="drastha-s34"
host_link="d34-host"
client_link="d34-client"

if [[ -e "$raw" ]]; then
  printf 'Refusing to overwrite existing raw evidence: %s\n' "$raw" >&2
  exit 1
fi
mkdir -p "$raw" "$zeek_out"

cleanup() {
  set +e
  [[ -n "${tcpdump_pid:-}" ]] && kill -INT "$tcpdump_pid" 2>/dev/null
  [[ -n "${http_pid:-}" ]] && kill "$http_pid" 2>/dev/null
  [[ -n "${c2_server_pid:-}" ]] && kill "$c2_server_pid" 2>/dev/null
  [[ -n "${iodined_pid:-}" ]] && kill "$iodined_pid" 2>/dev/null
  ip netns del "$namespace" 2>/dev/null
  ip link del "$host_link" 2>/dev/null
}
trap cleanup EXIT

ip netns del "$namespace" 2>/dev/null || true
ip link del "$host_link" 2>/dev/null || true
ip netns add "$namespace"
ip link add "$host_link" type veth peer name "$client_link"
ip link set "$client_link" netns "$namespace"
ip address add 10.34.0.1/30 dev "$host_link"
ip link set "$host_link" up
ip netns exec "$namespace" ip address add 10.34.0.2/30 dev "$client_link"
ip netns exec "$namespace" ip link set "$client_link" up
ip netns exec "$namespace" ip link set lo up

tcpdump -i "$host_link" -U -s 0 -w "$pcap" \
  'tcp port 18081 or tcp port 18443 or udp port 53' \
  >"$raw/tcpdump.stdout.txt" 2>"$raw/tcpdump.stderr.txt" &
tcpdump_pid=$!
sleep 1

python3 "$root/scripts/lab_http_sink.py" \
  >"$raw/http-sink.stdout.txt" 2>"$raw/http-sink.stderr.txt" &
http_pid=$!
sleep 1
ip netns exec "$namespace" slowhttptest -H -c 24 -i 60 -l 130 -r 24 \
  -x 2 -p 3 -u http://10.34.0.1:18081/ -g -o "$raw/slowhttptest" \
  >"$raw/slowhttptest.stdout.txt" 2>"$raw/slowhttptest.stderr.txt"
kill "$http_pid" 2>/dev/null || true
wait "$http_pid" 2>/dev/null || true
unset http_pid

python3 "$root/scripts/lab_c2_emulator.py" server \
  >"$raw/c2-server.stdout.txt" 2>"$raw/c2-server.stderr.txt" &
c2_server_pid=$!
sleep 1
ip netns exec "$namespace" python3 "$root/scripts/lab_c2_emulator.py" client \
  >"$raw/c2-client.stdout.txt" 2>"$raw/c2-client.stderr.txt"
wait "$c2_server_pid"
unset c2_server_pid

iodined -f -c -l 10.34.0.1 -P drastha-lab 10.35.0.1/24 s34.test \
  >"$raw/iodined.stdout.txt" 2>"$raw/iodined.stderr.txt" &
iodined_pid=$!
sleep 2
ip netns exec "$namespace" timeout 25 iodine -f -r -T TXT -I 1 \
  -P drastha-lab 10.34.0.1 s34.test \
  >"$raw/iodine.stdout.txt" 2>"$raw/iodine.stderr.txt" &
iodine_pid=$!
sleep 7
ip netns exec "$namespace" ping -c 8 -i 0.25 10.35.0.1 \
  >"$raw/iodine-ping.txt" 2>&1 || true
wait "$iodine_pid" || test "$?" -eq 124
kill "$iodined_pid" 2>/dev/null || true
wait "$iodined_pid" 2>/dev/null || true
unset iodined_pid

kill -INT "$tcpdump_pid"
wait "$tcpdump_pid"
unset tcpdump_pid

(
  cd "$zeek_out"
  /opt/zeek/bin/zeek -C -r "$pcap" LogAscii::use_json=T
)

{
  /opt/zeek/bin/zeek --version
  tcpdump --version | head -1
  slowhttptest -h 2>&1 | head -1
  iodine -v 2>&1 | head -1 || true
  python3 --version
} >"$raw/tool-versions.txt"
sha256sum "$pcap" "$zeek_out"/*.log >"$raw/SHA256SUMS"
printf 'Generated isolated Sprint 34 capture: %s\n' "$pcap"
