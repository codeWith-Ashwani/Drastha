#!/usr/bin/env bash
set -euo pipefail

root="${1:-$(pwd)}"
raw="$root/data/raw/sih26145-real-tools-v1/benign-health"
pcap="$raw/jittered-health-check.pcap"
zeek_out="$raw/zeek"
namespace="drastha-s34b"
host_link="d34b-host"
client_link="d34b-client"

if [[ -e "$raw" ]]; then
  printf 'Refusing to overwrite existing raw evidence: %s\n' "$raw" >&2
  exit 1
fi
mkdir -p "$raw" "$zeek_out"

cleanup() {
  set +e
  [[ -n "${tcpdump_pid:-}" ]] && kill -INT "$tcpdump_pid" 2>/dev/null
  [[ -n "${server_pid:-}" ]] && kill "$server_pid" 2>/dev/null
  ip netns del "$namespace" 2>/dev/null
  ip link del "$host_link" 2>/dev/null
}
trap cleanup EXIT

ip netns del "$namespace" 2>/dev/null || true
ip link del "$host_link" 2>/dev/null || true
ip netns add "$namespace"
ip link add "$host_link" type veth peer name "$client_link"
ip link set "$client_link" netns "$namespace"
ip address add 10.34.1.1/30 dev "$host_link"
ip link set "$host_link" up
ip netns exec "$namespace" ip address add 10.34.1.2/30 dev "$client_link"
ip netns exec "$namespace" ip link set "$client_link" up
ip netns exec "$namespace" ip link set lo up

tcpdump -i "$host_link" -U -s 0 -w "$pcap" 'tcp port 18444' \
  >"$raw/tcpdump.stdout.txt" 2>"$raw/tcpdump.stderr.txt" &
tcpdump_pid=$!
sleep 1
python3 "$root/scripts/lab_health_emulator.py" server \
  >"$raw/server.stdout.txt" 2>"$raw/server.stderr.txt" &
server_pid=$!
sleep 1
ip netns exec "$namespace" python3 "$root/scripts/lab_health_emulator.py" client \
  >"$raw/client.stdout.txt" 2>"$raw/client.stderr.txt"
wait "$server_pid"
unset server_pid
kill -INT "$tcpdump_pid"
wait "$tcpdump_pid"
unset tcpdump_pid

(
  cd "$zeek_out"
  /opt/zeek/bin/zeek -C -r "$pcap" LogAscii::use_json=T
)
sha256sum "$pcap" "$zeek_out"/*.log >"$raw/SHA256SUMS"
printf 'Generated isolated benign health-check capture: %s\n' "$pcap"
