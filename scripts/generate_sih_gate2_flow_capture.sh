#!/usr/bin/env bash
set -euo pipefail

# Capture fresh PS-tool traffic on a private veth with no route to production.
# Each capture is an independent labelled scenario before detector inference.
root="${1:-$(pwd)}"
capture_id="${2:-sih26145-gate2-flow-v1}"
if [[ ! "$capture_id" =~ ^sih26145-gate2-flow-v[0-9]+$ ]]; then
  printf 'Invalid fixed lab capture id: %s\n' "$capture_id" >&2
  exit 1
fi
raw="$root/data/raw/$capture_id"
namespace="drastha-g2"
host_link="d-g2-host"
client_link="d-g2-client"
host_ip="10.36.0.1"
client_ip="10.36.0.2"

if [[ -e "$raw" ]]; then
  printf 'Refusing to overwrite existing raw evidence: %s\n' "$raw" >&2
  exit 1
fi
if ip netns list | grep -q "^$namespace "; then
  printf 'Refusing to reuse an existing network namespace: %s\n' "$namespace" >&2
  exit 1
fi
if ip link show "$host_link" >/dev/null 2>&1; then
  printf 'Refusing to reuse an existing network link: %s\n' "$host_link" >&2
  exit 1
fi
mkdir -p "$raw"

cleanup() {
  set +e
  [[ -n "${capture_pid:-}" ]] && kill -INT "$capture_pid" 2>/dev/null
  [[ -n "${iperf_pid:-}" ]] && kill "$iperf_pid" 2>/dev/null
  [[ -n "${reflector_pid:-}" ]] && kill "$reflector_pid" 2>/dev/null
  [[ "${created_namespace:-0}" == 1 ]] && ip netns del "$namespace" 2>/dev/null
  [[ "${created_link:-0}" == 1 ]] && ip link del "$host_link" 2>/dev/null
}
trap cleanup EXIT

ip netns add "$namespace"
created_namespace=1
ip link add "$host_link" type veth peer name "$client_link"
created_link=1
ip link set "$client_link" netns "$namespace"
ip address add "$host_ip/30" dev "$host_link"
ip link set "$host_link" up
ip netns exec "$namespace" ip address add "$client_ip/30" dev "$client_link"
ip netns exec "$namespace" ip link set "$client_link" up
ip netns exec "$namespace" ip link set lo up
if [[ -n "$(ip netns exec "$namespace" ip route show default)" ]]; then
  printf 'Isolated lab unexpectedly has a default route\n' >&2
  exit 1
fi
ip netns exec "$namespace" ip route >"$raw/client-routes.txt"

start_capture() {
  local scenario="$1"
  mkdir -p "$raw/$scenario/zeek"
  tcpdump -i "$host_link" -U -s 0 -w "$raw/$scenario/traffic.pcap" \
    >"$raw/$scenario/tcpdump.stdout.txt" 2>"$raw/$scenario/tcpdump.stderr.txt" &
  capture_pid=$!
  sleep 1
}

finish_capture() {
  local scenario="$1"
  # Give tcpdump time to drain the burst from the kernel before SIGINT.
  sleep 2
  kill -INT "$capture_pid"
  wait "$capture_pid"
  unset capture_pid
  (cd "$raw/$scenario/zeek" && /opt/zeek/bin/zeek -C -r "$raw/$scenario/traffic.pcap" LogAscii::use_json=T)
}

start_capture benign-iperf
iperf3 -s -1 -B "$host_ip" -p 52031 >"$raw/benign-iperf/server.txt" 2>&1 &
iperf_pid=$!
sleep 1
ip netns exec "$namespace" iperf3 -c "$host_ip" -p 52031 -t 2 -b 2M -J \
  >"$raw/benign-iperf/client.json"
wait "$iperf_pid"
unset iperf_pid
finish_capture benign-iperf

start_capture syn-flood
ip netns exec "$namespace" hping3 --syn --count 140 --interval u5000 \
  --baseport 41000 --destport 18080 "$host_ip" \
  >"$raw/syn-flood/hping3.txt" 2>&1
finish_capture syn-flood

start_capture port-scan
for port in 21001 21002 21003 21004 21005 21006 21007 21008; do
  ip netns exec "$namespace" hping3 --syn --count 1 --baseport 42000 \
    --destport "$port" "$host_ip" >>"$raw/port-scan/hping3.txt" 2>&1
done
finish_capture port-scan

start_capture udp-flood
ip netns exec "$namespace" hping3 --udp --count 600 --interval u2000 \
  --baseport 44000 --destport 19000 --data 1 "$host_ip" \
  >"$raw/udp-flood/hping3.txt" 2>&1 || true
grep -q '600 packets transmitted' "$raw/udp-flood/hping3.txt"
finish_capture udp-flood

start_capture udp-amplification-shape
python3 "$root/scripts/lab_udp_reflector.py" \
  >"$raw/udp-amplification-shape/responder.stdout.txt" \
  2>"$raw/udp-amplification-shape/responder.stderr.txt" &
reflector_pid=$!
sleep 1
ip netns exec "$namespace" python3 "$root/scripts/lab_udp_probe.py" \
  >"$raw/udp-amplification-shape/probe.txt" 2>&1
test "$(grep -c 'valid response' "$raw/udp-amplification-shape/probe.txt")" -eq 16
kill "$reflector_pid"
wait "$reflector_pid" 2>/dev/null || true
unset reflector_pid
finish_capture udp-amplification-shape

start_capture bulk-asymmetry
iperf3 -s -1 -B "$host_ip" -p 52032 >"$raw/bulk-asymmetry/server.txt" 2>&1 &
iperf_pid=$!
sleep 1
ip netns exec "$namespace" iperf3 -c "$host_ip" -p 52032 -t 2 -b 200M -J \
  >"$raw/bulk-asymmetry/client.json"
wait "$iperf_pid"
unset iperf_pid
finish_capture bulk-asymmetry

{
  /opt/zeek/bin/zeek --version
  iperf3 --version | head -1
  hping3 --version 2>&1 | head -1
  tcpdump --version | head -1
} >"$raw/tool-versions.txt"
find "$raw" -type f \( -name '*.pcap' -o -name 'conn.log' -o -name 'dns.log' \) \
  -print0 | sort -z | xargs -0 sha256sum >"$raw/SHA256SUMS"
printf 'Generated fresh isolated Gate 2 captures in %s\n' "$raw"
