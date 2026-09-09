#!/usr/bin/env bash
set -euo pipefail

# Generates only loopback traffic inside the current Linux/WSL host.  It never
# targets a production address or external interface. Raw PCAPs remain ignored
# by Git and are converted to passive Zeek metadata for local verification.
root="${1:-$(pwd)}"
raw="$root/data/raw/sih26145-tools-v1"
zeek_out="$raw/zeek"
pcap="$raw/iperf3-hping3-loopback.pcap"
mkdir -p "$raw" "$zeek_out"
rm -f "$pcap" "$zeek_out"/*.log "$raw"/*.txt

cleanup() {
  jobs -pr | xargs -r kill 2>/dev/null || true
}
trap cleanup EXIT

timeout 12 tcpdump -i lo -U -w "$pcap" \
  '(tcp port 52031) or (tcp port 18080) or (udp port 19000)' \
  >"$raw/tcpdump.stdout.txt" 2>"$raw/tcpdump.stderr.txt" &
capture_pid=$!
sleep 1

iperf3 -s -1 -p 52031 >"$raw/iperf3-server.txt" 2>&1 &
server_pid=$!
sleep 1
iperf3 -c 127.0.0.1 -p 52031 -t 2 -J >"$raw/iperf3-client.json"
wait "$server_pid"

hping3 --syn --count 40 --interval u5000 --baseport 40000 --keep --destport 18080 127.0.0.1 \
  >"$raw/hping3-syn.txt" 2>&1
hping3 --udp --count 40 --interval u5000 --baseport 40001 --keep --destport 19000 127.0.0.1 \
  >"$raw/hping3-udp.txt" 2>&1
wait "$capture_pid" || test "$?" -eq 124

(
  cd "$zeek_out"
  /opt/zeek/bin/zeek -r "$pcap" LogAscii::use_json=T
)
sha256sum "$pcap" "$zeek_out"/*.log >"$raw/SHA256SUMS"
printf 'Generated local-only SIH capture: %s\n' "$pcap"
