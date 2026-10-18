#!/usr/bin/env bash
# Pillar 1: L4 Throughput & Encryption Overhead Benchmark (iperf3)
# Compares direct LAN throughput vs. SSE mTLS tunnel throughput with 8 parallel streams.

set -e

if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

TARGET_HOST=${INTERNAL_HOST:-"10.0.1.100"}
PARALLEL_STREAMS=8
DURATION=30
RESULTS_DIR="$(dirname "$0")/results"
mkdir -p "$RESULTS_DIR"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUT_JSON="$RESULTS_DIR/iperf3_${TARGET_HOST}_${TIMESTAMP}.json"

echo "[*] Running iperf3 benchmark against $TARGET_HOST ($PARALLEL_STREAMS parallel streams, ${DURATION}s)..."
echo "[*] Make sure 'iperf3 -s' is running on SR-TARGET-WEB!"

iperf3 -c "$TARGET_HOST" -P "$PARALLEL_STREAMS" -t "$DURATION" -J > "$OUT_JSON"

# Extract summary metrics using jq
BITS_PER_SEC=$(jq -r '.end.sum_received.bits_per_second' "$OUT_JSON")
MBPS=$(awk "BEGIN {printf \"%.2f\", $BITS_PER_SEC / 1000000}")
RETRANSMITS=$(jq -r '.end.sum_sent.retransmits' "$OUT_JSON")

echo "[+] Test finished! Summary:"
echo "    -> Throughput: $MBPS Mbps"
echo "    -> TCP Retransmissions: $RETRANSMITS"
echo "    -> Detailed JSON saved to: $OUT_JSON"