#!/usr/bin/env bash
# Pillar 1: Background System Telemetry Collector (run on the Connector VM)
# Captures 1-second resolution CPU (user, system, softirq), memory, and network I/O via sar.

DURATION=${1:-300} # Default 5 minutes
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_Prefix="connector_telemetry_${TIMESTAMP}"

echo "[*] Recording Connector telemetry for ${DURATION} seconds..."
echo "[*] Tracking CPU (%usr, %sys, %softirq) and Network interface throughput..."

# Record CPU utilization (including softirq) and network device stats every 1 second
sar -u ALL -n DEV 1 "$DURATION" > "${LOG_Prefix}.txt" &
SAR_PID=$!

echo "[+] sar running in background (PID: $SAR_PID). Output: ${LOG_Prefix}.txt"
wait $SAR_PID
echo "[+] Telemetry recording complete."