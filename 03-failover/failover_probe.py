#!/usr/bin/env python3
"""
Pillar 3: High-Resolution Network Failover & Convergence Probe
Performs high-frequency (default 50ms) TCP/TLS probes across the active SSE ZTNA tunnel
to measure exact outage duration (Convergence Time in ms) and packet loss during failover.
"""

import os
import csv
import time
import socket
import argparse
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()


def parse_args():
    parser = argparse.ArgumentParser(description="High-Frequency ZTNA Failover Convergence Probe")
    parser.add_argument("--host", default=os.getenv("INTERNAL_HOST", "richard-internal-web.local"))
    parser.add_argument("--port", type=int, default=int(os.getenv("TCP_TARGET_PORT", "443")))
    parser.add_argument("--interval-ms", type=float, default=50.0, help="Probe interval in milliseconds (default: 50ms)")
    parser.add_argument("--timeout-ms", type=float, default=250.0, help="Socket timeout per probe in milliseconds")
    parser.add_argument("--duration-sec", type=int, default=60, help="Total test duration in seconds")
    return parser.parse_args()


def tcp_ping(host: str, port: int, timeout_sec: float) -> tuple[bool, float]:
    """Attempts a TCP handshake and returns (success_bool, rtt_ms)."""
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout_sec):
            rtt_ms = (time.perf_counter() - start) * 1000.0
            return True, round(rtt_ms, 2)
    except OSError:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return False, round(elapsed_ms, 2)


def main():
    args = parse_args()
    interval_sec = args.interval_ms / 1000.0
    timeout_sec = args.timeout_ms / 1000.0

    output_dir = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(output_dir, exist_ok=True)
    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = os.path.join(output_dir, f"failover_probe_{ts_str}.csv")

    print(f"[*] Starting High-Frequency Failover Probe -> {args.host}:{args.port}")
    print(f"[*] Sampling Interval: {args.interval_ms} ms | Timeout: {args.timeout_ms} ms | Duration: {args.duration_sec}s")
    print("[*] Simulate Connector 1 NIC disconnect or Zone outage now! (Press Ctrl+C to finish early)\n")

    records = []
    outage_start_perf = None
    last_success_perf = time.perf_counter()
    max_convergence_ms = 0.0
    failed_probes = 0
    total_probes = 0

    start_test = time.perf_counter()

    with open(csv_path, mode="w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["seq", "elapsed_ms", "status", "rtt_ms"])
        writer.writeheader()

        try:
            while (time.perf_counter() - start_test) < args.duration_sec:
                loop_start = time.perf_counter()
                total_probes += 1

                ok, rtt_ms = tcp_ping(args.host, args.port, timeout_sec)
                now_perf = time.perf_counter()
                rel_ms = round((now_perf - start_test) * 1000.0, 1)

                if ok:
                    if outage_start_perf is not None:
                        convergence_ms = round((now_perf - last_success_perf) * 1000.0, 2)
                        if convergence_ms > max_convergence_ms:
                            max_convergence_ms = convergence_ms
                        print(f"[+] SERVICE RESTORED at {rel_ms} ms! Convergence Time: {convergence_ms} ms")
                        outage_start_perf = None
                    last_success_perf = now_perf
                    status_str = "OK"
                else:
                    failed_probes += 1
                    status_str = "DROP"
                    if outage_start_perf is None:
                        outage_start_perf = now_perf
                        print(f"[!] OUTAGE DETECTED at {rel_ms} ms (Probe #{total_probes} dropped)")

                row = {
                    "seq": total_probes,
                    "elapsed_ms": rel_ms,
                    "status": status_str,
                    "rtt_ms": rtt_ms if ok else -1.0
                }
                writer.writerow(row)
                records.append(row)

                # Maintain strict sampling cadence
                elapsed_loop = time.perf_counter() - loop_start
                sleep_time = max(0.0, interval_sec - elapsed_loop)
                time.sleep(sleep_time)

        except KeyboardInterrupt:
            print("\n[*] Probe stopped by user.")

    loss_pct = round((failed_probes / total_probes) * 100.0, 2) if total_probes > 0 else 0.0
    print("\n" + "=" * 55)
    print("FAILOVER & CONVERGENCE SUMMARY")
    print("=" * 55)
    print(f"Total Probes Sent       : {total_probes}")
    print(f"Dropped Probes          : {failed_probes} ({loss_pct}%)")
    print(f"Max Convergence Time    : {max_convergence_ms} ms")
    print(f"Detailed Time-Series CSV: {csv_path}")
    print("=" * 55)


if __name__ == "__main__":
    main()