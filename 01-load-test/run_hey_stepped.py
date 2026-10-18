#!/usr/bin/env python3
"""
Pillar 1: Configurable Stepped HTTP Load Testing with 'hey'
Supports dynamic percentiles (e.g., p10, p25, p50, p75, p90, p95, p99),
custom concurrency steps, rate limiting (QPS), and duration via CLI or .env.
"""

import os
import re
import csv
import time
import argparse
import subprocess
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()


def parse_args():
    parser = argparse.ArgumentParser(description="Configurable Stepped HTTP Load Tester (hey)")
    parser.add_argument(
        "--url",
        default=os.getenv("TARGET_APP_URL", "https://richard-internal-web.local"),
        help="Target application URL through the SSE tunnel"
    )
    parser.add_argument(
        "--steps",
        default=os.getenv("LOAD_CONCURRENCY_STEPS", "10,25,50,100,150,200,300,400,500"),
        help="Comma-separated list of concurrency levels (e.g., '10,50,100,200')"
    )
    parser.add_argument(
        "--duration",
        default=os.getenv("LOAD_STEP_DURATION", "30s"),
        help="Duration per concurrency step (e.g., '15s', '30s', '1m')"
    )
    parser.add_argument(
        "--qps",
        type=int,
        default=int(os.getenv("LOAD_RATE_LIMIT_QPS", "0")),
        help="Rate limit in queries per second per worker (0 = no limit)"
    )
    parser.add_argument(
        "--percentiles",
        default=os.getenv("LOAD_PERCENTILES", "50,75,90,95,99"),
        help="Comma-separated percentiles to extract (supported by hey: 10,25,50,75,90,95,99)"
    )
    parser.add_argument(
        "--cooldown",
        type=int,
        default=5,
        help="Cooldown time in seconds between steps"
    )
    return parser.parse_args()


def parse_hey_output(output: str, percentiles: list) -> dict:
    """Extracts RPS, average latency, dynamic percentiles, and error rate from 'hey' stdout."""
    metrics = {
        "rps": 0.0,
        "avg_ms": 0.0,
        "min_ms": 0.0,
        "max_ms": 0.0,
        "total_requests": 0,
        "status_200": 0,
        "error_rate_pct": 0.0
    }

    # Initialize requested percentile keys
    for p in percentiles:
        metrics[f"p{p}_ms"] = 0.0

    rps_match = re.search(r"Requests/sec:\s+([0-9.]+)", output)
    if rps_match:
        metrics["rps"] = float(rps_match.group(1))

    avg_match = re.search(r"Average:\s+([0-9.]+)\s+secs", output)
    if avg_match:
        metrics["avg_ms"] = round(float(avg_match.group(1)) * 1000, 2)

    fastest_match = re.search(r"Fastest:\s+([0-9.]+)\s+secs", output)
    if fastest_match:
        metrics["min_ms"] = round(float(fastest_match.group(1)) * 1000, 2)

    slowest_match = re.search(r"Slowest:\s+([0-9.]+)\s+secs", output)
    if slowest_match:
        metrics["max_ms"] = round(float(slowest_match.group(1)) * 1000, 2)

    # Extract any requested percentile (10, 25, 50, 75, 90, 95, 99)
    for p in percentiles:
        p_match = re.search(rf"{p}%\s+in\s+([0-9.]+)\s+secs", output)
        if p_match:
            metrics[f"p{p}_ms"] = round(float(p_match.group(1)) * 1000, 2)

    status_matches = re.findall(r"\[(\d+)\]\s+(\d+)\s+responses", output)
    total_resp = 0
    ok_resp = 0
    for code, count in status_matches:
        c = int(count)
        total_resp += c
        if code == "200":
            ok_resp += c

    err_matches = re.findall(r"\[(\d+)\]\s+Get\s+", output)
    transport_errors = sum(int(x) for x in err_matches)
    total_attempts = total_resp + transport_errors

    metrics["total_requests"] = total_attempts
    metrics["status_200"] = ok_resp

    if total_attempts > 0:
        failed = total_attempts - ok_resp
        metrics["error_rate_pct"] = round((failed / total_attempts) * 100, 2)

    return metrics


def main():
    args = parse_args()
    steps = [int(s.strip()) for s in args.steps.split(",") if s.strip()]
    percentiles = [p.strip() for p in args.percentiles.split(",") if p.strip()]

    output_dir = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = os.path.join(output_dir, f"hey_stepped_benchmark_{timestamp}.csv")

    print(f"[*] Target URL       : {args.url}")
    print(f"[*] Concurrency Steps: {steps}")
    print(f"[*] Step Duration    : {args.duration} (QPS limit: {args.qps if args.qps > 0 else 'None'})")
    print(f"[*] Tracked Percentiles: {['p' + p for p in percentiles]}")
    print(f"[*] Output CSV       : {csv_path}\n")

    percentile_cols = [f"p{p}_ms" for p in percentiles]
    fieldnames = (
        ["concurrency", "rps", "avg_ms", "min_ms", "max_ms"]
        + percentile_cols
        + ["total_requests", "status_200", "error_rate_pct"]
    )

    with open(csv_path, mode="w", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        for c in steps:
            print(f"[+] Running step: Concurrency = {c} for {args.duration}...")
            cmd = ["hey", "-z", args.duration, "-c", str(c)]
            if args.qps > 0:
                cmd.extend(["-q", str(args.qps)])
            cmd.append(args.url)

            try:
                res = subprocess.run(cmd, capture_output=True, text=True, check=False)
                parsed = parse_hey_output(res.stdout, percentiles)
                parsed["concurrency"] = c
                writer.writerow(parsed)
                csv_file.flush()

                p_summary = " | ".join([f"p{p}: {parsed[f'p{p}_ms']} ms" for p in percentiles])
                print(f"    -> RPS: {parsed['rps']} | Avg: {parsed['avg_ms']} ms | {p_summary} | Err: {parsed['error_rate_pct']}%")

            except FileNotFoundError:
                print("[!] Error: 'hey' command not found. Install with: sudo apt install hey")
                return

            time.sleep(args.cooldown)

    print("\n[+] Benchmark completed successfully!")


if __name__ == "__main__":
    main()