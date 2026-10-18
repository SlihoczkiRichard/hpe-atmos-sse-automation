#!/usr/bin/env python3
"""
Pillar 2: Event-Driven Horizontal Autoscaler Daemon (Proxmox VE API)
Monitors primary HPE Aruba SSE Connector CPU utilization and triggers horizontal
scale-out / scale-in of secondary Connector VM, logging time-series telemetry to CSV.
"""

import os
import csv
import time
import argparse
import urllib3
import requests
from datetime import datetime
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()


def parse_args():
    parser = argparse.ArgumentParser(description="HPE SSE Connector Horizontal Autoscaler PoC")
    parser.add_argument("--pve-url", default=os.getenv("PROXMOX_URL", "https://10.0.1.10:8006"))
    parser.add_argument("--pve-node-1", default=os.getenv("PROXMOX_NODE_1", os.getenv("PROXMOX_NODE", "pve-node-01")))
    parser.add_argument("--pve-node-2", default=os.getenv("PROXMOX_NODE_2", os.getenv("PROXMOX_NODE", "pve-node-02")))
    parser.add_argument("--vmid-1", type=int, default=int(os.getenv("CONNECTOR_1_VMID", "101")))
    parser.add_argument("--vmid-2", type=int, default=int(os.getenv("CONNECTOR_2_VMID", "102")))
    parser.add_argument("--scale-out-pct", type=float, default=float(os.getenv("CPU_SCALE_OUT_THRESHOLD", "80.0")))
    parser.add_argument("--scale-in-pct", type=float, default=float(os.getenv("CPU_SCALE_IN_THRESHOLD", "30.0")))
    parser.add_argument("--window-sec", type=int, default=int(os.getenv("TRIGGER_WINDOW_SEC", "15")))
    parser.add_argument("--poll-sec", type=int, default=int(os.getenv("POLL_INTERVAL_SEC", "5")))
    parser.add_argument("--dry-run", action="store_true", help="Simulate API actions without starting/stopping VMs")
    return parser.parse_args()


class ProxmoxClient:
    def __init__(self, base_url: str, token_id: str, token_secret: str, dry_run: bool = False):
        self.base_url = base_url.rstrip("/")
        self.dry_run = dry_run
        self.headers = {
            "Authorization": f"PVEAPIToken={token_id}={token_secret}"
        }

    def get_vm_status(self, node: str, vmid: int) -> dict:
        """Returns VM status ('running'/'stopped') and current CPU load percentage (0-100)."""
        if self.dry_run:
            return {"status": "running", "cpu_pct": 0.0}
        url = f"{self.base_url}/api2/json/nodes/{node}/qemu/{vmid}/status/current"
        resp = requests.get(url, headers=self.headers, verify=False, timeout=5)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        # Proxmox returns 'cpu' as a fraction (e.g., 0.85 for 85%)
        cpu_pct = round(float(data.get("cpu", 0.0)) * 100.0, 2)
        return {"status": data.get("status", "unknown"), "cpu_pct": cpu_pct}

    def start_vm(self, node: str, vmid: int) -> str:
        if self.dry_run:
            print(f"    [DRY-RUN] Would send START command to VM {vmid} on node {node}")
            return "UPID:dry-run:start"
        url = f"{self.base_url}/api2/json/nodes/{node}/qemu/{vmid}/status/start"
        resp = requests.post(url, headers=self.headers, verify=False, timeout=10)
        resp.raise_for_status()
        return resp.json().get("data", "")

    def stop_vm(self, node: str, vmid: int) -> str:
        if self.dry_run:
            print(f"    [DRY-RUN] Would send SHUTDOWN command to VM {vmid} on node {node}")
            return "UPID:dry-run:shutdown"
        url = f"{self.base_url}/api2/json/nodes/{node}/qemu/{vmid}/status/shutdown"
        resp = requests.post(url, headers=self.headers, verify=False, timeout=10)
        resp.raise_for_status()
        return resp.json().get("data", "")


def main():
    args = parse_args()
    token_id = os.getenv("PROXMOX_TOKEN_ID", "user@pam!token")
    token_secret = os.getenv("PROXMOX_TOKEN_SECRET", "secret")

    pve = ProxmoxClient(args.pve_url, token_id, token_secret, dry_run=args.dry_run)

    output_dir = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(output_dir, exist_ok=True)
    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = os.path.join(output_dir, f"scaler_timeseries_{ts_str}.csv")

    high_load_duration = 0
    low_load_duration = 0
    scale_out_triggered_at = None
    connector_2_active_logged = False

    print(f"[*] Starting Autoscaler Daemon (Poll: {args.poll_sec}s | Window: {args.window_sec}s)")
    print(f"[*] Scale-Out Threshold: > {args.scale_out_pct}% | Scale-In Threshold: < {args.scale_in_pct}%")
    print(f"[*] Logging telemetry to: {csv_path}\n")

    fieldnames = [
        "timestamp", "c1_status", "c1_cpu_pct",
        "c2_status", "c2_cpu_pct", "event", "provisioning_sec"
    ]

    with open(csv_path, mode="w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        try:
            while True:
                now_iso = datetime.now().strftime("%H:%M:%S")
                c1 = pve.get_vm_status(args.pve_node_1, args.vmid_1)
                c2 = pve.get_vm_status(args.pve_node_2, args.vmid_2)

                c1_cpu = c1["cpu_pct"]
                c2_cpu = c2["cpu_pct"]
                c2_status = c2["status"]
                event = "NORMAL"
                prov_sec = ""

                # Measure provisioning completion (when Connector 2 begins processing traffic/CPU > 5%)
                if scale_out_triggered_at and not connector_2_active_logged:
                    if c2_status == "running" and c2_cpu > 5.0:
                        elapsed = round(time.time() - scale_out_triggered_at, 2)
                        prov_sec = str(elapsed)
                        event = f"C2_ACTIVE_TRAFFIC ({elapsed}s)"
                        connector_2_active_logged = True
                        print(f"[+] Connector 2 active and handling load! Provisioning time: {elapsed}s")

                # Check Scale-Out condition
                if c1_cpu >= args.scale_out_pct:
                    high_load_duration += args.poll_sec
                    low_load_duration = 0
                    if high_load_duration >= args.window_sec and c2_status != "running":
                        print(f"[!] SCALE-OUT TRIGGERED: C1 CPU {c1_cpu}% >= {args.scale_out_pct}% for {high_load_duration}s")
                        pve.start_vm(args.pve_node_2, args.vmid_2)
                        scale_out_triggered_at = time.time()
                        connector_2_active_logged = False
                        event = "SCALE_OUT_START"
                        high_load_duration = 0

                # Check Scale-In condition (when both are low)
                elif c1_cpu <= args.scale_in_pct and c2_cpu <= args.scale_in_pct:
                    low_load_duration += args.poll_sec
                    high_load_duration = 0
                    if low_load_duration >= args.window_sec and c2_status == "running":
                        print(f"[*] SCALE-IN TRIGGERED: Load <= {args.scale_in_pct}% for {low_load_duration}s. Stopping VM {args.vmid_2}...")
                        pve.stop_vm(args.pve_node_2, args.vmid_2)
                        event = "SCALE_IN_STOP"
                        low_load_duration = 0
                        scale_out_triggered_at = None
                else:
                    high_load_duration = 0
                    low_load_duration = 0

                print(f"[{now_iso}] C1 ({args.vmid_1}): {c1_cpu}% | C2 ({args.vmid_2}): {c2_status} ({c2_cpu}%) | Event: {event}")

                writer.writerow({
                    "timestamp": now_iso,
                    "c1_status": c1["status"],
                    "c1_cpu_pct": c1_cpu,
                    "c2_status": c2_status,
                    "c2_cpu_pct": c2_cpu,
                    "event": event,
                    "provisioning_sec": prov_sec
                })
                f.flush()
                time.sleep(args.poll_sec)

        except KeyboardInterrupt:
            print("\n[*] Stopping Autoscaler Daemon.")


if __name__ == "__main__":
    main()