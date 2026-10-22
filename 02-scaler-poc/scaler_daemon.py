#!/usr/bin/env python3
"""
Pillar 2: Event-Driven Horizontal Autoscaler Daemon (VMware ESXi Testbed)
- Samples Primary Connector (SR-CONN01 on ibm09esxi) CPU via guest SSH.
- Provisions Standby Connector (SR-CONN02 on ibm06esxi) via ESXi vim-cmd.
- Validates end-to-end cloud data path reachability.
"""

import os
import csv
import time
import argparse
import logging
from datetime import datetime
import paramiko
import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def parse_args():
    parser = argparse.ArgumentParser(description="HPE SSE Connector Horizontal Autoscaler")
    # Primary Connector (ibm09esxi guest)
    parser.add_argument("--c1-ip", default=os.getenv("CONNECTOR_1_IP", "10.0.1.121"), help="SR-CONN01 IP")
    parser.add_argument("--c1-user", default=os.getenv("CONNECTOR_SSH_USER", "richard"), help="SR-CONN01 SSH user")
    parser.add_argument("--c1-password", default=os.getenv("CONNECTOR_SSH_PASSWORD", ""), help="SR-CONN01 SSH password")

    # Secondary Connector Hypervisor (ibm06esxi)
    parser.add_argument("--esxi-host", default=os.getenv("ESXI_HOST", "ibm06esxi.szinva.net"), help="ibm06esxi FQDN/IP")
    parser.add_argument("--esxi-user", default=os.getenv("ESXI_USER", "root"), help="ESXi management user")
    parser.add_argument("--esxi-password", default=os.getenv("ESXI_PASSWORD", ""), help="ESXi root password")
    parser.add_argument("--c2-vmid", type=int, default=int(os.getenv("CONNECTOR_2_VMID", "12")), help="SR-CONN02 VMID on ibm06esxi")

    # Thresholds
    parser.add_argument("--scale-out-pct", type=float, default=float(os.getenv("CPU_SCALE_OUT_THRESHOLD", "80.0")))
    parser.add_argument("--scale-in-pct", type=float, default=float(os.getenv("CPU_SCALE_IN_THRESHOLD", "30.0")))
    parser.add_argument("--window-sec", type=float, default=float(os.getenv("TRIGGER_WINDOW_SEC", "15.0")))
    parser.add_argument("--poll-sec", type=float, default=float(os.getenv("POLL_INTERVAL_SEC", "5.0")))
    parser.add_argument("--target-url", default=os.getenv("TARGET_APP_URL", "https://sr-target-web-szinvanet.axisapps.io/"))
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


class ESXiHost:
    """Manages SR-CONN02 VM lifecycle on ibm06esxi."""
    def __init__(self, host, user, password, dry_run=False):
        self.host = host
        self.user = user
        self.password = password
        self.dry_run = dry_run

    def _exec(self, cmd):
        if self.dry_run:
            return 0, "", ""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(hostname=self.host, username=self.user, password=self.password, timeout=5)
            _, stdout, stderr = client.exec_command(cmd)
            code = stdout.channel.recv_exit_status()
            return code, stdout.read().decode().strip(), stderr.read().decode().strip()
        except Exception as exc:
            logging.error(f"ESXi SSH communication error ({self.host}): {exc}")
            return -1, "", str(exc)
        finally:
            client.close()

    def get_power_state(self, vmid):
        code, out, _ = self._exec(f"vim-cmd vmsvc/power.getstate {vmid}")
        if code != 0 or not out:
            return "unknown"
        if "Powered on" in out:
            return "running"
        elif "Powered off" in out:
            return "stopped"
        return "unknown"

    def start_vm(self, vmid):
        if self.dry_run:
            logging.info(f"[DRY-RUN] Power on VM {vmid} on {self.host}")
            return True
        code, _, _ = self._exec(f"vim-cmd vmsvc/power.on {vmid}")
        time.sleep(1.0)
        return self.get_power_state(vmid) == "running"

    def stop_vm(self, vmid):
        if self.dry_run:
            logging.info(f"[DRY-RUN] Shutdown VM {vmid} on {self.host}")
            return True
        logging.info(f"Dispatching ACPI shutdown to VM {vmid} on {self.host}...")
        self._exec(f"vim-cmd vmsvc/power.shutdown {vmid}")
        
        # Wait up to 10 seconds for graceful shutdown, else force power off
        t0 = time.monotonic()
        while time.monotonic() - t0 < 10.0:
            if self.get_power_state(vmid) == "stopped":
                return True
            time.sleep(2.0)
        
        logging.warning(f"Graceful shutdown timed out. Forcing power off for VM {vmid}...")
        self._exec(f"vim-cmd vmsvc/power.off {vmid}")
        time.sleep(1.0)
        return self.get_power_state(vmid) == "stopped"


def get_guest_cpu(ip, user, password):
    """Samples guest CPU load (100 - Idle%) directly from SR-CONN01."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=ip, username=user, password=password, timeout=3.5)
        cmd = "LC_ALL=C top -bn2 -d 0.5 | grep 'Cpu(s)' | tail -n 1 | awk '{print 100 - $8}'"
        _, stdout, _ = client.exec_command(cmd)
        raw = stdout.read().decode().strip()
        val = float(raw)
        return max(0.0, min(val, 100.0))
    except Exception:
        return None
    finally:
        client.close()


def verify_application_path(target_url):
    """Verifies that the ZTNA tunnel forwards requests to the backend successfully."""
    try:
        resp = requests.get(target_url, timeout=2.5, verify=False)
        return resp.status_code == 200
    except Exception:
        return False


def main():
    args = parse_args()
    esxi = ESXiHost(args.esxi_host, args.esxi_user, args.esxi_password, args.dry_run)

    output_dir = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(output_dir, exist_ok=True)
    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = os.path.join(output_dir, f"scaler_timeseries_{ts_str}.csv")

    high_load_start = None
    low_load_start = None
    scale_out_triggered_at = None
    probe_ok_logged = False

    print(f"[*] Starting Autoscaler Daemon for SSE Hybrid Testbed")
    print(f"[*] Primary Node  : SR-CONN01 ({args.c1_ip} on ibm09esxi)")
    print(f"[*] Standby Node  : SR-CONN02 (VMID {args.c2_vmid} on {args.esxi_host})")
    print(f"[*] Target Backend: {args.target_url}")
    print(f"[*] Logging to    : {csv_path}\n")

    fieldnames = [
        "timestamp", "sample_duration_sec",
        "c1_cpu_pct", "c2_state", "event", "provisioning_sec"
    ]

    with open(csv_path, mode="w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        try:
            while True:
                loop_start = time.monotonic()
                now_iso = datetime.now().strftime("%H:%M:%S")

                c1_cpu = get_guest_cpu(args.c1_ip, args.c1_user, args.c1_password)
                c2_state = esxi.get_power_state(args.c2_vmid)

                event = "NORMAL"
                prov_sec = ""

                if c1_cpu is None:
                    event = "TELEMETRY_ERROR_C1"
                    high_load_start = None
                    low_load_start = None

                # Provisioning time tracking
                if scale_out_triggered_at and not probe_ok_logged:
                    if c2_state == "running" and verify_application_path(args.target_url):
                        elapsed = round(time.monotonic() - scale_out_triggered_at, 2)
                        prov_sec = str(elapsed)
                        event = f"APPLICATION_PROBE_OK ({elapsed}s)"
                        probe_ok_logged = True
                        print(f"[+] Application path verified responsive through SSE fabric in {elapsed}s.")

                # Scale-Out Condition
                if c1_cpu is not None and c1_cpu >= args.scale_out_pct:
                    if high_load_start is None:
                        high_load_start = time.monotonic()
                    low_load_start = None

                    elapsed_high = time.monotonic() - high_load_start
                    if elapsed_high >= args.window_sec and c2_state == "stopped":
                        print(f"[!] SCALE-OUT: C1 CPU sustained {c1_cpu}% for {elapsed_high:.1f}s. Starting SR-CONN02 on {args.esxi_host}...")
                        action_start = time.monotonic()
                        if esxi.start_vm(args.c2_vmid):
                            scale_out_triggered_at = action_start
                            probe_ok_logged = False
                            event = "SCALE_OUT_START"
                            high_load_start = None

                # Scale-In Condition
                elif c1_cpu is not None and c1_cpu <= args.scale_in_pct:
                    if low_load_start is None:
                        low_load_start = time.monotonic()
                    high_load_start = None

                    elapsed_low = time.monotonic() - low_load_start
                    if elapsed_low >= args.window_sec and c2_state == "running":
                        print(f"[*] SCALE-IN: C1 CPU under threshold ({c1_cpu}%) for {elapsed_low:.1f}s. Stopping SR-CONN02...")
                        if esxi.stop_vm(args.c2_vmid):
                            event = "SCALE_IN_STOP"
                            low_load_start = None
                            scale_out_triggered_at = None
                else:
                    high_load_start = None
                    low_load_start = None

                sample_duration = round(time.monotonic() - loop_start, 3)
                c1_str = f"{c1_cpu:.1f}%" if c1_cpu is not None else "ERR"
                print(f"[{now_iso}] C1 CPU: {c1_str} | C2 (ibm06esxi): {c2_state} | Event: {event}")

                writer.writerow({
                    "timestamp": now_iso,
                    "sample_duration_sec": sample_duration,
                    "c1_cpu_pct": c1_cpu if c1_cpu is not None else "",
                    "c2_state": c2_state,
                    "event": event,
                    "provisioning_sec": prov_sec
                })
                f.flush()

                # Drift compensation
                execution_time = time.monotonic() - loop_start
                time.sleep(max(0.1, args.poll_sec - execution_time))

        except KeyboardInterrupt:
            print("\n[*] Autoscaler Daemon gracefully stopped.")


if __name__ == "__main__":
    main()