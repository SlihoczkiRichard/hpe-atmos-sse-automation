#!/usr/bin/env python3
"""
Pillar 1: L4 throughput comparison of two configured paths with iperf3 (client side).

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

Each path has a configured LABEL (e.g. "direct", "sse") and a separate VERIFICATION STATUS:
  not_verified       default; the label is only what the operator configured
  operator_asserted  the operator states, with a recorded evidence note, that the path was checked
                     (e.g. SSE TCP application configured and traffic seen on the connector)
A host name such as SSE_HOST does not prove that traffic used the SSE path; this script cannot
verify the path itself and never opens ports or changes SSE configuration.

Runs alternate between the paths (A, B, A, B, ...) for REPETITIONS rounds to reduce drift effects.
Output collisions: results/<RUN_ID>/ must not already contain iperf3_runs.csv, iperf3_summary.csv,
iperf3_manifest.json or raw files of this RUN_ID; otherwise the tool refuses to start. Files are
created with mode 'x'. Interruption (Ctrl+C; SIGTERM where delivered): the in-flight run is recorded
as invalid, raw files are kept, summary and manifest are written with status "interrupted".

A run is invalid if iperf3 is missing, exits non-zero, times out, returns an "error" field or its
JSON lacks end.sum_received. Invalid runs keep empty metrics (never zero) and make the path summary
"invalid".

Metrics per run (TCP only; iperf3 says nothing about HTTP):
  received_bps / sent_bps            end.sum_received / end.sum_sent bits_per_second
  received_bytes / sent_bytes        end.sum_received / end.sum_sent bytes
  measured_duration_sec              end.sum_received.seconds
  sender_tcp_retransmits             end.sum_sent.retransmits (client side)
  sender_mean_rtt_us                 mean of end.streams[].sender.mean_rtt (kernel smoothed RTT)
  sender_max_rtt_us                  max of end.streams[].sender.max_rtt
  sender_max_snd_cwnd_bytes          max of end.streams[].sender.max_snd_cwnd
  host_cpu_pct / remote_cpu_pct      end.cpu_utilization_percent.host_total / remote_total
Every optional field is left empty if this iperf3 build does not report it (RTT and cwnd come
from Linux TCP_INFO). Retransmits are not packet loss and say nothing about segments beyond the
client's TCP connection. A run whose JSON reports a protocol other than TCP is invalid.

Timing: UTC start/end per run (ms) and monotonic start/end relative to the comparison start.
"""

import os
import sys
import re
import csv
import json
import time
import shutil
import signal
import argparse
import platform
import statistics
import subprocess
from datetime import datetime, timezone

RUN_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
LABEL_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
NOT_VERIFIED = "not_verified"
OPERATOR_ASSERTED = "operator_asserted"

RUN_FIELDS = [
    "run_id", "round", "path_label", "path_verification", "host", "port", "valid", "invalid_reason",
    "exit_code", "started_utc", "ended_utc", "mono_start_sec", "mono_end_sec", "wall_duration_sec",
    "raw_output_file", "iperf3_version",
    "received_bps", "received_mbps", "sent_bps", "received_bytes", "sent_bytes", "measured_duration_sec",
    "sender_tcp_retransmits", "sender_mean_rtt_us", "sender_max_rtt_us", "sender_max_snd_cwnd_bytes",
    "host_cpu_pct", "remote_cpu_pct",
]
SUMMARY_FIELDS = [
    "path_label", "path_verification", "verification_evidence", "host", "port", "status",
    "expected_runs", "valid_runs", "received_mbps_median", "received_mbps_min", "received_mbps_max",
    "sender_tcp_retransmits_median", "sender_mean_rtt_us_median",
]


class PathSpec:
    def __init__(self, label, host, port=5201, verification=NOT_VERIFIED, evidence=""):
        if not LABEL_RE.match(label):
            raise ValueError(f"invalid path label: {label!r}")
        if not re.match(r"^[A-Za-z0-9.:-]{1,253}$", host):
            raise ValueError(f"invalid host for path {label}: {host!r}")
        if not 0 < int(port) < 65536:
            raise ValueError(f"invalid port for path {label}: {port}")
        if verification not in (NOT_VERIFIED, OPERATOR_ASSERTED):
            raise ValueError(f"invalid verification status: {verification}")
        if verification == OPERATOR_ASSERTED and not evidence.strip():
            raise ValueError(f"path {label}: operator_asserted requires an evidence note")
        self.label, self.host, self.port = label, host, int(port)
        self.verification, self.evidence = verification, evidence.strip()


def parse_iperf3_json(text):
    """Returns (metrics, invalid_reason)."""
    try:
        data = json.loads(text)
    except ValueError:
        return None, "output is not JSON"
    if data.get("error"):
        return None, f"iperf3 error: {str(data['error'])[:200]}"
    protocol = ((data.get("start") or {}).get("test_start") or {}).get("protocol")
    if protocol is not None and protocol != "TCP":
        return None, f"protocol is {protocol}, not TCP"
    end = data.get("end") or {}
    rcv = end.get("sum_received") or {}
    received = rcv.get("bits_per_second")
    if received is None:
        return None, "end.sum_received.bits_per_second missing"
    sent = end.get("sum_sent") or {}
    senders = [st.get("sender") or {} for st in end.get("streams") or []]

    def stream_values(key):
        return [s[key] for s in senders if isinstance(s.get(key), (int, float))]

    mean_rtts, max_rtts, cwnds = stream_values("mean_rtt"), stream_values("max_rtt"), stream_values("max_snd_cwnd")
    cpu = end.get("cpu_utilization_percent") or {}
    return {
        "iperf3_version": (data.get("start") or {}).get("version"),
        "received_bps": float(received),
        "received_mbps": round(float(received) / 1e6, 3),
        "sent_bps": float(sent["bits_per_second"]) if "bits_per_second" in sent else None,
        "received_bytes": rcv.get("bytes"),
        "sent_bytes": sent.get("bytes"),
        "measured_duration_sec": rcv.get("seconds"),
        "sender_tcp_retransmits": sent.get("retransmits"),
        "sender_mean_rtt_us": round(statistics.mean(mean_rtts), 1) if mean_rtts else None,
        "sender_max_rtt_us": max(max_rtts) if max_rtts else None,
        "sender_max_snd_cwnd_bytes": max(cwnds) if cwnds else None,
        "host_cpu_pct": cpu.get("host_total"),
        "remote_cpu_pct": cpu.get("remote_total"),
    }, ""


def summarize_path(path, runs, expected_runs):
    valid = [r for r in runs if r["valid"]]
    row = {"path_label": path.label, "path_verification": path.verification,
           "verification_evidence": path.evidence, "host": path.host, "port": path.port,
           "expected_runs": expected_runs, "valid_runs": len(valid),
           "status": "complete" if len(valid) == expected_runs == len(runs) else "invalid"}
    if valid:
        mbps = [r["received_mbps"] for r in valid]
        row.update({"received_mbps_median": statistics.median(mbps),
                    "received_mbps_min": min(mbps), "received_mbps_max": max(mbps)})
        retrans = [r["sender_tcp_retransmits"] for r in valid if r["sender_tcp_retransmits"] is not None]
        row["sender_tcp_retransmits_median"] = statistics.median(retrans) if retrans else None
        rtts = [r["sender_mean_rtt_us"] for r in valid if r["sender_mean_rtt_us"] is not None]
        row["sender_mean_rtt_us_median"] = statistics.median(rtts) if rtts else None
    return row


def subprocess_runner(cmd, timeout):
    try:
        # explicit UTF-8: on Windows text=True alone would decode with the ANSI code page
        res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                             timeout=timeout, check=False)
        return res.returncode, res.stdout, res.stderr
    except FileNotFoundError:
        return None, "", f"executable not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return None, "", f"iperf3 did not finish within {timeout:.0f}s"


def synthetic_iperf3_json(path, round_no):
    """Deterministic, made-up iperf3 JSON for --dry-run (NOT a measurement)."""
    bps = (900e6 if path.label == "direct" else 300e6) - round_no * 1e6
    return json.dumps({"start": {"version": "synthetic", "test_start": {"protocol": "TCP"}},
                       "end": {"sum_received": {"bits_per_second": bps, "bytes": int(bps * 30 / 8), "seconds": 30.0},
                               "sum_sent": {"bits_per_second": bps * 1.01, "bytes": int(bps * 1.01 * 30 / 8),
                                            "retransmits": 3 * round_no},
                               "streams": [{"sender": {"mean_rtt": 1500 + 100 * round_no, "max_rtt": 4000,
                                                       "max_snd_cwnd": 262144}}],
                               "cpu_utilization_percent": {"host_total": 12.5, "remote_total": 30.0}}})


def _iso(dt):
    return dt.isoformat(timespec="milliseconds")


def check_output_free(out_dir, run_id):
    """Raises FileExistsError if iperf3 results of this RUN_ID already exist (nothing is overwritten)."""
    taken = [n for n in ("iperf3_runs.csv", "iperf3_summary.csv", "iperf3_manifest.json")
             if os.path.exists(os.path.join(out_dir, n))]
    raw_dir = os.path.join(out_dir, "raw")
    if os.path.isdir(raw_dir):
        taken += [f"raw/{n}" for n in sorted(os.listdir(raw_dir)) if n.startswith(f"{run_id}_r")][:3]
    if taken:
        raise FileExistsError(f"iperf3 results of RUN_ID {run_id} already exist in {out_dir} ({', '.join(taken)}); "
                              "nothing was overwritten - use a new RUN_ID")


def run_comparison(cfg, runner, sleep=time.sleep, now=lambda: datetime.now(timezone.utc), clock=time.monotonic):
    """Refuses to start if results of the same RUN_ID exist; an interruption still writes the
    summary and the manifest (status "interrupted")."""
    out_dir = os.path.join(cfg.output_dir, cfg.run_id)
    raw_dir = os.path.join(out_dir, "raw")
    check_output_free(out_dir, cfg.run_id)
    os.makedirs(raw_dir, exist_ok=True)
    started = now()
    mono0 = clock()
    runs = []
    interrupted = None
    with open(os.path.join(out_dir, "iperf3_runs.csv"), "x", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=RUN_FIELDS)
        writer.writeheader()
        try:
            for round_no in range(1, cfg.repetitions + 1):
                for path in cfg.paths:
                    stop = _one_run(cfg, runner, now, clock, mono0, raw_dir, writer, f, runs, round_no, path)
                    if stop:
                        interrupted = stop
                        raise KeyboardInterrupt
                    sleep(cfg.cooldown_sec)
        except KeyboardInterrupt:
            interrupted = interrupted or {"during": "pause between runs"}

    summaries = [summarize_path(p, [r for r in runs if r["path_label"] == p.label], cfg.repetitions)
                 for p in cfg.paths]
    if interrupted:
        for summary in summaries:
            summary["status"] = "interrupted"
    with open(os.path.join(out_dir, "iperf3_summary.csv"), "x", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=SUMMARY_FIELDS)
        writer.writeheader()
        for s in summaries:
            writer.writerow({k: ("" if s.get(k) is None else s.get(k)) for k in SUMMARY_FIELDS})

    manifest = {
        "run_id": cfg.run_id,
        "status": "interrupted" if interrupted else "complete",
        "interruption": interrupted,
        "mode": "dry-run: synthetic iperf3 output, NOT a measurement" if cfg.dry_run else "measurement",
        "started_utc": _iso(started), "ended_utc": _iso(now()),
        "config": {"parallel_streams": cfg.parallel, "duration_sec": cfg.duration_sec,
                   "repetitions": cfg.repetitions, "cooldown_sec": cfg.cooldown_sec,
                   "order": "alternating per round: " + ", ".join(p.label for p in cfg.paths),
                   "paths": [{"label": p.label, "host": p.host, "port": p.port,
                              "verification": p.verification, "evidence": p.evidence} for p in cfg.paths]},
        "environment": {"host": platform.node(), "python": platform.python_version()},
        "validity": {"status": "interrupted" if interrupted else
                     ("all_runs_valid" if all(r["valid"] for r in runs) else "contains_invalid_runs"),
                     "valid_runs": sum(1 for r in runs if r["valid"]), "total_runs": len(runs)},
        "invalid_runs": [{"round": r["round"], "path_label": r["path_label"], "reason": r["invalid_reason"]}
                         for r in runs if not r["valid"]],
        "timing": "UTC wall clock per run (ms); mono_*_sec = time.monotonic() relative to comparison start",
        "notes": ["path labels are configured values; see 'verification' for each path",
                  "TCP metrics only; iperf3 provides no HTTP status, latency percentile or error-rate data",
                  "RTT/cwnd fields are the client kernel's TCP_INFO estimates and are empty where not reported",
                  "sender_tcp_retransmits are reported by the iperf3 client; they are not packet loss",
                  "this script does not open ports or change SSE configuration"],
        "summaries": summaries,
    }
    with open(os.path.join(out_dir, "iperf3_manifest.json"), "x", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    return runs, summaries, manifest


def _one_run(cfg, runner, now, clock, mono0, raw_dir, writer, f, runs, round_no, path):
    """One iperf3 client run; returns the interruption info if it was interrupted, else None."""
    cmd = [cfg.iperf3_path, "-c", path.host, "-p", str(path.port), "-P", str(cfg.parallel),
           "-t", str(cfg.duration_sec), "-J"]
    t0, w0 = clock(), now()
    stop = None
    try:
        code, stdout, stderr = runner(cmd, cfg.duration_sec + cfg.timeout_margin)
    except KeyboardInterrupt:
        stop = {"during": "measurement run", "round": round_no, "path_label": path.label}
        code, stdout, stderr = None, "", "interrupted by the operator; iperf3 output was not captured"
    t1, w1 = clock(), now()
    raw_name = f"{cfg.run_id}_r{round_no}_{path.label}.json"
    with open(os.path.join(raw_dir, raw_name), "x", encoding="utf-8") as raw:
        raw.write(stdout)
    if stderr:
        with open(os.path.join(raw_dir, raw_name + ".stderr.txt"), "x", encoding="utf-8") as err:
            err.write(stderr)

    row = {k: None for k in RUN_FIELDS}
    row.update({"run_id": cfg.run_id, "round": round_no, "path_label": path.label,
                "path_verification": path.verification, "host": path.host, "port": path.port,
                "exit_code": code, "started_utc": _iso(w0), "ended_utc": _iso(w1),
                "mono_start_sec": round(t0 - mono0, 3), "mono_end_sec": round(t1 - mono0, 3),
                "wall_duration_sec": round(t1 - t0, 3), "raw_output_file": f"raw/{raw_name}"})
    metrics, reason = parse_iperf3_json(stdout) if stdout else (None, "")
    if code != 0:
        reason = reason or stderr.strip()[:200] or f"iperf3 exit code {code}"
        metrics = None
    elif metrics is None:
        reason = reason or "empty output"
    row.update({"valid": metrics is not None, "invalid_reason": "" if metrics else reason})
    if metrics:
        row.update(metrics)
    writer.writerow({k: ("" if v is None else v) for k, v in row.items()})
    f.flush()
    runs.append(row)
    print(f"[round {round_no}/{cfg.repetitions}] {path.label} ({path.verification}): "
          + (f"{row['received_mbps']} Mbit/s received" if row["valid"] else f"INVALID ({reason})"))
    return stop

def _env(env, key, default=""):
    value = env.get(key)
    return default if value is None or not value.strip() else value.strip()


def parse_path_arg(text):
    """'label=host[:port]' -> (label, host, port)."""
    m = re.match(r"^([a-z0-9_-]+)=([A-Za-z0-9.-]+)(?::(\d+))?$", text)
    if not m:
        raise ValueError(f"path must look like label=host[:port], got {text!r}")
    return m.group(1), m.group(2), int(m.group(3) or 5201)


def build_paths(args, env):
    specs = list(args.path or [])
    if not specs:
        for label, key in (("direct", "IPERF3_DIRECT_HOST"), ("sse", "IPERF3_SSE_HOST")):
            if _env(env, key):
                specs.append(f"{label}={_env(env, key)}")
    evidence = dict(e.split("=", 1) for e in (args.path_evidence or []))
    paths = []
    for spec in specs:
        label, host, port = parse_path_arg(spec)
        note = evidence.get(label, "")
        paths.append(PathSpec(label, host, port, OPERATOR_ASSERTED if note else NOT_VERIFIED, note))
    if len(paths) < 2:
        raise ValueError("two paths are required (e.g. --path direct=10.0.1.123 --path sse=app.example)")
    if len({p.label for p in paths}) != len(paths):
        raise ValueError("path labels must be unique")
    if len({(p.host.lower(), p.port) for p in paths}) != len(paths):
        raise ValueError("two paths use the same host:port; that would not be a comparison")
    unknown = set(evidence) - {p.label for p in paths}
    if unknown:
        raise ValueError(f"evidence given for unknown path label(s): {sorted(unknown)}")
    return paths


def parse_args(argv, env):
    p = argparse.ArgumentParser(description="iperf3 throughput comparison of two configured paths")
    p.add_argument("--path", action="append", help="label=host[:port]; repeat for each path")
    p.add_argument("--path-evidence", action="append",
                   help="label=note: operator-asserted path verification evidence (recorded verbatim)")
    p.add_argument("--parallel", type=int, default=_env(env, "IPERF3_PARALLEL", "8"))
    p.add_argument("--duration", type=int, default=_env(env, "IPERF3_DURATION_SEC", "30"))
    p.add_argument("--repetitions", type=int, default=_env(env, "IPERF3_REPETITIONS", "3"))
    p.add_argument("--cooldown", type=float, default=_env(env, "IPERF3_COOLDOWN_SEC", "10"))
    p.add_argument("--run-id", default=_env(env, "RUN_ID"))
    p.add_argument("--iperf3-path", default=_env(env, "IPERF3_PATH", "iperf3"))
    p.add_argument("--output-dir", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "results"))
    p.add_argument("--dry-run", action="store_true", help="Synthetic iperf3 output; no traffic, not a measurement")
    return p.parse_args(argv)


class Config:
    def __init__(self, args, env):
        self.paths = build_paths(args, env)
        self.parallel = args.parallel
        self.duration_sec = args.duration
        self.repetitions = args.repetitions
        self.cooldown_sec = args.cooldown
        self.iperf3_path = args.iperf3_path
        self.output_dir = args.output_dir
        self.dry_run = args.dry_run
        self.timeout_margin = 30.0
        self.run_id = args.run_id or f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-iperf3"
        if not RUN_ID_RE.match(self.run_id):
            raise ValueError("RUN_ID may contain only letters, digits, '.', '_' and '-'")
        if self.parallel < 1 or self.duration_sec < 1 or self.repetitions < 1:
            raise ValueError("parallel, duration and repetitions must be >= 1")


def _raise_interrupt(signum, frame):
    raise KeyboardInterrupt


def _sigterm_as_interrupt():
    """Best effort: treat SIGTERM like Ctrl+C where the platform delivers it to Python."""
    try:
        return signal.signal(signal.SIGTERM, _raise_interrupt)
    except (ValueError, OSError, AttributeError):
        return None


def _restore_sigterm(previous):
    if previous is not None:
        try:
            signal.signal(signal.SIGTERM, previous)
        except (ValueError, OSError):
            pass


def _runtime_environ(argv):
    """Configuration source for a command-line start. --help and --dry-run never read .env or the
    process environment: they run on an empty, synthetic configuration, so a broken or incomplete
    live configuration cannot block them. Only the live modes load .env (python-dotenv)."""
    if any(a in ("-h", "--help", "--dry-run") for a in argv):
        return {}
    from dotenv import load_dotenv
    load_dotenv()
    return os.environ


def main(argv=None, environ=None, runner=None, sleep=time.sleep):
    if environ is None:
        environ = _runtime_environ(sys.argv[1:] if argv is None else argv)
    cfg = Config(parse_args(argv, environ), environ)
    if cfg.dry_run:
        by_target = {(p.host, str(p.port)): p for p in cfg.paths}
        rounds = {}

        def runner(cmd, timeout):  # noqa: F811 - dry-run replacement
            path = by_target[(cmd[cmd.index("-c") + 1], cmd[cmd.index("-p") + 1])]
            rounds[path.label] = rounds.get(path.label, 0) + 1
            return 0, synthetic_iperf3_json(path, rounds[path.label]), ""
        sleep = lambda _s: None  # noqa: E731
    elif runner is None:
        if shutil.which(cfg.iperf3_path) is None:
            print(f"[!] '{cfg.iperf3_path}' not found; nothing was run.")
            return 2
        runner = subprocess_runner

    print(f"[*] Run ID : {cfg.run_id}{'  (DRY-RUN: synthetic output, not a measurement)' if cfg.dry_run else ''}")
    for p in cfg.paths:
        print(f"[*] Path   : {p.label} -> {p.host}:{p.port} (verification: {p.verification})")
    print("[*] The iperf3 server must already be listening on each target; this script opens no ports.")
    previous = _sigterm_as_interrupt()
    try:
        _, summaries, manifest = run_comparison(cfg, runner, sleep=sleep)
    except FileExistsError as exc:
        print(f"[!] {exc}")
        return 2
    finally:
        _restore_sigterm(previous)
    for s in summaries:
        print(f"[+] {s['path_label']} ({s['path_verification']}): status={s['status']} "
              f"median={s.get('received_mbps_median')} Mbit/s")
    if manifest["status"] == "interrupted":
        print(f"[!] Interrupted ({manifest['interruption']}); manifest written with status 'interrupted'.")
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
