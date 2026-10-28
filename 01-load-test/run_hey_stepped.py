#!/usr/bin/env python3
"""
Pillar 1: Stepped HTTP load test with 'hey', repeated as full sweeps.

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

Terms
  measurement run   one hey process at one concurrency level in one sweep
  request attempt   one HTTP request execution by hey; it ends either with an HTTP response
                    (any status code) or with a transport error (timeout, refused, reset, TLS, ...)
  sweep             one pass over all configured concurrency levels in ascending order

Definitions (per measurement run)
  success                      HTTP response whose status is in SUCCESS_STATUSES (default: 200 only)
  attempts (denominator)       HTTP responses + transport errors
  primary error rate           (non-success HTTP responses + transport errors) / attempts
  5xx+transport error rate     (HTTP 5xx responses + transport errors) / attempts
                               (separate metric, kept for comparison with the original plan;
                               never used for acceptance and never mixed with the primary rate)
  successful RPS               successful responses / hey "Total" time of the run
  latency (all_responses)      hey's latency statistics; they cover every request that returned an
                               HTTP response (any status) and exclude transport errors. hey cannot
                               report success-only latency; use the k6 export for that.

Timing: every run records UTC start/end (wall clock, ms) and monotonic start/end in seconds since
the start of the benchmark (time.monotonic); durations are taken from the monotonic clock.

Output collisions: results/<RUN_ID>/ must not already contain runs.csv, levels.csv, manifest.json or
raw files of this RUN_ID; otherwise the tool refuses to start (nothing is overwritten). Every file is
created with mode 'x'. Use a new RUN_ID for every run.

Interruption (Ctrl+C; SIGTERM where the platform delivers it): the in-flight run is recorded as
invalid ("interrupted"), raw files written so far are kept, levels.csv and manifest.json are still
written, and the manifest status is "interrupted": an interrupted benchmark is never an acceptable
capacity result (no accepted level, no primary result). A hard kill (SIGKILL, power loss) leaves
no manifest.

Validity: a run is invalid if hey is missing, exits non-zero, times out, or its summary cannot be
parsed (no Summary/Total, no attempts). Metrics of an invalid run are left empty, never zero.

Acceptance (per concurrency level)
  A level is accepted only if all SWEEPS runs exist, are valid, and each run's primary error rate
  is strictly below ACCEPT_MAX_ERROR_RATE (default 0.01). Missing or invalid runs make the level
  "invalid"; it cannot be accepted from the remaining runs.

Primary result
  The largest median successful RPS among accepted levels. This is the best observed throughput
  under the acceptance condition for the tested levels only; it is NOT a physical saturation
  point or a general connector capacity limit.

Redirects: hey follows redirects by default and records the final response status; with
--no-follow-redirects (hey -disable-redirects) a 3xx is recorded as a non-success response.
TLS: hey does not verify server certificates (hey's own client setting); TLS problems therefore do
not show up as transport errors here.
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

HEY_PERCENTILES = ("10", "25", "50", "75", "90", "95", "99")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")

RUN_FIELDS = [
    "run_id", "sweep", "concurrency", "valid", "invalid_reason", "exit_code",
    "started_utc", "ended_utc", "mono_start_sec", "mono_end_sec", "wall_duration_sec", "raw_output_file",
    "hey_total_sec", "hey_reported_rps",
    "attempts", "http_responses", "success_responses", "non_success_responses", "http_5xx_responses",
    "transport_errors", "status_counts_json", "transport_error_classes_json",
    "successful_rps",
    "primary_error_numerator", "primary_error_denominator", "primary_error_rate",
    "err5xx_transport_numerator", "err5xx_transport_denominator", "err5xx_transport_error_rate",
    "lat_all_responses_avg_ms", "lat_all_responses_min_ms", "lat_all_responses_max_ms",
]

LEVEL_FIELDS = [
    "concurrency", "status", "expected_runs", "valid_runs", "invalid_runs",
    "successful_rps_median", "successful_rps_min", "successful_rps_max",
    "primary_error_rate_pooled", "primary_error_rate_max_run",
    "err5xx_transport_error_rate_pooled", "err5xx_transport_error_rate_max_run",
    "err5xx_transport_all_runs_below_threshold",
]


# ------------------------------------------------------------------------------
# Parsing (pure)
# ------------------------------------------------------------------------------

def parse_status_set(text):
    """'200' or '200,204' -> frozenset({200, 204})."""
    codes = set()
    for token in (t.strip() for t in text.split(",")):
        if not token:
            continue
        if not token.isdigit() or not 100 <= int(token) <= 599:
            raise ValueError(f"invalid HTTP status code: {token!r}")
        codes.add(int(token))
    if not codes:
        raise ValueError("SUCCESS_STATUSES is empty")
    return frozenset(codes)


def classify_transport_error(message):
    m = message.lower()
    if "timeout" in m or "deadline exceeded" in m:
        return "timeout"
    if "connection refused" in m:
        return "connection_refused"
    if "connection reset" in m:
        return "connection_reset"
    if "tls" in m or "x509" in m or "certificate" in m:
        return "tls"
    if "eof" in m:
        return "eof"
    if "no such host" in m or "lookup" in m:
        return "dns"
    return "other"


def _section(output, header):
    """Lines of the hey report section that starts with `header` (until the next blank line)."""
    lines = output.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == header:
            body = []
            for nxt in lines[i + 1:]:
                if not nxt.strip():
                    break
                body.append(nxt)
            return body
    return []


def _secs_to_ms(pattern, output):
    m = re.search(pattern, output)
    return round(float(m.group(1)) * 1000.0, 3) if m else None


def parse_hey_output(output, percentiles, success_statuses):
    """Parses hey's text summary. Returns (metrics, invalid_reason). Missing values are None."""
    if "Summary:" not in output:
        return None, "no hey summary in output"
    total = re.search(r"Total:\s+([0-9.]+)\s+secs", output)
    if not total or float(total.group(1)) <= 0:
        return None, "hey Total time missing or zero"
    total_sec = float(total.group(1))

    status_counts = {}
    for line in _section(output, "Status code distribution:"):
        m = re.match(r"^\s*\[(\d{3})\]\s+(\d+)\s+responses?\s*$", line)
        if not m:
            return None, f"unparseable status line: {line.strip()!r}"
        status_counts[int(m.group(1))] = status_counts.get(int(m.group(1)), 0) + int(m.group(2))

    error_classes, transport_errors = {}, 0
    for line in _section(output, "Error distribution:"):
        m = re.match(r"^\s*\[(\d+)\]\s+(.*)$", line)
        if not m:
            return None, f"unparseable error line: {line.strip()!r}"
        count = int(m.group(1))
        transport_errors += count
        cls = classify_transport_error(m.group(2))
        error_classes[cls] = error_classes.get(cls, 0) + count

    responses = sum(status_counts.values())
    attempts = responses + transport_errors
    if attempts == 0:
        return None, "no request attempts reported"
    success = sum(n for code, n in status_counts.items() if code in success_statuses)
    http_5xx = sum(n for code, n in status_counts.items() if 500 <= code <= 599)
    rps = re.search(r"Requests/sec:\s+([0-9.]+)", output)

    metrics = {
        "hey_total_sec": total_sec,
        "hey_reported_rps": float(rps.group(1)) if rps else None,
        "attempts": attempts,
        "http_responses": responses,
        "success_responses": success,
        "non_success_responses": responses - success,
        "http_5xx_responses": http_5xx,
        "transport_errors": transport_errors,
        "status_counts_json": json.dumps({str(k): v for k, v in sorted(status_counts.items())}),
        "transport_error_classes_json": json.dumps(dict(sorted(error_classes.items()))),
        "successful_rps": round(success / total_sec, 3),
        "primary_error_numerator": (responses - success) + transport_errors,
        "primary_error_denominator": attempts,
        "primary_error_rate": ((responses - success) + transport_errors) / attempts,
        "err5xx_transport_numerator": http_5xx + transport_errors,
        "err5xx_transport_denominator": attempts,
        "err5xx_transport_error_rate": (http_5xx + transport_errors) / attempts,
        "lat_all_responses_avg_ms": _secs_to_ms(r"Average:\s+([0-9.]+)\s+secs", output),
        "lat_all_responses_min_ms": _secs_to_ms(r"Fastest:\s+([0-9.]+)\s+secs", output),
        "lat_all_responses_max_ms": _secs_to_ms(r"Slowest:\s+([0-9.]+)\s+secs", output),
    }
    for p in percentiles:
        metrics[f"lat_all_responses_p{p}_ms"] = _secs_to_ms(rf"\b{p}%\s+in\s+([0-9.]+)\s+secs", output)
    return metrics, ""


# ------------------------------------------------------------------------------
# Aggregation (pure)
# ------------------------------------------------------------------------------

def _pooled(runs, prefix):
    num = sum(r[f"{prefix}_numerator"] for r in runs)
    den = sum(r[f"{prefix}_denominator"] for r in runs)
    return num / den if den else None


def aggregate_level(concurrency, runs, expected_runs, max_error_rate, percentiles):
    valid = [r for r in runs if r["valid"]]
    invalid = len(runs) - len(valid)
    row = {"concurrency": concurrency, "expected_runs": expected_runs,
           "valid_runs": len(valid), "invalid_runs": invalid}
    if len(runs) < expected_runs or invalid:
        row["status"] = "invalid"  # missing or invalid runs: never accepted from the remainder
    elif all(r["primary_error_rate"] < max_error_rate for r in valid):
        row["status"] = "accepted"
    else:
        row["status"] = "rejected"

    if valid:
        rps = [r["successful_rps"] for r in valid]
        row.update({
            "successful_rps_median": statistics.median(rps),
            "successful_rps_min": min(rps),
            "successful_rps_max": max(rps),
            "primary_error_rate_pooled": _pooled(valid, "primary_error"),
            "primary_error_rate_max_run": max(r["primary_error_rate"] for r in valid),
            "err5xx_transport_error_rate_pooled": _pooled(valid, "err5xx_transport"),
            "err5xx_transport_error_rate_max_run": max(r["err5xx_transport_error_rate"] for r in valid),
            "err5xx_transport_all_runs_below_threshold": (
                len(valid) == expected_runs and invalid == 0
                and all(r["err5xx_transport_error_rate"] < max_error_rate for r in valid)),
        })
        for p in percentiles:
            values = [r[f"lat_all_responses_p{p}_ms"] for r in valid if r.get(f"lat_all_responses_p{p}_ms") is not None]
            row[f"lat_all_responses_p{p}_ms_median_of_runs"] = statistics.median(values) if values else None
    return row


def primary_result(levels):
    """Largest median successful RPS among accepted levels, with a non-monotonic flag."""
    accepted = [lv for lv in levels if lv["status"] == "accepted"]
    if not accepted:
        return {"accepted_levels": [], "best_level": None, "best_successful_rps_median": None,
                "non_monotonic": False}
    best = max(accepted, key=lambda lv: lv["successful_rps_median"])
    ordered = sorted(levels, key=lambda lv: lv["concurrency"])
    first_bad = next((lv["concurrency"] for lv in ordered if lv["status"] != "accepted"), None)
    non_monotonic = first_bad is not None and any(lv["concurrency"] > first_bad for lv in accepted)
    return {"accepted_levels": [lv["concurrency"] for lv in accepted],
            "best_level": best["concurrency"],
            "best_successful_rps_median": best["successful_rps_median"],
            "best_successful_rps_min": best["successful_rps_min"],
            "non_monotonic": non_monotonic}


# ------------------------------------------------------------------------------
# Execution
# ------------------------------------------------------------------------------

def duration_to_seconds(text):
    m = re.match(r"^(\d+(?:\.\d+)?)(ms|s|m|h)$", text.strip())
    if not m:
        raise ValueError(f"unsupported duration (use e.g. 30s, 1m): {text!r}")
    return float(m.group(1)) * {"ms": 0.001, "s": 1, "m": 60, "h": 3600}[m.group(2)]


def build_hey_command(hey_path, url, concurrency, duration, qps, follow_redirects):
    cmd = [hey_path, "-z", duration, "-c", str(concurrency)]
    if qps > 0:
        cmd += ["-q", str(qps)]  # hey: rate limit per worker
    if not follow_redirects:
        cmd.append("-disable-redirects")
    cmd.append(url)
    return cmd


def subprocess_runner(cmd, timeout):
    """Returns (exit_code, stdout, stderr); exit_code None when hey could not be run to completion."""
    try:
        # explicit UTF-8: on Windows text=True alone would decode with the ANSI code page
        res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                             timeout=timeout, check=False)
        return res.returncode, res.stdout, res.stderr
    except FileNotFoundError:
        return None, "", f"executable not found: {cmd[0]}"
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        return None, out, f"hey did not finish within {timeout:.0f}s"


def synthetic_hey_output(concurrency):
    """Deterministic, made-up hey report for --dry-run (NOT a measurement)."""
    total = 30.0
    errors_503 = max(0, concurrency - 200)
    ok = concurrency * 60
    latency = 0.02 + concurrency / 5000.0
    return (
        "\nSummary:\n"
        f"  Total:\t{total:.4f} secs\n  Slowest:\t{latency * 4:.4f} secs\n  Fastest:\t{latency / 4:.4f} secs\n"
        f"  Average:\t{latency:.4f} secs\n  Requests/sec:\t{(ok + errors_503) / total:.4f}\n\n"
        "Latency distribution:\n"
        + "".join(f"  {p}% in {latency * (1 + int(p) / 100):.4f} secs\n" for p in HEY_PERCENTILES)
        + "\nStatus code distribution:\n"
        f"  [200]\t{ok} responses\n" + (f"  [503]\t{errors_503} responses\n" if errors_503 else "")
        + "\n"
    )


def _utc_now():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.isoformat(timespec="milliseconds")


def check_output_free(out_dir, run_id):
    """Raises FileExistsError if results of this RUN_ID already exist (nothing is overwritten)."""
    taken = [n for n in ("runs.csv", "levels.csv", "manifest.json") if os.path.exists(os.path.join(out_dir, n))]
    raw_dir = os.path.join(out_dir, "raw")
    if os.path.isdir(raw_dir):
        taken += [f"raw/{n}" for n in sorted(os.listdir(raw_dir)) if n.startswith(f"{run_id}_s")][:3]
    if taken:
        raise FileExistsError(f"results of RUN_ID {run_id} already exist in {out_dir} ({', '.join(taken)}); "
                              "nothing was overwritten - use a new RUN_ID")


def run_benchmark(cfg, runner, sleep=time.sleep, clock=time.monotonic, now=_utc_now):
    """Runs cfg.sweeps ascending sweeps; writes raw outputs, runs.csv, levels.csv and manifest.json.
    Refuses to start if results of the same RUN_ID exist; an interruption still writes the manifest."""
    out_dir = os.path.join(cfg.output_dir, cfg.run_id)
    raw_dir = os.path.join(out_dir, "raw")
    check_output_free(out_dir, cfg.run_id)
    os.makedirs(raw_dir, exist_ok=True)
    percentiles = cfg.percentiles
    run_fields = RUN_FIELDS + [f"lat_all_responses_p{p}_ms" for p in percentiles]
    started = now()
    mono0 = clock()
    runs = []
    interrupted = None

    with open(os.path.join(out_dir, "runs.csv"), "x", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=run_fields)
        writer.writeheader()
        try:
            _sweep_loop(cfg, runner, sleep, clock, now, mono0, raw_dir, run_fields, writer, f, runs)
        except _Interrupted as stop:
            interrupted = stop.where
        except KeyboardInterrupt:
            interrupted = {"during": "pause between runs"}
    return _finish_benchmark(cfg, out_dir, runs, percentiles, started, now, interrupted)


class _Interrupted(Exception):
    def __init__(self, where):
        super().__init__("interrupted")
        self.where = where


def _sweep_loop(cfg, runner, sleep, clock, now, mono0, raw_dir, run_fields, writer, f, runs):
    for sweep in range(1, cfg.sweeps + 1):
        for level in cfg.steps:
            cmd = build_hey_command(cfg.hey_path, cfg.url, level, cfg.duration, cfg.qps, cfg.follow_redirects)
            t0, w0 = clock(), now()
            stop = None
            try:
                code, stdout, stderr = runner(cmd, cfg.timeout_sec)
            except KeyboardInterrupt:
                stop = {"during": "measurement run", "sweep": sweep, "concurrency": level}
                code, stdout, stderr = None, "", "interrupted by the operator; hey output was not captured"
            t1, w1 = clock(), now()

            raw_name = f"{cfg.run_id}_s{sweep}_c{level}.txt"
            with open(os.path.join(raw_dir, raw_name), "x", encoding="utf-8") as raw:
                raw.write(f"# command: {' '.join(cmd)}\n# exit_code: {code}\n# started_utc: {_iso(w0)}\n"
                          f"# ended_utc: {_iso(w1)}\n# --- stdout ---\n{stdout}\n# --- stderr ---\n{stderr}\n")

            row = {name: None for name in run_fields}
            row.update({"run_id": cfg.run_id, "sweep": sweep, "concurrency": level, "exit_code": code,
                        "started_utc": _iso(w0), "ended_utc": _iso(w1),
                        "mono_start_sec": round(t0 - mono0, 3), "mono_end_sec": round(t1 - mono0, 3),
                        "wall_duration_sec": round(t1 - t0, 3), "raw_output_file": f"raw/{raw_name}"})
            if code != 0:
                reason = stderr.strip()[:200] or f"hey exit code {code}"
                row.update({"valid": False, "invalid_reason": reason})
            else:
                metrics, reason = parse_hey_output(stdout, cfg.percentiles, cfg.success_statuses)
                row.update({"valid": metrics is not None, "invalid_reason": reason})
                if metrics:
                    row.update(metrics)
            writer.writerow({k: ("" if v is None else v) for k, v in row.items()})
            f.flush()
            runs.append(row)
            print(f"[sweep {sweep}/{cfg.sweeps}] c={level}: "
                  + (f"successful_rps={row['successful_rps']} primary_err={row['primary_error_rate']:.4%}"
                     if row["valid"] else f"INVALID ({row['invalid_reason']})"))
            if stop:
                raise _Interrupted(stop)
            sleep(cfg.cooldown_sec)


def _finish_benchmark(cfg, out_dir, runs, percentiles, started, now, interrupted):
    levels = [aggregate_level(level, [r for r in runs if r["concurrency"] == level], cfg.sweeps,
                              cfg.accept_max_error_rate, percentiles) for level in cfg.steps]
    computed_status = {lv["concurrency"]: lv["status"] for lv in levels}
    if interrupted:
        for lv in levels:   # an interrupted benchmark is never an acceptable capacity result
            lv["status"] = "interrupted_run"
    level_fields = LEVEL_FIELDS + [f"lat_all_responses_p{p}_ms_median_of_runs" for p in percentiles]
    with open(os.path.join(out_dir, "levels.csv"), "x", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=level_fields)
        writer.writeheader()
        for lv in levels:
            writer.writerow({k: ("" if lv.get(k) is None else lv.get(k)) for k in level_fields})

    result = primary_result(levels)
    if interrupted:
        result["note"] = "benchmark interrupted: no acceptable capacity result"
    manifest = {
        "run_id": cfg.run_id,
        "status": "interrupted" if interrupted else "complete",
        "interruption": interrupted,
        "level_status_if_it_had_completed": computed_status if interrupted else None,
        "mode": "dry-run: synthetic hey output, NOT a measurement" if cfg.dry_run else "measurement",
        "started_utc": _iso(started), "ended_utc": _iso(now()),
        "config": {"url": cfg.url, "concurrency_steps": cfg.steps, "duration_per_run": cfg.duration,
                   "qps_per_worker": cfg.qps, "sweeps": cfg.sweeps, "cooldown_sec": cfg.cooldown_sec,
                   "success_statuses": sorted(cfg.success_statuses),
                   "accept_max_error_rate": cfg.accept_max_error_rate,
                   "follow_redirects": cfg.follow_redirects,
                   "redirect_handling": ("hey follows redirects; the final response status is recorded"
                                         if cfg.follow_redirects else
                                         "hey -disable-redirects; a 3xx response is a non-success response"),
                   "tls_certificate_verification": "not performed (hey client setting, not configurable)",
                   "percentiles": percentiles, "hey_path": cfg.hey_path},
        "environment": {"host": platform.node(), "python": platform.python_version()},
        "definitions": {
            "measurement_run": "one hey process at one concurrency level in one sweep",
            "request_attempt": "one HTTP request execution; ends with an HTTP response or a transport error",
            "primary_error_rate": "(non-success HTTP responses + transport errors) / attempts",
            "err5xx_transport_error_rate": "(HTTP 5xx + transport errors) / attempts; comparison only",
            "acceptance": "all runs present and valid, each primary_error_rate < accept_max_error_rate",
            "latency": "hey statistics over all HTTP responses (any status), transport errors excluded",
        },
        "validity": {"status": "interrupted" if interrupted else
                     ("all_runs_valid" if all(r["valid"] for r in runs) else "contains_invalid_runs"),
                     "valid_runs": sum(1 for r in runs if r["valid"]), "total_runs": len(runs),
                     "levels_by_status": {st: [lv["concurrency"] for lv in levels if lv["status"] == st]
                                          for st in sorted({lv["status"] for lv in levels})}},
        "timing": "UTC wall clock per run (ms); mono_*_sec = time.monotonic() relative to benchmark start",
        "primary_result": result,
        "interpretation_note": ("best_successful_rps_median is the best observed throughput under the "
                                "acceptance condition for the tested levels only; it is not a physical "
                                "saturation point or a general connector capacity limit"),
        "known_limitations": ["hey does not verify TLS certificates",
                              "hey -q limits the rate per worker, not in total",
                              "latency percentiles cannot be restricted to successful responses with hey"],
        "invalid_runs": [{"sweep": r["sweep"], "concurrency": r["concurrency"], "reason": r["invalid_reason"]}
                         for r in runs if not r["valid"]],
    }
    with open(os.path.join(out_dir, "manifest.json"), "x", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    return runs, levels, manifest


# ------------------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------------------

def _env(env, key, default):
    value = env.get(key)
    return default if value is None or not value.strip() else value.strip()


def parse_args(argv, env):
    p = argparse.ArgumentParser(description="Stepped HTTP load test with hey (repeated sweeps)")
    p.add_argument("--url", default=_env(env, "TARGET_APP_URL", ""), help="Target URL through the SSE path")
    p.add_argument("--steps", default=_env(env, "LOAD_CONCURRENCY_STEPS", "10,25,50,100,150,200,300,400,500"))
    p.add_argument("--duration", default=_env(env, "LOAD_STEP_DURATION", "30s"), help="Duration of one run")
    p.add_argument("--qps", type=int, default=_env(env, "LOAD_RATE_LIMIT_QPS", "0"),
                   help="hey rate limit per worker (0 = none)")
    p.add_argument("--percentiles", default=_env(env, "LOAD_PERCENTILES", "50,75,90,95,99"))
    p.add_argument("--cooldown", type=float, default=_env(env, "LOAD_COOLDOWN_SEC", "5"))
    p.add_argument("--sweeps", type=int, default=_env(env, "LOAD_SWEEPS", "3"))
    p.add_argument("--success-statuses", default=_env(env, "SUCCESS_STATUSES", "200"))
    p.add_argument("--accept-max-error-rate", type=float, default=_env(env, "ACCEPT_MAX_ERROR_RATE", "0.01"))
    p.add_argument("--no-follow-redirects", action="store_true",
                   default=_env(env, "LOAD_FOLLOW_REDIRECTS", "true").lower() in ("0", "false", "no", "off"))
    p.add_argument("--run-id", default=_env(env, "RUN_ID", ""))
    p.add_argument("--label", default="hey")
    p.add_argument("--hey-path", default=_env(env, "HEY_PATH", "hey"))
    p.add_argument("--timeout-margin", type=float, default=60.0, help="Extra seconds before a run is aborted")
    p.add_argument("--output-dir", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "results"))
    p.add_argument("--dry-run", action="store_true", help="Synthetic hey output; no traffic, not a measurement")
    return p.parse_args(argv)


class Config:
    def __init__(self, args, now=_utc_now):
        self.url = args.url
        self.steps = [int(s) for s in args.steps.split(",") if s.strip()]
        self.duration = args.duration
        self.qps = args.qps
        self.percentiles = [p.strip() for p in args.percentiles.split(",") if p.strip()]
        self.cooldown_sec = args.cooldown
        self.sweeps = args.sweeps
        self.success_statuses = parse_status_set(args.success_statuses)
        self.accept_max_error_rate = args.accept_max_error_rate
        self.follow_redirects = not args.no_follow_redirects
        self.hey_path = args.hey_path
        self.dry_run = args.dry_run
        self.output_dir = args.output_dir
        self.timeout_sec = duration_to_seconds(args.duration) + args.timeout_margin
        self.run_id = args.run_id or f"{now().strftime('%Y%m%dT%H%M%SZ')}-{args.label}"
        self.validate()

    def validate(self):
        if not self.url and not self.dry_run:
            raise ValueError("target URL missing (--url or TARGET_APP_URL)")
        if not self.steps or any(s <= 0 for s in self.steps) or self.steps != sorted(set(self.steps)):
            raise ValueError("steps must be distinct positive integers in ascending order")
        if self.sweeps < 1:
            raise ValueError("sweeps must be >= 1")
        if not 0 < self.accept_max_error_rate < 1:
            raise ValueError("accept_max_error_rate must be between 0 and 1")
        bad = [p for p in self.percentiles if p not in HEY_PERCENTILES]
        if bad:
            raise ValueError(f"hey only reports percentiles {', '.join(HEY_PERCENTILES)}; got {bad}")
        if not RUN_ID_RE.match(self.run_id):
            raise ValueError("RUN_ID may contain only letters, digits, '.', '_' and '-'")


def _raise_interrupt(signum, frame):
    raise KeyboardInterrupt


def _sigterm_as_interrupt():
    """Best effort: treat SIGTERM like Ctrl+C where the platform delivers it to Python."""
    try:
        return signal.signal(signal.SIGTERM, _raise_interrupt)
    except (ValueError, OSError, AttributeError):   # not in the main thread / not supported
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
    cfg = Config(parse_args(argv, environ))
    if cfg.dry_run:
        cfg.url = cfg.url or "https://dry-run.invalid/"
        runner = runner or (lambda cmd, timeout: (0, synthetic_hey_output(int(cmd[cmd.index("-c") + 1])), ""))
        sleep = lambda _s: None  # noqa: E731
    elif runner is None:
        if shutil.which(cfg.hey_path) is None:
            print(f"[!] '{cfg.hey_path}' not found; nothing was run.")
            return 2
        runner = subprocess_runner

    print(f"[*] Run ID   : {cfg.run_id}{'  (DRY-RUN: synthetic output, not a measurement)' if cfg.dry_run else ''}")
    print(f"[*] Target   : {cfg.url}")
    print(f"[*] Levels   : {cfg.steps} x {cfg.sweeps} sweeps, {cfg.duration} per run")
    print(f"[*] Success  : HTTP {sorted(cfg.success_statuses)}; accept if every run < {cfg.accept_max_error_rate:.2%}")
    previous = _sigterm_as_interrupt()
    try:
        _, _, manifest = run_benchmark(cfg, runner, sleep=sleep)
    except FileExistsError as exc:
        print(f"[!] {exc}")
        return 2
    finally:
        _restore_sigterm(previous)
    if manifest["status"] == "interrupted":
        print(f"\n[!] Interrupted ({manifest['interruption']}); manifest written with status 'interrupted'. "
              "Not an acceptable capacity result.")
        return 3
    res = manifest["primary_result"]
    print(f"\n[+] Accepted levels: {res['accepted_levels']}")
    print(f"[+] Best median successful RPS under the acceptance condition: {res['best_successful_rps_median']} "
          f"(level {res['best_level']}){'  [non-monotonic]' if res['non_monotonic'] else ''}")
    print(f"[+] Results: {os.path.join(cfg.output_dir, cfg.run_id)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
