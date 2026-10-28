"""Builds a complete SIMULATED input set for 05-results from the modules' own dry-run code paths.

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

Everything is simulated (scripted outputs, simulated clocks); nothing contacts a host or an API.
The simulated wall clocks of all sources start at 2026-01-01T00:00:00Z so that the demo's
cross-source view has overlapping UTC ranges (a property of the simulation, not of real data).
The sadf and k6 raw files are synthetic text in the documented formats.
"""

import contextlib
import glob
import io
import json
import os
from datetime import datetime, timedelta, timezone

from _helpers import load_module

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
RUN = "SIM-ALL-1"


def _quiet(fn, *a, **k):
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return fn(*a, **k)


def sadf_text(host="sim-c1", start=T0, n=90, interval=1, busy=lambda i: 20 + (60 if 15 <= i < 60 else 0)):
    lines = ["# hostname;interval;timestamp;CPU;%usr;%nice;%sys;%iowait;%steal;%irq;%soft;%guest;%gnice;%idle"]
    for i in range(n):
        b = busy(i)
        ts = (start + timedelta(seconds=i * interval)).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines.append(f"{host};{interval};{ts};-1;{b * 0.7:.2f};0.00;{b * 0.2:.2f};1.00;0.50;0.00;"
                     f"{b * 0.1 - 1.5:.2f};0.00;0.00;{100 - b:.2f}")
    return "\n".join(lines) + "\n"


def sadf_mem_text(host="sim-c1", start=T0, n=90, interval=1, used=lambda i: 40 + (15 if 15 <= i < 60 else 0),
                  kbavail=True):
    cols = "kbmemfree;kbavail;kbmemused;%memused;kbbuffers;kbcached;kbcommit;%commit;kbactive;kbinact;kbdirty"
    if not kbavail:
        cols = cols.replace("kbavail;", "")
    lines = [f"# hostname;interval;timestamp;{cols}"]
    total = 4000000
    for i in range(n):
        u = used(i)
        ts = (start + timedelta(seconds=i * interval)).strftime("%Y-%m-%d %H:%M:%S UTC")
        free = int(total * (100 - u) / 100 * 0.5)
        avail = f"{int(total * (100 - u) / 100)};" if kbavail else ""
        lines.append(f"{host};{interval};{ts};{free};{avail}{int(total * u / 100)};{u:.2f};1000;200000;"
                     f"1500000;20.00;900000;300000;12")
    return "\n".join(lines) + "\n"


def _raw_stage(s):
    return "s01_ramp_to_50" if s < 30 else ("s02_hold_50" if s < 60 else "s03_ramp_down")


def k6_raw_text(start=T0, seconds=90, rate=20):
    out = [json.dumps({"type": "Metric", "metric": "request_attempts", "data": {"type": "counter"}})]
    for s in range(seconds):
        for k in range(rate):
            t = (start + timedelta(seconds=s, milliseconds=k * (1000 // rate))).isoformat().replace("+00:00", "Z")
            ok = not (20 <= s < 24 and k % 3 == 0)
            tags = {"stage": _raw_stage(s)}
            out.append(json.dumps({"type": "Point", "metric": "request_attempts",
                                   "data": {"time": t, "value": 1, "tags": tags}}))
            if ok:
                out.append(json.dumps({"type": "Point", "metric": "responses_success",
                                       "data": {"time": t, "value": 1, "tags": tags}}))
                out.append(json.dumps({"type": "Point", "metric": "success_request_chain_duration",
                                       "data": {"time": t, "value": 40 + (s % 10) * 3, "tags": tags}}))
    return "\n".join(out) + "\n"


def k6_stage_results():
    """SIMULATED stage_results block in the k6_summary.js schema (hand-made, not from a k6 run)."""
    spec = [("s01_ramp_to_50", "ramp", 0, 50, 0, 30000, 300, 300, 1, 50, 20, 25),
            ("s02_hold_50", "hold", 50, 50, 30000, 90000, 3000, 2970, 50, 50, 40, 55),
            ("s03_ramp_to_200", "ramp", 50, 200, 90000, 120000, 3500, 3400, 50, 200, 90, 140),
            ("s04_hold_200", "hold", 200, 200, 120000, 180000, 9000, 8100, 200, 200, 250, 400),
            ("s05_ramp_down", "ramp_down", 200, 0, 180000, 210000, 1500, 1450, 1, 200, 120, 200),
            ("after_planned_end", "after_planned_end", 0, 0, 210000, None, 3, 3, 1, 2, 30, 30)]
    stages = []
    for label, kind, frm, tgt, s, e, att, succ, vmin, vmax, p95, p99 in spec:
        hold = kind == "hold"
        stages.append({
            "planned": {"label": label, "kind": kind, "from_vus": frm, "target_vus": tgt, "start_ms": s, "end_ms": e},
            "observed": {"first_request_start_ms": s + 3, "last_request_start_ms": (e or 210400) - 5,
                         "vus_at_request_start_min": vmin, "vus_at_request_start_max": vmax, "complete": True,
                         "complete_reason": "SIMULATED"},
            "counts": {"attempts": att, "success_responses": succ, "transport_errors": 0, "responses_5xx": att - succ},
            "derived": {"primary_error_rate": (att - succ) / att, "err5xx_transport_error_rate": (att - succ) / att,
                        "latency_success_request_chain_ms": {"p(95)": p95, "p(99)": p99},
                        "target_vus_observed": "maintained_at_request_starts" if hold else "not_applicable",
                        "constant_vu_result": hold, "successful_rps": succ / ((e - s) / 1000) if hold else None},
            "null_reasons": {} if hold else {"successful_rps": f"{kind}: the VU count is not constant"}})
    return {"valid": True, "problems": [], "attribution": "request start (SIMULATED)",
            "rate_basis": "successful attempts started in the hold / planned hold duration",
            "completeness_rule": "SIMULATED", "selector_threshold_note": "selector thresholds (SIMULATED)",
            "stages": stages}


def build(root):
    """Creates the simulated outputs under root; returns a dict of the important paths."""
    paths = {}
    # 01 hey dry-run with simulated wall clock aligned to T0
    hey = load_module("01-load-test/run_hey_stepped.py", "fx_hey")
    args = hey.parse_args(["--dry-run", "--steps", "50,150,300", "--sweeps", "3", "--duration", "5s",
                           "--run-id", RUN, "--output-dir", os.path.join(root, "01")], {})
    cfg = hey.Config(args)
    cfg.url = "https://dry-run.invalid/"
    ticks = {"t": 0.0}

    def runner(cmd, timeout):
        ticks["t"] += 5.0
        return 0, hey.synthetic_hey_output(int(cmd[cmd.index("-c") + 1])), ""
    _quiet(hey.run_benchmark, cfg, runner, sleep=lambda s: ticks.__setitem__("t", ticks["t"] + 1.0),
           clock=lambda: ticks["t"], now=lambda: T0 + timedelta(seconds=ticks["t"]))
    paths["hey"] = os.path.join(root, "01", RUN)
    # 01 iperf3 dry-run
    ip = load_module("01-load-test/run_iperf3_comparison.py", "fx_ip")
    _quiet(ip.main, ["--dry-run", "--path", "direct=10.0.1.123", "--path", "sse=app.test.invalid",
                     "--repetitions", "2", "--run-id", RUN, "--output-dir", os.path.join(root, "01")], environ={})
    # 01 k6 summary (synthetic, labelled)
    with open(os.path.join(root, "01", f"k6_{RUN}_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"run_id": RUN, "tool": "k6", "mode": "SIMULATED - NOT A REAL MEASUREMENT", "valid": True,
                   "invalid_reason": "", "derived": {"attempts": 1000, "successful_rps_whole_test": 10.9,
                                                     "primary_error_rate": 0.015, "err5xx_transport_error_rate": 0.01,
                                                     "latency_success_request_chain_ms": {"p(95)": 122.0, "p(99)": 315.0},
                                                     "latency_success_final_hop_ms": {"p(95)": 120.0, "p(99)": 310.0}},
                   "stage_results": k6_stage_results()},
                  f)
    # 01 telemetry metadata + sadf export (synthetic)
    tel = os.path.join(root, "01", "telemetry")
    os.makedirs(tel)
    for role, host, coverage, complete in (("c1", "sim-c1", "full_from_run_start", True),
                                           ("c2", "sim-c2", "partial_late_start", False)):
        with open(os.path.join(tel, f"telemetry_{RUN}_{role}_{host}_meta.json"), "w", encoding="utf-8") as f:
            json.dump({"run_id": RUN, "role": role, "hostname": host, "coverage": coverage,
                       "complete_time_series": complete}, f)
    with open(os.path.join(tel, f"telemetry_{RUN}_c1_sim-c1_cpu_sadf.csv"), "w", encoding="utf-8") as f:
        f.write(sadf_text())
    # memory export starts 20 s late: the first hey runs get partial/missing memory windows (CPU complete)
    with open(os.path.join(tel, f"telemetry_{RUN}_c1_sim-c1_mem_sadf.csv"), "w", encoding="utf-8") as f:
        f.write(sadf_mem_text(start=T0 + timedelta(seconds=20), n=70))
    with open(os.path.join(tel, f"telemetry_{RUN}_c2_sim-c2_cpu_sadf.csv"), "w", encoding="utf-8") as f:
        f.write(sadf_text("sim-c2", T0 + timedelta(seconds=25), 60, busy=lambda i: 15 + (20 if i > 5 else 0)))
    paths["k6_raw"] = os.path.join(root, "01", f"k6_{RUN}_raw.json")
    with open(paths["k6_raw"], "w", encoding="utf-8") as f:
        f.write(k6_raw_text())
    # 02 scaler dry-run (SimClock starts at T0)
    scaler = load_module("02-scaler-poc/scaler_daemon.py", "fx_scaler")
    _quiet(scaler.main, ["--dry-run", "--output-dir", os.path.join(root, "02"), "--max-cycles", "18"], environ={})
    paths["scaler"] = glob.glob(os.path.join(root, "02", "scaler_dryrun_*_timeseries.csv"))[0]
    # 03 failover dry-runs + analysis
    fo = load_module("03-failover/failover_probe.py", "fx_fo")
    for probe in ("tcp", "http", "persistent"):
        _quiet(fo.main, ["run", "--probe", probe, "--run-id", RUN, "--dry-run", "--duration-sec", "60",
                         "--output-dir", os.path.join(root, "03")], environ={})
        _quiet(fo.main, ["analyze", "--probe", probe, "--run-id", RUN, "--output-dir", os.path.join(root, "03")],
               environ={})
    # 04 canary: signature + two repetitions; sync plan
    cb = load_module("04-threat-intel/canary_block_test.py", "fx_cb")
    out4 = os.path.join(root, "04")
    _quiet(cb.main, ["validate-signature", "--run-id", RUN, "--dry-run", "--output-dir", out4], environ={})
    sig = glob.glob(os.path.join(out4, RUN, "signature", "signature_validation.json"))[0]
    for rep, commit in ((1, "after-update"), (2, "none")):
        _quiet(cb.main, ["run", "--run-id", RUN, "--dry-run", "--commit", commit, "--repetition", str(rep),
                         "--signature-file", sig, "--output-dir", out4], environ={})
    feed = os.path.join(root, "feed.csv")
    with open(feed, "w", encoding="utf-8") as f:
        f.write('"2","2026-10-26 10:00:00","http://bad-a.example.invalid/x","online","","","","",""\n'
                '"1","2026-10-26 09:00:00","http://198.51.100.9/z","online","","","","",""\n')
    sync = load_module("04-threat-intel/sync_threat_intel.py", "fx_sync")
    _quiet(sync.main, ["plan", "--run-id", RUN, "--feed-file", feed, "--output-dir", out4], environ={})
    return paths


def reviewed_spec(root, scan_entries, processing_id="SIM-DEMO", time_sync=True):
    """Turns a scan draft into a reviewed SIMULATED spec (what the operator would do by hand)."""
    datasets = []
    for e in scan_entries:
        e = dict(e)
        e["provenance"] = "simulated"
        if e["kind"] == "scaler":
            e["run_id"] = RUN
        datasets.append(e)
    datasets.append({"id": "k6raw-1", "kind": "k6_raw", "path": os.path.join(root, "01", f"k6_{RUN}_raw.json"),
                     "provenance": "simulated"})
    scaler_id = next(d["id"] for d in datasets if d["kind"] == "scaler")
    hey_id = next(d["id"] for d in datasets if d["kind"] == "hey")
    sar_c1 = next(d["id"] for d in datasets if d["kind"] == "sar_cpu" and "sim-c1" in d["path"])
    mem_c1 = next(d["id"] for d in datasets if d["kind"] == "sar_mem")
    spec = {"processing_id": processing_id, "reviewed_by_operator": True, "k6_raw_bin_sec": 1.0,
            "time_sync": {"statement": "SIMULATED sources share one simulated clock starting 2026-01-01T00:00Z",
                          "source": "fixture builder (simulation)", "known_uncertainty": "not applicable (simulated)"}
            if time_sync else None,
            "groups": {"m2": [{"scaler": scaler_id, "app": [hey_id, "k6raw-1"]}],
                       "m1_resources": [{"hey": hey_id, "sar_cpu": sar_c1, "sar_mem": mem_c1, "warmup_sec": 1.0,
                                         "min_coverage": 0.9}]},
            "datasets": datasets}
    return spec
