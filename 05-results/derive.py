#!/usr/bin/env python3
"""
Results: pure computations behind the figures (no I/O, no plotting).

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

Rules applied everywhere
  - Missing or invalid values become NaN (gaps in a curve), never 0.
  - Statuses (acceptance, activation checks, recovery outcomes, run validity, canary outcomes) are
    shown exactly as the measurement module logged them; nothing is re-classified here.
  - Times: within one process the module's monotonic clock (seconds relative to a stated
    reference); UTC only for cross-source views, and only with an operator time-sync statement.
  - No time offset, interpolation or smoothing is applied.
"""

import math
import re
from datetime import datetime, timedelta, timezone

NAN = float("nan")


def num(value):
    if value in (None, ""):
        return NAN
    try:
        return float(value)
    except (TypeError, ValueError):
        return NAN


def parse_utc(text):
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else None   # naive times are not accepted as UTC


def is_nan(x):
    return isinstance(x, float) and math.isnan(x)


# ------------------------------------------------------------------------------
# Measurement 1
# ------------------------------------------------------------------------------

def hey_points(runs):
    """One row per measurement run; invalid runs keep NaN metrics."""
    out = []
    for r in runs:
        valid = r.get("valid") == "True"
        out.append({"concurrency": int(r["concurrency"]), "sweep": int(r["sweep"]), "valid": valid,
                    "successful_rps": num(r.get("successful_rps")) if valid else NAN,
                    "primary_error_rate": num(r.get("primary_error_rate")) if valid else NAN,
                    "err5xx_transport_error_rate": num(r.get("err5xx_transport_error_rate")) if valid else NAN,
                    "lat_all_responses_p95_ms": num(r.get("lat_all_responses_p95_ms")) if valid else NAN,
                    "lat_all_responses_p99_ms": num(r.get("lat_all_responses_p99_ms")) if valid else NAN,
                    "invalid_reason": r.get("invalid_reason", "")})
    return sorted(out, key=lambda p: (p["concurrency"], p["sweep"]))


def hey_levels(levels, manifest):
    best = (manifest.get("primary_result") or {}).get("best_level")
    out = []
    for lv in levels:
        c = int(lv["concurrency"])
        out.append({"concurrency": c, "status": lv.get("status", ""),
                    "successful_rps_median": num(lv.get("successful_rps_median")),
                    "primary_error_rate_max_run": num(lv.get("primary_error_rate_max_run")),
                    "lat_all_responses_p95_ms_median": num(lv.get("lat_all_responses_p95_ms_median_of_runs")),
                    "lat_all_responses_p99_ms_median": num(lv.get("lat_all_responses_p99_ms_median_of_runs")),
                    "best_accepted_level": c == best})
    return sorted(out, key=lambda x: x["concurrency"])


def hey_meta(manifest):
    cfg = manifest.get("config") or {}
    res = manifest.get("primary_result") or {}
    return {"accept_max_error_rate": cfg.get("accept_max_error_rate"), "best_level": res.get("best_level"),
            "non_monotonic": res.get("non_monotonic"), "percentiles": cfg.get("percentiles") or []}


def k6_rows(summary):
    d = summary.get("derived") or {}
    lat = d.get("latency_success_request_chain_ms") or {}
    final = d.get("latency_success_final_hop_ms") or {}
    return [{"run_id": summary.get("run_id"), "valid": bool(summary.get("valid")),
             "invalid_reason": summary.get("invalid_reason", ""), "attempts": d.get("attempts"),
             "successful_rps_whole_test": d.get("successful_rps_whole_test", NAN) if d else NAN,
             "primary_error_rate": d.get("primary_error_rate", NAN) if d else NAN,
             "err5xx_transport_error_rate": d.get("err5xx_transport_error_rate", NAN) if d else NAN,
             "chain_p95_ms": lat.get("p(95)", NAN), "chain_p99_ms": lat.get("p(99)", NAN),
             "final_hop_p95_ms": final.get("p(95)", NAN), "final_hop_p99_ms": final.get("p(99)", NAN)}]


def k6_stage_rows(summary):
    """One row per planned stage (plus after_planned_end) from summary.stage_results; planned times,
    observed evidence and derived values stay in separate columns; nulls keep their reasons."""
    sr = summary.get("stage_results") or {}
    out = []
    for st in sr.get("stages") or []:
        pl, ob, co, de = st["planned"], st["observed"], st["counts"], st["derived"]
        lat = de.get("latency_success_request_chain_ms") or {}
        out.append({"run_id": summary.get("run_id"), "stage": pl["label"], "kind": pl["kind"],
                    "target_vus": pl.get("target_vus"), "planned_start_ms": pl.get("start_ms"),
                    "planned_end_ms": pl.get("end_ms"), "observed_first_request_start_ms": ob.get("first_request_start_ms"),
                    "observed_last_request_start_ms": ob.get("last_request_start_ms"),
                    "observed_vus_min": ob.get("vus_at_request_start_min"),
                    "observed_vus_max": ob.get("vus_at_request_start_max"), "complete": ob.get("complete"),
                    "complete_reason": ob.get("complete_reason"), "attempts": co.get("attempts"),
                    "success_responses": co.get("success_responses"),
                    "primary_error_rate": NAN if de.get("primary_error_rate") is None else de["primary_error_rate"],
                    "successful_rps": NAN if de.get("successful_rps") is None else de["successful_rps"],
                    "chain_p95_ms": lat.get("p(95)", NAN), "chain_p99_ms": lat.get("p(99)", NAN),
                    "target_vus_observed": de.get("target_vus_observed"),
                    "constant_vu_result": bool(de.get("constant_vu_result")),
                    "stage_results_valid": bool(sr.get("valid")),
                    "null_reasons": "; ".join(f"{k}: {v}" for k, v in sorted((st.get("null_reasons") or {}).items()))})
    return out


def iperf3_rows(runs):
    return [{"path_label": r["path_label"], "path_verification": r["path_verification"], "round": int(r["round"]),
             "valid": r.get("valid") == "True",
             "received_mbps": num(r.get("received_mbps")) if r.get("valid") == "True" else NAN,
             "sender_tcp_retransmits": num(r.get("sender_tcp_retransmits")) if r.get("valid") == "True" else NAN}
            for r in runs]


def hey_intervals(runs):
    """Each hey run as an interval [started_utc, ended_utc] with its aggregate values (not a curve)."""
    out = []
    for r in runs:
        s, e = parse_utc(r.get("started_utc")), parse_utc(r.get("ended_utc"))
        if not s or not e:
            continue
        valid = r.get("valid") == "True"
        out.append({"start_utc": s, "end_utc": e, "concurrency": int(r["concurrency"]), "sweep": int(r["sweep"]),
                    "valid": valid, "successful_rps": num(r.get("successful_rps")) if valid else NAN,
                    "primary_error_rate": num(r.get("primary_error_rate")) if valid else NAN})
    return out


# ------------------------------------------------------------------------------
# Measurement 1: connector resources per hey workload interval
# ------------------------------------------------------------------------------
# Window of a hey run: [started_utc + warmup_sec, ended_utc] as logged by run_hey_stepped.py (load
# generator clock); comparing it with sar timestamps (connector VM clock) needs spec.time_sync.
# CPU: a record counts only if its whole averaging interval [t - interval, t] lies inside the window;
#      a record overlapping the previous counted record is excluded (cpu_overlap_excluded), so the
#      covered time is a sum of disjoint intervals: cpu_coverage = covered seconds / window seconds <= 1.
# Memory: instantaneous readings at t inside the window; the window is split into slots of the
#      sampling interval and only the first reading per slot counts (mem_extra_excluded), so
#      mem_coverage = filled slots / slots <= 1.
# Status per resource: complete (coverage >= min_coverage), partial (some samples), missing (none),
#      no_window (no UTC times or nothing left after the warm-up), not_provided (no dataset).
# Level aggregate (primary): only runs with a valid hey result AND a complete resource window; partial
#      or missing windows are kept in the per-run table and counted, never mixed into the median.
# Correlation only: the same window shows load and resource use; no bottleneck is inferred.

RESOURCE_STATUS_RULE = ("complete: coverage >= min_coverage; partial: some samples; missing: none; "
                        "level medians use only hey-valid runs with a complete window")
CPU_STATS = ("cpu_not_idle_pct", "cpu_busy_excl_iowait_pct")
CPU_COMPONENT_MEANS = ("usr_pct", "sys_pct", "iowait_pct", "steal_pct", "irq_pct", "soft_pct")


def _pctl(values, q):
    """Nearest-rank percentile; NaN for no values."""
    if not values:
        return NAN
    v = sorted(values)
    return v[min(len(v) - 1, max(0, math.ceil(q * len(v)) - 1))]


def _mean(values):
    return sum(values) / len(values) if values else NAN


def _median(values):
    v = sorted(x for x in values if not is_nan(x))
    if not v:
        return NAN
    mid = len(v) // 2
    return v[mid] if len(v) % 2 else (v[mid - 1] + v[mid]) / 2


def _status(n, coverage, min_coverage):
    if n == 0:
        return "missing"
    return "complete" if coverage >= min_coverage else "partial"


def resource_windows(runs, warmup_sec):
    """One aggregation window per hey run (see the rules above)."""
    out = []
    for r in runs:
        s, e = parse_utc(r.get("started_utc")), parse_utc(r.get("ended_utc"))
        valid = r.get("valid") == "True"
        w = {"concurrency": int(r["concurrency"]), "sweep": int(r["sweep"]), "hey_valid": valid,
             "successful_rps": num(r.get("successful_rps")) if valid else NAN,
             "run_started_utc": s, "run_ended_utc": e, "warmup_sec": warmup_sec,
             "window_start_utc": None, "window_end_utc": None, "window_sec": NAN}
        if not s or not e:
            w["window_state"] = "no_utc_times"
        else:
            start = s + timedelta(seconds=warmup_sec)
            span = (e - start).total_seconds()
            w.update({"window_start_utc": start, "window_end_utc": e, "window_sec": span,
                      "window_state": "ok" if span > 0 else "empty_after_warmup"})
        out.append(w)
    return out


def cpu_window(rows, start, end, min_coverage):
    used, overlap, last_end = [], 0, None
    for r in rows:
        t1 = r["utc"]
        t0 = t1 - timedelta(seconds=r["interval_sec"])
        if t0 < start or t1 > end:
            continue
        if last_end is not None and t0 < last_end:
            overlap += 1
            continue
        used.append(r)
        last_end = t1
    covered = float(sum(r["interval_sec"] for r in used))
    coverage = covered / (end - start).total_seconds()
    out = {"cpu_samples": len(used), "cpu_overlap_excluded": overlap, "cpu_covered_sec": covered,
           "cpu_coverage": round(coverage, 4), "cpu_status": _status(len(used), coverage, min_coverage)}
    for key in CPU_STATS:
        vals = [r[key] for r in used]
        out.update({f"{key}_mean": _mean(vals), f"{key}_p95": _pctl(vals, 0.95), f"{key}_max": max(vals) if vals else NAN})
    for comp in CPU_COMPONENT_MEANS:
        vals = [r[comp] for r in used]
        out[f"{comp}_mean"] = NAN if any(is_nan(v) for v in vals) else _mean(vals)   # absent in the -u set
    return out


def mem_window(rows, start, end, interval, min_coverage):
    span = (end - start).total_seconds()
    slots = max(1, math.ceil(span / interval - 1e-9))
    used, filled, extra = [], set(), 0
    for r in rows:
        if not start <= r["utc"] <= end:
            continue
        slot = min(slots - 1, int((r["utc"] - start).total_seconds() // interval))
        if slot in filled:
            extra += 1
            continue
        filled.add(slot)
        used.append(r)
    coverage = len(filled) / slots
    used_pct = [r["mem_used_pct"] for r in used]
    avail = [r["mem_available_kb"] for r in used if not is_nan(r["mem_available_kb"])]
    return {"mem_samples": len(used), "mem_extra_excluded": extra, "mem_slots": slots,
            "mem_coverage": round(coverage, 4), "mem_status": _status(len(used), coverage, min_coverage),
            "mem_used_pct_mean": _mean(used_pct), "mem_used_pct_max": max(used_pct) if used_pct else NAN,
            "mem_available_kb_min": min(avail) if avail and len(avail) == len(used) else NAN,
            "mem_available_kb_mean": _mean(avail) if avail and len(avail) == len(used) else NAN}


def resources_by_run(windows, cpu_data, mem_data, min_coverage):
    """Per-run rows; mem_data may be None (memory then 'not_provided')."""
    mem_interval = None
    if mem_data is not None:
        ivs = mem_data.get("interval_sec") or []
        mem_interval = ivs[0] if len(ivs) == 1 else None
    out = []
    for w in windows:
        row = dict(w, min_coverage=min_coverage)
        if w["window_state"] != "ok":
            row.update({"cpu_status": "no_window", "mem_status": "no_window" if mem_data is not None else "not_provided"})
            out.append(row)
            continue
        row.update(cpu_window(cpu_data["rows"], w["window_start_utc"], w["window_end_utc"], min_coverage))
        if mem_data is None:
            row["mem_status"] = "not_provided"
        elif mem_interval is None:
            row["mem_status"] = "mixed_or_unknown_interval"
        else:
            row.update(mem_window(mem_data["rows"], w["window_start_utc"], w["window_end_utc"], mem_interval,
                                  min_coverage))
        out.append(row)
    return out


def resources_by_level(run_rows):
    """Primary aggregate per concurrency level (complete windows of hey-valid runs only)."""
    out = []
    for c in sorted({r["concurrency"] for r in run_rows}):
        rs = [r for r in run_rows if r["concurrency"] == c]
        valid = [r for r in rs if r["hey_valid"]]
        lv = {"concurrency": c, "runs_total": len(rs), "runs_hey_invalid": len(rs) - len(valid)}
        for res in ("cpu", "mem"):
            ok = [r for r in valid if r.get(f"{res}_status") == "complete"]
            lv[f"{res}_runs_used"] = len(ok)
            lv[f"{res}_runs_partial"] = sum(r.get(f"{res}_status") == "partial" for r in valid)
            lv[f"{res}_runs_missing_or_no_window"] = sum(r.get(f"{res}_status") in ("missing", "no_window",
                                                                                    "mixed_or_unknown_interval")
                                                         for r in valid)
            lv[f"{res}_runs_not_provided"] = sum(r.get(f"{res}_status") == "not_provided" for r in valid)
            if res == "cpu":
                for key in CPU_STATS:
                    means = [r[f"{key}_mean"] for r in ok]
                    lv[f"{key}_mean_median"] = _median(means)
                    lv[f"{key}_mean_min"] = min(means) if means else NAN
                    lv[f"{key}_mean_max"] = max(means) if means else NAN
                    lv[f"{key}_p95_median"] = _median([r[f"{key}_p95"] for r in ok])
                for comp in CPU_COMPONENT_MEANS:
                    lv[f"{comp}_mean_median"] = _median([r[f"{comp}_mean"] for r in ok])
                lv["successful_rps_median_cpu_runs"] = _median([r["successful_rps"] for r in ok])
            else:
                lv["mem_used_pct_mean_median"] = _median([r["mem_used_pct_mean"] for r in ok])
                lv["mem_used_pct_max_max"] = max((r["mem_used_pct_max"] for r in ok), default=NAN)
                lv["mem_available_kb_min_min"] = min((r["mem_available_kb_min"] for r in ok
                                                      if not is_nan(r["mem_available_kb_min"])), default=NAN)
        out.append(lv)
    return out


def window_description(warmup_sec):
    return ("whole hey run interval" if warmup_sec == 0
            else f"hey run interval excluding an explicitly configured warm-up of the first {warmup_sec:g} s")


# ------------------------------------------------------------------------------
# Measurement 2
# ------------------------------------------------------------------------------

def scaler_series(rows):
    """CPU per cycle on the scaler's monotonic clock (C1 at its sample end time; C2 at its sample end
    time when it was sampled). Empty values stay NaN."""
    out = []
    for r in rows:
        out.append({"cycle_start_s": num(r.get("monotonic_s")), "utc": parse_utc(r.get("timestamp_utc")),
                    "c1_t_s": num(r.get("c1_sample_end_s")), "c1_cpu_pct": num(r.get("c1_cpu_pct")),
                    "c2_t_s": num(r.get("c2_sample_end_s")), "c2_cpu_pct": num(r.get("c2_cpu_pct")),
                    "c2_power_state": r.get("c2_power_state", ""), "decision_s": num(r.get("decision_s")),
                    "application_reachable": r.get("application_reachable", ""),
                    "power_on_in_progress": r.get("power_on_in_progress", "")})
    return out


def scaler_events(events):
    return [{"t_s": num(e.get("monotonic_s")), "utc": parse_utc(e.get("timestamp_utc")), "event": e.get("event", ""),
             "detail": e.get("detail", "")} for e in events]


def logged_threshold(events):
    """Scale-out threshold as logged in a THRESHOLD_MET detail (evidence), else None."""
    for e in events:
        if e.get("event") == "THRESHOLD_MET":
            m = re.search(r">=\s*([0-9.]+)%", e.get("detail", ""))
            if m:
                return float(m.group(1))
    return None


def activation_checks(events):
    """Per activation (closed by ACTIVATION_SUMMARY): the logged check statuses, verbatim."""
    activations, current = [], []
    for e in events:
        if e.get("event") == "ACTIVATION_CHECK":
            fields = dict(part.split("=", 1) for part in e["detail"].split("; ")[:2] if "=" in part)
            current.append({"check": fields.get("check", "?"), "status": fields.get("status", "?"),
                            "detail": "; ".join(e["detail"].split("; ")[2:]), "t_s": num(e.get("monotonic_s"))})
        elif e.get("event") == "ACTIVATION_SUMMARY":
            reason = re.match(r"reason=([^;]*)", e.get("detail", ""))
            activations.append({"close_t_s": num(e.get("monotonic_s")), "reason": reason.group(1) if reason else "",
                                "checks": current})
            current = []
    return activations


def sar_series(sar_data, ref_utc=None):
    rows = sar_data.get("rows") or []
    ref = ref_utc or (rows[0]["utc"] if rows else None)
    return [{"utc": r["utc"], "t_rel_s": (r["utc"] - ref).total_seconds() if ref else NAN,
             "cpu_not_idle_pct": r["cpu_not_idle_pct"], "cpu_busy_excl_iowait_pct": r["cpu_busy_excl_iowait_pct"],
             "iowait_pct": r["iowait_pct"], "steal_pct": r["steal_pct"]} for r in rows]


def time_sync_statement(spec_time_sync):
    """(allowed, footnote_or_reason). A cross-machine UTC overlay needs an operator statement with its
    source and known uncertainty; the processor does not verify its accuracy."""
    ts = spec_time_sync or {}
    missing = [k for k in ("statement", "source", "known_uncertainty") if not str(ts.get(k, "")).strip()]
    if missing:
        return False, f"cross-machine UTC alignment not declared (missing {missing} in spec.time_sync)"
    return True, (f"UTC alignment by operator statement (not verified by the processor): {ts['statement']}; "
                  f"source: {ts['source']}; known uncertainty: {ts['known_uncertainty']}")


# ------------------------------------------------------------------------------
# Measurement 3
# ------------------------------------------------------------------------------

def failover_series(records, ref_mono):
    out = []
    for r in records:
        if r.get("event") not in ("probe", "exchange", "connect", "end"):
            continue
        s, e = num(r.get("start_mono_s")), num(r.get("end_mono_s"))
        out.append({"seq": int(r["seq"]), "event": r.get("event"), "t_s": s - ref_mono, "end_t_s": e - ref_mono,
                    "duration_ms": (e - s) * 1000.0, "ok": r.get("ok") == "True",
                    "error_class": r.get("error_class", "")})
    return out


def failover_states(analysis, ref_mono, probe):
    """Logged outcome/validity/recovery times of 03's analysis, verbatim (times made relative)."""
    if not analysis:
        return None

    def rel(ref, key):
        return None if not ref else ref[key] - ref_mono

    if probe == "persistent":
        return {"continuity": analysis.get("continuity"), "end_reason": analysis.get("end_reason"),
                "end_cause": analysis.get("end_cause"), "run_validity": analysis.get("run_validity"),
                "validity_reasons": analysis.get("validity_reasons", []),
                "end_t_s": None if analysis.get("end_mono_s") is None else analysis["end_mono_s"] - ref_mono,
                "markers": [m["monotonic_s"] - ref_mono for m in analysis.get("markers_used", [])]
                if analysis.get("markers_used") else []}
    rec = analysis.get("recovery") or {}
    return {"outcome": rec.get("outcome") if rec else "not_evaluated (no usable fault marker)",
            "run_validity": analysis.get("run_validity"), "validity_reasons": analysis.get("validity_reasons", []),
            "first_failure_t_s": rel(rec.get("first_failure"), "start_mono_s"),
            "first_success_t_s": rel(rec.get("first_success"), "end_mono_s"),
            "stable_first_success_t_s": rel(rec.get("stable_first_success"), "start_mono_s"),
            "stable_confirmed_t_s": rel(rec.get("stable_confirmed"), "end_mono_s"),
            "markers": [{"kind": m.get("kind"), "t_s": m["monotonic_s"] - ref_mono}
                        for m in analysis.get("markers_used", [])],
            "markers_rejected": analysis.get("markers_rejected", [])}


def markers_from_rows(rows):
    """markers.csv rows -> marker dicts in the shape used by 03's select_markers()."""
    out = []
    for r in rows:
        est = r.get("boot_epoch_estimate")
        out.append({"run_id": r.get("run_id"), "kind": r.get("kind"), "utc": r.get("utc", ""),
                    "monotonic_s": num(r.get("monotonic_s")),
                    "clock_domain": {"host": r.get("host"), "system": r.get("system"), "boot_id": r.get("boot_id", ""),
                                     "boot_epoch_estimate": num(est) if est else None,
                                     "simulated": r.get("simulated") == "True"}})
    return out


def outage_spans(outages, ref_mono):
    return [{"index": int(o["outage_index"]), "start_t_s": num(o["first_failure_start_mono_s"]) - ref_mono,
             "end_t_s": num(o["last_failure_end_mono_s"]) - ref_mono, "failed_probes": int(o["failed_probes"]),
             "isolated": o.get("isolated_failure") == "True", "failure_span_ms": num(o.get("failure_span_ms")),
             "bracket_interval_ms": num(o.get("bracket_interval_ms")),
             "bracket_interval_reason": o.get("bracket_interval_reason", "")} for o in outages]


# ------------------------------------------------------------------------------
# Measurement 4
# ------------------------------------------------------------------------------

def canary_series(probes, ref_mono):
    return [{"seq": int(p["seq"]), "t_s": num(p["start_mono_s"]) - ref_mono,
             "end_t_s": num(p["end_mono_s"]) - ref_mono, "class": p.get("class", ""), "phase": p.get("phase", "")}
            for p in probes]


def canary_events(events, ref_mono):
    return [{"event": e["event"], "t_s": num(e["mono_s"]) - ref_mono, "utc": e.get("utc", ""),
             "detail": e.get("detail", "")} for e in events]


def canary_latency_rows(datasets):
    """One row per (canary run, reference event); signed values as logged (negative kept)."""
    rows = []
    for ds in datasets:
        s = ds.data["summary"]
        for ref, values in sorted((s.get("observed_blocking_latency_ms") or {}).items()):
            rows.append({"run_id": ds.run_id, "attempt": ds.attempt, "repetition": ds.repetition,
                         "reference": ref, "outcome": s.get("outcome"), "run_validity": s.get("run_validity"),
                         **{k: (NAN if v is None else v) for k, v in values.items()}})
    return rows


def sync_rows(datasets):
    rows = []
    for ds in datasets:
        ind, res, man = ds.data["indicators"], ds.data["result"], ds.data["manifest"]
        rows.append({"run_id": ds.run_id, "command": man.get("command"), "attempt": ds.attempt,
                     "state": res.get("state"), "hosts": len(ind.get("hosts") or []),
                     "ip_indicators_saved_only": len(ind.get("ip_indicators") or []),
                     "excluded": len(ind.get("excluded") or []), "rejected": len(ind.get("rejected") or []),
                     "write_outcome": (res.get("write") or {}).get("outcome", ""),
                     "commit_outcome": (res.get("commit") or {}).get("outcome", "")})
    return rows


def duplicate_repetitions(datasets):
    """(run_id, repetition) pairs used by more than one canary dataset."""
    seen, dup = {}, set()
    for ds in datasets:
        key = (ds.run_id, ds.repetition)
        if key in seen:
            dup.add(key)
        seen[key] = ds
    return sorted(dup)
