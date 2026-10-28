#!/usr/bin/env python3
"""
Pillar 3: offline evaluation of failover probe records (pure functions, no I/O).

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

Input records come from failover_probe.py (one probe type per process, shared RUN_ID). Every
record of a new-connection probe (tcp, http) has: seq, start_mono_s, end_mono_s, start_utc,
end_utc, ok, error_class. Times are compared on the monotonic clock of the measuring host; UTC is
kept for reference only.

Outage
  A maximal run of consecutive failed probes. A run of exactly one failed probe is flagged
  isolated_failure (it is still listed).
  failure_span_ms      = end of the last failed probe - start of the first failed probe
  bracket_interval_ms  = start of the first successful probe after the outage
                         - end of the last successful probe before it
  Both are observations derived from probe START/END times (formulas above). They depend on the
  probe interval, the probe timeouts and DNS/TLS work inside each probe; they are NOT proven
  lower/upper limits of the real interruption and NOT an internal tunnel convergence time.
  If there is no successful probe before (or after) the outage, bracket_interval_ms is empty and
  bracket_interval_reason says why.

Recovery after the fault marker
  first failure after the marker -> first success after that failure -> stable recovery:
    stable_first_success  start of the first probe of the first run of N consecutive successes
    stable_confirmed      end of the N-th success of that run, i.e. the moment stability could
                          actually be confirmed
  Outcomes: no_outage_observed, recovered_stable, recovered_unstable (successes, but no run of N
  until the end of the data), not_recovered (the data ends with failures).
  Marker-relative times are (probe time - marker monotonic time); the formula used is named in
  each field. The marker is an operator_signal: it is when the operator says the fault was
  injected, not proof of when the network failure actually happened.

Baseline rule (explicit; evaluated on the BASELINE_SEC immediately before the fault marker)
  1. coverage: the earliest probe starts no later than marker - BASELINE_SEC + MAX_GAP
  2. continuity: no gap > MAX_GAP between consecutive probe starts in the window, nor between the
     last probe start and the marker
  3. success: at most BASELINE_MAX_FAILURES failed probes in the window (default 0)
  A failed or incomplete baseline makes the run "not_valid" for the failover evaluation.

Markers are used only if their run_id equals the run and their clock domain (host, OS, boot)
equals the probe process's; otherwise they are rejected with a reason, never silently aligned.
"""

import statistics

OUTCOME_NO_OUTAGE = "no_outage_observed"
OUTCOME_STABLE = "recovered_stable"
OUTCOME_UNSTABLE = "recovered_unstable"
OUTCOME_NOT_RECOVERED = "not_recovered"

OPERATOR_SIGNAL = "operator_signal"
FAULT_INJECTED = "fault_injected"
FAULT_CLEARED = "fault_cleared"

DEFAULTS = {"recovery_n": 10, "baseline_sec": 30.0, "baseline_max_failures": 0, "baseline_max_gap_sec": 1.0,
            "boot_tolerance_sec": 2.0}


def _ms(seconds):
    return None if seconds is None else round(seconds * 1000.0, 3)


def _probe_ref(r):
    return None if r is None else {"seq": r["seq"], "start_mono_s": r["start_mono_s"], "end_mono_s": r["end_mono_s"],
                                   "start_utc": r.get("start_utc", ""), "end_utc": r.get("end_utc", "")}


# ------------------------------------------------------------------------------
# Clock domains and markers
# ------------------------------------------------------------------------------

def clock_domains_match(a, b, boot_tolerance_sec=DEFAULTS["boot_tolerance_sec"]):
    """(match, reason). Same host and OS, and the same boot: boot_id if both have one,
    otherwise the boot time estimate (UTC - monotonic) within the tolerance."""
    if not a or not b:
        return False, "clock domain missing"
    if a.get("simulated") or b.get("simulated"):
        return (bool(a.get("simulated")) == bool(b.get("simulated")) and a.get("host") == b.get("host"),
                "simulated clock domain")
    if (a.get("host"), a.get("system")) != (b.get("host"), b.get("system")):
        return False, f"different host/OS: {a.get('host')}/{a.get('system')} vs {b.get('host')}/{b.get('system')}"
    if a.get("boot_id") and b.get("boot_id"):
        return (a["boot_id"] == b["boot_id"]), ("same boot_id" if a["boot_id"] == b["boot_id"] else "different boot_id")
    ea, eb = a.get("boot_epoch_estimate"), b.get("boot_epoch_estimate")
    if ea is None or eb is None:
        return False, "no boot identification"
    diff = abs(float(ea) - float(eb))
    if diff > boot_tolerance_sec:
        return False, f"boot time estimates differ by {diff:.3f}s (> {boot_tolerance_sec}s): other boot or clock step"
    return True, f"boot time estimates within {diff:.3f}s"


def select_markers(markers, run_id, probe_domain, boot_tolerance_sec=DEFAULTS["boot_tolerance_sec"]):
    """Splits markers into (usable, rejected[{marker, reason}])."""
    usable, rejected = [], []
    for m in markers:
        if m.get("run_id") != run_id:
            rejected.append({"marker": m, "reason": f"run_id {m.get('run_id')!r} != {run_id!r}"})
            continue
        ok, reason = clock_domains_match(m.get("clock_domain"), probe_domain, boot_tolerance_sec)
        if not ok:
            rejected.append({"marker": m, "reason": f"clock domain mismatch: {reason}"})
            continue
        usable.append(m)
    return sorted(usable, key=lambda m: m["monotonic_s"]), rejected


# ------------------------------------------------------------------------------
# New-connection probes (tcp, http)
# ------------------------------------------------------------------------------

def find_outages(records):
    """Maximal runs of failed probes, in seq order."""
    out = []
    i, n = 0, len(records)
    while i < n:
        if records[i]["ok"]:
            i += 1
            continue
        j = i
        while j + 1 < n and not records[j + 1]["ok"]:
            j += 1
        first, last = records[i], records[j]
        prev = records[i - 1] if i > 0 else None
        nxt = records[j + 1] if j + 1 < n else None
        classes = {}
        for r in records[i:j + 1]:
            classes[r.get("error_class") or "unknown"] = classes.get(r.get("error_class") or "unknown", 0) + 1
        if prev is None and nxt is None:
            reason = "no successful probe before and after the outage"
        elif prev is None:
            reason = "no successful probe before the outage"
        elif nxt is None:
            reason = "no successful probe after the outage (data ends with failures)"
        else:
            reason = ""
        out.append({
            "outage_index": len(out) + 1,
            "first_index": i, "last_index": j,
            "first_failed_seq": first["seq"], "last_failed_seq": last["seq"],
            "failed_probes": j - i + 1,
            "isolated_failure": i == j,
            "error_classes": classes,
            "first_failure_start_mono_s": first["start_mono_s"],
            "last_failure_end_mono_s": last["end_mono_s"],
            "failure_span_ms": _ms(last["end_mono_s"] - first["start_mono_s"]),
            "failure_span_formula": "last failed probe end - first failed probe start",
            "prev_success": _probe_ref(prev),
            "next_success": _probe_ref(nxt),
            "bracket_interval_ms": None if reason else _ms(nxt["start_mono_s"] - prev["end_mono_s"]),
            "bracket_interval_formula": "first success after start - last success before end",
            "bracket_interval_reason": reason,
        })
        i = j + 1
    return out


def stable_run(records, from_index, n):
    """(first, confirming) records of the first run of n consecutive successes from from_index."""
    streak = 0
    for k in range(from_index, len(records)):
        if records[k]["ok"]:
            streak += 1
            if streak == n:
                return records[k - n + 1], records[k]
        else:
            streak = 0
    return None, None


def evaluate_baseline(records, fault_t, baseline_sec, max_failures, max_gap_sec):
    window_start = fault_t - baseline_sec
    window = [r for r in records if window_start <= r["start_mono_s"] < fault_t]
    reasons = []
    earliest = records[0]["start_mono_s"] if records else None
    if earliest is None or earliest > window_start + max_gap_sec:
        reasons.append(f"coverage: probes start {('%.3f' % (earliest - window_start)) if earliest is not None else 'never'}"
                       f"s after the baseline window start (max {max_gap_sec}s)")
    starts = [r["start_mono_s"] for r in window]
    gaps = [b - a for a, b in zip(starts, starts[1:])] + ([fault_t - starts[-1]] if starts else [])
    max_gap = max(gaps) if gaps else None
    if not window:
        reasons.append("no probe in the baseline window")
    elif max_gap > max_gap_sec:
        reasons.append(f"continuity: gap of {max_gap:.3f}s between probe starts (max {max_gap_sec}s)")
    failures = sum(1 for r in window if not r["ok"])
    if failures > max_failures:
        reasons.append(f"success: {failures} failed probe(s) in the baseline window (max {max_failures})")
    status = "ok" if not reasons else ("incomplete" if any(x.startswith(("coverage", "no probe", "continuity"))
                                                          for x in reasons) else "failed")
    return {"status": status, "reasons": reasons, "window_start_mono_s": window_start, "window_end_mono_s": fault_t,
            "probes": len(window), "failed_probes": failures,
            "max_gap_ms": _ms(max_gap) if max_gap is not None else None,
            "rule": f"last {baseline_sec}s before the fault marker: coverage and gaps <= {max_gap_sec}s, "
                    f"failed probes <= {max_failures}"}


def scheduling_stats(records, target_interval_sec):
    starts = [r["start_mono_s"] for r in records]
    intervals = [b - a for a, b in zip(starts, starts[1:])]
    if not intervals:
        return {"target_interval_ms": _ms(target_interval_sec), "actual_interval_ms": None}
    q = sorted(intervals)
    p95 = q[min(len(q) - 1, int(round(0.95 * (len(q) - 1))))]
    return {"target_interval_ms": _ms(target_interval_sec),
            "actual_interval_ms": {"p50": _ms(statistics.median(q)), "p95": _ms(p95), "max": _ms(q[-1])},
            "skipped_slots_total": sum(int(r.get("skipped_slots") or 0) for r in records),
            "note": "the target interval is not a guaranteed resolution; a failing probe lasts up to its timeout"}


def analyze_new_connection(records, markers, run_id, probe_domain, target_interval_sec, **options):
    """Summary of one tcp/http probe file. Returns (summary, outages)."""
    opt = dict(DEFAULTS, **options)
    records = sorted(records, key=lambda r: r["seq"])
    outages = find_outages(records)
    usable, rejected = select_markers(markers, run_id, probe_domain, opt["boot_tolerance_sec"])
    faults = [m for m in usable if m.get("kind") == FAULT_INJECTED]
    total = len(records)
    summary = {
        "run_id": run_id,
        "probes": total,
        "failed_probes": sum(1 for r in records if not r["ok"]),
        "failed_probe_ratio": round(sum(1 for r in records if not r["ok"]) / total, 6) if total else None,
        "failed_probe_ratio_note": "share of failed probe attempts; not packet loss",
        "outages": len(outages),
        "isolated_failures": sum(1 for o in outages if o["isolated_failure"]),
        "scheduling": scheduling_stats(records, target_interval_sec),
        "markers_used": [{"kind": m.get("kind"), "monotonic_s": m["monotonic_s"], "utc": m.get("utc", "")}
                         for m in usable],
        "markers_rejected": [{"kind": r["marker"].get("kind"), "reason": r["reason"]} for r in rejected],
        "marker_source": OPERATOR_SIGNAL,
        "marker_note": "the marker is the operator's signal, not proof of when the network failure happened",
        "time_basis": "monotonic clock of the measuring host; UTC kept for reference",
        "recovery_n": opt["recovery_n"],
    }
    reasons = []
    if not faults:
        reasons.append("no usable fault_injected marker" + (" (markers were rejected)" if rejected else ""))
        summary.update({"baseline": None, "recovery": None})
    else:
        if len(faults) > 1:
            reasons.append(f"{len(faults)} fault_injected markers; only the first is evaluated")
        fault_t = faults[0]["monotonic_s"]
        baseline = evaluate_baseline(records, fault_t, opt["baseline_sec"], opt["baseline_max_failures"],
                                     opt["baseline_max_gap_sec"])
        summary["baseline"] = baseline
        if baseline["status"] != "ok":
            reasons.append(f"baseline {baseline['status']}: " + "; ".join(baseline["reasons"]))
        summary["recovery"] = recovery_after(records, fault_t, opt["recovery_n"])
        if summary["recovery"]["outcome"] == OUTCOME_NO_OUTAGE:
            reasons.append("no outage observed after the fault marker")
        summary["outages_before_marker"] = sum(1 for o in outages if o["first_failure_start_mono_s"] < fault_t)
    summary["run_validity"] = "valid" if not reasons else "not_valid"
    summary["validity_reasons"] = reasons
    return summary, outages


def recovery_after(records, fault_t, n):
    idx_fail = next((i for i, r in enumerate(records) if r["start_mono_s"] >= fault_t and not r["ok"]), None)
    result = {"outcome": OUTCOME_NO_OUTAGE, "first_failure": None, "first_success": None,
              "stable_first_success": None, "stable_confirmed": None, "outages_until_stable": 0,
              "outages_after_stable": None,
              "marker_relative_ms": {}, "formulas": {
                  "first_failure_ms": "first failed probe start - marker",
                  "first_success_ms": "first successful probe end - marker",
                  "stable_first_success_ms": "start of the first of N consecutive successes - marker",
                  "stable_confirmed_ms": "end of the N-th consecutive success - marker"}}
    if idx_fail is None:
        return result
    first_fail = records[idx_fail]
    result["first_failure"] = _probe_ref(first_fail)
    idx_ok = next((i for i in range(idx_fail, len(records)) if records[i]["ok"]), None)
    rel = result["marker_relative_ms"]
    rel["first_failure_ms"] = _ms(first_fail["start_mono_s"] - fault_t)
    if idx_ok is None:
        result["outcome"] = OUTCOME_NOT_RECOVERED
        return result
    result["first_success"] = _probe_ref(records[idx_ok])
    rel["first_success_ms"] = _ms(records[idx_ok]["end_mono_s"] - fault_t)
    first, confirm = stable_run(records, idx_ok, n)
    end_index = len(records) if first is None else records.index(confirm) + 1
    result["outages_until_stable"] = len(find_outages(records[idx_fail:end_index]))
    if first is None:
        result["outcome"] = OUTCOME_NOT_RECOVERED if not records[-1]["ok"] else OUTCOME_UNSTABLE
        return result
    result["outcome"] = OUTCOME_STABLE
    result["outages_after_stable"] = len(find_outages(records[end_index:]))
    result["stable_first_success"] = _probe_ref(first)
    result["stable_confirmed"] = _probe_ref(confirm)
    rel["stable_first_success_ms"] = _ms(first["start_mono_s"] - fault_t)
    rel["stable_confirmed_ms"] = _ms(confirm["end_mono_s"] - fault_t)
    return result


# ------------------------------------------------------------------------------
# Persistent connection
# ------------------------------------------------------------------------------

def analyze_persistent(records, markers, run_id, probe_domain, **options):
    """Continuity of one connection that must exist before the fault marker.
    records: event=connect / exchange / end rows of one persistent probe process."""
    opt = dict(DEFAULTS, **options)
    records = sorted(records, key=lambda r: r["seq"])
    usable, rejected = select_markers(markers, run_id, probe_domain, opt["boot_tolerance_sec"])
    faults = [m for m in usable if m.get("kind") == FAULT_INJECTED]
    connect = next((r for r in records if r.get("event") == "connect"), None)
    exchanges = [r for r in records if r.get("event") == "exchange"]
    end = next((r for r in records if r.get("event") == "end"), None)
    summary = {"run_id": run_id, "exchanges": len(exchanges),
               "connected": bool(connect and connect["ok"]),
               "markers_rejected": [{"kind": r["marker"].get("kind"), "reason": r["reason"]} for r in rejected],
               "marker_source": OPERATOR_SIGNAL,
               "end_reason": end.get("error_class") if end else None,
               "end_detail": end.get("detail") if end else None,
               "end_cause": "unknown (no evidence)" if end and end.get("error_class") != "server_connection_close"
               else ("server sent Connection: close" if end else None),
               "end_mono_s": end["start_mono_s"] if end else None}
    reasons = []
    if not summary["connected"]:
        reasons.append("persistent connection was never established")
    if not faults:
        reasons.append("no usable fault_injected marker")
        summary["continuity"] = "not_evaluated"
    elif summary["connected"]:
        fault_t = faults[0]["monotonic_s"]
        before = [r for r in exchanges if r["end_mono_s"] < fault_t and r["ok"]]
        if connect["end_mono_s"] >= fault_t:
            reasons.append("connection established only after the fault marker")
        if not before:
            reasons.append("no successful exchange before the fault marker")
        if end is not None and end["start_mono_s"] < fault_t:
            reasons.append("connection ended before the fault marker")
        after_ok = [r for r in exchanges if r["start_mono_s"] >= fault_t and r["ok"]]
        if end is not None and end["start_mono_s"] >= fault_t and end.get("error_class") == "server_connection_close":
            # a regular close announced by the server is not counted as an interruption by the fault
            summary["continuity"] = "ended_by_server_connection_close"
            summary["end_after_marker_ms"] = _ms(end["start_mono_s"] - fault_t)
        elif end is not None and end["start_mono_s"] >= fault_t and end.get("error_class") != "probe_stopped":
            summary["continuity"] = "interrupted"
            summary["end_after_marker_ms"] = _ms(end["start_mono_s"] - fault_t)
            last_ok = max((r for r in exchanges if r["ok"]), key=lambda r: r["seq"], default=None)
            summary["last_successful_exchange"] = _probe_ref(last_ok)
        else:
            summary["continuity"] = "survived" if after_ok else "no_exchange_after_marker"
        summary["successful_exchanges_after_marker"] = len(after_ok)
    summary["run_validity"] = "valid" if not reasons else "not_valid"
    summary["validity_reasons"] = reasons
    return summary
