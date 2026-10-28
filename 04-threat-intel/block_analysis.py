#!/usr/bin/env python3
"""
Pillar 4: classification of canary probes and the observed blocking timeline (pure, no I/O).

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

Probe classes
  reachable            expected status AND the canary token in the body
  blocked              the configured block signature matched (status and/or body pattern and/or
                       redirect Location pattern; at least one pattern is required). A signature is
                       only usable after validate_signature() accepted it on the reference host.
  unclassified_403     HTTP 403 without the block signature - NOT counted as blocking
  unexpected_response  any other HTTP answer
  <error class>        timeout, tls_error, dns_error, refused, reset, eof, other - NOT blocking

Timeline (monotonic seconds; UTC kept next to every time)
  T_baseline_ok        end of the probe with which the baseline rule was first met
  T_update_sent / T_update_response / T_commit_sent / T_commit_response   API steps
  T_first_blocked      first blocked probe after T_update_sent (its start AND end are reported)
  T_stable_blocked     first run of STABLE_N consecutive blocked probes: start of its first probe
                       (stable_run_first) and end of its N-th probe (stable_run_confirmed)
  observed_blocking_latency_ms = (probe time) - (reference event); for every reference event and
  for the first-blocked start/end and the stable times. Values are SIGNED: if blocking is seen
  before an API response, the offset is negative and kept; the real order is in "event_order".
  This is the delay perceived by the probes, not an internal rule-enforcement time.

Baseline rule: in the BASELINE_SEC before the evaluation point every probe is reachable, probes cover
the window (first start <= window start + MAX_GAP) and no gap between probe starts exceeds MAX_GAP.
"""

import re

REACHABLE = "reachable"
BLOCKED = "blocked"
UNCLASSIFIED_403 = "unclassified_403"
UNEXPECTED = "unexpected_response"
NOT_BLOCKING_NOTE = "403, timeout, TLS, DNS and connection errors are not counted as blocking"


class CanaryCheck:
    def __init__(self, expect_status, token):
        if not token:
            raise ValueError("a canary token is required")
        self.expect_status, self.token = int(expect_status), token.encode("utf-8")

    def matches(self, status, body):
        return status == self.expect_status and self.token in (body or b"")


class BlockSignature:
    def __init__(self, status=None, body_regex="", location_regex=""):
        if not body_regex and not location_regex:
            raise ValueError("a block signature needs a body or Location pattern; a status code alone is not enough")
        self.status = int(status) if status not in (None, "") else None
        self.body_regex, self.location_regex = body_regex, location_regex
        self._body = re.compile(body_regex.encode("utf-8")) if body_regex else None
        self._loc = re.compile(location_regex) if location_regex else None

    def describe(self):
        return {"status": self.status, "body_regex": self.body_regex, "location_regex": self.location_regex}

    def matches(self, status, body, location):
        if self.status is not None and status != self.status:
            return False
        if self._body and not self._body.search(body or b""):
            return False
        if self._loc and not self._loc.search(location or ""):
            return False
        return True


def classify(probe, canary, signature):
    if probe.get("error_class"):
        return probe["error_class"]
    status, body, location = probe.get("status"), probe.get("body") or b"", probe.get("location") or ""
    if canary is not None and canary.matches(status, body):
        return REACHABLE
    if signature is not None and signature.matches(status, body, location):
        return BLOCKED
    if status == 403:
        return UNCLASSIFIED_403
    return UNEXPECTED


def validate_signature(classes, required=5):
    """Reference-host probe classes -> validation result: at least `required` probes, all blocked."""
    counts = {}
    for c in classes:
        counts[c] = counts.get(c, 0) + 1
    reasons = []
    if len(classes) < required:
        reasons.append(f"only {len(classes)} reference probes (need {required})")
    if any(c != BLOCKED for c in classes):
        reasons.append(f"not every reference probe matched the signature: {counts}")
    return {"validated": not reasons, "reasons": reasons, "class_counts": counts, "required": required,
            "rule": f">= {required} reference probes, every one classified blocked"}


def _ref(p):
    return None if p is None else {"seq": p["seq"], "start_mono_s": p["start_mono_s"], "end_mono_s": p["end_mono_s"],
                                   "start_utc": p.get("start_utc", ""), "end_utc": p.get("end_utc", "")}


def _ms(x):
    return None if x is None else round(x * 1000.0, 3)


def baseline_met(probes, until, baseline_sec, max_gap):
    """(met, reasons) for the window [until - baseline_sec, until)."""
    window_start = until - baseline_sec
    window = [p for p in probes if window_start <= p["start_mono_s"] < until]
    reasons = []
    if not probes or probes[0]["start_mono_s"] > window_start + max_gap:
        reasons.append("coverage: probes started too late for the baseline window")
    starts = [p["start_mono_s"] for p in window]
    gaps = [b - a for a, b in zip(starts, starts[1:])]
    if not window:
        reasons.append("no probe in the baseline window")
    elif gaps and max(gaps) > max_gap:
        reasons.append(f"continuity: gap {max(gaps):.3f}s > {max_gap}s")
    bad = [p["class"] for p in window if p["class"] != REACHABLE]
    if bad:
        reasons.append(f"{len(bad)} probe(s) not reachable in the window: {sorted(set(bad))}")
    return not reasons, reasons


def first_run(probes, cls, n, start_index=0):
    streak = 0
    for k in range(start_index, len(probes)):
        if probes[k]["class"] == cls:
            streak += 1
            if streak == n:
                return probes[k - n + 1], probes[k], k
        else:
            streak = 0
    return None, None, None


def analyze_canary(probes, events, stable_n=10, baseline_sec=30.0, max_gap_sec=1.0, outcome_hint=""):
    """probes: classified records (seq, start/end mono+utc, class); events: {name: {mono, utc, ...}}."""
    probes = sorted(probes, key=lambda p: p["seq"])
    ev = {k: v for k, v in events.items() if v and v.get("mono") is not None}
    summary = {"stable_n": stable_n, "not_blocking_note": NOT_BLOCKING_NOTE, "time_basis": "monotonic; UTC kept"}
    reasons = []

    sent = ev.get("UPDATE_SENT")
    if "BASELINE_OK" in ev:
        met, why = baseline_met(probes, ev["BASELINE_OK"]["mono"] + 1e-9, baseline_sec, max_gap_sec)
        summary["baseline"] = {"status": "ok" if met else "failed", "reasons": why,
                               "T_baseline_ok": ev["BASELINE_OK"]}
        if not met:
            reasons.append("baseline rule not met")
    else:
        summary["baseline"] = {"status": "not_reached", "reasons": ["BASELINE_OK was never recorded"]}
        reasons.append("baseline not reached")

    if sent is None:
        summary.update({"outcome": outcome_hint or "not_started", "run_validity": "not_valid",
                        "validity_reasons": reasons + ["no update was sent"],
                        "restore": {"category_state": "not_attempted", "access": "not_evaluated"}})
        return summary

    pre = [p for p in probes if p["start_mono_s"] < sent["mono"] and p["class"] == BLOCKED]
    if pre:
        reasons.append("blocked probes before T_update_sent (previously blocked target)")
    start_idx = next((i for i, p in enumerate(probes) if p["start_mono_s"] >= sent["mono"]), len(probes))
    restore_t = ev.get("RESTORE_SENT", {}).get("mono", float("inf"))
    window = [p for p in probes[start_idx:] if p["start_mono_s"] < restore_t]
    first = next((p for p in window if p["class"] == BLOCKED), None)
    s_first, s_conf, _ = first_run(window, BLOCKED, stable_n)

    times = {"T_first_blocked": _ref(first), "stable_run_first": _ref(s_first), "stable_run_confirmed": _ref(s_conf)}
    summary["timeline"] = {name: ev.get(key) for name, key in (
        ("T_update_sent", "UPDATE_SENT"), ("T_update_response", "UPDATE_RESPONSE"),
        ("T_commit_sent", "COMMIT_SENT"), ("T_commit_response", "COMMIT_RESPONSE"))}
    summary["timeline"]["commit"] = "skipped" if "COMMIT_SKIPPED" in ev else ("sent" if "COMMIT_SENT" in ev else "none")
    summary["timeline"].update(times)

    latency = {}
    for ref_name, key in (("from_update_sent", "UPDATE_SENT"), ("from_update_response", "UPDATE_RESPONSE"),
                          ("from_commit_sent", "COMMIT_SENT"), ("from_commit_response", "COMMIT_RESPONSE")):
        if key not in ev:
            continue
        t = ev[key]["mono"]
        latency[ref_name] = {
            "first_blocked_start_ms": _ms(first["start_mono_s"] - t) if first else None,
            "first_blocked_end_ms": _ms(first["end_mono_s"] - t) if first else None,
            "stable_run_first_start_ms": _ms(s_first["start_mono_s"] - t) if s_first else None,
            "stable_run_confirmed_end_ms": _ms(s_conf["end_mono_s"] - t) if s_conf else None,
        }
    summary["observed_blocking_latency_ms"] = latency
    summary["observed_blocking_latency_note"] = ("signed (probe time - event); negative values are kept; "
                                                 "perceived by probes, not an internal enforcement time")
    # equal times keep the recording order (event seq); probe-derived points follow recorded events
    late = float("inf")
    order = [(v["mono"], v.get("seq", late), k) for k, v in ev.items()]
    if first:
        order += [(first["start_mono_s"], late, "FIRST_BLOCKED_PROBE_START"),
                  (first["end_mono_s"], late, "FIRST_BLOCKED_PROBE_END")]
    if s_conf:
        order.append((s_conf["end_mono_s"], late, "STABLE_RUN_CONFIRMED_PROBE_END"))
    summary["event_order"] = [name for _, _, name in sorted(order)]
    until_block = window[:window.index(first)] if first else window
    counts = {}
    for p in until_block:
        counts[p["class"]] = counts.get(p["class"], 0) + 1
    summary["classes_before_first_block"] = counts

    if outcome_hint:
        outcome = outcome_hint
    elif pre:
        outcome = "previously_blocked"
    elif s_conf:
        outcome = "blocked_stable"
    elif first:
        outcome = "blocked_unstable"
    else:
        outcome = "not_blocked_within_timeout"
    summary["outcome"] = outcome

    # restore: category state and access are separate results
    rr = ev.get("RESTORE_RESPONSE")
    summary["restore"] = {"category_state": next((k for k in ("CATEGORY_RESTORED", "CATEGORY_RESTORE_FAILED",
                                                              "RESTORE_CONFLICT", "RESTORE_REJECTED",
                                                              "RESTORE_NOT_NEEDED", "RESTORE_STATE_UNKNOWN")
                                                  if k in ev), "not_attempted")}
    if rr:
        after = [p for p in probes if p["start_mono_s"] >= rr["mono"]]
        ok_first, ok_conf, _ = first_run(after, REACHABLE, stable_n)
        summary["restore"].update({
            "access": "restored_stable" if ok_conf else "not_restored_within_observation",
            "access_stable_run_first": _ref(ok_first), "access_stable_run_confirmed": _ref(ok_conf),
            "access_confirmed_after_restore_response_ms": _ms(ok_conf["end_mono_s"] - rr["mono"]) if ok_conf else None})
    else:
        summary["restore"]["access"] = "not_evaluated"
    if outcome not in ("blocked_stable",):
        reasons.append(f"outcome {outcome}")
    summary["run_validity"] = "valid" if not reasons else "not_valid"
    summary["validity_reasons"] = reasons
    return summary
