#!/usr/bin/env python3
"""
Results: adapter for k6's raw JSON output (k6 run --out json=<file>), one supported format.

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

SUPPORTED FORMAT: newline-delimited JSON as documented for k6's JSON output: lines with
  {"type": "Metric", "metric": <name>, "data": {...}}  and
  {"type": "Point",  "metric": <name>, "data": {"time": <RFC 3339>, "value": <number>, "tags": {...}}}
Used points (names from 01-load-test/k6_workload.js):
  request_attempts                 one per request attempt (counter value 1)
  responses_success                one per successful attempt
  success_request_chain_duration   wall time of a successful http.get() incl. redirects (ms)
Built-in http_req_* points are counted per redirect hop by k6, so they are not used for rates.
Points are binned into fixed UTC intervals (bin_sec); per bin: attempts, successes, success ratio,
success-chain latency p50/p95/max. Empty bins stay empty (no interpolation, no smoothing).

OPEN DATA REQUIREMENT: written from the documented k6 JSON output and tested on synthetic lines
only. The current pipeline does not store this output by default (k6_workload.js only suggests
--out json). A real file from the testbed and the k6 version (`k6 version`) are needed before
figures based on it count as validated.
"""

import json
import math
from datetime import datetime, timezone

USED_METRICS = ("request_attempts", "responses_success", "success_request_chain_duration")
SOURCE_LABEL = "k6 raw JSON output (--out json), load-generator clock"


class UnsupportedFormat(ValueError):
    pass


def _parse_time(text):
    t = text.replace("Z", "+00:00")
    if "." in t:   # k6 may write nanoseconds; datetime accepts microseconds
        head, frac = t.split(".", 1)
        n = 0
        while n < len(frac) and frac[n].isdigit():   # only the leading fraction digits, not the offset
            n += 1
        digits, rest = frac[:n], frac[n:]
        t = f"{head}.{(digits + '000000')[:6]}{rest}"
    dt = datetime.fromisoformat(t)
    if dt.tzinfo is None:
        raise UnsupportedFormat(f"time {text!r} has no UTC offset")
    return dt.astimezone(timezone.utc)


def _percentile(values, q):
    v = sorted(values)
    return v[min(len(v) - 1, int(round(q * (len(v) - 1))))]


def load_k6_raw(text, bin_sec=1.0, source_name="<text>"):
    if bin_sec <= 0:
        raise ValueError("bin_sec must be positive")
    points, issues, seen_types = [], [], set()
    for no, line in enumerate((text or "").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            raise UnsupportedFormat(f"{source_name}: line {no} is not JSON (expected k6 --out json NDJSON)")
        if not isinstance(rec, dict) or rec.get("type") not in ("Metric", "Point"):
            raise UnsupportedFormat(f"{source_name}: line {no} is not a k6 Metric/Point record")
        seen_types.add(rec["type"])
        if rec["type"] != "Point" or rec.get("metric") not in USED_METRICS:
            continue
        data = rec.get("data") or {}
        try:
            points.append((rec["metric"], _parse_time(data["time"]), float(data["value"]),
                           (data.get("tags") or {}).get("stage", "")))
        except (KeyError, ValueError, TypeError) as exc:
            issues.append(f"line {no}: unusable point ({exc}); skipped")
    if "Point" not in seen_types:
        raise UnsupportedFormat(f"{source_name}: no Point records")
    if not any(m == "request_attempts" for m, _, _, _ in points):
        raise UnsupportedFormat(f"{source_name}: no request_attempts points (not produced by k6_workload.js?)")
    t0 = min(t for _, t, _, _ in points)
    bins = {}
    for metric, t, value, _ in points:
        k = int(math.floor((t - t0).total_seconds() / bin_sec))
        b = bins.setdefault(k, {"attempts": 0.0, "success": 0.0, "latency": []})
        if metric == "request_attempts":
            b["attempts"] += value
        elif metric == "responses_success":
            b["success"] += value
        else:
            b["latency"].append(value)
    rows = []
    for k in range(max(bins) + 1):
        b = bins.get(k)
        start = t0.timestamp() + k * bin_sec
        if not b or not b["attempts"]:
            rows.append({"bin_start_utc": datetime.fromtimestamp(start, timezone.utc), "attempts": 0 if b else None,
                         "success": None, "success_ratio": None, "success_latency_p50_ms": None,
                         "success_latency_p95_ms": None, "success_latency_max_ms": None})
            continue
        lat = b["latency"]
        rows.append({"bin_start_utc": datetime.fromtimestamp(start, timezone.utc), "attempts": b["attempts"],
                     "success": b["success"], "success_ratio": b["success"] / b["attempts"],
                     "success_latency_p50_ms": _percentile(lat, 0.5) if lat else None,
                     "success_latency_p95_ms": _percentile(lat, 0.95) if lat else None,
                     "success_latency_max_ms": max(lat) if lat else None})
    return {"bin_sec": bin_sec, "rows": rows, "issues": issues, "source_label": SOURCE_LABEL,
            "first_point_utc": t0, "stages": _stage_rows(points)}


def _stage_rows(points):
    """Per stage tag (k6_workload.js tags every sample with the stage in which the request STARTED):
    counts and latency percentiles from the raw samples. Empty if the points carry no stage tag."""
    stages = {}
    for metric, t, value, stage in points:
        if not stage:
            continue
        s = stages.setdefault(stage, {"attempts": 0.0, "success": 0.0, "latency": [], "first": t, "last": t})
        s["first"], s["last"] = min(s["first"], t), max(s["last"], t)
        if metric == "request_attempts":
            s["attempts"] += value
        elif metric == "responses_success":
            s["success"] += value
        else:
            s["latency"].append(value)
    out = []
    for stage in sorted(stages):
        s = stages[stage]
        lat = s["latency"]
        out.append({"stage": stage, "attempts": s["attempts"], "success": s["success"],
                    "primary_error_rate": (s["attempts"] - s["success"]) / s["attempts"] if s["attempts"] else None,
                    "success_latency_p95_ms": _percentile(lat, 0.95) if lat else None,
                    "success_latency_p99_ms": _percentile(lat, 0.99) if lat else None,
                    "first_sample_utc": s["first"], "last_sample_utc": s["last"]})
    return out
