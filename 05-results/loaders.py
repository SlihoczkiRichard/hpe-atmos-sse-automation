#!/usr/bin/env python3
"""
Results: read-only loaders for the outputs of the four measurement modules.

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

Every loader only reads files and returns a Dataset with the parsed data, the sha256 of every file
it read, the provenance claimed by the files' own metadata and a list of issues. Issue severities:
  FATAL    the dataset cannot be used at all (processing stops)
  FIGURE   a figure that needs the missing/invalid part is skipped (with the reason)
  PARTIAL  the data can be shown, but with a warning (e.g. empty values, partial coverage)

Provenance (three states): simulated, real, unknown.
  simulated  the tool metadata says so (dry-run modes, "SIMULATED", "NOT a measurement",
             scaler_dryrun_ file prefix, simulated marker clock domain)
  real       the tool metadata explicitly says "measurement"
  unknown    no explicit metadata (scaler_ prefix without dryrun, telemetry, sar/k6 raw exports,
             sync outputs); the missing dry-run prefix does NOT prove a real measurement
Contradicting metadata inside one dataset is FATAL.
"""

import os
import csv
import json
import glob
import hashlib
from dataclasses import dataclass, field

FATAL, FIGURE, PARTIAL = "fatal", "figure", "partial"
SIMULATED, REAL, UNKNOWN = "simulated", "real", "unknown"


@dataclass
class Issue:
    severity: str
    message: str

    def as_dict(self):
        return {"severity": self.severity, "message": self.message}


@dataclass
class Dataset:
    kind: str
    path: str
    run_id: str = ""
    attempt: int = 1
    repetition: int = 0
    claimed_provenance: str = UNKNOWN
    provenance_evidence: str = ""
    files: list = field(default_factory=list)
    data: dict = field(default_factory=dict)
    issues: list = field(default_factory=list)

    def issue(self, severity, message):
        self.issues.append(Issue(severity, message))

    def fatal(self):
        return [i for i in self.issues if i.severity == FATAL]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _read(ds, path, kind="csv", required=True):
    """Reads a file (csv rows / json / text), recording its hash. None if missing."""
    if not os.path.isfile(path):
        if required:
            ds.issue(FATAL, f"missing file {os.path.basename(path)}")
        return None
    ds.files.append({"path": os.path.abspath(path), "sha256": sha256(path)})
    try:
        if kind == "csv":
            with open(path, newline="", encoding="utf-8") as f:
                return list(csv.DictReader(f))
        with open(path, encoding="utf-8") as f:
            return json.load(f) if kind == "json" else f.read()
    except (ValueError, UnicodeDecodeError, csv.Error) as exc:
        ds.issue(FATAL if required else FIGURE, f"cannot parse {os.path.basename(path)}: {exc}")
        return None


def provenance_from_mode(mode):
    """(provenance, evidence) from a tool 'mode' string."""
    if not mode:
        return UNKNOWN, "no mode metadata"
    text = str(mode)
    if "SIMULATED" in text or "NOT a measurement" in text or text.lower().startswith("dry-run"):
        return SIMULATED, f"mode={text!r}"
    if text == "measurement":
        return REAL, f"mode={text!r} (tool metadata)"
    return UNKNOWN, f"mode={text!r} does not state simulated or measurement"


def _claim(ds, *claims):
    """Combines several (provenance, evidence) claims; contradictions are FATAL."""
    known = {p for p, _ in claims if p != UNKNOWN}
    ds.provenance_evidence = "; ".join(e for _, e in claims)
    if len(known) > 1:
        ds.issue(FATAL, f"contradicting provenance metadata: {ds.provenance_evidence}")
        ds.claimed_provenance = UNKNOWN
    else:
        ds.claimed_provenance = known.pop() if known else UNKNOWN


def _partial_messages(ds, messages, limit=5):
    """Adds per-line adapter messages as PARTIAL issues; long lists are summarised, with the count."""
    for msg in messages[:limit]:
        ds.issue(PARTIAL, msg)
    if len(messages) > limit:
        ds.issue(PARTIAL, f"... and {len(messages) - limit} more skipped line(s) of the same kind")


def _float(v):
    try:
        return float(v) if v not in (None, "") else None
    except ValueError:
        return None


def _require_columns(ds, rows, name, columns, severity=FATAL):
    if rows is None:
        return False
    if not rows:
        ds.issue(severity, f"{name} has no data rows")
        return False
    missing = [c for c in columns if c not in rows[0]]
    if missing:
        ds.issue(severity, f"{name} lacks columns {missing}")
        return False
    return True


# ------------------------------------------------------------------------------
# 01-load-test
# ------------------------------------------------------------------------------

def load_hey(path):
    ds = Dataset("hey", path)
    manifest = _read(ds, os.path.join(path, "manifest.json"), "json")
    runs = _read(ds, os.path.join(path, "runs.csv"))
    levels = _read(ds, os.path.join(path, "levels.csv"))
    if manifest is None:
        return ds
    ds.run_id = manifest.get("run_id", "")
    _claim(ds, provenance_from_mode(manifest.get("mode")))
    _require_columns(ds, runs, "runs.csv", ["run_id", "sweep", "concurrency", "valid", "successful_rps",
                                            "primary_error_rate", "started_utc", "ended_utc"])
    _require_columns(ds, levels, "levels.csv", ["concurrency", "status", "successful_rps_median"])
    if runs and any(r["run_id"] != ds.run_id for r in runs):
        ds.issue(FATAL, "runs.csv contains rows of another run_id")
    if runs and any(r.get("valid") != "True" for r in runs):
        ds.issue(PARTIAL, f"{sum(r.get('valid') != 'True' for r in runs)} invalid hey run(s); shown as invalid")
    if manifest.get("status") == "interrupted":
        ds.issue(PARTIAL, f"hey benchmark interrupted ({manifest.get('interruption')}): not an acceptable "
                          "capacity result")
    ds.data = {"manifest": manifest, "runs": runs or [], "levels": levels or []}
    return ds


def load_k6_summary(path):
    ds = Dataset("k6_summary", path)
    s = _read(ds, path, "json")
    if s is None:
        return ds
    ds.run_id = s.get("run_id", "")
    _claim(ds, provenance_from_mode(s.get("mode")))
    if not s.get("valid"):
        ds.issue(PARTIAL, f"k6 summary invalid: {s.get('invalid_reason')}")
    ds.data = {"summary": s}
    return ds


def load_iperf3(path):
    ds = Dataset("iperf3", path)
    manifest = _read(ds, os.path.join(path, "iperf3_manifest.json"), "json")
    runs = _read(ds, os.path.join(path, "iperf3_runs.csv"))
    if manifest is None:
        return ds
    ds.run_id = manifest.get("run_id", "")
    _claim(ds, provenance_from_mode(manifest.get("mode")))
    _require_columns(ds, runs, "iperf3_runs.csv", ["path_label", "path_verification", "round", "valid",
                                                   "received_mbps", "sender_tcp_retransmits"])
    if manifest.get("status") == "interrupted":
        ds.issue(PARTIAL, f"iperf3 comparison interrupted ({manifest.get('interruption')})")
    ds.data = {"manifest": manifest, "runs": runs or []}
    return ds


def load_telemetry_meta(path):
    ds = Dataset("telemetry_meta", path)
    meta = _read(ds, path, "json")
    if meta is None:
        return ds
    ds.run_id = meta.get("run_id", "")
    _claim(ds, (UNKNOWN, "telemetry metadata has no provenance field"))
    if meta.get("complete_time_series") is not True:
        ds.issue(PARTIAL, f"telemetry coverage {meta.get('coverage')} ({meta.get('role')}): not a complete time series")
    ds.data = {"meta": meta}
    return ds


def load_sar_cpu(path, sar_adapter):
    ds = Dataset("sar_cpu", path)
    text = _read(ds, path, "text")
    if text is None:
        return ds
    _claim(ds, (UNKNOWN, "sadf export has no provenance field"))
    try:
        ds.data = sar_adapter.load_sadf_cpu(text, os.path.basename(path))
    except sar_adapter.UnsupportedFormat as exc:
        ds.issue(FIGURE, f"unsupported sar export: {exc}")
        return ds
    _partial_messages(ds, ds.data["issues"])
    if not ds.data["rows"]:
        ds.issue(FIGURE, "no aggregate CPU rows")
    return ds


def load_sar_mem(path, sar_adapter):
    ds = Dataset("sar_mem", path)
    text = _read(ds, path, "text")
    if text is None:
        return ds
    _claim(ds, (UNKNOWN, "sadf export has no provenance field"))
    try:
        ds.data = sar_adapter.load_sadf_mem(text, os.path.basename(path))
    except sar_adapter.UnsupportedFormat as exc:
        ds.issue(FIGURE, f"unsupported sar memory export: {exc}")
        return ds
    _partial_messages(ds, ds.data["issues"])
    if not ds.data["rows"]:
        ds.issue(FIGURE, "no memory rows")
    return ds


def load_k6_raw(path, k6_adapter, bin_sec=1.0):
    ds = Dataset("k6_raw", path)
    text = _read(ds, path, "text")
    if text is None:
        return ds
    _claim(ds, (UNKNOWN, "k6 raw JSON has no provenance field"))
    try:
        ds.data = k6_adapter.load_k6_raw(text, bin_sec, os.path.basename(path))
    except k6_adapter.UnsupportedFormat as exc:
        ds.issue(FIGURE, f"unsupported k6 raw output: {exc}")
        return ds
    _partial_messages(ds, ds.data["issues"])
    return ds


# ------------------------------------------------------------------------------
# 02-scaler-poc
# ------------------------------------------------------------------------------

SCALER_COLUMNS = ["timestamp_utc", "monotonic_s", "c1_sample_end_s", "c1_cpu_pct", "c2_state_observed_s",
                  "c2_power_state", "c2_cpu_pct", "decision_s", "application_reachable", "events"]


def load_scaler(timeseries_path):
    """timeseries_path: <prefix>_timeseries.csv; events/errors are found by the same prefix."""
    ds = Dataset("scaler", timeseries_path)
    if not timeseries_path.endswith("_timeseries.csv"):
        ds.issue(FATAL, "scaler input must be a *_timeseries.csv file")
        return ds
    prefix = timeseries_path[:-len("_timeseries.csv")]
    rows = _read(ds, timeseries_path)
    events = _read(ds, prefix + "_events.csv")
    errors = _read(ds, prefix + "_errors.csv", required=False)
    base = os.path.basename(prefix)
    _claim(ds, (SIMULATED, "file prefix scaler_dryrun_") if base.startswith("scaler_dryrun_")
           else (UNKNOWN, "scaler output without explicit provenance (no dry-run prefix does not prove real)"))
    _require_columns(ds, rows, "timeseries", SCALER_COLUMNS)
    _require_columns(ds, events, "events", ["timestamp_utc", "monotonic_s", "event", "detail"])
    ds.issue(PARTIAL, "scaler outputs carry no RUN_ID/attempt/repetition; taken from the reviewed spec")
    ds.data = {"rows": rows or [], "events": events or [], "errors": errors or [], "prefix": base}
    return ds


# ------------------------------------------------------------------------------
# 03-failover
# ------------------------------------------------------------------------------

def _suffix(n, label):
    return "" if n == 1 else f".{label}{n}"


def load_failover(run_dir, probe, attempt=1, rev=1):
    ds = Dataset(f"failover_{probe}", run_dir, attempt=attempt)
    sfx = _suffix(attempt, "attempt")
    records = _read(ds, os.path.join(run_dir, f"probes_{probe}{sfx}.csv"))
    manifest = _read(ds, os.path.join(run_dir, f"manifest_{probe}{sfx}.json"), "json")
    markers = _read(ds, os.path.join(run_dir, "markers.csv"), required=False)
    analysis = _read(ds, os.path.join(run_dir, f"analysis_{probe}{sfx}{_suffix(rev, 'rev')}.json"), "json",
                     required=False)
    outages = _read(ds, os.path.join(run_dir, f"outages_{probe}{sfx}{_suffix(rev, 'rev')}.csv"), required=False)
    if manifest is None:
        return ds
    ds.run_id = manifest.get("run_id", "")
    claims = [provenance_from_mode(manifest.get("mode"))]
    if analysis:
        claims.append(provenance_from_mode(analysis.get("mode")))
    sim_markers = {m.get("simulated") for m in (markers or []) if m.get("run_id") == ds.run_id}
    if sim_markers == {"True"}:
        claims.append((SIMULATED, "markers.csv simulated=True"))
    elif sim_markers == {"False"}:
        claims.append((UNKNOWN, "markers.csv simulated=False (marker clock, not a measurement claim)"))
    elif len(sim_markers) > 1:
        ds.issue(FATAL, "markers.csv mixes simulated and non-simulated markers")
    _claim(ds, *claims)
    _require_columns(ds, records, f"probes_{probe}", ["seq", "event", "start_mono_s", "end_mono_s", "ok",
                                                      "error_class"])
    if records and any(r.get("run_id") != ds.run_id for r in records):
        ds.issue(FATAL, "probe records of another run_id")
    if analysis is None:
        ds.issue(PARTIAL, f"no analysis_{probe} file: probes shown without outcome/recovery (run 03 analyze first)")
    ds.data = {"records": records or [], "manifest": manifest, "markers": markers or [], "analysis": analysis,
               "outages": outages or [], "probe": probe}
    return ds


# ------------------------------------------------------------------------------
# 04-threat-intel
# ------------------------------------------------------------------------------

def load_canary(run_dir):
    ds = Dataset("canary", run_dir)
    manifest = _read(ds, os.path.join(run_dir, "manifest.json"), "json")
    summary = _read(ds, os.path.join(run_dir, "summary.json"), "json")
    probes = _read(ds, os.path.join(run_dir, "probes.csv"))
    events = _read(ds, os.path.join(run_dir, "events.csv"))
    if manifest is None or summary is None:
        return ds
    ds.run_id, ds.attempt = manifest.get("run_id", ""), manifest.get("attempt", 1)
    ds.repetition = manifest.get("repetition", 0)
    _claim(ds, provenance_from_mode(manifest.get("mode")), provenance_from_mode(summary.get("mode")))
    _require_columns(ds, probes, "probes.csv", ["seq", "start_mono_s", "end_mono_s", "class"], FIGURE)
    _require_columns(ds, events, "events.csv", ["event", "mono_s", "utc"], FIGURE)
    if summary.get("run_validity") != "valid":
        ds.issue(PARTIAL, f"canary run not valid: {summary.get('validity_reasons')}")
    ds.data = {"manifest": manifest, "summary": summary, "probes": probes or [], "events": events or []}
    return ds


def load_sync(run_dir):
    ds = Dataset("sync", run_dir)
    manifest = _read(ds, os.path.join(run_dir, "manifest.json"), "json")
    result = _read(ds, os.path.join(run_dir, "result.json"), "json")
    indicators = _read(ds, os.path.join(run_dir, "indicators.json"), "json", required=False)
    if manifest is None:
        return ds
    ds.run_id, ds.attempt = manifest.get("run_id", ""), manifest.get("attempt", 1)
    _claim(ds, (UNKNOWN, f"sync mode={manifest.get('mode')!r} carries no measurement provenance"))
    ds.data = {"manifest": manifest, "result": result or {}, "indicators": indicators or {}}
    return ds


# ------------------------------------------------------------------------------
# Scan (read-only discovery for the spec draft)
# ------------------------------------------------------------------------------

def scan(roots):
    """Finds known output layouts under the roots. Returns spec dataset entries (unreviewed)."""
    found = []

    def add(kind, path, **extra):
        found.append({"id": f"{kind}-{len(found) + 1}", "kind": kind, "path": os.path.abspath(path), **extra})

    for root in roots:
        for manifest in glob.glob(os.path.join(root, "**", "manifest.json"), recursive=True):
            d = os.path.dirname(manifest)
            if os.path.exists(os.path.join(d, "runs.csv")) and os.path.exists(os.path.join(d, "levels.csv")):
                add("hey", d)
            elif os.path.exists(os.path.join(d, "summary.json")) and os.path.exists(os.path.join(d, "probes.csv")):
                add("canary", d)
            elif os.path.basename(d).startswith("sync_"):
                add("sync", d)
        for p in glob.glob(os.path.join(root, "**", "iperf3_manifest.json"), recursive=True):
            add("iperf3", os.path.dirname(p))
        for p in glob.glob(os.path.join(root, "**", "k6_*_summary*.json"), recursive=True):
            add("k6_summary", p)
        for p in glob.glob(os.path.join(root, "**", "telemetry_*_meta.json"), recursive=True):
            add("telemetry_meta", p)
        for p in glob.glob(os.path.join(root, "**", "*_cpu_sadf.csv"), recursive=True):
            add("sar_cpu", p)
        for p in glob.glob(os.path.join(root, "**", "*_mem_sadf.csv"), recursive=True):
            add("sar_mem", p)
        for p in glob.glob(os.path.join(root, "**", "*_timeseries.csv"), recursive=True):
            add("scaler", p, run_id="", note="scaler outputs have no RUN_ID: set run_id by hand")
        for p in glob.glob(os.path.join(root, "**", "manifest_*.json"), recursive=True):
            name = os.path.basename(p)[len("manifest_"):-len(".json")]
            probe, _, att = name.partition(".attempt")
            add("failover", os.path.dirname(p), probe=probe, attempt=int(att or 1))
    return found
