#!/usr/bin/env python3
"""
Results: common processing and figure generation for the four measurements (read-only on inputs).

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

  scan     finds known output layouts under --root and writes a spec DRAFT (never overwritten);
           the operator must review it, set run ids/groups/provenance and "reviewed_by_operator": true
  process  reads only the files named in a reviewed spec, writes figures (PNG, PDF), the CSV behind
           every figure and processing_manifest.json into a new directory (never overwritten)

Spec fields
  processing_id, reviewed_by_operator (must be true), provenance per dataset (simulated|real|unknown),
  time_sync (optional operator statement for cross-machine UTC views: statement, source,
  known_uncertainty; an operator claim, not verified here; there is no default),
  groups.m2: [{"scaler": id, "app": [hey/k6_raw ids], "sar": [ids]}], k6_raw_bin_sec,
  groups.m1_resources: [{"hey": id, "sar_cpu": id, "sar_mem": id (optional), "warmup_sec": seconds
  (required, 0 = whole run), "min_coverage": 0..1 (optional, default 0.9)}] (needs time_sync).
Provenance: a dataset's tool metadata (simulated/real) must agree with the spec; unknown metadata
needs the operator's classification; all datasets of one processing run must share one provenance
(no mixing). Unknown data is never labelled as a real measurement.
Issue severities: fatal (processing stops; a manifest with status "failed" is still written),
figure (that figure is skipped with the reason), partial (shown with a warning).

No measurement program, SSH, network or API call is made. Nothing is loaded from .env.
"""

import os
import sys
import json
import argparse
import importlib.util
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


loaders = _load(os.path.join(HERE, "loaders.py"), "results_loaders")
derive = _load(os.path.join(HERE, "derive.py"), "results_derive")
sar_adapter = _load(os.path.join(HERE, "sar_adapter.py"), "results_sar_adapter")
k6_adapter = _load(os.path.join(HERE, "k6_raw_adapter.py"), "results_k6_raw_adapter")
failover_analysis = _load(os.path.join(ROOT, "03-failover", "failover_analysis.py"), "results_fo_analysis")

PROVENANCES = (loaders.SIMULATED, loaders.REAL, loaders.UNKNOWN)

DATA_REQUIREMENTS = [
    {"figure": "m2_sar_cpu_*", "status": "adapter implemented, real sample missing",
     "needed": "a real `sadf -d <telemetry_...>.sa -- -u ALL` export from each connector VM and `sadf -V` output "
               "(sysstat version); the human-readable *_sar.txt is not supported"},
    {"figure": "m2_app_performance_* (k6 part)", "status": "adapter implemented, data not produced by default",
     "needed": "a real `k6 run --out json=<file>` output of k6_workload.js and `k6 version`; proposal for a later "
               "round: let a wrapper store this file next to the k6 summary with the RUN_ID"},
    {"figure": "m2_app_performance_*", "status": "needs operator input",
     "needed": "spec.time_sync statement (source, known uncertainty) because the load generator and the scaler "
               "run on different machines; without it the figure is skipped"},
    {"figure": "m2_* (scaler)", "status": "needs operator input",
     "needed": "RUN_ID and provenance of each scaler output in the spec (the scaler writes neither); proposal for a "
               "later round: a RUN_ID option and a mode field in the scaler outputs"},
    {"figure": "m1_resources_*", "status": "adapters implemented, real samples missing",
     "needed": "real `sadf -d ... -- -u ALL` and `sadf -d ... -- -r` exports and `sadf -V`, to confirm the "
               "headers, the meaning of %memused for that sysstat version and the temporal interpretation "
               "(CPU = interval average ending at t, memory = reading at t); plus spec.time_sync because hey "
               "and sar run on different machines"},
    {"figure": "m1_k6_stages", "status": "implemented, not yet seen with a real k6 run",
     "needed": "one real run of k6_workload.js with `k6 version` recorded, to confirm that k6 emits the "
               "stage submetrics into handleSummary and that k6/execution scenario timing is available"},
]


def make_out_dir(base, processing_id):
    os.makedirs(base, exist_ok=True)
    for n in range(1, 100):
        path = os.path.join(base, processing_id if n == 1 else f"{processing_id}.attempt{n}")
        try:
            os.mkdir(path)
            return path, n
        except FileExistsError:
            continue
    raise FileExistsError("no free output directory")


def load_dataset(entry, bin_sec):
    kind, path = entry.get("kind"), entry.get("path", "")
    if kind == "hey":
        return loaders.load_hey(path)
    if kind == "k6_summary":
        return loaders.load_k6_summary(path)
    if kind == "k6_raw":
        return loaders.load_k6_raw(path, k6_adapter, bin_sec)
    if kind == "iperf3":
        return loaders.load_iperf3(path)
    if kind == "telemetry_meta":
        return loaders.load_telemetry_meta(path)
    if kind == "sar_cpu":
        return loaders.load_sar_cpu(path, sar_adapter)
    if kind == "sar_mem":
        return loaders.load_sar_mem(path, sar_adapter)
    if kind == "scaler":
        return loaders.load_scaler(path)
    if kind == "failover":
        return loaders.load_failover(path, entry.get("probe", ""), int(entry.get("attempt", 1)),
                                     int(entry.get("analysis_rev", 1)))
    if kind == "canary":
        return loaders.load_canary(path)
    if kind == "sync":
        return loaders.load_sync(path)
    ds = loaders.Dataset(kind or "?", path)
    ds.issue(loaders.FATAL, f"unknown dataset kind {kind!r}")
    return ds


def resolve_provenance(entry, ds):
    """Final provenance from the spec, checked against the tool metadata."""
    declared = entry.get("provenance")
    if declared not in PROVENANCES:
        ds.issue(loaders.FATAL, f"spec provenance must be one of {PROVENANCES}, got {declared!r}")
        return None
    claimed = ds.claimed_provenance
    if claimed != loaders.UNKNOWN and declared != claimed:
        ds.issue(loaders.FATAL, f"spec says {declared!r} but the tool metadata says {claimed!r} "
                                f"({ds.provenance_evidence})")
        return None
    return declared


class Processor:
    def __init__(self, spec, out_dir, plots):
        self.spec, self.out_dir, self.plots = spec, out_dir, plots
        self.datasets = {}
        self.issues = []
        self.writer = None

    def add_issue(self, severity, message, dataset=None):
        self.issues.append({"severity": severity, "dataset": dataset, "message": message})

    # --- figures -------------------------------------------------------------------
    def run_figures(self):
        w = self.writer
        by_kind = {}
        for did, ds in self.datasets.items():
            by_kind.setdefault(ds.kind, []).append((did, ds))
        self.fig_m1(by_kind)
        self.fig_m2(by_kind)
        self.fig_m3(by_kind)
        self.fig_m4(by_kind)
        return w

    def fig_m1(self, by_kind):
        w, p = self.writer, self.plots
        for did, ds in by_kind.get("hey", []):
            points = derive.hey_points(ds.data["runs"])
            levels = derive.hey_levels(ds.data["levels"], ds.data["manifest"])
            meta = derive.hey_meta(ds.data["manifest"])
            p.m1_rps(w, f"m1_rps_vs_concurrency_{did}", points, levels, meta, ds.run_id)
            pct = {str(x) for x in meta["percentiles"]}
            if {"95", "99"} <= pct:
                p.m1_latency(w, f"m1_latency_p95_p99_{did}", points, levels, ds.run_id)
            else:
                w.skip(f"m1_latency_p95_p99_{did}", f"hey run did not record p95 and p99 (percentiles={sorted(pct)})")
            p.m1_errors(w, f"m1_error_rate_vs_concurrency_{did}", points, meta, ds.run_id)
        self.fig_m1_resources()
        k6 = [r for _, ds in by_kind.get("k6_summary", []) for r in derive.k6_rows(ds.data["summary"])]
        if k6:
            p.m1_k6(w, "m1_k6_summary", k6)
        for did, ds in by_kind.get("k6_summary", []):
            fid = f"m1_k6_stages_{did}"
            sr = ds.data["summary"].get("stage_results")
            if not sr:
                w.skip(fid, "k6 summary has no stage_results (produced by an older k6_workload.js)")
                continue
            rows = derive.k6_stage_rows(ds.data["summary"])
            if not sr.get("valid"):
                w.skip(fid, f"stage results invalid: {'; '.join(sr.get('problems') or [])}")
                w.table(f"m1_k6_stages_table_{did}", rows, ["stage results invalid; table kept for diagnosis"])
                continue
            notes = [f"attribution: {sr.get('attribution')}", f"rate basis: {sr.get('rate_basis')}",
                     f"completeness: {sr.get('completeness_rule')}", sr.get("selector_threshold_note", "")]
            if not any(r["constant_vu_result"] for r in rows):
                w.skip(fid, "no hold stage qualifies as a constant-VU result (see the table)")
                w.table(f"m1_k6_stages_table_{did}", rows, notes)
                continue
            p.m1_k6_stages(w, fid, rows, ds.run_id, notes)
        for did, ds in by_kind.get("k6_raw", []):
            if ds.data.get("stages"):
                w.table(f"m1_k6_raw_stages_{did}", ds.data["stages"],
                        ["cross-check from k6 --out json points tagged with the stage (request start attribution); "
                         "percentiles computed from the raw samples"])
        for did, ds in by_kind.get("iperf3", []):
            p.m1_iperf3(w, f"m1_iperf3_{did}", derive.iperf3_rows(ds.data["runs"]), ds.run_id)

    def fig_m1_resources(self):
        w, p = self.writer, self.plots
        groups = (self.spec.get("groups") or {}).get("m1_resources") or []
        allowed, note = derive.time_sync_statement(self.spec.get("time_sync"))
        for i, g in enumerate(groups, 1):
            fid = f"m1_resources_vs_concurrency_{i}"
            hey, cpu = self.datasets.get(g.get("hey")), self.datasets.get(g.get("sar_cpu"))
            mem = self.datasets.get(g.get("sar_mem")) if g.get("sar_mem") else None
            if hey is None or hey.kind != "hey" or cpu is None or cpu.kind != "sar_cpu":
                w.skip(fid, f"group {i}: hey / sar_cpu dataset not loaded ({g.get('hey')!r}, {g.get('sar_cpu')!r})")
                continue
            if g.get("sar_mem") and (mem is None or mem.kind != "sar_mem"):
                w.skip(fid, f"group {i}: sar_mem dataset {g.get('sar_mem')!r} not loaded")
                continue
            if "warmup_sec" not in g:
                w.skip(fid, f"group {i}: warmup_sec must be set explicitly (0 = whole run interval)")
                continue
            warmup, min_cov = float(g["warmup_sec"]), float(g.get("min_coverage", 0.9))
            if warmup < 0 or not 0 < min_cov <= 1:
                w.skip(fid, f"group {i}: warmup_sec must be >= 0 and min_coverage in (0, 1]")
                continue
            if not allowed:
                w.skip(fid, note)
                continue
            if not cpu.data.get("rows"):
                w.skip(fid, f"group {i}: no usable CPU rows")
                continue
            mem_data = mem.data if mem is not None and mem.data.get("rows") else None
            runs = derive.resources_by_run(derive.resource_windows(hey.data["runs"], warmup), cpu.data, mem_data,
                                           min_cov)
            levels = derive.resources_by_level(runs)
            window = derive.window_description(warmup)
            notes = [f"window: {window}; CPU {cpu.data['temporal']}; memory "
                     f"{mem.data['temporal'] if mem_data else 'not provided'}",
                     f"status: {derive.RESOURCE_STATUS_RULE}; min_coverage={min_cov:g}; n = used/total runs",
                     "load and resource use in the same window; correlation only, no bottleneck is inferred",
                     note]
            p.m1_resources(w, fid, levels, runs, notes, f"{hey.run_id} / {cpu.data['host']}")
            w.table(f"m1_resources_by_run_{i}", runs, notes)

    def fig_m2(self, by_kind):
        w, p = self.writer, self.plots
        for did, ds in by_kind.get("scaler", []):
            series = derive.scaler_series(ds.data["rows"])
            events = derive.scaler_events(ds.data["events"])
            label = f"{ds.run_id} ({ds.data['prefix']})"
            p.m2_cpu(w, f"m2_cpu_timeline_{did}", series, events, derive.logged_threshold(ds.data["events"]), label)
            p.m2_activation(w, f"m2_activation_timeline_{did}", events, derive.activation_checks(ds.data["events"]),
                            series, label)
        metas = [ds.data["meta"] for _, ds in by_kind.get("telemetry_meta", [])]
        for did, ds in by_kind.get("sar_cpu", []):
            if not ds.data.get("rows"):
                w.skip(f"m2_sar_cpu_{did}", "; ".join(i.message for i in ds.issues) or "no rows")
                continue
            host = ds.data["host"]
            meta = next((m for m in metas if m.get("hostname") == host), None)
            note = (f"telemetry coverage for {host}: {meta['coverage']} (complete_time_series={meta['complete_time_series']})"
                    if meta else f"no telemetry metadata found for host {host}: coverage unknown")
            p.m2_sar(w, f"m2_sar_cpu_{did}", derive.sar_series(ds.data), host, note)
        allowed, note = derive.time_sync_statement(self.spec.get("time_sync"))
        groups = (self.spec.get("groups") or {}).get("m2") or []
        if not groups and by_kind.get("scaler"):
            w.skip("m2_app_performance", "no spec.groups.m2 entry linking the scaler output to hey/k6 raw data")
        for i, g in enumerate(groups, 1):
            fid = f"m2_app_performance_{i}"
            scaler = self.datasets.get(g.get("scaler"))
            apps = [self.datasets.get(a) for a in g.get("app", [])]
            if scaler is None or scaler.kind != "scaler":
                w.skip(fid, f"group {i}: scaler dataset {g.get('scaler')!r} not loaded")
                continue
            if not apps or any(a is None for a in apps):
                w.skip(fid, f"group {i}: no (or unknown) hey / k6 raw dataset listed in app")
                continue
            if not allowed:
                w.skip(fid, note)
                continue
            hey = [iv for a in apps if a.kind == "hey" for iv in derive.hey_intervals(a.data["runs"])]
            bins = [b for a in apps if a.kind == "k6_raw" and a.data.get("rows") for b in a.data["rows"]]
            if not hey and not bins:
                w.skip(fid, f"group {i}: the listed app datasets contain no usable intervals/bins")
                continue
            p.m2_app(w, fid, derive.scaler_series(scaler.data["rows"]), derive.scaler_events(scaler.data["events"]),
                     hey, bins, note, scaler.run_id)

    def fig_m3(self, by_kind):
        w, p = self.writer, self.plots
        runs = {}
        for did, ds in by_kind.get("failover", []) + by_kind.get("failover_tcp", []) + \
                by_kind.get("failover_http", []) + by_kind.get("failover_persistent", []):
            probe = ds.data["probe"]
            ref = ds.data["manifest"]["started_mono_s"]
            series = derive.failover_series(ds.data["records"], ref)
            states = derive.failover_states(ds.data["analysis"], ref, probe)
            if probe == "persistent":
                if states is not None:
                    # 03's persistent analysis does not list the marker it used; select it with 03's own rule
                    usable, _ = failover_analysis.select_markers(derive.markers_from_rows(ds.data["markers"]),
                                                                 ds.run_id, ds.data["manifest"].get("clock_domain"))
                    states["markers"] = [m["monotonic_s"] - ref for m in usable if m["kind"] == "fault_injected"]
                p.m3_persistent(w, f"m3_persistent_{did}", series, states, ds.run_id)
            else:
                p.m3_probe(w, f"m3_{probe}_probes_{did}", series, derive.outage_spans(ds.data["outages"], ref), states,
                           probe, ds.run_id)
            runs.setdefault((ds.run_id, ds.attempt), []).append(ds)
        for (run_id, attempt), group in runs.items():
            fid = f"m3_combined_{run_id}_a{attempt}"
            if len(group) < 2:
                continue
            domains = [g.data["manifest"].get("clock_domain") for g in group]
            mismatch = [failover_analysis.clock_domains_match(domains[0], d)[1] for d in domains[1:]
                        if not failover_analysis.clock_domains_match(domains[0], d)[0]]
            if mismatch:
                w.skip(fid, f"probe processes are not in one clock domain ({'; '.join(mismatch)}): "
                            "monotonic times are not comparable")
                continue
            ref = min(g.data["manifest"]["started_mono_s"] for g in group)
            panels = [(g.data["probe"], derive.failover_series(g.data["records"], ref)) for g in group]
            p.m3_combined(w, fid, panels, run_id, "common monotonic axis: all processes in the same clock domain "
                                                  "(03 clock_domain rule)")

    def fig_m4(self, by_kind):
        w, p = self.writer, self.plots
        canaries = [ds for _, ds in by_kind.get("canary", [])]
        for did, ds in by_kind.get("canary", []):
            probes = ds.data["probes"]
            if not probes:
                w.skip(f"m4_canary_timeline_{did}", "canary probes missing")
                continue
            ref = float(probes[0]["start_mono_s"])
            p.m4_canary(w, f"m4_canary_timeline_{did}", derive.canary_series(probes, ref),
                        derive.canary_events(ds.data["events"], ref), ds.data["summary"], ref,
                        f"{ds.run_id} rep {ds.repetition} attempt {ds.attempt}")
        for run_id in sorted({ds.run_id for ds in canaries}):
            group = [ds for ds in canaries if ds.run_id == run_id]
            dups = derive.duplicate_repetitions(group)
            if dups:
                self.add_issue(loaders.PARTIAL, f"canary run {run_id}: repetitions {dups} appear in several attempts; "
                                                "shown separately per attempt, not merged")
            rows = derive.canary_latency_rows(group)
            if rows:
                p.m4_latency(w, f"m4_latency_by_repetition_{run_id}", rows, run_id)
            else:
                w.skip(f"m4_latency_by_repetition_{run_id}", "no observed latency values (no update sent?)")
        sync = [ds for _, ds in by_kind.get("sync", [])]
        if sync:
            p.m4_sync(w, "m4_feed_sync_summary", derive.sync_rows(sync))


def cmd_process(args):
    with open(args.spec, encoding="utf-8") as f:
        spec = json.load(f)
    pid = spec.get("processing_id") or ""
    if not pid or any(c in pid for c in "/\\:") or pid.startswith("."):
        print("[!] spec.processing_id is required (no path characters)", file=sys.stderr)
        return 2
    out_dir, attempt = make_out_dir(args.output_dir, pid)
    proc = Processor(spec, out_dir, _load(os.path.join(HERE, "plots.py"), "results_plots"))
    manifest = {"processing_id": pid, "attempt": attempt, "created_utc": datetime.now(timezone.utc).isoformat(),
                "spec": {"path": os.path.abspath(args.spec), "sha256": loaders.sha256(args.spec)},
                "time_sync": spec.get("time_sync"), "inputs": [], "issues": [], "figures": [],
                "figures_skipped": [], "data_requirements": DATA_REQUIREMENTS,
                "rules": ["missing values are gaps, never zero", "statuses are shown as logged",
                          "no hidden time offset, interpolation or smoothing",
                          "monotonic times compared only within one process or one clock domain"]}
    status = "ok"
    if spec.get("reviewed_by_operator") is not True:
        proc.add_issue(loaders.FATAL, "spec is not marked reviewed_by_operator: true")
    else:
        for entry in spec.get("datasets", []):
            did = entry.get("id")
            if not did or did in proc.datasets:
                proc.add_issue(loaders.FATAL, f"dataset id {did!r} missing or duplicated")
                continue
            ds = load_dataset(entry, float(spec.get("k6_raw_bin_sec", 1.0)))
            if ds.kind == "scaler":
                ds.run_id = entry.get("run_id", "")
                if not ds.run_id:
                    ds.issue(loaders.FATAL, "scaler dataset needs run_id in the spec")
            elif entry.get("run_id") and entry["run_id"] != ds.run_id:
                ds.issue(loaders.FATAL, f"spec run_id {entry['run_id']!r} != file run_id {ds.run_id!r}")
            final = resolve_provenance(entry, ds)
            manifest["inputs"].append({"id": did, "kind": ds.kind, "path": ds.path, "run_id": ds.run_id,
                                       "attempt": ds.attempt, "repetition": ds.repetition, "files": ds.files,
                                       "provenance": final, "claimed_provenance": ds.claimed_provenance,
                                       "provenance_evidence": ds.provenance_evidence,
                                       "operator_classified": ds.claimed_provenance == loaders.UNKNOWN})
            for issue in ds.issues:
                proc.add_issue(issue.severity, issue.message, did)
            proc.datasets[did] = ds
            ds.final_provenance = final
        finals = {getattr(ds, "final_provenance", None) for ds in proc.datasets.values()}
        if len(finals - {None}) > 1:
            proc.add_issue(loaders.FATAL, f"datasets of different provenance in one processing run: {sorted(finals - {None})}")
    if any(i["severity"] == loaders.FATAL for i in proc.issues) or not proc.datasets:
        status = "failed"
        if not proc.datasets:
            proc.add_issue(loaders.FATAL, "no datasets")
    else:
        provenance = next(iter({ds.final_provenance for ds in proc.datasets.values()}))
        evidence = "; ".join(sorted({ds.provenance_evidence for ds in proc.datasets.values()}))[:200]
        proc.writer = proc.plots.FigureWriter(out_dir, provenance, evidence)
        manifest["provenance"] = provenance
        proc.run_figures()
        manifest["figures"] = proc.writer.produced
        manifest["figures_skipped"] = proc.writer.skipped
    manifest["status"] = status
    manifest["issues"] = proc.issues
    with open(os.path.join(out_dir, "processing_manifest.json"), "x", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, default=str)
    print(f"[{'+' if status == 'ok' else '!'}] processing {status}: {len(manifest['figures'])} figures, "
          f"{len(manifest['figures_skipped'])} skipped -> {out_dir}")
    for i in proc.issues:
        if i["severity"] == loaders.FATAL:
            print(f"    fatal: {i['message']} ({i['dataset']})", file=sys.stderr)
    return 0 if status == "ok" else 2


def cmd_scan(args):
    entries = loaders.scan(args.root)
    datasets = []
    for e in entries:
        ds = load_dataset(e, 1.0)
        e.update({"provenance": ds.claimed_provenance, "provenance_evidence": ds.provenance_evidence,
                  "run_id": e.get("run_id", ds.run_id), "review_note": "check provenance, run_id and grouping"})
        datasets.append(e)
    spec = {"processing_id": "", "reviewed_by_operator": False, "time_sync": None, "k6_raw_bin_sec": 1.0,
            "groups": {"m2": [], "m1_resources": []}, "datasets": datasets,
            "notes": ["draft written by scan; review every entry and set reviewed_by_operator to true",
                      "unknown provenance needs your classification (simulated / real / unknown)",
                      "time_sync is an operator statement: {statement, source, known_uncertainty}; no default"]}
    with open(args.out, "x", encoding="utf-8") as f:
        json.dump(spec, f, indent=2, default=str)
    print(f"[+] spec draft with {len(datasets)} dataset(s) -> {args.out} (review before processing)")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="Common result processing (read-only on inputs)")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scan")
    s.add_argument("--root", action="append", required=True)
    s.add_argument("--out", required=True)
    r = sub.add_parser("process")
    r.add_argument("--spec", required=True)
    r.add_argument("--output-dir", default=os.path.join(HERE, "processed"))
    args = p.parse_args(argv)
    try:
        return cmd_scan(args) if args.command == "scan" else cmd_process(args)
    except (FileExistsError, FileNotFoundError, ValueError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
