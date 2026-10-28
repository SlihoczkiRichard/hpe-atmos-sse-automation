#!/usr/bin/env python3
"""
Results: matplotlib figures (Agg backend) from derived data; every figure is saved as PNG and PDF
together with the CSV of exactly the values it shows.

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

Provenance marking: simulated input -> watermark "SIMULATED – NOT A REAL MEASUREMENT"; unknown
provenance -> watermark "PROVENANCE UNKNOWN – NOT CLASSIFIED AS A REAL MEASUREMENT"; real input
(tool metadata or operator classification) -> a footer naming the provenance evidence.
Statuses are drawn as logged; colours are generic per status value, no status is special-cased.
"""

import os
import csv
import math

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt          # noqa: E402
import matplotlib.dates as mdates        # noqa: E402

WATERMARKS = {"simulated": "SIMULATED – NOT A REAL MEASUREMENT",
              "unknown": "PROVENANCE UNKNOWN – NOT CLASSIFIED AS A REAL MEASUREMENT"}
STATUS_COLORS = {"verified": "#2e7d32", "unverified": "#f9a825", "not_checked": "#9e9e9e", "failed": "#c62828",
                 "timeout": "#ef6c00"}
CLASS_COLORS = {"reachable": "#2e7d32", "blocked": "#c62828", "unclassified_403": "#ef6c00",
                "unexpected_response": "#6a1b9a"}
EVENT_STYLE = {"THRESHOLD_MET": "#1565c0", "SCALE_OUT_DECISION": "#283593", "POWER_ON_SENT": "#000000",
               "VM_POWERED_ON": "#2e7d32", "POWER_ON_TIMEOUT": "#c62828", "POWER_ON_FAILED": "#c62828"}


class FigureWriter:
    def __init__(self, out_dir, provenance, evidence_note=""):
        self.out_dir, self.provenance, self.evidence_note = out_dir, provenance, evidence_note
        self.produced, self.skipped = [], []

    def skip(self, figure_id, reason):
        self.skipped.append({"figure": figure_id, "reason": reason})

    def _mark(self, fig, footnotes):
        if self.provenance in WATERMARKS:
            text = WATERMARKS[self.provenance]
            fig.text(0.5, 0.5, text, fontsize=26, color="#c62828", alpha=0.22, ha="center", va="center",
                     rotation=24, transform=fig.transFigure, zorder=1000)
            fig.text(0.5, 0.995, text, fontsize=11, color="#c62828", ha="center", va="top", weight="bold")
        else:
            footnotes = [f"provenance: real ({self.evidence_note})"] + footnotes
        if footnotes:
            fig.text(0.01, 0.005, "\n".join(footnotes), fontsize=7, ha="left", va="bottom", color="#424242")

    def save(self, fig, figure_id, rows, footnotes=(), notes=""):
        self._mark(fig, list(footnotes))
        paths = {}
        for ext in ("png", "pdf"):
            path = os.path.join(self.out_dir, f"{figure_id}.{ext}")
            if os.path.exists(path):
                raise FileExistsError(path)
            fig.savefig(path, dpi=130)
            paths[ext] = os.path.basename(path)
        plt.close(fig)
        csv_path = os.path.join(self.out_dir, f"{figure_id}.csv")
        fields = sorted({k for r in rows for k in r}) if rows else ["empty"]
        with open(csv_path, "x", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            for r in rows:
                w.writerow({k: _cell(r.get(k)) for k in fields})
        self.produced.append({"figure": figure_id, "files": [paths["png"], paths["pdf"], os.path.basename(csv_path)],
                              "rows": len(rows), "notes": notes, "footnotes": list(footnotes),
                              "watermark": WATERMARKS.get(self.provenance, "")})

    def table(self, table_id, rows, notes=()):
        """A processed CSV table without a figure; every row carries the provenance column (a CSV cannot
        carry a watermark)."""
        rows = _table_rows(rows, self.provenance)
        csv_path = os.path.join(self.out_dir, f"{table_id}.csv")
        fields = sorted({k for r in rows for k in r}) if rows else ["empty"]
        with open(csv_path, "x", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            for r in rows:
                w.writerow({k: _cell(r.get(k)) for k in fields})
        self.produced.append({"figure": table_id, "kind": "table", "files": [os.path.basename(csv_path)],
                              "rows": len(rows), "notes": list(notes), "footnotes": [],
                              "watermark": WATERMARKS.get(self.provenance, "")})


def _table_rows(rows, provenance):
    return [dict(r, provenance=provenance) for r in rows]


def _cell(v):
    if isinstance(v, float) and math.isnan(v):
        return ""
    if hasattr(v, "isoformat"):
        return v.isoformat()
    return v


def _fig(rows=1, height=4.2, sharex=True, left=0.08, right=0.97):
    fig, axes = plt.subplots(rows, 1, figsize=(12, height * rows), sharex=sharex, squeeze=False)
    fig.subplots_adjust(top=0.88, bottom=0.17, left=left, right=right, hspace=0.4)
    return fig, [a[0] for a in axes]


_LINESTYLES = ("--", "-.", ":", (0, (5, 1, 1, 1)))


def _vlines(axes, events, key="t_s", label_key="event"):
    """Event lines with legend labels (one legend entry per event name; no overlapping in-plot text)."""
    axes = axes if isinstance(axes, (list, tuple)) else [axes]
    names = []
    for e in events:
        x = e[key]
        if x is None or (isinstance(x, float) and math.isnan(x)):
            continue
        name = e[label_key]
        first = name not in names
        if first:
            names.append(name)
        i = names.index(name)
        color = EVENT_STYLE.get(name, plt.cm.tab10(i % 10))
        for n, ax in enumerate(axes):
            ax.axvline(x, color=color, lw=1.0, ls=_LINESTYLES[i % len(_LINESTYLES)], alpha=0.85,
                       label=name if (n == 0 and first) else None)


def _outside_legend(ax):
    ax.legend(fontsize=7, loc="upper left", bbox_to_anchor=(1.01, 1.0), borderaxespad=0.0)


# ------------------------------------------------------------------------------
# Measurement 1
# ------------------------------------------------------------------------------

def m1_rps(w, fid, points, levels, meta, run_id):
    fig, (ax,) = _fig()
    for sweep in sorted({p["sweep"] for p in points}):
        ps = [p for p in points if p["sweep"] == sweep]
        ax.plot([p["concurrency"] for p in ps], [p["successful_rps"] for p in ps], "o", alpha=0.6,
                label=f"sweep {sweep} (run)")
    ax.plot([lv["concurrency"] for lv in levels], [lv["successful_rps_median"] for lv in levels], "-", color="k",
            label="median of runs (levels.csv)")
    for lv in levels:
        if lv["status"] == "accepted":
            ax.axvspan(lv["concurrency"] * 0.97, lv["concurrency"] * 1.03, color="#c8e6c9", alpha=0.6, zorder=0)
        elif lv["status"] == "invalid":
            ax.axvspan(lv["concurrency"] * 0.97, lv["concurrency"] * 1.03, color="#ffcdd2", alpha=0.6, zorder=0)
        if lv["best_accepted_level"]:
            ax.annotate(f"best accepted level c={lv['concurrency']}", (lv["concurrency"], lv["successful_rps_median"]),
                        xytext=(-140, -30), textcoords="offset points", arrowprops={"arrowstyle": "->"}, fontsize=8)
    ax.set(xlabel="concurrency (hey -c)", ylabel="successful responses / s",
           title=f"hey {run_id}: successful RPS per run (green = accepted level, red = invalid level)")
    ax.legend(fontsize=8)
    notes = ["acceptance: every run of a level valid and primary error rate < "
             f"{meta['accept_max_error_rate']}; best accepted level is not a physical saturation point"]
    if meta.get("non_monotonic"):
        notes.append("non_monotonic: a higher level was accepted after a rejected one")
    w.save(fig, fid, points + [dict(lv, row="level") for lv in levels], notes)


def m1_latency(w, fid, points, levels, run_id):
    fig, (ax,) = _fig()
    for key, marker in (("lat_all_responses_p95_ms", "o"), ("lat_all_responses_p99_ms", "s")):
        ax.plot([p["concurrency"] for p in points], [p[key] for p in points], marker, alpha=0.5,
                label=key.replace("lat_all_responses_", "").replace("_ms", "") + " per run")
    ax.plot([lv["concurrency"] for lv in levels], [lv["lat_all_responses_p95_ms_median"] for lv in levels], "-",
            label="p95 median of runs")
    ax.plot([lv["concurrency"] for lv in levels], [lv["lat_all_responses_p99_ms_median"] for lv in levels], "--",
            label="p99 median of runs")
    ax.set(xlabel="concurrency", ylabel="latency [ms]",
           title=f"hey {run_id}: latency percentiles over ALL HTTP responses (not success-only)")
    ax.legend(fontsize=8)
    w.save(fig, fid, points, ["hey latency covers every HTTP response (any status), transport errors excluded"])


def m1_errors(w, fid, points, meta, run_id):
    fig, (ax,) = _fig()
    ax.plot([p["concurrency"] for p in points], [p["primary_error_rate"] for p in points], "o",
            label="primary error rate (non-success + transport) per run")
    ax.plot([p["concurrency"] for p in points], [p["err5xx_transport_error_rate"] for p in points], "x",
            label="5xx + transport rate per run (comparison only)")
    if meta.get("accept_max_error_rate") is not None:
        ax.axhline(meta["accept_max_error_rate"], color="#c62828", ls="--", label="acceptance limit (strictly below)")
    ax.set(xlabel="concurrency", ylabel="share of request attempts", title=f"hey {run_id}: error rates per run")
    ax.legend(fontsize=8)
    w.save(fig, fid, points)


def m1_resources(w, fid, levels, run_rows, footnotes, label):
    """Per-level medians of complete windows (lines) plus every run (points; hollow = not complete,
    not part of the median). Load and resource use are shown side by side; no causality is implied."""
    fig, (ax1, ax2, ax3) = _fig(3, 3.0)
    xs = [lv["concurrency"] for lv in levels]
    for key, style, name in (("cpu_not_idle_pct", "o-", "cpu_not_idle_pct"),
                             ("cpu_busy_excl_iowait_pct", "s--", "cpu_busy_excl_iowait_pct")):
        ys = [lv[f"{key}_mean_median"] for lv in levels]
        lo = [y - lv[f"{key}_mean_min"] for y, lv in zip(ys, levels)]
        hi = [lv[f"{key}_mean_max"] - y for y, lv in zip(ys, levels)]
        ax1.errorbar(xs, ys, yerr=[lo, hi], fmt=style, capsize=3, label=f"{name}\n(median, min-max)")
    part = [r for r in run_rows if r.get("cpu_status") == "partial"]
    if part:
        ax1.plot([r["concurrency"] for r in part], [r["cpu_not_idle_pct_mean"] for r in part], "o", mfc="none",
                 color="#757575", label="partial window\n(not in the median)")
    for lv in levels:
        ax1.annotate(f"n={lv['cpu_runs_used']}/{lv['runs_total']}", (lv["concurrency"], 2), fontsize=7, ha="center")
    ax1.set(ylabel="CPU % (window mean)", ylim=(0, 105), title=f"connector CPU per hey level: {label}")
    _outside_legend(ax1)
    ax2.plot(xs, [lv["mem_used_pct_mean_median"] for lv in levels], "o-", label="mem_used_pct\n(sysstat %memused)")
    for lv in levels:
        ax2.annotate(f"n={lv['mem_runs_used']}/{lv['runs_total']}", (lv["concurrency"], 2), fontsize=7, ha="center")
    ax2.set(ylabel="memory used % (window mean)", ylim=(0, 105), title="connector memory per hey level")
    _outside_legend(ax2)
    ax3.plot(xs, [lv["successful_rps_median_cpu_runs"] for lv in levels], "o-", color="k",
             label="hey successful RPS\n(median, same runs as CPU)")
    ax3.set(xlabel="concurrency (hey -c)", ylabel="successful responses / s", title="offered load result (hey)")
    _outside_legend(ax3)
    fig.subplots_adjust(right=0.78)
    footnotes = ["cpu_not_idle_pct = 100 - %idle; cpu_busy_excl_iowait_pct = 100 - %idle - %iowait (scaler formula, "
                 "comparable, not identical)"] + [n for n in footnotes if n]
    w.save(fig, fid, levels, footnotes)


def m1_k6(w, fid, rows):
    fig, (ax,) = _fig(height=3.2)
    ax.axis("off")
    keys = ["run_id", "valid", "attempts", "successful_rps_whole_test", "primary_error_rate",
            "err5xx_transport_error_rate", "chain_p95_ms", "chain_p99_ms", "final_hop_p95_ms", "final_hop_p99_ms"]
    cells = [[_fmt(r.get(k)) for k in keys] for r in rows]
    t = ax.table(cellText=cells, colLabels=keys, loc="center")
    t.auto_set_font_size(False)
    t.set_fontsize(7)
    ax.set_title("k6 whole-test summary (not per concurrency level; separate from hey)")
    w.save(fig, fid, rows, ["k6 summary values cover the whole test incl. ramps; no per-plateau split"])


def m1_k6_stages(w, fid, rows, run_id, notes):
    """Only constant-VU hold results are plotted (x = target VUs); ramp, warm-up, ramp-down and
    after-planned-end rows stay in the CSV with their reasons."""
    holds = [r for r in rows if r["constant_vu_result"]]
    fig, (ax1, ax2, ax3) = _fig(3, 2.8)
    xs = [r["target_vus"] for r in holds]
    ax1.plot(xs, [r["successful_rps"] for r in holds], "o-", label="successful attempts started / s (hold)")
    ax1.set(ylabel="successful / s", title=f"k6 {run_id}: constant-VU hold stages only")
    ax2.plot(xs, [r["primary_error_rate"] for r in holds], "o-", color="#c62828", label="primary error rate")
    ax2.set(ylabel="share of attempts")
    ax3.plot(xs, [r["chain_p95_ms"] for r in holds], "o-", label="p95 (success request chain)")
    ax3.plot(xs, [r["chain_p99_ms"] for r in holds], "s--", label="p99 (success request chain)")
    ax3.set(xlabel="target VUs of the hold", ylabel="latency [ms]")
    for ax in (ax1, ax2, ax3):
        ax.legend(fontsize=8)
    excluded = [f"{r['stage']} ({r['kind']})" for r in rows if not r["constant_vu_result"]]
    footnotes = [n for n in notes if n] + ([f"not plotted (see CSV): {', '.join(excluded)}"] if excluded else [])
    w.save(fig, fid, rows, footnotes)


def m1_iperf3(w, fid, rows, run_id):
    fig, (ax1, ax2) = _fig(2, 3.2)
    for label in sorted({r["path_label"] for r in rows}):
        rs = sorted((r for r in rows if r["path_label"] == label), key=lambda r: r["round"])
        ver = rs[0]["path_verification"] if rs else ""
        ax1.plot([r["round"] for r in rs], [r["received_mbps"] for r in rs], "o-", label=f"{label} ({ver})")
        ax2.plot([r["round"] for r in rs], [r["sender_tcp_retransmits"] for r in rs], "s-", label=label)
    ax1.set(ylabel="received Mbit/s", title=f"iperf3 {run_id}: per round (label != verified path)")
    ax2.set(xlabel="round", ylabel="sender TCP retransmits (not packet loss)")
    ax1.legend(fontsize=8)
    w.save(fig, fid, rows)


def _fmt(v):
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "—"
    return f"{v:.4g}" if isinstance(v, float) else str(v)


# ------------------------------------------------------------------------------
# Measurement 2
# ------------------------------------------------------------------------------

def m2_cpu(w, fid, series, events, threshold, label):
    fig, (ax,) = _fig(right=0.74)
    ax.plot([s["c1_t_s"] for s in series], [s["c1_cpu_pct"] for s in series], "-o", ms=3, label="C1 CPU (scaler)")
    ax.plot([s["c2_t_s"] for s in series], [s["c2_cpu_pct"] for s in series], "-o", ms=3,
            label="C2 CPU (scaler; only when sampled, gaps = no valid sample)")
    if threshold is not None:
        ax.axhline(threshold, color="#1565c0", ls=":", label=f"scale-out threshold {threshold}% (as logged)")
    _vlines(ax, [e for e in events if e["event"] in EVENT_STYLE])
    ax.set(xlabel="scaler monotonic time [s]", ylabel="busy CPU [%]", ylim=(0, 105),
           title=f"scaler {label}: C1/C2 CPU and activation events")
    _outside_legend(ax)
    w.save(fig, fid, series, ["source: scaler GuestCpuSampler (/proc/stat over SSH), not sar"])


def m2_activation(w, fid, events, activations, series, label):
    fig, (ax1, ax2) = _fig(2, 3.6, sharex=False, left=0.24)
    names = []
    for e in events:
        if e["event"] in ("ACTIVATION_CHECK", "ACTIVATION_SUMMARY"):
            continue
        if e["event"] not in names:
            names.append(e["event"])
        ax1.plot(e["t_s"], names.index(e["event"]), "|", ms=12, color=EVENT_STYLE.get(e["event"], "#616161"))
    reach = [(s["cycle_start_s"], s["application_reachable"]) for s in series if s["application_reachable"]]
    if reach:
        names.append("application_reachable (scaler probe)")
        y = len(names) - 1
        for t, v in reach:
            ax1.plot(t, y, "s", ms=4, color="#2e7d32" if v == "yes" else "#c62828")
    ax1.set_yticks(range(len(names)), names, fontsize=7)
    ax1.set(xlabel="scaler monotonic time [s]", title=f"scaler {label}: logged events")
    ax2.axis("off")
    rows = []
    for i, act in enumerate(activations, 1):
        for c in act["checks"]:
            rows.append({"activation": i, "close_reason": act["reason"], **c})
    if rows:
        t = ax2.table(cellText=[[r["activation"], r["check"], r["status"], r["detail"][:70]] for r in rows],
                      colLabels=["#", "check", "logged status", "logged detail"], loc="upper center",
                      colWidths=[0.05, 0.33, 0.14, 0.48], cellLoc="left")
        t.auto_set_font_size(False)
        t.set_fontsize(6.5)
        for (ri, ci), cell in t.get_celld().items():
            if ri > 0 and ci == 2:
                cell.set_facecolor(STATUS_COLORS.get(rows[ri - 1]["status"], "#ffffff"))
    ax2.set_title("activation checks as logged by the scaler (statuses shown verbatim)", fontsize=9)
    w.save(fig, fid, rows or [{"note": "no ACTIVATION_CHECK events"}])


def m2_sar(w, fid, series, host, coverage_note):
    fig, (ax,) = _fig()
    ax.plot([s["utc"] for s in series], [s["cpu_not_idle_pct"] for s in series], "-",
            label="cpu_not_idle_pct = 100 - %idle")
    ax.plot([s["utc"] for s in series], [s["cpu_busy_excl_iowait_pct"] for s in series], "-", lw=0.8,
            label="cpu_busy_excl_iowait_pct = 100 - %idle - %iowait (scaler formula)")
    ax.plot([s["utc"] for s in series], [s["iowait_pct"] for s in series], "-", lw=0.8, label="%iowait")
    ax.plot([s["utc"] for s in series], [s["steal_pct"] for s in series], "-", lw=0.8, label="%steal")
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
    ax.set(xlabel="UTC (VM clock as exported by sadf)", ylabel="%", ylim=(0, 105),
           title=f"sar CPU on {host} (separate source from the scaler CPU samples)")
    ax.legend(fontsize=8)
    w.save(fig, fid, series, [coverage_note] if coverage_note else [])


def m2_app(w, fid, scaler_series, scaler_events, hey_intervals, k6_bins, footnote, label):
    fig, (ax1, ax2) = _fig(2, 3.8, right=0.74)
    ax1.plot([s["utc"] for s in scaler_series], [s["c1_cpu_pct"] for s in scaler_series], "-o", ms=2, label="C1 CPU")
    ax1.plot([s["utc"] for s in scaler_series], [s["c2_cpu_pct"] for s in scaler_series], "-o", ms=2, label="C2 CPU")
    _vlines([ax1, ax2], [e for e in scaler_events if e["event"] in EVENT_STYLE and e["utc"]], key="utc")
    ax1.set(ylabel="busy CPU [%] (scaler)", title=f"activation {label} and application performance (UTC)")
    _outside_legend(ax1)
    rows = []
    for iv in hey_intervals:
        ax2.hlines(iv["successful_rps"], iv["start_utc"], iv["end_utc"], colors="#1565c0" if iv["valid"] else "#c62828",
                   lw=3, label=None if rows else "hey run aggregate over its interval")
        rows.append(dict(iv, source="hey run aggregate (interval, not a continuous curve)"))
    if k6_bins:
        ax2.plot([b["bin_start_utc"] for b in k6_bins], [b["success"] for b in k6_bins], ".", color="#6a1b9a",
                 label="k6 successes per bin (raw JSON)")
        rows += [dict(b, source="k6 raw bin") for b in k6_bins]
    ax2.set(xlabel="UTC", ylabel="successful responses / s (hey) or per bin (k6)")
    ax2.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
    _outside_legend(ax2)
    w.save(fig, fid, rows + [dict(s, source="scaler") for s in scaler_series],
           [footnote, "hey values are per-run aggregates drawn over each run's interval"])


# ------------------------------------------------------------------------------
# Measurement 3
# ------------------------------------------------------------------------------

def m3_probe(w, fid, series, spans, states, probe, run_id):
    fig, (ax1, ax2) = _fig(2, 3.2, right=0.76)
    ok = [s for s in series if s["ok"]]
    bad = [s for s in series if not s["ok"]]
    ax1.plot([s["t_s"] for s in ok], [1] * len(ok), "|", color="#2e7d32", label="success")
    ax1.plot([s["t_s"] for s in bad], [0] * len(bad), "|", color="#c62828", label="failure")
    ax2.plot([s["t_s"] for s in series], [s["duration_ms"] for s in series], ".", ms=2)
    for sp in spans:
        for ax in (ax1, ax2):
            ax.axvspan(sp["start_t_s"], sp["end_t_s"], color="#ffcdd2", alpha=0.5, zorder=0)
    title = f"{probe} probes {run_id}"
    notes = []
    if states:
        lines = [{"t_s": m["t_s"], "event": f"marker {m['kind']} (operator_signal)"} for m in states["markers"]]
        lines += [{"t_s": states[k], "event": k.replace("_t_s", "")}
                  for k in ("first_failure_t_s", "first_success_t_s", "stable_first_success_t_s", "stable_confirmed_t_s")
                  if states.get(k) is not None]
        _vlines([ax1, ax2], lines)
        title += f" | outcome={states['outcome']} | run_validity={states['run_validity']}"
        if states["run_validity"] != "valid":
            fig.text(0.5, 0.93, "NOT VALID: " + "; ".join(states["validity_reasons"])[:160], color="#c62828",
                     ha="center", fontsize=9, weight="bold")
        notes += [f"rejected marker: {m['reason']}" for m in states.get("markers_rejected", [])]
    else:
        notes.append("no analysis file: outcome and recovery not shown")
    ax1.set(ylim=(-0.6, 1.5), yticks=[0, 1], yticklabels=["fail", "ok"], title=title)
    ax2.set(xlabel="seconds since probe process start (monotonic)", ylabel="probe duration [ms]")
    _outside_legend(ax1)
    w.save(fig, fid, series + [dict(sp, row="outage") for sp in spans], notes)


def m3_persistent(w, fid, series, states, run_id):
    fig, (ax,) = _fig(height=3.2, right=0.7)
    ex = [s for s in series if s["event"] == "exchange"]
    ax.plot([s["t_s"] for s in ex if s["ok"]], [1] * sum(1 for s in ex if s["ok"]), "|", color="#2e7d32")
    ax.plot([s["t_s"] for s in ex if not s["ok"]], [0] * sum(1 for s in ex if not s["ok"]), "|", color="#c62828")
    title = f"persistent connection {run_id}"
    if states:
        lines = [{"t_s": t, "event": "marker (operator_signal)"} for t in states["markers"]]
        if states.get("end_t_s") is not None:
            lines.append({"t_s": states["end_t_s"],
                          "event": f"end: {states['end_reason']} (cause: {states['end_cause']})"})
        _vlines(ax, lines)
        _outside_legend(ax)
        title += f" | continuity={states['continuity']} | run_validity={states['run_validity']}"
    ax.set(ylim=(-0.6, 1.5), yticks=[0, 1], yticklabels=["fail", "ok"], title=title,
           xlabel="seconds since probe process start (monotonic)")
    w.save(fig, fid, series)


def m3_combined(w, fid, panels, run_id, note):
    fig, axes = _fig(len(panels), 1.8)
    rows = []
    for ax, (probe, series) in zip(axes, panels):
        ax.plot([s["t_s"] for s in series if s["ok"]], [1] * sum(s["ok"] for s in series), "|", color="#2e7d32")
        ax.plot([s["t_s"] for s in series if not s["ok"]], [0] * sum(not s["ok"] for s in series), "|",
                color="#c62828")
        ax.set(ylim=(-0.6, 1.6), yticks=[0, 1], yticklabels=["fail", "ok"], ylabel=probe)
        rows += [dict(s, probe=probe) for s in series]
    axes[0].set_title(f"failover {run_id}: probe types on one monotonic axis")
    axes[-1].set_xlabel("seconds since the earliest probe process start (common monotonic clock)")
    w.save(fig, fid, rows, [note])


# ------------------------------------------------------------------------------
# Measurement 4
# ------------------------------------------------------------------------------

def m4_canary(w, fid, series, events, summary, ref_mono, label):
    fig, (ax,) = _fig(height=4.6, left=0.13, right=0.72)
    classes = sorted({s["class"] for s in series})
    for i, c in enumerate(classes):
        pts = [s["t_s"] for s in series if s["class"] == c]
        ax.plot(pts, [i] * len(pts), "|", ms=10, color=CLASS_COLORS.get(c, "#616161"), label=c)
    tl = summary.get("timeline") or {}
    lines = list(events)
    # first blocked probe (start and end), stable run start and its confirmation: separate entries
    for key, edge in (("T_first_blocked", "start_mono_s"), ("T_first_blocked", "end_mono_s"),
                      ("stable_run_first", "start_mono_s"), ("stable_run_confirmed", "end_mono_s")):
        if tl.get(key):
            lines.append({"t_s": tl[key][edge] - ref_mono, "event": f"{key} ({edge.split('_')[0]})"})
    _vlines(ax, lines)
    _outside_legend(ax)
    ax.set_yticks(range(len(classes)), classes, fontsize=8)
    ax.set(xlabel="seconds since the first canary probe (monotonic)",
           title=f"canary {label}: outcome={summary.get('outcome')} | run_validity={summary.get('run_validity')}")
    w.save(fig, fid, series + [dict(e, row="event") for e in events],
           ["403/timeout/TLS/DNS are separate classes, not blocking; restore of category and access are separate"])


def m4_latency(w, fid, rows, run_id):
    fig, (ax,) = _fig(right=0.68)
    refs = sorted({r["reference"] for r in rows})
    reps = sorted({(r["repetition"], r["attempt"]) for r in rows})
    combos = [(ref, metric) for ref in refs for metric in ("first_blocked_start_ms", "stable_run_confirmed_end_ms")]
    width = 0.84 / len(combos)
    for k, (ref, metric) in enumerate(combos):
        xs, ys = [], []
        for j, rep in enumerate(reps):
            r = next((x for x in rows if x["reference"] == ref and (x["repetition"], x["attempt"]) == rep), None)
            if r is not None:
                xs.append(j - 0.42 + width * (k + 0.5))
                ys.append(r.get(metric, float("nan")))
        ax.bar(xs, ys, width * 0.95, color=plt.cm.tab20(k % 20),
               label=f"{'first blocked (start)' if metric.startswith('first') else 'stable confirmed (end)'}, {ref}")
    ax.axhline(0, color="k", lw=0.8)
    ax.set_xticks(range(len(reps)), [f"repetition {r} (attempt {a})" for r, a in reps], fontsize=8)
    ax.set(ylabel="observed blocking latency [ms] (signed)",
           title=f"canary {run_id}: observed blocking latency per repetition (negative values kept)")
    _outside_legend(ax)
    w.save(fig, fid, rows, ["perceived by the probes; not an internal rule-enforcement time"])


def m4_sync(w, fid, rows):
    fig, (ax,) = _fig(height=2.8)
    ax.axis("off")
    keys = ["run_id", "command", "attempt", "state", "hosts", "ip_indicators_saved_only", "excluded", "rejected",
            "write_outcome", "commit_outcome"]
    t = ax.table(cellText=[[_fmt(r.get(k)) for k in keys] for r in rows], colLabels=keys, loc="center")
    t.auto_set_font_size(False)
    t.set_fontsize(7)
    ax.set_title("feed synchronisation results (separate from the canary measurement)")
    w.save(fig, fid, rows)
