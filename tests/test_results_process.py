"""05-results end to end: scan -> reviewed spec -> process, on SIMULATED module outputs (offline).

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

The inputs come from the modules' own dry-run code paths (_results_fixtures.build); figures are
checked for existence, manifests and skip reasons, not pixel by pixel.
"""

import contextlib
import copy
import glob
import io
import json
import os
import re
import shutil
import tempfile
import unittest

import matplotlib.pyplot as plt

from _helpers import OfflineTestCase, load_module
import _results_fixtures as fx

pr = load_module("05-results/process_results.py", "process_results")
plots = load_module("05-results/plots.py", "results_plots")


def quiet(fn, *a):
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return fn(*a)


class ProcessTests(OfflineTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.tmp = tempfile.mkdtemp()
        cls.inputs = os.path.join(cls.tmp, "inputs")
        fx.build(cls.inputs)
        draft = os.path.join(cls.tmp, "draft.json")
        assert quiet(pr.main, ["scan", "--root", cls.inputs, "--out", draft]) == 0
        with open(draft, encoding="utf-8") as f:
            cls.draft = json.load(f)
        cls.hashes = {p: pr.loaders.sha256(p) for p in glob.glob(os.path.join(cls.inputs, "**", "*"), recursive=True)
                      if os.path.isfile(p)}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)
        super().tearDownClass()

    def run_spec(self, spec, name):
        path = os.path.join(self.tmp, f"{name}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(spec, f)
        out = os.path.join(self.tmp, "out")
        code = quiet(pr.main, ["process", "--spec", path, "--output-dir", out, "--diagnostic"])
        pid = spec.get("processing_id")
        dirs = [d for d in glob.glob(os.path.join(out, f"{pid}*"))
                if re.fullmatch(re.escape(pid) + r"(\.attempt\d+)?", os.path.basename(d))]
        run_dir = max(dirs, key=lambda d: int(d.rsplit(".attempt", 1)[1]) if ".attempt" in d else 1)
        with open(os.path.join(run_dir, "processing_manifest.json"), encoding="utf-8") as f:
            return code, json.load(f), run_dir

    def spec(self, pid, **kw):
        return fx.reviewed_spec(self.inputs, copy.deepcopy(self.draft["datasets"]), pid, **kw)

    def test_scan_draft_needs_review(self):
        self.assertFalse(self.draft["reviewed_by_operator"])
        kinds = sorted({d["kind"] for d in self.draft["datasets"]})
        self.assertEqual(kinds, ["canary", "failover", "hey", "iperf3", "k6_summary", "sar_cpu", "sar_mem", "scaler",
                                 "sync", "telemetry_meta"])
        unknown = {d["kind"] for d in self.draft["datasets"] if d["provenance"] == "unknown"}
        self.assertEqual(unknown, {"sar_cpu", "sar_mem", "telemetry_meta", "sync"})
        draft = dict(self.draft, processing_id="UNREVIEWED")
        code, manifest, _ = self.run_spec(draft, "unreviewed")
        self.assertEqual((code, manifest["status"]), (2, "failed"))
        self.assertIn("reviewed_by_operator", manifest["issues"][0]["message"])

    def test_full_simulated_processing(self):
        code, m, run_dir = self.run_spec(self.spec("FULL"), "full")
        self.assertEqual((code, m["status"], m["provenance"]), (0, "ok", "simulated"))
        figures = {f["figure"] for f in m["figures"]}
        for prefix in ("m1_rps_vs_concurrency", "m1_latency_p95_p99", "m1_error_rate_vs_concurrency", "m1_k6_summary",
                       "m1_iperf3", "m2_cpu_timeline", "m2_activation_timeline", "m2_sar_cpu", "m2_app_performance",
                       "m3_tcp_probes", "m3_http_probes", "m3_persistent", "m3_combined", "m4_canary_timeline",
                       "m4_latency_by_repetition", "m4_feed_sync_summary", "m1_resources_vs_concurrency",
                       "m1_resources_by_run", "m1_k6_stages", "m1_k6_raw_stages"):
            self.assertTrue(any(f.startswith(prefix) for f in figures), prefix)
        for f in m["figures"]:
            self.assertEqual(f["watermark"], "SIMULATED – NOT A REAL MEASUREMENT")
            for name in f["files"]:
                self.assertGreater(os.path.getsize(os.path.join(run_dir, name)), 0, name)
        self.assertEqual(m["figures_skipped"], [])
        self.assertTrue(any("RUN_ID" in i["message"] for i in m["issues"] if i["severity"] == "partial"))
        self.assertTrue(any("partial_late_start" in i["message"] for i in m["issues"]))
        self.assertTrue(any(r["figure"].startswith("m2_sar") for r in m["data_requirements"]))
        # raw inputs untouched
        for path, digest in self.hashes.items():
            self.assertEqual(pr.loaders.sha256(path), digest, path)
        # the sar figure CSV keeps the sar source separate from the scaler CPU
        with open(os.path.join(run_dir, next(f for f in figures if f.startswith("m2_sar")) + ".csv"),
                  encoding="utf-8") as f:
            header = f.readline()
        self.assertIn("cpu_not_idle_pct", header)
        self.assertIn("cpu_busy_excl_iowait_pct", header)

    def test_resource_tables_keep_partial_windows_out_of_the_level_median(self):
        code, m, run_dir = self.run_spec(self.spec("RES"), "res")
        self.assertEqual(code, 0)
        import csv
        with open(os.path.join(run_dir, "m1_resources_by_run_1.csv"), encoding="utf-8") as f:
            runs = list(csv.DictReader(f))
        with open(os.path.join(run_dir, "m1_resources_vs_concurrency_1.csv"), encoding="utf-8") as f:
            levels = {int(r["concurrency"]): r for r in csv.DictReader(f)}
        self.assertTrue(all(r["provenance"] == "simulated" for r in runs))
        self.assertTrue(all(r["cpu_status"] == "complete" for r in runs))          # sadf CPU covers every run
        mem_states = {r["mem_status"] for r in runs}
        self.assertTrue({"complete"} < mem_states)                                # the late memory export
        for r in runs:
            self.assertLessEqual(float(r["cpu_coverage"]), 1.0)
            if r["mem_coverage"]:
                self.assertLessEqual(float(r["mem_coverage"]), 1.0)
        for c, lv in levels.items():
            used = sum(r["mem_status"] == "complete" and r["hey_valid"] == "True" for r in runs
                       if int(r["concurrency"]) == c)
            self.assertEqual(int(lv["mem_runs_used"]), used)
            if used == 0:
                self.assertEqual(lv["mem_used_pct_mean_median"], "")              # gap, never 0
        footnotes = next(f for f in m["figures"] if f["figure"] == "m1_resources_vs_concurrency_1")["footnotes"]
        self.assertTrue(any("excluding an explicitly configured warm-up of the first 1 s" in n for n in footnotes))
        self.assertTrue(any("no bottleneck is inferred" in n for n in footnotes))

    def test_k6_stage_figure_plots_only_constant_vu_holds(self):
        code, m, run_dir = self.run_spec(self.spec("K6S"), "k6s")
        import csv
        fid = next(f["figure"] for f in m["figures"] if f["figure"].startswith("m1_k6_stages"))
        with open(os.path.join(run_dir, fid + ".csv"), encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(len(rows), 6)                                      # every stage stays in the CSV
        plotted = [r["stage"] for r in rows if r["constant_vu_result"] == "True"]
        self.assertEqual(plotted, ["s02_hold_50", "s04_hold_200"])
        ramps = [r for r in rows if r["kind"] != "hold"]
        self.assertTrue(all(r["successful_rps"] == "" for r in ramps))      # no constant-VU rate for ramps
        footnotes = next(f for f in m["figures"] if f["figure"] == fid)["footnotes"]
        self.assertTrue(any("not plotted" in n and "s05_ramp_down (ramp_down)" in n for n in footnotes))

    def test_k6_summary_without_stage_results_is_skipped_with_a_reason(self):
        old = os.path.join(self.tmp, "k6_old_summary.json")
        with open(old, "w", encoding="utf-8") as f:
            json.dump({"run_id": fx.RUN, "tool": "k6", "mode": "SIMULATED - NOT A REAL MEASUREMENT", "valid": True,
                       "invalid_reason": "", "derived": {"attempts": 1}}, f)
        spec = self.spec("OLDK6")
        spec["datasets"].append({"id": "oldk6", "kind": "k6_summary", "path": old, "provenance": "simulated"})
        code, m, _ = self.run_spec(spec, "oldk6")
        skipped = {s["figure"]: s["reason"] for s in m["figures_skipped"]}
        self.assertIn("no stage_results", skipped["m1_k6_stages_oldk6"])

    def test_resource_group_needs_an_explicit_warmup(self):
        spec = self.spec("NOWARM")
        del spec["groups"]["m1_resources"][0]["warmup_sec"]
        code, m, _ = self.run_spec(spec, "nowarm")
        skipped = {s["figure"]: s["reason"] for s in m["figures_skipped"]}
        self.assertEqual(code, 0)
        self.assertIn("warmup_sec must be set explicitly", skipped["m1_resources_vs_concurrency_1"])

    def test_repeated_processing_never_overwrites(self):
        spec = self.spec("REPEAT")
        _, _, first = self.run_spec(spec, "repeat1")
        _, m2, second = self.run_spec(spec, "repeat2")
        self.assertNotEqual(first, second)
        self.assertTrue(second.endswith("REPEAT.attempt2"))
        self.assertEqual(m2["attempt"], 2)

    def test_missing_time_sync_skips_only_the_cross_machine_figure(self):
        code, m, _ = self.run_spec(self.spec("NOSYNC", time_sync=False), "nosync")
        self.assertEqual(code, 0)
        skipped = {s["figure"]: s["reason"] for s in m["figures_skipped"]}
        self.assertIn("cross-machine UTC alignment not declared", skipped["m2_app_performance_1"])
        self.assertIn("cross-machine UTC alignment not declared", skipped["m1_resources_vs_concurrency_1"])
        self.assertTrue(any(f["figure"].startswith("m2_cpu_timeline") for f in m["figures"]))

    def test_provenance_rules(self):
        spec = self.spec("CONTRA")
        next(d for d in spec["datasets"] if d["kind"] == "hey")["provenance"] = "real"   # contradicts metadata
        code, m, _ = self.run_spec(spec, "contra")
        self.assertEqual((code, m["status"]), (2, "failed"))
        self.assertTrue(any("tool metadata says 'simulated'" in i["message"] for i in m["issues"]))
        spec = self.spec("MIX")
        next(d for d in spec["datasets"] if d["kind"] == "sar_cpu")["provenance"] = "real"   # allowed alone ...
        code, m, _ = self.run_spec(spec, "mix")
        self.assertEqual(code, 2)                                                          # ... but no mixing
        self.assertTrue(any("different provenance" in i["message"] for i in m["issues"]))

    def test_unknown_provenance_is_never_labelled_real(self):
        datasets = [dict(d, provenance="unknown") for d in self.draft["datasets"]
                    if d["kind"] in ("sar_cpu", "telemetry_meta")]
        spec = {"processing_id": "UNKNOWN", "reviewed_by_operator": True, "datasets": datasets}
        code, m, _ = self.run_spec(spec, "unknown")
        self.assertEqual((code, m["provenance"]), (0, "unknown"))
        self.assertTrue(m["figures"])
        self.assertTrue(all("PROVENANCE UNKNOWN" in f["watermark"] for f in m["figures"]))

    def test_scaler_needs_run_id_and_unsupported_sar_is_figure_level(self):
        spec = self.spec("NORUN")
        next(d for d in spec["datasets"] if d["kind"] == "scaler")["run_id"] = ""
        code, m, _ = self.run_spec(spec, "norun")
        self.assertEqual(code, 2)
        self.assertTrue(any("needs run_id" in i["message"] for i in m["issues"]))

        bad = os.path.join(self.tmp, "bad_cpu_sadf.csv")
        with open(bad, "w", encoding="utf-8") as f:
            f.write("Linux 6.8.0 (vm) 2026-01-01 _x86_64_ (4 CPU)\n")
        spec = self.spec("BADSAR")
        spec["datasets"].append({"id": "badsar", "kind": "sar_cpu", "path": bad, "provenance": "simulated"})
        code, m, _ = self.run_spec(spec, "badsar")
        self.assertEqual(code, 0)
        skipped = {s["figure"]: s["reason"] for s in m["figures_skipped"]}
        self.assertIn("not supported", skipped["m2_sar_cpu_badsar"])
        self.assertTrue(any(i["severity"] == "figure" for i in m["issues"]))

    def test_contradicting_metadata_inside_a_dataset_is_fatal(self):
        canary_dir = next(d["path"] for d in self.draft["datasets"] if d["kind"] == "canary")
        copy_dir = os.path.join(self.tmp, "canary_copy")
        shutil.copytree(canary_dir, copy_dir)
        with open(os.path.join(copy_dir, "summary.json"), encoding="utf-8") as f:
            summary = json.load(f)
        summary["mode"] = "measurement"
        with open(os.path.join(copy_dir, "summary.json"), "w", encoding="utf-8") as f:
            json.dump(summary, f)
        spec = {"processing_id": "CONTRADICT", "reviewed_by_operator": True,
                "datasets": [{"id": "c", "kind": "canary", "path": copy_dir, "provenance": "simulated"}]}
        code, m, _ = self.run_spec(spec, "contradict")
        self.assertEqual(code, 2)
        self.assertTrue(any("contradicting provenance" in i["message"] for i in m["issues"]))


class WatermarkTests(OfflineTestCase):
    def test_watermark_and_footer(self):
        for provenance, expected in (("simulated", "SIMULATED – NOT A REAL MEASUREMENT"),
                                     ("unknown", "PROVENANCE UNKNOWN – NOT CLASSIFIED AS A REAL MEASUREMENT"),
                                     ("real", "provenance: real (mode='measurement')")):
            with self.subTest(provenance=provenance):
                fig = plt.figure()
                plots.FigureWriter(".", provenance, "mode='measurement'")._mark(fig, ["note"])
                texts = " | ".join(t.get_text() for t in fig.texts)
                plt.close(fig)
                self.assertIn(expected, texts)
                if provenance == "real":
                    self.assertNotIn("SIMULATED", texts)


class ThesisModeProcessTests(OfflineTestCase):
    """Default publication style vs. --diagnostic; the manifest keeps the ids in both."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.tmp = tempfile.mkdtemp()
        cls.inputs = os.path.join(cls.tmp, "inputs")
        fx.build(cls.inputs)
        draft = os.path.join(cls.tmp, "draft.json")
        assert quiet(pr.main, ["scan", "--root", cls.inputs, "--out", draft]) == 0
        with open(draft, encoding="utf-8") as f:
            cls.draft = json.load(f)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)
        super().tearDownClass()

    def process(self, pid, *extra):
        spec = fx.reviewed_spec(self.inputs, copy.deepcopy(self.draft["datasets"]), pid)
        path = os.path.join(self.tmp, f"{pid}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(spec, f)
        out = os.path.join(self.tmp, "out")
        code = quiet(pr.main, ["process", "--spec", path, "--output-dir", out, *extra])
        run_dir = os.path.join(out, pid)
        with open(os.path.join(run_dir, "processing_manifest.json"), encoding="utf-8") as f:
            return code, json.load(f), run_dir

    def test_thesis_mode_produces_the_same_figures_without_identifiers_or_dates(self):
        code_std, std, _ = self.process("STD", "--diagnostic")
        code, m, run_dir = self.process("THESIS", "--label", "E1")
        self.assertEqual((code_std, code, m["status"], m["mode"], m["label"]), (0, 0, "ok", "publication", "E1"))
        self.assertEqual(std["mode"], "diagnostic")
        self.assertEqual(m["figures_skipped"], [])
        # curated set: one figure kind per essential result, descriptive names and titles
        names = {f["figure"] for f in m["figures"]}
        for expected in ("load_throughput", "load_latency", "load_resources", "load_k6_stages", "load_iperf3",
                         "scaling_cpu_timeline", "scaling_cpu_events", "scaling_app_performance",
                         "failover_probes", "threat_canary", "threat_blocking_delay"):
            self.assertIn(expected, names)
        self.assertLess(len(m["figures"]), len(std["figures"]))
        omitted = {o["figure"] for o in m["figures_omitted"]}
        self.assertTrue(any(o.startswith("m1_error_rate") for o in omitted))
        self.assertTrue(any(o.startswith("m4_feed_sync_summary") for o in omitted))
        run_ids = {i["run_id"] for i in m["inputs"] if i["run_id"]}
        self.assertIn(fx.RUN, run_ids)                     # traceability kept in the manifest
        experiments = tuple(plots.THESIS_EXPERIMENTS.values())
        for f in m["figures"]:
            self.assertTrue(f["thesis"])
            self.assertTrue(f["title"].startswith(experiments), f["title"])
            self.assertIsNone(plots.DATE_TEXT.search(f["title"]))
            for rid in run_ids:
                self.assertNotIn(rid, f["figure"])
                self.assertNotIn(rid, f["title"])
            for name in f["files"]:
                path = os.path.join(run_dir, name)
                self.assertGreater(os.path.getsize(path), 0, name)
                if name.endswith(".pdf"):
                    with open(path, "rb") as fh:
                        self.assertNotIn(b"CreationDate", fh.read(), name)
            # simulated input stays watermarked in thesis mode
            self.assertEqual(f["watermark"], "SIMULATED – NOT A REAL MEASUREMENT")

    def test_thesis_mode_without_label_shows_no_identifier(self):
        code, m, _ = self.process("NOLABEL")
        self.assertEqual((code, m["status"], m["mode"], m["label"]), (0, "ok", "publication", ""))
        self.assertEqual(m["figures_skipped"], [])
        for f in m["figures"]:
            self.assertNotIn(fx.RUN, f["figure"])
            self.assertNotIn(fx.RUN, f["title"])

    def test_diagnostic_mode_keeps_the_internal_figures(self):
        code, m, _ = self.process("DIAG", "--diagnostic")
        self.assertEqual((code, m["mode"]), (0, "diagnostic"))
        self.assertNotIn("label", m)
        self.assertTrue(all(f["thesis"] is False for f in m["figures"]))


class ThesisWriterTests(OfflineTestCase):
    RUN_ID = "E1-20261101-01"

    def setUp(self):
        super().setUp()
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)
        super().tearDown()

    def writer(self, provenance="real"):
        return plots.FigureWriter(self.tmp, provenance, "mode='measurement'", thesis=True, thesis_label="E1",
                                  redact=[self.RUN_ID, self.RUN_ID + "-P1"])

    @staticmethod
    def texts(fig):
        return " | ".join(t.get_text() for t in fig.findobj(plots.Text))

    def test_titles_footer_and_run_ids_are_removed(self):
        w = self.writer()
        fig, ax = plt.subplots()
        ax.plot([10, 500], [40, 1918], label=f"median ({self.RUN_ID})")
        ax.set_title(f"hey {self.RUN_ID}: successful RPS")
        fig.suptitle(f"processing {self.RUN_ID}-P1")
        ax.legend()
        w.save(fig, f"m1_rps_vs_concurrency_{self.RUN_ID}", [{"x": 1}], ["provenance footnote that must not be drawn"])
        self.assertEqual(w.skipped, [])
        self.assertEqual(w.produced[0]["figure"], "load_throughput")
        self.assertEqual(w.produced[0]["title"], "Load test (single connector): successful throughput vs. concurrency")
        text = self.texts(fig)
        self.assertNotIn(self.RUN_ID, text)
        self.assertNotIn("provenance", text)
        self.assertNotIn("hey E1", text)                   # internal title removed
        self.assertNotIn("Load test", text)                # no title at all: the caption is in LaTeX
        self.assertIn("median (E1)", text)                 # legend kept, id neutralised
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "load_throughput.pdf")))
        # the footnotes are still recorded in the manifest entry
        self.assertEqual(w.produced[0]["footnotes"], ["provenance footnote that must not be drawn"])

    def test_figure_with_time_of_day_axis_is_skipped(self):
        from datetime import datetime, timedelta, timezone
        w = self.writer()
        t0 = datetime(2026, 11, 1, 15, 50, 41, tzinfo=timezone.utc)
        fig, ax = plt.subplots()
        ax.plot([t0 + timedelta(seconds=i) for i in range(60)], list(range(60)))
        ax.xaxis.set_major_formatter(plots.mdates.DateFormatter("%H:%M:%S"))
        w.save(fig, "m2_sar_cpu_raw_utc", [{"x": 1}])
        self.assertEqual(w.produced, [])
        self.assertEqual(len(w.skipped), 1)
        self.assertIn("date or time", w.skipped[0]["reason"])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "load_cpu_timeline.png")))

    def test_load_test_figures_use_the_clean_layout(self):
        w = self.writer()
        points = [{"concurrency": c, "sweep": s, "successful_rps": c * 4.0, "lat_all_responses_p95_ms": 220.0,
                   "lat_all_responses_p99_ms": 500.0} for c in (10, 100, 500) for s in (1, 2, 3)]
        levels = [{"concurrency": c, "status": "accepted", "best_accepted_level": c == 500,
                   "successful_rps_median": c * 4.0, "lat_all_responses_p95_ms_median": 220.0,
                   "lat_all_responses_p99_ms_median": 500.0} for c in (10, 100, 500)]
        captured = []
        real_save = w.save
        w.save = lambda fig, *a, **k: (captured.append(fig), real_save(fig, *a, **k))
        plots.m1_rps(w, f"m1_rps_vs_concurrency_{self.RUN_ID}", points, levels, {"accept_max_error_rate": 0.01},
                     self.RUN_ID)
        plots.m1_latency(w, f"m1_latency_p95_p99_{self.RUN_ID}", points, levels, self.RUN_ID)
        self.assertEqual([f["figure"] for f in w.produced], ["load_throughput", "load_latency"])
        for fig in captured:
            text = self.texts(fig)
            for clutter in ("best accepted level", "levels.csv", "hey -c", "(run)"):
                self.assertNotIn(clutter, text)
            self.assertIn("parallel HTTP clients", text)
            self.assertEqual([ax.get_title() for ax in fig.axes], [""] * len(fig.axes))
            self.assertEqual(fig.texts, [])                # no footer, no suptitle

    def test_figures_outside_the_thesis_set_are_omitted(self):
        w = self.writer()
        fig, ax = plt.subplots()
        ax.plot([1, 2], [1, 2])
        w.save(fig, f"m1_error_rate_vs_concurrency_{self.RUN_ID}", [{"x": 1}])
        w.table(f"m1_resources_by_run_{self.RUN_ID}", [{"x": 1}])
        self.assertEqual((w.produced, w.skipped), ([], []))
        self.assertEqual(len(w.omitted), 2)
        self.assertEqual(os.listdir(self.tmp), [])

    def test_second_figure_of_a_kind_gets_a_suffix(self):
        w = self.writer()
        for _ in range(2):
            fig, ax = plt.subplots()
            ax.plot([1, 2], [1, 2])
            w.save(fig, f"m1_latency_p95_p99_{self.RUN_ID}", [{"x": 1}])
        self.assertEqual([f["figure"] for f in w.produced], ["load_latency", "load_latency_2"])

    def test_sar_series_uses_relative_seconds(self):
        from datetime import datetime, timedelta, timezone
        w = self.writer()
        t0 = datetime(2026, 11, 1, 15, 50, 41, tzinfo=timezone.utc)
        series = [{"utc": t0 + timedelta(seconds=i), "cpu_not_idle_pct": 30.0, "cpu_busy_excl_iowait_pct": 29.0,
                   "iowait_pct": 1.0, "steal_pct": 0.0} for i in range(120)]
        plots.m2_sar(w, f"m2_sar_cpu_{self.RUN_ID}", series, "sr-conn01", "")
        self.assertEqual(w.skipped, [])
        self.assertEqual(w.produced[0]["figure"], "load_cpu_timeline")
        self.assertEqual(w.produced[0]["title"], "Load test (single connector): connector CPU over time (1 s samples)")

    def test_without_label_the_identifier_is_removed(self):
        w = plots.FigureWriter(self.tmp, "real", "", thesis=True, redact=[self.RUN_ID])
        fig, ax = plt.subplots()
        ax.plot([1, 2], [1, 2], label=f"median ({self.RUN_ID})")
        ax.legend()
        w.save(fig, f"m4_latency_by_repetition_{self.RUN_ID}", [{"x": 1}])
        self.assertEqual(w.produced[0]["figure"], "threat_blocking_delay")
        self.assertEqual(w.produced[0]["source_figure"], "m4_latency_by_repetition")
        text = self.texts(fig)
        self.assertNotIn(self.RUN_ID, text)
        self.assertIn("median", text)
        self.assertNotIn("()", text)

    def test_watermark_kept_and_real_footer_dropped(self):
        for provenance, present, absent in (("simulated", "SIMULATED – NOT A REAL MEASUREMENT", "provenance: real"),
                                            ("real", None, "provenance: real")):
            with self.subTest(provenance=provenance):
                w = self.writer(provenance)
                fig, ax = plt.subplots()
                ax.plot([1, 2], [1, 2])
                w.save(fig, f"m1_latency_p95_p99_{provenance}", [{"x": 1}], ["note"])
                text = " | ".join(t.get_text() for t in fig.texts)
                if present:
                    self.assertIn(present, text)
                self.assertNotIn(absent, text)
                self.assertNotIn("note", text)

    def test_date_pattern(self):
        for text in ("2026-11-01", "2026.11.01", "E1-20261101-01", "15:52:05", "1793546070", "1793546070.52"):
            self.assertIsNotNone(plots.DATE_TEXT.search(text), text)
        for text in ("p95 [ms]", "c=500", "1918.2", "n=3/3", "649102", "0.0003", "sweep 3", "E1", "10:30"):
            self.assertIsNone(plots.DATE_TEXT.search(text), text)


if __name__ == "__main__":
    unittest.main()
