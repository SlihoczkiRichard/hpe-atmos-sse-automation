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
        code = quiet(pr.main, ["process", "--spec", path, "--output-dir", out])
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


if __name__ == "__main__":
    unittest.main()
