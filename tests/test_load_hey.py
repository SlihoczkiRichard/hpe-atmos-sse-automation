"""run_hey_stepped.py: parser, definitions, validity, aggregation and run loop (offline, fake hey).

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.
"""

import csv
import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from _helpers import OfflineTestCase, load_module

hey = load_module("01-load-test/run_hey_stepped.py", "run_hey_stepped")

PCTS = ["50", "95", "99"]
OK200 = frozenset({200})

# Synthetic hey report in hey's text format (made-up numbers)
MIXED = """
Summary:
  Total:\t30.0000 secs
  Slowest:\t0.9000 secs
  Fastest:\t0.0100 secs
  Average:\t0.0500 secs
  Requests/sec:\t100.0000

Latency distribution:
  10% in 0.0200 secs
  50% in 0.0400 secs
  95% in 0.2000 secs
  99% in 0.5000 secs

Status code distribution:
  [200]\t2900 responses
  [302]\t20 responses
  [404]\t30 responses
  [503]\t40 responses

Error distribution:
  [5]\tGet "https://app.test.invalid/": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
  [3]\tGet "https://app.test.invalid/": dial tcp 192.0.2.10:443: connect: connection refused
  [2]\tPost "https://app.test.invalid/": read: connection reset by peer
"""


def report(ok, extra_status="", errors="", total="30.0000"):
    return (f"\nSummary:\n  Total:\t{total} secs\n  Average:\t0.0500 secs\n  Requests/sec:\t10.0\n\n"
            "Latency distribution:\n  50% in 0.0400 secs\n  95% in 0.2000 secs\n  99% in 0.5000 secs\n\n"
            f"Status code distribution:\n  [200]\t{ok} responses\n{extra_status}\n"
            + (f"Error distribution:\n{errors}\n" if errors else ""))


class ParserTests(OfflineTestCase):
    def test_counts_and_both_error_definitions(self):
        m, reason = hey.parse_hey_output(MIXED, PCTS, OK200)
        self.assertEqual(reason, "")
        self.assertEqual(m["http_responses"], 2990)
        self.assertEqual(m["transport_errors"], 10)
        self.assertEqual(m["attempts"], 3000)
        self.assertEqual(m["success_responses"], 2900)
        self.assertEqual(m["non_success_responses"], 90)
        self.assertEqual(m["http_5xx_responses"], 40)
        self.assertEqual((m["primary_error_numerator"], m["primary_error_denominator"]), (100, 3000))
        self.assertEqual((m["err5xx_transport_numerator"], m["err5xx_transport_denominator"]), (50, 3000))
        self.assertAlmostEqual(m["primary_error_rate"], 100 / 3000)
        self.assertAlmostEqual(m["err5xx_transport_error_rate"], 50 / 3000)
        self.assertEqual(m["successful_rps"], round(2900 / 30.0, 3))
        self.assertEqual(m["hey_reported_rps"], 100.0)
        self.assertEqual(json.loads(m["status_counts_json"]), {"200": 2900, "302": 20, "404": 30, "503": 40})
        self.assertEqual(json.loads(m["transport_error_classes_json"]),
                         {"connection_refused": 3, "connection_reset": 2, "timeout": 5})

    def test_latency_fields_are_named_for_all_responses(self):
        m, _ = hey.parse_hey_output(MIXED, PCTS, OK200)
        self.assertEqual(m["lat_all_responses_p95_ms"], 200.0)
        self.assertEqual(m["lat_all_responses_avg_ms"], 50.0)
        self.assertFalse(any(k.startswith("lat_success") for k in m))

    def test_success_statuses_are_configurable(self):
        m, _ = hey.parse_hey_output(MIXED, PCTS, frozenset({200, 302}))
        self.assertEqual(m["success_responses"], 2920)

    def test_missing_values_are_none_not_zero(self):
        m, _ = hey.parse_hey_output(MIXED, ["50", "75"], OK200)
        self.assertIsNone(m["lat_all_responses_p75_ms"])  # not in the report
        m2, _ = hey.parse_hey_output(report(10), PCTS, OK200)  # report without Fastest/Slowest
        self.assertIsNone(m2["lat_all_responses_min_ms"])
        self.assertIsNone(m2["lat_all_responses_max_ms"])

    def test_invalid_outputs(self):
        cases = {
            "": "no hey summary",
            "Summary:\n  Average:\t0.1 secs\n": "Total time missing",
            report(0).replace("  [200]\t0 responses\n", ""): "no request attempts",
            report(5, extra_status="  [abc]\tbroken\n"): "unparseable status line",
        }
        for output, expected in cases.items():
            with self.subTest(expected=expected):
                metrics, reason = hey.parse_hey_output(output, PCTS, OK200)
                self.assertIsNone(metrics)
                self.assertIn(expected, reason)

    def test_status_set_parsing(self):
        self.assertEqual(hey.parse_status_set("200"), frozenset({200}))
        self.assertEqual(hey.parse_status_set("200, 204"), frozenset({200, 204}))
        for bad in ("", "2xx", "99", "600"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                hey.parse_status_set(bad)

    def test_hey_command(self):
        cmd = hey.build_hey_command("hey", "https://app.test.invalid/", 50, "30s", 0, True)
        self.assertEqual(cmd, ["hey", "-z", "30s", "-c", "50", "https://app.test.invalid/"])
        cmd = hey.build_hey_command("hey", "https://app.test.invalid/", 50, "30s", 5, False)
        self.assertEqual(cmd[-3:], ["5", "-disable-redirects", "https://app.test.invalid/"])


def run_row(rate, valid=True, rps=100.0, rate5xx=None, p95=200.0):
    num = round(rate * 1000)
    num5 = round((rate if rate5xx is None else rate5xx) * 1000)
    return {"valid": valid, "successful_rps": rps if valid else None,
            "primary_error_numerator": num, "primary_error_denominator": 1000, "primary_error_rate": num / 1000,
            "err5xx_transport_numerator": num5, "err5xx_transport_denominator": 1000,
            "err5xx_transport_error_rate": num5 / 1000, "lat_all_responses_p95_ms": p95}


class AggregationTests(OfflineTestCase):
    def test_accepted_only_if_every_run_strictly_below_threshold(self):
        lv = hey.aggregate_level(50, [run_row(0.0), run_row(0.005), run_row(0.009)], 3, 0.01, ["95"])
        self.assertEqual(lv["status"], "accepted")
        lv = hey.aggregate_level(50, [run_row(0.0), run_row(0.0), run_row(0.010)], 3, 0.01, ["95"])
        self.assertEqual(lv["status"], "rejected")  # exactly 1% is not strictly below

    def test_invalid_or_missing_run_blocks_acceptance(self):
        lv = hey.aggregate_level(50, [run_row(0.0), run_row(0.0), run_row(0.0, valid=False)], 3, 0.01, ["95"])
        self.assertEqual(lv["status"], "invalid")
        self.assertEqual((lv["valid_runs"], lv["invalid_runs"]), (2, 1))
        lv = hey.aggregate_level(50, [run_row(0.0), run_row(0.0)], 3, 0.01, ["95"])
        self.assertEqual(lv["status"], "invalid")

    def test_pooled_rates_and_medians(self):
        lv = hey.aggregate_level(50, [run_row(0.001, rps=90), run_row(0.003, rps=100), run_row(0.002, rps=120)],
                                 3, 0.01, ["95"])
        self.assertEqual(lv["successful_rps_median"], 100)
        self.assertEqual((lv["successful_rps_min"], lv["successful_rps_max"]), (90, 120))
        self.assertAlmostEqual(lv["primary_error_rate_pooled"], 6 / 3000)
        self.assertEqual(lv["lat_all_responses_p95_ms_median_of_runs"], 200.0)

    def test_5xx_definition_is_separate_from_acceptance(self):
        rows = [run_row(0.05, rate5xx=0.0) for _ in range(3)]  # many 404s, no 5xx
        lv = hey.aggregate_level(50, rows, 3, 0.01, ["95"])
        self.assertEqual(lv["status"], "rejected")
        self.assertTrue(lv["err5xx_transport_all_runs_below_threshold"])
        self.assertEqual(lv["err5xx_transport_error_rate_pooled"], 0.0)

    def test_primary_result_and_non_monotonic_flag(self):
        levels = [
            {"concurrency": 10, "status": "accepted", "successful_rps_median": 100, "successful_rps_min": 95},
            {"concurrency": 50, "status": "accepted", "successful_rps_median": 300, "successful_rps_min": 280},
            {"concurrency": 100, "status": "rejected", "successful_rps_median": 350, "successful_rps_min": 340},
        ]
        res = hey.primary_result(levels)
        self.assertEqual((res["best_level"], res["best_successful_rps_median"]), (50, 300))
        self.assertFalse(res["non_monotonic"])
        levels.append({"concurrency": 200, "status": "accepted", "successful_rps_median": 250,
                       "successful_rps_min": 240})
        self.assertTrue(hey.primary_result(levels)["non_monotonic"])
        self.assertIsNone(hey.primary_result([dict(levels[2])])["best_level"])


class RunLoopTests(OfflineTestCase):
    def _cfg(self, out_dir, *extra):
        args = hey.parse_args(["--url", "https://app.test.invalid/", "--steps", "10,50", "--sweeps", "3",
                               "--duration", "10s", "--percentiles", "50,95,99", "--run-id", "T-1",
                               "--output-dir", out_dir, *extra], {})
        return hey.Config(args)

    def test_sweeps_raw_files_and_manifest(self):
        calls, sleeps = [], []

        def runner(cmd, timeout):
            calls.append(cmd)
            return 0, report(980, extra_status="  [503]\t5 responses\n"), ""

        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()):
            cfg = self._cfg(d)
            runs, levels, manifest = hey.run_benchmark(cfg, runner, sleep=sleeps.append)
            out = os.path.join(d, "T-1")
            raw_files = sorted(os.listdir(os.path.join(out, "raw")))
            with open(os.path.join(out, "runs.csv"), encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            with open(os.path.join(out, "manifest.json"), encoding="utf-8") as f:
                saved = json.load(f)
        self.assertEqual([int(c[c.index("-c") + 1]) for c in calls], [10, 50] * 3)  # ascending, 3 sweeps
        self.assertEqual(len(raw_files), 6)
        self.assertIn("T-1_s3_c50.txt", raw_files)
        self.assertEqual(sleeps, [5.0] * 6)
        self.assertTrue(all(r["started_utc"] and r["ended_utc"] and r["run_id"] == "T-1" for r in rows))
        self.assertEqual(saved["mode"], "measurement")
        self.assertIn("not a physical saturation point", saved["interpretation_note"])
        self.assertEqual(saved["config"]["success_statuses"], [200])
        self.assertEqual([lv["status"] for lv in levels], ["accepted", "accepted"])
        self.assertEqual(saved["validity"]["status"], "all_runs_valid")
        self.assertIn("not performed", saved["config"]["tls_certificate_verification"])
        self.assertIn("final response status", saved["config"]["redirect_handling"])

    def test_injected_clocks_give_utc_and_monotonic_times(self):
        ticks = iter(range(100, 1000, 7))          # monotonic seconds
        base = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)
        walls = iter(base + timedelta(seconds=s) for s in range(0, 1000, 3))
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()):
            runs, _, manifest = hey.run_benchmark(self._cfg(d, "--no-follow-redirects"),
                                                  lambda c, t: (0, report(1000), ""), sleep=lambda s: None,
                                                  clock=lambda: next(ticks), now=lambda: next(walls))
        first = runs[0]
        self.assertEqual((first["mono_start_sec"], first["mono_end_sec"], first["wall_duration_sec"]), (7, 14, 7))
        self.assertEqual(first["started_utc"], "2026-10-26T12:00:03.000+00:00")
        self.assertTrue(all(b["mono_start_sec"] > a["mono_end_sec"] for a, b in zip(runs, runs[1:])))
        self.assertIn("3xx response is a non-success", manifest["config"]["redirect_handling"])

    def test_subprocess_runner_decodes_utf8_explicitly(self):
        fake = mock.Mock(returncode=0, stdout="ok", stderr="")
        with mock.patch.object(hey.subprocess, "run", return_value=fake) as run:
            self.assertEqual(hey.subprocess_runner(["hey", "x"], 5), (0, "ok", ""))
        self.assertEqual((run.call_args.kwargs["encoding"], run.call_args.kwargs["errors"]), ("utf-8", "replace"))

    def test_failed_hey_run_is_invalid_and_never_zero(self):
        outputs = iter([(0, report(1000), ""), (1, "", "boom"), (None, "", "hey did not finish within 70s")] * 2)
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()):
            runs, levels, manifest = hey.run_benchmark(self._cfg(d), lambda c, t: next(outputs),
                                                       sleep=lambda s: None)
            with open(os.path.join(d, "T-1", "runs.csv"), encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
        bad = [r for r in rows if r["valid"] == "False"]
        self.assertEqual(len(bad), 4)
        self.assertTrue(all(r["successful_rps"] == "" and r["primary_error_rate"] == "" for r in bad))
        self.assertEqual({lv["status"] for lv in levels}, {"invalid"})
        self.assertEqual(len(manifest["invalid_runs"]), 4)
        self.assertEqual(manifest["validity"]["status"], "contains_invalid_runs")
        self.assertEqual(manifest["validity"]["levels_by_status"], {"invalid": [10, 50]})
        self.assertIsNone(manifest["primary_result"]["best_level"])

    def test_dry_run_makes_no_subprocess_call_and_is_labelled(self):
        with tempfile.TemporaryDirectory() as d, \
                mock.patch("subprocess.run", side_effect=AssertionError("no subprocess in dry-run")), \
                contextlib.redirect_stdout(io.StringIO()):
            code = hey.main(["--dry-run", "--steps", "100,300", "--run-id", "DRY-1", "--output-dir", d], environ={})
            with open(os.path.join(d, "DRY-1", "manifest.json"), encoding="utf-8") as f:
                manifest = json.load(f)
        self.assertEqual(code, 0)
        self.assertIn("NOT a measurement", manifest["mode"])

    def test_missing_hey_binary_runs_nothing(self):
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()) as out:
            code = hey.main(["--url", "https://app.test.invalid/", "--hey-path", "definitely-not-hey",
                             "--output-dir", d], environ={})
            self.assertEqual(os.listdir(d), [])
        self.assertEqual(code, 2)
        self.assertIn("nothing was run", out.getvalue())

    def test_config_validation(self):
        with tempfile.TemporaryDirectory() as d:
            for extra in (["--steps", "50,10"], ["--sweeps", "0"], ["--percentiles", "97"],
                          ["--run-id", "../x"], ["--accept-max-error-rate", "1.5"]):
                with self.subTest(extra=extra), self.assertRaises(ValueError):
                    self._cfg(d, *extra)

    def test_env_defaults(self):
        args = hey.parse_args([], {"SUCCESS_STATUSES": "", "LOAD_SWEEPS": "3"})
        self.assertEqual(args.success_statuses, "200")
        self.assertEqual(args.accept_max_error_rate, 0.01)
        self.assertFalse(args.no_follow_redirects)
        self.assertTrue(hey.parse_args([], {"LOAD_FOLLOW_REDIRECTS": "false"}).no_follow_redirects)


if __name__ == "__main__":
    unittest.main()
