"""Runtime safety: configuration loading (--help / --dry-run never read .env), output collisions and
interrupted runs of the 01 tools (offline).

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

In every test that starts a tool through main(environ=None), python-dotenv's load_dotenv is replaced:
it either fails the test (help / dry-run must not call it) or records the call without reading any
file (live mode). A deliberately broken synthetic environment is injected with mock.patch.dict; the
real .env file is never read.
"""

import contextlib
import csv
import glob
import hashlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from _helpers import OfflineTestCase, load_module

hey = load_module("01-load-test/run_hey_stepped.py", "rs_hey")
ip = load_module("01-load-test/run_iperf3_comparison.py", "rs_iperf3")
scaler = load_module("02-scaler-poc/scaler_daemon.py", "rs_scaler")
fo = load_module("03-failover/failover_probe.py", "rs_failover")
sync = load_module("04-threat-intel/sync_threat_intel.py", "rs_sync")
cb = load_module("04-threat-intel/canary_block_test.py", "rs_canary")
loaders = load_module("05-results/loaders.py", "rs_loaders")

BROKEN_ENV = {   # unusable live values; they must not matter for --help or --dry-run
    "CONNECTOR_2_VMID": "your_c2_vmid_here", "CPU_SCALE_OUT_THRESHOLD": "high", "LOAD_SWEEPS": "many",
    "LOAD_RATE_LIMIT_QPS": "fast", "IPERF3_PARALLEL": "lots", "FAILOVER_TCP_PORT": "https",
    "FAILOVER_DURATION_SEC": "long", "CANARY_STABLE_N": "ten", "ATMOS_PAGE_SIZE": "big",
    "SCALER_COOLDOWN_SEC": "soon", "TARGET_APP_URL": "not a url",
}


def must_not_load(*_a, **_k):
    raise AssertionError("load_dotenv must not be called for --help / --dry-run")


def quiet(fn, *a, **k):
    with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
        try:
            code = fn(*a, **k)
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue() + err.getvalue()


def digest(paths):
    return {p: hashlib.sha256(open(p, "rb").read()).hexdigest() for p in paths}


class ConfigLoadingTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        patch = mock.patch.dict(os.environ, BROKEN_ENV)
        patch.start()
        self.addCleanup(patch.stop)

    def test_help_never_loads_dotenv(self):
        cases = [(hey.main, ["--help"]), (ip.main, ["--help"]), (scaler.main, ["--help"]),
                 (fo.main, ["run", "--help"]), (fo.main, ["analyze", "-h"]), (sync.main, ["apply", "--help"]),
                 (cb.main, ["run", "--help"]), (cb.main, ["restore", "--help"])]
        for fn, argv in cases:
            with self.subTest(argv=argv), mock.patch("dotenv.load_dotenv", side_effect=must_not_load):
                code, text = quiet(fn, argv)
                self.assertEqual(code, 0, text)
                self.assertIn("usage:", text)
                self.assertNotIn("your_c2_vmid_here", text)

    def test_dry_runs_use_only_synthetic_configuration(self):
        out = self.dir
        cases = [
            (hey.main, ["--dry-run", "--run-id", "CFG-1", "--steps", "10", "--sweeps", "1", "--output-dir", out]),
            (ip.main, ["--dry-run", "--path", "direct=10.0.1.123", "--path", "sse=app.test.invalid",
                       "--repetitions", "1", "--run-id", "CFG-1", "--output-dir", out]),
            (scaler.main, ["--dry-run", "--max-cycles", "3", "--output-dir", out]),
            (fo.main, ["run", "--probe", "tcp", "--run-id", "CFG-1", "--dry-run", "--duration-sec", "5",
                       "--output-dir", out]),
            (cb.main, ["validate-signature", "--run-id", "CFG-1", "--dry-run", "--output-dir", out]),
        ]
        for fn, argv in cases:
            with self.subTest(tool=argv[:2]), mock.patch("dotenv.load_dotenv", side_effect=must_not_load):
                code, text = quiet(fn, argv)
                self.assertEqual(code, 0, text)

    def test_live_mode_reports_its_own_configuration_errors(self):
        # broken values only fail the mode that needs them, with a clear argparse error
        code, text = quiet(scaler.main, ["--c1-ip", "192.0.2.11", "--esxi-host", "esxi.test.invalid"],
                           environ={"CONNECTOR_2_VMID": "your_c2_vmid_here"})
        self.assertEqual(code, 2)
        self.assertIn("invalid int value", text)
        code, text = quiet(hey.main, ["--url", "https://app.test.invalid/"], environ={"LOAD_SWEEPS": "many"})
        self.assertEqual(code, 2)
        self.assertIn("--sweeps", text)
        # an explicit option overrides a broken environment value without converting it
        self.assertEqual(scaler.parse_args(["--c2-vmid", "12"], {"CONNECTOR_2_VMID": "bad"}).c2_vmid, 12)

    def test_live_mode_loads_dotenv(self):
        calls = []
        with mock.patch("dotenv.load_dotenv", side_effect=lambda *a, **k: calls.append(1)):
            code, text = quiet(fo.main, ["mark", "--run-id", "CFG-2", "--kind", "note", "--output-dir", self.dir])
        self.assertEqual((code, calls), (0, [1]), text)


class HeyCollisionAndInterruptTests(OfflineTestCase):
    def cfg(self, out, *extra):
        return hey.Config(hey.parse_args(["--url", "https://app.test.invalid/", "--steps", "10,50", "--sweeps", "2",
                                          "--duration", "5s", "--percentiles", "50,95,99", "--run-id", "R-1",
                                          "--output-dir", out, *extra], {}))

    def report(self):
        return hey.synthetic_hey_output(10)

    def test_same_run_id_is_refused_and_nothing_is_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            quiet(hey.run_benchmark, self.cfg(d), lambda c, t: (0, self.report(), ""), lambda s: None)
            files = [p for p in glob.glob(os.path.join(d, "R-1", "**", "*"), recursive=True) if os.path.isfile(p)]
            before = digest(files)
            with self.assertRaisesRegex(FileExistsError, "use a new RUN_ID"):
                hey.run_benchmark(self.cfg(d), lambda c, t: (0, self.report(), ""), lambda s: None)
            code, text = quiet(hey.main, ["--url", "https://app.test.invalid/", "--steps", "10,50", "--sweeps", "2",
                                          "--run-id", "R-1", "--output-dir", d], environ={},
                               runner=lambda c, t: (0, self.report(), ""), sleep=lambda s: None)
            self.assertEqual(code, 2)
            self.assertIn("nothing was overwritten", text)
            self.assertEqual(digest(files), before)

    def test_interrupted_run_keeps_manifest_and_is_not_acceptable(self):
        calls = {"n": 0}

        def runner(cmd, timeout):
            calls["n"] += 1
            if calls["n"] == 3:
                raise KeyboardInterrupt
            return 0, self.report(), ""
        with tempfile.TemporaryDirectory() as d:
            code, text = quiet(hey.main, ["--url", "https://app.test.invalid/", "--steps", "10,50", "--sweeps", "2",
                                          "--run-id", "R-2", "--output-dir", d], environ={}, runner=runner,
                               sleep=lambda s: None)
            run_dir = os.path.join(d, "R-2")
            with open(os.path.join(run_dir, "manifest.json"), encoding="utf-8") as f:
                manifest = json.load(f)
            with open(os.path.join(run_dir, "runs.csv"), encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            with open(os.path.join(run_dir, "levels.csv"), encoding="utf-8") as f:
                levels = list(csv.DictReader(f))
            raw = sorted(os.listdir(os.path.join(run_dir, "raw")))
            ds = loaders.load_hey(run_dir)
        self.assertEqual(code, 3)
        self.assertEqual((manifest["status"], manifest["validity"]["status"]), ("interrupted", "interrupted"))
        self.assertEqual(manifest["interruption"], {"during": "measurement run", "sweep": 2, "concurrency": 10})
        self.assertEqual((manifest["primary_result"]["best_level"], manifest["primary_result"]["accepted_levels"]),
                         (None, []))
        self.assertEqual({lv["status"] for lv in levels}, {"interrupted_run"})
        self.assertEqual(manifest["level_status_if_it_had_completed"], {"10": "invalid", "50": "invalid"})
        self.assertEqual(len(rows), 3)
        self.assertEqual((rows[2]["valid"], rows[2]["successful_rps"]), ("False", ""))
        self.assertIn("interrupted", rows[2]["invalid_reason"])
        self.assertEqual(raw, ["R-2_s1_c10.txt", "R-2_s1_c50.txt", "R-2_s2_c10.txt"])   # raw output kept
        self.assertTrue(any("interrupted" in i.message for i in ds.issues))

    def test_interrupt_during_pause(self):
        def sleep(_s):
            raise KeyboardInterrupt
        with tempfile.TemporaryDirectory() as d:
            _, levels, manifest = quiet(hey.run_benchmark, self.cfg(d), lambda c, t: (0, self.report(), ""),
                                        sleep)[0]
        self.assertEqual(manifest["interruption"], {"during": "pause between runs"})
        self.assertEqual(manifest["primary_result"]["best_level"], None)


class IperfCollisionAndInterruptTests(OfflineTestCase):
    ARGS = ["--path", "direct=10.0.1.123", "--path", "sse=app.test.invalid", "--repetitions", "2", "--run-id", "I-1"]

    def test_collision_and_interruption(self):
        good = json.dumps({"end": {"sum_received": {"bits_per_second": 1e8}, "sum_sent": {"bits_per_second": 1e8}}})
        with tempfile.TemporaryDirectory() as d:
            calls = {"n": 0}

            def runner(cmd, timeout):
                calls["n"] += 1
                if calls["n"] == 2:
                    raise KeyboardInterrupt
                return 0, good, ""
            code, _ = quiet(ip.main, self.ARGS + ["--output-dir", d], environ={}, runner=runner, sleep=lambda s: None)
            with open(os.path.join(d, "I-1", "iperf3_manifest.json"), encoding="utf-8") as f:
                manifest = json.load(f)
            raw = sorted(os.listdir(os.path.join(d, "I-1", "raw")))
            files = [p for p in glob.glob(os.path.join(d, "I-1", "**", "*"), recursive=True) if os.path.isfile(p)]
            before = digest(files)
            code2, text = quiet(ip.main, self.ARGS + ["--output-dir", d], environ={},
                                runner=lambda c, t: (0, good, ""), sleep=lambda s: None)
            self.assertEqual(digest(files), before)
        self.assertEqual(code, 3)
        self.assertEqual(manifest["status"], "interrupted")
        self.assertEqual({s["status"] for s in manifest["summaries"]}, {"interrupted"})
        self.assertIn("I-1_r1_direct.json", raw)
        self.assertEqual(code2, 2)
        self.assertIn("nothing was overwritten", text)


class K6SummaryNameTests(OfflineTestCase):
    def test_summary_name_is_timestamped_and_limits_documented(self):
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "01-load-test",
                               "k6_workload.js"), encoding="utf-8") as f:
            src = f.read()
        self.assertIn("k6_${RUN_ID}_summary.${stamp}.json", src)
        self.assertIn("replace(/[-:.]/g, '')", src)
        self.assertIn("WILL be", src)                       # --out json overwrite limitation stated
        self.assertNotIn("_summary.json`", src)


if __name__ == "__main__":
    unittest.main()
