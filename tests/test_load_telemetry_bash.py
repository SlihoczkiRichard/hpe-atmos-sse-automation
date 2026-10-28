"""Integration tests: collect_connector_telemetry.sh really executed by Bash (stubbed sar/df/hostname).

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

The same tests run once per runtime: native POSIX bash, Git Bash and WSL (see _bash_runtime).
A runtime that is not present or does not identify as expected is skipped with the probe's
reason; nothing is mocked to make such a test pass. sar, df and hostname are replaced by stub
scripts on PATH, so no real system statistics are read and no network is used.
"""

import json
import os
import tempfile
import time
import unittest

import _bash_runtime as br
from _helpers import ROOT, OfflineTestCase

TELEMETRY = os.path.join(ROOT, "01-load-test", "collect_connector_telemetry.sh")

STUB_SAR = """#!/usr/bin/env bash
echo "$*" >> "$STUB_LOG"
if [[ "$*" == "-F 1 1" ]]; then exit ${STUB_SAR_F_EXIT:-0}; fi
if [[ -n "${STUB_SAR_SIGNAL_PARENT:-}" ]]; then kill -"$STUB_SAR_SIGNAL_PARENT" "$PPID"; sleep 10; fi
if [[ -n "${STUB_SAR_SLEEP:-}" ]]; then sleep "$STUB_SAR_SLEEP"; fi
echo "Linux 6.8.0 (stub) sample output"
exit ${STUB_SAR_EXIT:-0}
"""
STUB_DF = """#!/usr/bin/env bash
echo "Filesystem 1024-blocks Used Available Capacity Mounted on"
echo "/dev/sda1 1000 500 500 50% /"
"""
STUB_HOSTNAME = """#!/usr/bin/env bash
echo stubhost
"""


class _TelemetryScriptTests:
    """Mixin; subclasses set KIND. Not collected on its own (not a TestCase)."""

    KIND = None

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        result = br.get_runtime(cls.KIND)
        if result.runtime is None:
            raise unittest.SkipTest(f"runtime not available: {result.reason}")
        cls.runtime = result.runtime
        cls.script = cls.runtime.to_runtime_path(TELEMETRY)

    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.bin = os.path.join(tmp.name, "bin")
        os.mkdir(self.bin)
        for name, body in (("sar", STUB_SAR), ("df", STUB_DF), ("hostname", STUB_HOSTNAME)):
            path = os.path.join(self.bin, name)
            with open(path, "w", newline="\n", encoding="utf-8") as f:
                f.write(body)
            os.chmod(path, 0o755)
        self.log = os.path.join(tmp.name, "sar_calls.log")
        self.out = os.path.join(tmp.name, "out")

    def run_script(self, *args, **env):
        rt = self.runtime
        full_env = {"STUB_LOG": rt.to_runtime_path(self.log), "ROLE": "c2", **env}
        cmd = rt.command(self.script, [*args, rt.to_runtime_path(self.out)], env=full_env,
                         prepend_path=rt.to_runtime_path(self.bin))
        code, out, err = br.subprocess_run(cmd, 120)
        return code, out, err

    def meta(self, run_id):
        with open(os.path.join(self.out, f"telemetry_{run_id}_c2_stubhost_meta.json"), encoding="utf-8") as f:
            return json.load(f)

    def test_full_coverage_collects_memory_disk_network(self):
        code, _, err = self.run_script("3", "1", RUN_ID="T-1", RUN_START_EPOCH=f"{time.time():.3f}",
                                       COVERAGE_TOLERANCE_SEC="3", STUB_SAR_SLEEP="3")
        self.assertEqual(code, 0, err)
        meta = self.meta("T-1")
        self.assertEqual(meta["coverage"], "full_from_run_start")
        self.assertIs(meta["complete_time_series"], True)
        self.assertEqual(meta["coverage_reasons"], [])
        self.assertEqual((meta["requested_samples"], meta["expected_sampling_sec"]), (3, 3))
        self.assertGreaterEqual(meta["collector_elapsed_sec"], 3)
        self.assertEqual(meta["metrics"]["filesystem_usage"], "sar -F")
        with open(self.log, encoding="utf-8") as f:
            main_call = f.read().splitlines()[-1]
        for flag in ("-u ALL", "-r", "-S", "-d", "-p", "-n DEV", "-F", "-o"):
            self.assertIn(flag, main_call)
        for suffix in ("_sar.txt", "_df_start.txt", "_df_end.txt"):
            self.assertTrue(os.path.exists(os.path.join(self.out, f"telemetry_T-1_c2_stubhost{suffix}")))

    def test_late_start_is_partial(self):
        code, _, err = self.run_script("1", "1", RUN_ID="T-2", RUN_START_EPOCH=f"{time.time() - 120:.3f}")
        self.assertEqual(code, 0, err)
        meta = self.meta("T-2")
        self.assertEqual(meta["coverage"], "partial_late_start")
        self.assertIs(meta["complete_time_series"], False)
        self.assertGreater(meta["start_lag_sec"], 100)
        self.assertIn("not a complete time series", meta["note"])

    def test_early_end_is_partial(self):
        # sar stub returns at once although 30 samples x 1 s were requested
        code, _, err = self.run_script("30", "1", RUN_ID="T-6", RUN_START_EPOCH=f"{time.time():.3f}")
        self.assertEqual(code, 0, err)
        meta = self.meta("T-6")
        self.assertEqual(meta["coverage"], "partial_early_end")
        self.assertIn("early_end", meta["coverage_reasons"])
        self.assertIs(meta["complete_time_series"], False)

    def test_interruption_is_partial_and_fails(self):
        code, _, err = self.run_script("30", "1", RUN_ID="T-7", RUN_START_EPOCH=f"{time.time():.3f}",
                                       STUB_SAR_SIGNAL_PARENT="TERM")
        self.assertEqual(code, 1, err)
        self.assertIn("interrupted by SIGTERM", err)
        meta = self.meta("T-7")
        self.assertEqual(meta["coverage"], "partial_interrupted")
        self.assertEqual(meta["interrupted_by"], "SIGTERM")
        self.assertIn("interrupted_by_SIGTERM", meta["coverage_reasons"])
        self.assertIs(meta["complete_time_series"], False)

    def test_unknown_run_start_and_missing_filesystem_support(self):
        code, _, err = self.run_script("1", "1", RUN_ID="T-3", STUB_SAR_F_EXIT="1")
        self.assertEqual(code, 0, err)
        meta = self.meta("T-3")
        self.assertEqual(meta["coverage"], "unknown_run_start")
        self.assertIsNone(meta["complete_time_series"])
        self.assertIsNone(meta["run_start_epoch"])
        self.assertIn("not collected", meta["metrics"]["filesystem_usage"])

    def test_sar_failure_is_invalid(self):
        code, _, _ = self.run_script("1", "1", RUN_ID="T-4", STUB_SAR_EXIT="3")
        self.assertEqual(code, 1)
        meta = self.meta("T-4")
        self.assertEqual((meta["sar_exit_code"], meta["coverage"]), (3, "invalid_sar_failed"))
        self.assertIs(meta["complete_time_series"], False)

    def test_existing_files_are_never_overwritten(self):
        code, _, err = self.run_script("1", "1", RUN_ID="T-8")
        self.assertEqual(code, 0, err)
        paths = sorted(os.path.join(self.out, n) for n in os.listdir(self.out))
        before = {p: open(p, "rb").read() for p in paths}
        code, _, err = self.run_script("1", "1", RUN_ID="T-8")
        self.assertEqual(code, 2)
        self.assertIn("nothing was overwritten", err)
        self.assertEqual({p: open(p, "rb").read() for p in paths}, before)
        self.assertEqual(sorted(os.path.join(self.out, n) for n in os.listdir(self.out)), paths)

    def test_input_validation(self):
        for args, env in ((["1", "1"], {}),                                   # RUN_ID missing
                          (["1", "1"], {"RUN_ID": "../x"}),
                          (["0", "1"], {"RUN_ID": "T-5"}),
                          (["1", "1"], {"RUN_ID": "T-5", "RUN_START_EPOCH": "yesterday"})):
            with self.subTest(args=args, env=env):
                code, _, err = self.run_script(*args, **env)
                self.assertEqual(code, 2, err)


class LineEndingTests(OfflineTestCase):
    """A CRLF checkout (core.autocrlf=true on Windows) would break the script in every Bash."""

    def test_script_has_lf_line_endings(self):
        with open(TELEMETRY, "rb") as f:
            self.assertNotIn(b"\r", f.read())

    def test_gitattributes_pins_lf_for_shell_scripts(self):
        with open(os.path.join(ROOT, ".gitattributes"), encoding="utf-8") as f:
            rules = [line.split() for line in f if line.strip() and not line.startswith("#")]
        self.assertIn(["*.sh", "text", "eol=lf"], rules)


class NativePosixTelemetryTests(_TelemetryScriptTests, OfflineTestCase):
    KIND = br.NATIVE_POSIX


class GitBashTelemetryTests(_TelemetryScriptTests, OfflineTestCase):
    KIND = br.GIT_BASH


class WslTelemetryTests(_TelemetryScriptTests, OfflineTestCase):
    KIND = br.WSL


if __name__ == "__main__":
    unittest.main()
