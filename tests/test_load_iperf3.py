"""run_iperf3_comparison.py: path labels vs verification, parsing, validity and run loop (offline).

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.
"""

import contextlib
import csv
import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from _helpers import OfflineTestCase, load_module

ip = load_module("01-load-test/run_iperf3_comparison.py", "run_iperf3_comparison")


def iperf_json(bps=500e6, retransmits=7):
    sent = {"bits_per_second": bps * 1.01}
    if retransmits is not None:
        sent["retransmits"] = retransmits
    return json.dumps({"end": {"sum_received": {"bits_per_second": bps}, "sum_sent": sent}})


class ParseTests(OfflineTestCase):
    def test_valid_output(self):
        m, reason = ip.parse_iperf3_json(iperf_json(500e6, 7))
        self.assertEqual(reason, "")
        self.assertEqual(m["received_mbps"], 500.0)
        self.assertEqual(m["sender_tcp_retransmits"], 7)

    def test_missing_retransmits_is_none(self):
        m, _ = ip.parse_iperf3_json(iperf_json(retransmits=None))
        self.assertIsNone(m["sender_tcp_retransmits"])

    def test_optional_tcp_fields_are_none_not_zero(self):
        m, _ = ip.parse_iperf3_json(iperf_json())
        for key in ("sender_mean_rtt_us", "sender_max_rtt_us", "sender_max_snd_cwnd_bytes", "host_cpu_pct",
                    "remote_cpu_pct", "received_bytes", "measured_duration_sec", "iperf3_version"):
            self.assertIsNone(m[key], key)

    def test_tcp_info_fields_from_streams(self):
        data = {"start": {"version": "iperf 3.12", "test_start": {"protocol": "TCP"}},
                "end": {"sum_received": {"bits_per_second": 4e8, "bytes": 1500000000, "seconds": 30.01},
                        "sum_sent": {"bits_per_second": 4.1e8, "bytes": 1530000000, "retransmits": 12},
                        "streams": [{"sender": {"mean_rtt": 1000, "max_rtt": 5000, "max_snd_cwnd": 100000}},
                                    {"sender": {"mean_rtt": 3000, "max_rtt": 9000, "max_snd_cwnd": 300000}},
                                    {"sender": {}}],
                        "cpu_utilization_percent": {"host_total": 11.5, "remote_total": 40.25}}}
        m, reason = ip.parse_iperf3_json(json.dumps(data))
        self.assertEqual(reason, "")
        self.assertEqual((m["sender_mean_rtt_us"], m["sender_max_rtt_us"], m["sender_max_snd_cwnd_bytes"]),
                         (2000.0, 9000, 300000))
        self.assertEqual((m["received_bytes"], m["sent_bytes"], m["measured_duration_sec"]),
                         (1500000000, 1530000000, 30.01))
        self.assertEqual((m["host_cpu_pct"], m["remote_cpu_pct"], m["iperf3_version"]), (11.5, 40.25, "iperf 3.12"))

    def test_non_tcp_protocol_is_invalid(self):
        data = json.loads(iperf_json())
        data["start"] = {"test_start": {"protocol": "UDP"}}
        m, reason = ip.parse_iperf3_json(json.dumps(data))
        self.assertIsNone(m)
        self.assertIn("not TCP", reason)

    def test_invalid_outputs(self):
        for text, expected in (("not json", "not JSON"),
                               (json.dumps({"error": "unable to connect to server"}), "iperf3 error"),
                               (json.dumps({"end": {}}), "sum_received")):
            with self.subTest(expected=expected):
                m, reason = ip.parse_iperf3_json(text)
                self.assertIsNone(m)
                self.assertIn(expected, reason)


class PathTests(OfflineTestCase):
    def args(self, *extra):
        return ip.parse_args(list(extra), {})

    def test_labels_are_not_verification(self):
        paths = ip.build_paths(self.args("--path", "direct=10.0.1.123", "--path", "sse=app.test.invalid"), {})
        self.assertEqual([p.verification for p in paths], [ip.NOT_VERIFIED, ip.NOT_VERIFIED])

    def test_operator_assertion_needs_evidence_and_is_recorded(self):
        paths = ip.build_paths(self.args("--path", "direct=10.0.1.123", "--path", "sse=app.test.invalid:5202",
                                         "--path-evidence", "sse=SSE TCP app configured; seen on C1 sar"), {})
        sse = paths[1]
        self.assertEqual((sse.verification, sse.port), (ip.OPERATOR_ASSERTED, 5202))
        self.assertIn("seen on C1", sse.evidence)
        with self.assertRaises(ValueError):
            ip.PathSpec("sse", "h", 5201, ip.OPERATOR_ASSERTED, "  ")

    def test_env_paths(self):
        paths = ip.build_paths(self.args(), {"IPERF3_DIRECT_HOST": "10.0.1.123", "IPERF3_SSE_HOST": "app.test.invalid"})
        self.assertEqual([p.label for p in paths], ["direct", "sse"])

    def test_rejected_configurations(self):
        bad = [
            ("--path", "direct=10.0.1.123"),                                            # only one path
            ("--path", "direct=10.0.1.123", "--path", "sse=10.0.1.123"),               # same host:port
            ("--path", "a=h1", "--path", "a=h2"),                                      # duplicate label
            ("--path", "direct=h1", "--path", "sse=h2", "--path-evidence", "x=note"),  # unknown label
            ("--path", "direct=h1;rm", "--path", "sse=h2"),                            # invalid host
        ]
        for extra in bad:
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                ip.build_paths(self.args(*extra), {})


class RunTests(OfflineTestCase):
    def cfg(self, d, *extra):
        return ip.Config(ip.parse_args(["--path", "direct=10.0.1.123", "--path", "sse=app.test.invalid",
                                        "--repetitions", "2", "--run-id", "IP-1", "--output-dir", d, *extra], {}), {})

    def test_alternating_order_raw_files_and_summary(self):
        calls = []

        def runner(cmd, timeout):
            calls.append(cmd[cmd.index("-c") + 1])
            return 0, iperf_json(900e6 if cmd[2] == "10.0.1.123" else 300e6), ""

        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()):
            runs, summaries, manifest = ip.run_comparison(self.cfg(d), runner, sleep=lambda s: None)
            raw = sorted(os.listdir(os.path.join(d, "IP-1", "raw")))
        self.assertEqual(calls, ["10.0.1.123", "app.test.invalid"] * 2)
        self.assertEqual(len(raw), 4)
        self.assertEqual([s["status"] for s in summaries], ["complete", "complete"])
        self.assertEqual(summaries[1]["received_mbps_median"], 300.0)
        self.assertEqual(summaries[1]["path_verification"], ip.NOT_VERIFIED)
        self.assertIn("not packet loss", " ".join(manifest["notes"]))
        self.assertIn("no HTTP status", " ".join(manifest["notes"]))
        self.assertEqual(manifest["validity"]["status"], "all_runs_valid")

    def test_injected_clocks_give_utc_and_monotonic_times(self):
        ticks = iter(range(50, 500, 10))
        base = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)
        walls = iter(base + timedelta(seconds=s) for s in range(0, 500, 31))
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()):
            runs, _, _ = ip.run_comparison(self.cfg(d), lambda c, t: (0, iperf_json(), ""), sleep=lambda s: None,
                                           now=lambda: next(walls), clock=lambda: next(ticks))
        self.assertEqual([(r["mono_start_sec"], r["mono_end_sec"], r["wall_duration_sec"]) for r in runs[:2]],
                         [(10, 20, 10), (30, 40, 10)])
        self.assertEqual((runs[0]["started_utc"], runs[0]["ended_utc"]),
                         ("2026-10-26T12:00:31.000+00:00", "2026-10-26T12:01:02.000+00:00"))

    def test_subprocess_runner_decodes_utf8_explicitly(self):
        fake = mock.Mock(returncode=0, stdout="{}", stderr="")
        with mock.patch.object(ip.subprocess, "run", return_value=fake) as run:
            ip.subprocess_runner(["iperf3", "-c", "h"], 5)
        self.assertEqual((run.call_args.kwargs["encoding"], run.call_args.kwargs["errors"]), ("utf-8", "replace"))

    def test_invalid_run_makes_path_invalid_without_zero_values(self):
        outputs = iter([(0, iperf_json(), ""), (1, json.dumps({"error": "unable to connect"}), ""),
                        (0, iperf_json(), ""), (None, "", "iperf3 did not finish within 60s")])
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()):
            runs, summaries, manifest = ip.run_comparison(self.cfg(d), lambda c, t: next(outputs),
                                                          sleep=lambda s: None)
            with open(os.path.join(d, "IP-1", "iperf3_runs.csv"), encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
        sse_rows = [r for r in rows if r["path_label"] == "sse"]
        self.assertTrue(all(r["valid"] == "False" and r["received_mbps"] == "" for r in sse_rows))
        self.assertIn("iperf3 error", sse_rows[0]["invalid_reason"])
        self.assertEqual([s["status"] for s in summaries], ["complete", "invalid"])
        self.assertEqual(manifest["validity"]["status"], "contains_invalid_runs")
        self.assertEqual([(r["round"], r["path_label"]) for r in manifest["invalid_runs"]], [(1, "sse"), (2, "sse")])

    def test_dry_run_is_labelled_and_runs_no_process(self):
        with tempfile.TemporaryDirectory() as d, \
                mock.patch("subprocess.run", side_effect=AssertionError("no subprocess in dry-run")), \
                contextlib.redirect_stdout(io.StringIO()):
            code = ip.main(["--dry-run", "--path", "direct=10.0.1.123", "--path", "sse=app.test.invalid",
                            "--run-id", "DRY-IP", "--output-dir", d], environ={})
            with open(os.path.join(d, "DRY-IP", "iperf3_manifest.json"), encoding="utf-8") as f:
                manifest = json.load(f)
        self.assertEqual(code, 0)
        self.assertIn("NOT a measurement", manifest["mode"])

    def test_missing_iperf3_runs_nothing(self):
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()) as out:
            code = ip.main(["--path", "direct=10.0.1.123", "--path", "sse=app.test.invalid",
                            "--iperf3-path", "definitely-not-iperf3", "--output-dir", d], environ={})
            self.assertEqual(os.listdir(d), [])
        self.assertEqual(code, 2)
        self.assertIn("nothing was run", out.getvalue())


if __name__ == "__main__":
    unittest.main()
