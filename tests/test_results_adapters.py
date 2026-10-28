"""05-results adapters: sadf -d CPU export and k6 raw JSON (synthetic files only).

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

Both formats are implemented from their documentation; real sample files are still required
(see the data requirements in the processing manifest).
"""

import json
import math
import unittest
from datetime import datetime, timezone

from _helpers import OfflineTestCase, load_module
import _results_fixtures as fx

sar = load_module("05-results/sar_adapter.py", "sar_adapter")
k6 = load_module("05-results/k6_raw_adapter.py", "k6_raw_adapter")


class SadfTests(OfflineTestCase):
    def test_u_all_export(self):
        data = sar.load_sadf_cpu(fx.sadf_text(n=5))
        self.assertEqual((data["host"], data["interval_sec"], data["column_set"]), ("sim-c1", [1], "u_all"))
        self.assertEqual(len(data["rows"]), 5)
        r = data["rows"][0]
        self.assertEqual(r["utc"], datetime(2026, 1, 1, tzinfo=timezone.utc))
        self.assertAlmostEqual(r["cpu_not_idle_pct"], 20.0)                 # 100 - %idle
        self.assertAlmostEqual(r["cpu_busy_excl_iowait_pct"], 19.0)         # 100 - %idle - %iowait
        self.assertEqual((r["iowait_pct"], r["steal_pct"]), (1.0, 0.5))
        self.assertAlmostEqual(r["usr_pct"] + r["sys_pct"] + r["soft_pct"], 20.0 - 1.0 - 0.5)
        self.assertEqual(data["temporal"], sar.CPU_TEMPORAL)
        self.assertNotIn("busy_pct", r)                                       # no ambiguous name

    def test_u_export_and_per_cpu_rows_ignored(self):
        text = ("# hostname;interval;timestamp;CPU;%user;%nice;%system;%iowait;%steal;%idle\n"
                "vm;1;2026-01-01 00:00:01 UTC;-1;10,0;0;5;1;0;84\n"
                "vm;1;2026-01-01 00:00:01 UTC;0;50;0;5;1;0;44\n"
                "vm;1;2026-01-01 00:00:02 UTC;all;20;0;5;1;0;74\n")
        data = sar.load_sadf_cpu(text)
        self.assertEqual(data["column_set"], "u")
        self.assertEqual([r["cpu_not_idle_pct"] for r in data["rows"]], [16.0, 26.0])   # decimal comma accepted
        self.assertEqual([r["cpu_busy_excl_iowait_pct"] for r in data["rows"]], [15.0, 25.0])
        self.assertTrue(math.isnan(data["rows"][0]["soft_pct"]))      # %system includes softirq in the -u set

    def test_unsupported_inputs_are_rejected_not_guessed(self):
        cases = {
            "sar text": "Linux 6.8.0 (vm) \t2026-01-01 \t_x86_64_\t(4 CPU)\n\n00:00:01 CPU %usr %idle\n",
            "local time": "# hostname;interval;timestamp;CPU;%user;%nice;%system;%iowait;%steal;%idle\n"
                          "vm;1;2026-01-01 01:00:01;-1;10;0;5;1;0;84\n",
            "unknown columns": "# hostname;interval;timestamp;CPU;%usr;%idle\nvm;1;2026-01-01 00:00:01 UTC;-1;1;99\n",
            "second activity": fx.sadf_text(n=2) + "# hostname;interval;timestamp;kbmemfree\n",
            "two hosts": fx.sadf_text("a", n=2) + "\n".join(fx.sadf_text("b", n=2).splitlines()[1:]) + "\n",
            "empty": "",
        }
        for name, text in cases.items():
            with self.subTest(name=name), self.assertRaises(sar.UnsupportedFormat):
                sar.load_sadf_cpu(text)

    def test_bad_rows_are_reported(self):
        text = fx.sadf_text(n=3) + "sim-c1;1;2026-01-01 00:00:09 UTC;-1;x;0;0;0;0;0;0;0;0;0\nshort;row\n"
        data = sar.load_sadf_cpu(text)
        self.assertEqual(len(data["rows"]), 3)
        self.assertEqual(len(data["issues"]), 2)


    def test_duplicates_and_overlaps_are_reported(self):
        text = fx.sadf_text(n=3) + "\n".join(fx.sadf_text(n=1).splitlines()[1:]) + "\n"   # repeated t0
        data = sar.load_sadf_cpu(text)
        self.assertEqual((len(data["rows"]), data["duplicates"]), (3, 1))
        self.assertTrue(any("duplicate" in i for i in data["issues"]))
        lines = fx.sadf_text(n=3, interval=2).splitlines()            # 2 s intervals stamped 2 s apart ...
        lines[2] = lines[2].replace("00:00:02 UTC", "00:00:01 UTC")   # ... one stamped only 1 s later
        data = sar.load_sadf_cpu("\n".join(lines) + "\n")
        self.assertEqual(data["overlaps"], 1)


class SadfMemTests(OfflineTestCase):
    def test_memory_export(self):
        data = sar.load_sadf_mem(fx.sadf_mem_text(n=4))
        self.assertEqual((data["host"], data["interval_sec"], len(data["rows"])), ("sim-c1", [1], 4))
        r = data["rows"][0]
        self.assertEqual((r["mem_used_pct"], r["mem_available_kb"]), (40.0, 2400000.0))
        self.assertEqual(data["temporal"], sar.MEM_TEMPORAL)
        self.assertIn("version dependent", data["definitions"]["mem_used_pct"])

    def test_missing_kbavail_is_nan_with_an_issue(self):
        data = sar.load_sadf_mem(fx.sadf_mem_text(n=2, kbavail=False))
        self.assertTrue(math.isnan(data["rows"][0]["mem_available_kb"]))
        self.assertTrue(any("kbavail" in i for i in data["issues"]))

    def test_unsupported_memory_inputs(self):
        for name, text in {"cpu export": fx.sadf_text(n=2),
                           "required column missing": "# hostname;interval;timestamp;kbmemfree;kbavail\n",
                           "second activity": fx.sadf_mem_text(n=2) + "# hostname;interval;timestamp;CPU;%idle\n",
                           "sar text": "Linux 6.8.0 (vm)\n"}.items():
            with self.subTest(name=name), self.assertRaises(sar.UnsupportedFormat):
                sar.load_sadf_mem(text)

    def test_duplicates_and_bad_rows(self):
        text = fx.sadf_mem_text(n=3) + "\n".join(fx.sadf_mem_text(n=1).splitlines()[1:]) + "\nshort;row\n"
        data = sar.load_sadf_mem(text)
        self.assertEqual((len(data["rows"]), data["duplicates"]), (3, 1))
        self.assertEqual(len(data["issues"]), 2)


class K6RawTests(OfflineTestCase):
    def point(self, metric, t, value=1):
        return json.dumps({"type": "Point", "metric": metric, "data": {"time": t, "value": value, "tags": {}}})

    def test_bins_and_empty_bins(self):
        lines = [self.point("request_attempts", "2026-01-01T00:00:00.123456789Z"),
                 self.point("responses_success", "2026-01-01T00:00:00.123456789Z"),
                 self.point("success_request_chain_duration", "2026-01-01T00:00:00.5+00:00", 40),
                 self.point("request_attempts", "2026-01-01T00:00:00.9Z"),
                 self.point("request_attempts", "2026-01-01T00:00:03Z"),
                 self.point("http_req_duration", "2026-01-01T00:00:03Z", 999)]
        data = k6.load_k6_raw("\n".join(lines), bin_sec=1.0)
        rows = data["rows"]           # bins start at the first point (00:00:00.123456)
        self.assertEqual(len(rows), 3)
        self.assertEqual((rows[0]["attempts"], rows[0]["success"], rows[0]["success_ratio"]), (2, 1, 0.5))
        self.assertEqual(rows[0]["success_latency_p95_ms"], 40)
        self.assertIsNone(rows[1]["attempts"])        # empty bin stays empty, not zero
        self.assertIsNone(rows[1]["success_ratio"])
        self.assertEqual((rows[2]["attempts"], rows[2]["success"], rows[2]["success_ratio"]), (1, 0.0, 0.0))
        self.assertEqual(data["issues"], [])

    def test_naive_time_is_skipped_and_reported(self):
        lines = [self.point("request_attempts", "2026-01-01T00:00:00Z"), self.point("request_attempts", "2026-01-01T00:00:01")]
        data = k6.load_k6_raw("\n".join(lines))
        self.assertEqual(len(data["issues"]), 1)
        self.assertIn("no UTC offset", data["issues"][0])

    def test_unsupported(self):
        for text in ("not json", json.dumps({"type": "Other"}),
                     json.dumps({"type": "Metric", "metric": "x", "data": {}}),
                     self.point("responses_success", "2026-01-01T00:00:00Z")):
            with self.subTest(text=text[:30]), self.assertRaises(k6.UnsupportedFormat):
                k6.load_k6_raw(text)

    def test_stage_tags_give_per_stage_raw_results(self):
        data = k6.load_k6_raw(fx.k6_raw_text(seconds=90))
        st = {s["stage"]: s for s in data["stages"]}
        self.assertEqual(sorted(st), ["s01_ramp_to_50", "s02_hold_50", "s03_ramp_down"])
        self.assertEqual(st["s02_hold_50"]["attempts"], 30 * 20)
        self.assertEqual(st["s02_hold_50"]["primary_error_rate"], 0.0)
        self.assertGreater(st["s01_ramp_to_50"]["primary_error_rate"], 0.0)   # the dip at 20-23 s
        untagged = k6.load_k6_raw(self.point("request_attempts", "2026-01-01T00:00:00Z"))
        self.assertEqual(untagged["stages"], [])

    def test_fixture_text_is_parsed(self):
        data = k6.load_k6_raw(fx.k6_raw_text(seconds=30))
        self.assertEqual(len(data["rows"]), 30)
        dip = data["rows"][21]
        self.assertTrue(dip["success_ratio"] < 1.0)
        self.assertFalse(any(isinstance(r["success_ratio"], float) and math.isnan(r["success_ratio"])
                             for r in data["rows"]))


if __name__ == "__main__":
    unittest.main()
