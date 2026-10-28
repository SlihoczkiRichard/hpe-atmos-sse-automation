"""05-results derive.py: computations behind the figures (pure, synthetic rows).

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.
"""

import math
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from _helpers import OfflineTestCase, load_module

d = load_module("05-results/derive.py", "results_derive")


def nan(x):
    return isinstance(x, float) and math.isnan(x)


class Measurement1Tests(OfflineTestCase):
    def test_invalid_runs_are_gaps_not_zero(self):
        runs = [{"concurrency": "50", "sweep": "1", "valid": "True", "successful_rps": "100", "primary_error_rate": "0",
                 "lat_all_responses_p95_ms": "20", "started_utc": "", "ended_utc": ""},
                {"concurrency": "50", "sweep": "2", "valid": "False", "successful_rps": "", "primary_error_rate": "",
                 "invalid_reason": "hey exit code 1"}]
        pts = d.hey_points(runs)
        self.assertEqual(pts[0]["successful_rps"], 100.0)
        self.assertTrue(nan(pts[1]["successful_rps"]) and nan(pts[1]["primary_error_rate"]))
        self.assertTrue(nan(pts[0]["lat_all_responses_p99_ms"]))      # missing column -> gap

    def test_levels_keep_logged_status_and_best_level(self):
        levels = [{"concurrency": "50", "status": "accepted", "successful_rps_median": "100"},
                  {"concurrency": "150", "status": "rejected", "successful_rps_median": "290"},
                  {"concurrency": "300", "status": "invalid", "successful_rps_median": ""}]
        out = d.hey_levels(levels, {"primary_result": {"best_level": 50}})
        self.assertEqual([lv["status"] for lv in out], ["accepted", "rejected", "invalid"])
        self.assertEqual([lv["best_accepted_level"] for lv in out], [True, False, False])
        self.assertTrue(nan(out[2]["successful_rps_median"]))

    def test_hey_intervals_need_utc(self):
        runs = [{"concurrency": "50", "sweep": "1", "valid": "True", "successful_rps": "10",
                 "primary_error_rate": "0", "started_utc": "2026-01-01T00:00:00.000+00:00",
                 "ended_utc": "2026-01-01T00:00:05.000+00:00"},
                {"concurrency": "50", "sweep": "2", "valid": "True", "successful_rps": "10", "primary_error_rate": "0",
                 "started_utc": "2026-01-01T00:00:00", "ended_utc": "2026-01-01T00:00:05"}]   # naive: not UTC
        iv = d.hey_intervals(runs)
        self.assertEqual(len(iv), 1)
        self.assertEqual((iv[0]["end_utc"] - iv[0]["start_utc"]).total_seconds(), 5.0)


class Measurement2Tests(OfflineTestCase):
    def test_c2_missing_samples_stay_nan(self):
        rows = [{"monotonic_s": "0", "timestamp_utc": "2026-01-01T00:00:00+00:00", "c1_sample_end_s": "0.5",
                 "c1_cpu_pct": "90", "c2_sample_end_s": "", "c2_cpu_pct": "", "decision_s": "0.6"},
                {"monotonic_s": "5", "timestamp_utc": "2026-01-01T00:00:05+00:00", "c1_sample_end_s": "5.5",
                 "c1_cpu_pct": "", "c2_sample_end_s": "6", "c2_cpu_pct": "0", "decision_s": "6.1"}]
        s = d.scaler_series(rows)
        self.assertTrue(nan(s[0]["c2_cpu_pct"]) and nan(s[1]["c1_cpu_pct"]))
        self.assertEqual(s[1]["c2_cpu_pct"], 0.0)   # a real zero stays zero

    def test_logged_threshold_and_checks_are_verbatim(self):
        events = [{"event": "THRESHOLD_MET", "detail": "c1_cpu=90.0% >= 75.5% for 15.0s", "monotonic_s": "15"},
                  {"event": "ACTIVATION_CHECK", "detail": "check=C2_TRAFFIC_OBSERVED; status=verified; +3.0s",
                   "monotonic_s": "20"},
                  {"event": "ACTIVATION_CHECK", "detail": "check=GUEST_REACHABLE; status=not_checked; no check configured",
                   "monotonic_s": "20"},
                  {"event": "ACTIVATION_SUMMARY", "detail": "reason=daemon stopped; ...", "monotonic_s": "20"}]
        self.assertEqual(d.logged_threshold(events), 75.5)
        (act,) = d.activation_checks(events)
        self.assertEqual(act["reason"], "daemon stopped")
        # a future verified C2_TRAFFIC_OBSERVED is shown as verified (no hard-coded rule)
        self.assertEqual([(c["check"], c["status"]) for c in act["checks"]],
                         [("C2_TRAFFIC_OBSERVED", "verified"), ("GUEST_REACHABLE", "not_checked")])
        self.assertIsNone(d.logged_threshold([]))

    def test_time_sync_statement_needs_source_and_uncertainty(self):
        self.assertFalse(d.time_sync_statement(None)[0])
        ok, reason = d.time_sync_statement({"statement": "NTP to the same server", "source": "operator"})
        self.assertFalse(ok)
        self.assertIn("known_uncertainty", reason)
        ok, note = d.time_sync_statement({"statement": "chrony", "source": "operator log",
                                          "known_uncertainty": "not measured"})
        self.assertTrue(ok)
        self.assertIn("not verified by the processor", note)


class Measurement3Tests(OfflineTestCase):
    def analysis(self, outcome, validity="valid"):
        ref = {"seq": 1, "start_mono_s": 110.0, "end_mono_s": 110.2}
        return {"run_validity": validity, "validity_reasons": [] if validity == "valid" else ["baseline failed"],
                "recovery": {"outcome": outcome, "first_failure": ref, "first_success": ref,
                             "stable_first_success": ref if outcome == "recovered_stable" else None,
                             "stable_confirmed": ref if outcome == "recovered_stable" else None},
                "markers_used": [{"kind": "fault_injected", "monotonic_s": 105.0}]}

    def test_outcomes_are_not_merged_and_validity_is_separate(self):
        for outcome in ("not_recovered", "recovered_unstable", "recovered_stable"):
            with self.subTest(outcome=outcome):
                s = d.failover_states(self.analysis(outcome, "not_valid"), 100.0, "tcp")
                self.assertEqual((s["outcome"], s["run_validity"]), (outcome, "not_valid"))
        s = d.failover_states(self.analysis("recovered_stable"), 100.0, "tcp")
        self.assertEqual(s["stable_first_success_t_s"], 10.0)
        self.assertAlmostEqual(s["stable_confirmed_t_s"], 10.2, places=9)
        self.assertEqual(s["markers"], [{"kind": "fault_injected", "t_s": 5.0}])
        self.assertIsNone(d.failover_states(None, 0, "tcp"))

    def test_outage_spans_and_series(self):
        spans = d.outage_spans([{"outage_index": "1", "first_failure_start_mono_s": "140", "last_failure_end_mono_s": "142.5",
                                 "failed_probes": "10", "isolated_failure": "False", "failure_span_ms": "2500",
                                 "bracket_interval_ms": "", "bracket_interval_reason": "no successful probe after"}], 100)
        self.assertEqual((spans[0]["start_t_s"], spans[0]["end_t_s"]), (40.0, 42.5))
        self.assertTrue(nan(spans[0]["bracket_interval_ms"]))
        series = d.failover_series([{"seq": "1", "event": "probe", "start_mono_s": "100.0", "end_mono_s": "100.004",
                                     "ok": "True", "error_class": ""}], 100.0)
        self.assertAlmostEqual(series[0]["duration_ms"], 4.0, places=6)

    def test_markers_from_rows(self):
        m = d.markers_from_rows([{"run_id": "R", "kind": "fault_injected", "monotonic_s": "35.0", "host": "h",
                                  "system": "Linux", "boot_id": "b", "boot_epoch_estimate": "", "simulated": "False"}])
        self.assertEqual((m[0]["monotonic_s"], m[0]["clock_domain"]["boot_epoch_estimate"]), (35.0, None))


class Measurement4Tests(OfflineTestCase):
    def ds(self, rep, attempt, latencies, outcome="blocked_stable"):
        return SimpleNamespace(run_id="R", attempt=attempt, repetition=rep, data={"summary": {
            "outcome": outcome, "run_validity": "valid", "observed_blocking_latency_ms": latencies}})

    def test_negative_latencies_are_kept(self):
        rows = d.canary_latency_rows([self.ds(1, 1, {"from_update_response": {"first_blocked_start_ms": -400.0,
                                                                                "stable_run_confirmed_end_ms": None}})])
        self.assertEqual(rows[0]["first_blocked_start_ms"], -400.0)
        self.assertTrue(nan(rows[0]["stable_run_confirmed_end_ms"]))

    def test_duplicate_repetitions_detected(self):
        dups = d.duplicate_repetitions([self.ds(1, 1, {}), self.ds(1, 2, {}), self.ds(2, 3, {})])
        self.assertEqual(dups, [("R", 1)])


T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def at(s):
    return T0 + timedelta(seconds=s)


def cpu_rows(times, not_idle=50.0, iowait=5.0, interval=1):
    return [{"utc": at(t), "interval_sec": interval, "cpu_not_idle_pct": not_idle,
             "cpu_busy_excl_iowait_pct": not_idle - iowait, "usr_pct": 30.0, "sys_pct": 10.0, "iowait_pct": iowait,
             "steal_pct": 0.0, "irq_pct": 0.0, "soft_pct": 5.0} for t in times]


def mem_rows(times, used=40.0, avail=1000.0):
    return [{"utc": at(t), "interval_sec": 1, "mem_used_pct": used, "mem_available_kb": avail, "mem_free_kb": 1.0}
            for t in times]


def hey_run(c, sweep, start, end, valid=True, rps=100.0):
    return {"concurrency": str(c), "sweep": str(sweep), "valid": str(valid), "successful_rps": str(rps),
            "started_utc": at(start).isoformat(), "ended_utc": at(end).isoformat()}


class ResourceWindowTests(OfflineTestCase):
    def test_cpu_interval_must_lie_fully_inside_the_window(self):
        rows = cpu_rows([10, 11, 12, 13])          # intervals (9,10] (10,11] (11,12] (12,13]
        out = d.cpu_window(rows, at(10), at(12.5), 0.9)
        self.assertEqual(out["cpu_samples"], 2)    # (10,11] and (11,12]; (9,10] starts before, (12,13] ends after
        self.assertAlmostEqual(out["cpu_coverage"], 2 / 2.5)
        self.assertEqual(out["cpu_status"], "partial")

    def test_overlapping_cpu_records_are_not_counted_twice(self):
        rows = cpu_rows([2, 4, 5, 6], interval=2)  # the record at 5 overlaps (3,5] with (2,4]
        out = d.cpu_window(rows, at(0), at(6), 0.9)
        self.assertEqual((out["cpu_samples"], out["cpu_overlap_excluded"]), (3, 1))
        self.assertLessEqual(out["cpu_coverage"], 1.0)
        self.assertEqual(out["cpu_covered_sec"], 6.0)

    def test_memory_slots_bound_coverage(self):
        rows = mem_rows([0, 0.2, 0.5, 1, 2, 3])   # three readings in the first 1 s slot
        out = d.mem_window(rows, at(0), at(4), 1, 0.9)
        self.assertEqual((out["mem_samples"], out["mem_extra_excluded"], out["mem_slots"]), (4, 2, 4))
        self.assertEqual((out["mem_coverage"], out["mem_status"]), (1.0, "complete"))

    def test_missing_telemetry_is_a_gap_not_zero(self):
        out = d.cpu_window([], at(0), at(5), 0.9)
        self.assertEqual((out["cpu_samples"], out["cpu_status"]), (0, "missing"))
        self.assertTrue(nan(out["cpu_not_idle_pct_mean"]))
        out = d.mem_window([], at(0), at(5), 1, 0.9)
        self.assertTrue(nan(out["mem_used_pct_mean"]))

    def test_cpu_components_absent_in_the_u_set_stay_nan(self):
        rows = cpu_rows([1, 2])
        for r in rows:
            r["soft_pct"] = float("nan")
        out = d.cpu_window(rows, at(0), at(2), 0.9)
        self.assertTrue(nan(out["soft_pct_mean"]))
        self.assertEqual(out["iowait_pct_mean"], 5.0)

    def test_warmup_is_explicit_and_can_empty_a_window(self):
        runs = [hey_run(50, 1, 0, 10), hey_run(50, 2, 20, 22)]
        w = d.resource_windows(runs, 3.0)
        self.assertEqual((w[0]["window_start_utc"], w[0]["window_sec"]), (at(3), 7.0))
        self.assertEqual(w[1]["window_state"], "empty_after_warmup")
        self.assertIn("warm-up of the first 3 s", d.window_description(3.0))
        self.assertEqual(d.window_description(0), "whole hey run interval")

    def test_level_aggregate_uses_complete_hey_valid_runs_only(self):
        runs = [hey_run(50, 1, 0, 10, rps=100), hey_run(50, 2, 10, 20, rps=110),
                hey_run(50, 3, 20, 30, rps=120), hey_run(150, 1, 30, 40, valid=False)]
        cpu = {"rows": cpu_rows(range(1, 21), not_idle=40.0) + cpu_rows(range(21, 24), not_idle=90.0)
               + cpu_rows(range(31, 41), not_idle=95.0)}
        mem = {"rows": mem_rows(range(0, 11)), "interval_sec": [1]}
        rows = d.resources_by_run(d.resource_windows(runs, 0.0), cpu, mem, 0.9)
        self.assertEqual([r["cpu_status"] for r in rows], ["complete", "complete", "partial", "complete"])
        # the reading at t=10 s lies on the boundary of the second window (closed interval): partial
        self.assertEqual([r["mem_status"] for r in rows], ["complete", "partial", "missing", "missing"])
        lv = {x["concurrency"]: x for x in d.resources_by_level(rows)}
        self.assertEqual((lv[50]["cpu_runs_used"], lv[50]["cpu_runs_partial"], lv[50]["runs_total"]), (2, 1, 3))
        self.assertEqual(lv[50]["cpu_not_idle_pct_mean_median"], 40.0)     # the partial 90 % run is not mixed in
        self.assertEqual(lv[50]["successful_rps_median_cpu_runs"], 105.0)
        self.assertEqual((lv[50]["mem_runs_used"], lv[50]["mem_runs_partial"], lv[50]["mem_runs_missing_or_no_window"]),
                         (1, 1, 1))
        self.assertEqual((lv[150]["runs_hey_invalid"], lv[150]["cpu_runs_used"]), (1, 0))
        self.assertTrue(nan(lv[150]["cpu_not_idle_pct_mean_median"]))      # invalid hey run: no value

    def test_memory_not_provided_is_explicit(self):
        rows = d.resources_by_run(d.resource_windows([hey_run(50, 1, 0, 3)], 0.0), {"rows": cpu_rows([1, 2, 3])},
                                  None, 0.9)
        self.assertEqual(rows[0]["mem_status"], "not_provided")
        self.assertEqual(d.resources_by_level(rows)[0]["mem_runs_not_provided"], 1)

if __name__ == "__main__":
    unittest.main()
