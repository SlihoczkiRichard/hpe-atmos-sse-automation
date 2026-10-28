"""failover_analysis.py: outages, recovery, baseline rule, markers/clock domains, persistent continuity.

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

Pure functions on synthetic records; nothing is executed against a network.
"""

import unittest

from _helpers import OfflineTestCase, load_module

fa = load_module("03-failover/failover_analysis.py", "failover_analysis")

DOMAIN = {"host": "probe-host", "system": "Linux", "boot_id": "boot-a", "boot_epoch_estimate": 1000.0,
          "simulated": False}


def series(pattern, interval=0.05, ok_dur=0.004, fail_dur=0.25, start=0.0):
    """'.' = success, 'x' = failure; one probe per grid slot, a failure lasts fail_dur."""
    recs, t = [], start
    for i, ch in enumerate(pattern, 1):
        ok = ch == "."
        dur = ok_dur if ok else fail_dur
        recs.append({"seq": i, "start_mono_s": round(t, 6), "end_mono_s": round(t + dur, 6), "ok": ok,
                     "error_class": "" if ok else "timeout", "start_utc": "", "end_utc": "", "skipped_slots": 0})
        t += max(interval, dur)
    return recs


def marker(t, kind="fault_injected", run_id="R1", domain=None):
    return {"run_id": run_id, "kind": kind, "monotonic_s": t, "utc": "", "clock_domain": dict(domain or DOMAIN)}


def analyze(recs, markers, **kw):
    return fa.analyze_new_connection(recs, markers, "R1", DOMAIN, 0.05, **kw)


class OutageTests(OfflineTestCase):
    def test_formulas_use_probe_start_and_end_times(self):
        recs = series("..xxx..")
        (o,) = fa.find_outages(recs)
        first, last, prev, nxt = recs[2], recs[4], recs[1], recs[5]
        self.assertEqual(o["failure_span_ms"], round((last["end_mono_s"] - first["start_mono_s"]) * 1000, 3))
        self.assertEqual(o["bracket_interval_ms"], round((nxt["start_mono_s"] - prev["end_mono_s"]) * 1000, 3))
        self.assertEqual(o["failure_span_formula"], "last failed probe end - first failed probe start")
        self.assertEqual(o["bracket_interval_formula"], "first success after start - last success before end")
        self.assertEqual((o["failed_probes"], o["isolated_failure"], o["error_classes"]), (3, False, {"timeout": 3}))

    def test_missing_neighbour_success_leaves_bracket_empty_with_reason(self):
        cases = {"xx..": "no successful probe before the outage",
                 "..xx": "no successful probe after the outage (data ends with failures)",
                 "xxx": "no successful probe before and after the outage"}
        for pattern, reason in cases.items():
            with self.subTest(pattern=pattern):
                (o,) = fa.find_outages(series(pattern))
                self.assertIsNone(o["bracket_interval_ms"])
                self.assertEqual(o["bracket_interval_reason"], reason)
                self.assertIsNotNone(o["failure_span_ms"])

    def test_multiple_outages_and_isolated_failure(self):
        outages = fa.find_outages(series("..x...xxx..x"))
        self.assertEqual([o["failed_probes"] for o in outages], [1, 3, 1])
        self.assertEqual([o["isolated_failure"] for o in outages], [True, False, True])
        self.assertEqual([o["outage_index"] for o in outages], [1, 2, 3])


class RecoveryTests(OfflineTestCase):
    BASE = "." * 700  # 35 s of successes at 50 ms

    def test_stable_recovery_first_success_and_confirmation_are_separate(self):
        recs = series(self.BASE + "xxxx" + "." * 12)
        summary, _ = analyze(recs, [marker(34.0)], recovery_n=10)
        r = summary["recovery"]
        self.assertEqual(r["outcome"], fa.OUTCOME_STABLE)
        first_ok = recs[704]
        self.assertEqual(r["stable_first_success"]["seq"], first_ok["seq"])
        self.assertEqual(r["stable_confirmed"]["seq"], first_ok["seq"] + 9)
        self.assertEqual(r["marker_relative_ms"]["stable_first_success_ms"],
                         round((first_ok["start_mono_s"] - 34.0) * 1000, 3))
        self.assertEqual(r["marker_relative_ms"]["stable_confirmed_ms"],
                         round((recs[713]["end_mono_s"] - 34.0) * 1000, 3))
        self.assertGreater(r["marker_relative_ms"]["stable_confirmed_ms"], r["marker_relative_ms"]["stable_first_success_ms"])
        self.assertEqual(summary["run_validity"], "valid")

    def test_flapping_moves_stable_recovery_later(self):
        recs = series(self.BASE + "xxx" + "...." + "xx" + "." * 10)
        r = analyze(recs, [marker(34.0)])[0]["recovery"]
        self.assertEqual(r["outcome"], fa.OUTCOME_STABLE)
        self.assertEqual(r["first_success"]["seq"], 704)           # first success after the first failure
        self.assertEqual(r["stable_first_success"]["seq"], 710)    # after the second outage
        self.assertEqual(r["outages_until_stable"], 2)

    def test_not_recovered_and_unstable(self):
        r = analyze(series(self.BASE + "xxxxx"), [marker(34.0)])[0]["recovery"]
        self.assertEqual(r["outcome"], fa.OUTCOME_NOT_RECOVERED)
        self.assertNotIn("first_success_ms", r["marker_relative_ms"])
        r = analyze(series(self.BASE + "xx" + "....."), [marker(34.0)])[0]["recovery"]
        self.assertEqual(r["outcome"], fa.OUTCOME_UNSTABLE)
        self.assertIsNone(r["stable_confirmed"])
        r = analyze(series(self.BASE + "xx" + "..x"), [marker(34.0)])[0]["recovery"]
        self.assertEqual(r["outcome"], fa.OUTCOME_NOT_RECOVERED)   # data ends with a failure

    def test_no_outage_after_marker_is_not_valid(self):
        summary, _ = analyze(series(self.BASE + "." * 50), [marker(34.0)])
        self.assertEqual(summary["recovery"]["outcome"], fa.OUTCOME_NO_OUTAGE)
        self.assertEqual(summary["run_validity"], "not_valid")

    def test_recovery_n_is_configurable(self):
        recs = series(self.BASE + "xx" + "." * 5)
        self.assertEqual(analyze(recs, [marker(34.0)], recovery_n=5)[0]["recovery"]["outcome"], fa.OUTCOME_STABLE)
        self.assertEqual(analyze(recs, [marker(34.0)], recovery_n=6)[0]["recovery"]["outcome"], fa.OUTCOME_UNSTABLE)

    def test_failed_probe_ratio_is_not_called_packet_loss(self):
        summary, _ = analyze(series("." * 8 + "xx"), [])
        self.assertEqual(summary["failed_probe_ratio"], 0.2)
        self.assertIn("not packet loss", summary["failed_probe_ratio_note"])
        self.assertNotIn("packet_loss", " ".join(summary))


class BaselineTests(OfflineTestCase):
    def test_ok(self):
        b = fa.evaluate_baseline(series("." * 700), 34.0, 30.0, 0, 1.0)
        self.assertEqual((b["status"], b["failed_probes"]), ("ok", 0))
        self.assertIn("failed probes <= 0", b["rule"])

    def test_failure_in_window_fails_and_invalidates_run(self):
        recs = series("." * 400 + "x" + "." * 299 + "xx..")
        summary, _ = analyze(recs, [marker(35.2)])
        self.assertEqual(summary["baseline"]["status"], "failed")
        self.assertEqual(summary["run_validity"], "not_valid")
        self.assertTrue(any(r.startswith("baseline failed") for r in summary["validity_reasons"]))
        # explicitly tolerating one failure is possible
        self.assertEqual(analyze(recs, [marker(35.2)], baseline_max_failures=1)[0]["baseline"]["status"], "ok")

    def test_too_short_baseline_is_incomplete(self):
        recs = series("." * 300 + "xx..", start=20.0)   # probes start only 15 s before the marker
        summary, _ = analyze(recs, [marker(35.0)])
        self.assertEqual(summary["baseline"]["status"], "incomplete")
        self.assertIn("coverage", summary["baseline"]["reasons"][0])
        self.assertEqual(summary["run_validity"], "not_valid")

    def test_gap_in_baseline_is_incomplete(self):
        recs = series("." * 300) + series("." * 300 + "xx..", start=17.0)   # 2 s hole at 15-17 s
        for i, r in enumerate(recs, 1):
            r["seq"] = i
        b = fa.evaluate_baseline(recs, 34.0, 30.0, 0, 1.0)
        self.assertEqual(b["status"], "incomplete")
        self.assertIn("continuity", b["reasons"][0])


class MarkerTests(OfflineTestCase):
    RECS = series("." * 700 + "xx" + "." * 12)

    def test_no_marker_means_not_valid(self):
        summary, _ = analyze(self.RECS, [])
        self.assertEqual(summary["run_validity"], "not_valid")
        self.assertIsNone(summary["recovery"])

    def test_markers_of_other_runs_or_clock_domains_are_rejected(self):
        bad = [marker(34.0, run_id="R2"),
               marker(34.0, domain=dict(DOMAIN, boot_id="boot-b")),
               marker(34.0, domain=dict(DOMAIN, host="other-host")),
               marker(34.0, domain=dict(DOMAIN, boot_id="", boot_epoch_estimate=1005.0)),
               marker(34.0, domain={"host": "simulated", "system": "simulated", "simulated": True})]
        summary, _ = analyze(self.RECS, bad)
        self.assertEqual(len(summary["markers_rejected"]), 5)
        self.assertEqual(summary["markers_used"], [])
        self.assertEqual(summary["run_validity"], "not_valid")
        reasons = " | ".join(r["reason"] for r in summary["markers_rejected"])
        for text in ("run_id 'R2'", "different boot_id", "different host/OS", "boot time estimates differ"):
            self.assertIn(text, reasons)

    def test_boot_estimate_within_tolerance_is_accepted_without_boot_id(self):
        probe_domain = dict(DOMAIN, boot_id="")
        ok, reason = fa.clock_domains_match(dict(probe_domain, boot_epoch_estimate=1001.5), probe_domain)
        self.assertTrue(ok, reason)

    def test_marker_is_an_operator_signal_and_multiple_faults_are_flagged(self):
        summary, _ = analyze(self.RECS, [marker(34.0), marker(34.5)])
        self.assertEqual(summary["marker_source"], fa.OPERATOR_SIGNAL)
        self.assertIn("not proof", summary["marker_note"])
        self.assertTrue(any("2 fault_injected markers" in r for r in summary["validity_reasons"]))
        self.assertEqual(summary["recovery"]["marker_relative_ms"]["first_failure_ms"], 1000.0)

    def test_scheduling_statistics(self):
        stats = fa.scheduling_stats(series("..x.."), 0.05)
        self.assertEqual(stats["actual_interval_ms"]["max"], 250.0)
        self.assertIn("not a guaranteed resolution", stats["note"])


def persistent(events, start=0.0, interval=0.2):
    """events: 'C' connect ok, '.' exchange ok, 'x' failed exchange, then an end record ('E:<class>')."""
    recs, t, seq = [], start, 0
    for ev in events:
        seq += 1
        if ev == "C":
            recs.append({"seq": seq, "event": "connect", "start_mono_s": t, "end_mono_s": t + 0.01, "ok": True})
        elif ev in ".x":
            recs.append({"seq": seq, "event": "exchange", "start_mono_s": t, "end_mono_s": t + 0.004,
                         "ok": ev == ".", "error_class": "" if ev == "." else "eof"})
            t += interval
        else:
            cls = ev.split(":", 1)[1]
            recs.append({"seq": seq, "event": "end", "start_mono_s": t, "end_mono_s": t, "ok": cls == "probe_stopped",
                         "error_class": cls, "detail": ""})
    return recs


class PersistentTests(OfflineTestCase):
    def run_case(self, events, marker_t=5.0):
        return fa.analyze_persistent(persistent(events), [marker(marker_t)], "R1", DOMAIN)

    def test_interrupted_connection_keeps_cause_unknown(self):
        s = self.run_case(["C"] + ["."] * 30 + ["x", "E:eof"])
        self.assertEqual((s["continuity"], s["end_reason"]), ("interrupted", "eof"))
        self.assertEqual(s["end_cause"], "unknown (no evidence)")
        self.assertEqual(s["run_validity"], "valid")
        self.assertEqual(s["last_successful_exchange"]["seq"], 31)

    def test_survived(self):
        s = self.run_case(["C"] + ["."] * 50 + ["E:probe_stopped"])
        self.assertEqual(s["continuity"], "survived")
        self.assertGreater(s["successful_exchanges_after_marker"], 0)

    def test_server_connection_close_is_logged_separately(self):
        s = self.run_case(["C"] + ["."] * 30 + ["E:server_connection_close"])
        self.assertEqual(s["continuity"], "ended_by_server_connection_close")
        self.assertEqual(s["end_cause"], "server sent Connection: close")

    def test_connection_must_exist_and_work_before_the_marker(self):
        ended_early = self.run_case(["C"] + ["."] * 5 + ["x", "E:reset"])        # ends at 1.2 s
        self.assertEqual(ended_early["run_validity"], "not_valid")
        self.assertIn("connection ended before the fault marker", ended_early["validity_reasons"])
        late = fa.analyze_persistent(persistent(["C"] + ["."] * 10 + ["E:probe_stopped"], start=6.0),
                                     [marker(5.0)], "R1", DOMAIN)
        self.assertIn("connection established only after the fault marker", late["validity_reasons"])
        never = fa.analyze_persistent([{"seq": 1, "event": "connect", "start_mono_s": 0, "end_mono_s": 0.01,
                                        "ok": False}], [marker(5.0)], "R1", DOMAIN)
        self.assertIn("persistent connection was never established", never["validity_reasons"])

    def test_without_marker_continuity_is_not_evaluated(self):
        s = fa.analyze_persistent(persistent(["C", ".", "E:probe_stopped"]), [], "R1", DOMAIN)
        self.assertEqual((s["continuity"], s["run_validity"]), ("not_evaluated", "not_valid"))


if __name__ == "__main__":
    unittest.main()
