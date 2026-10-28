"""ScalerDaemon orchestration with simulated clock, ESXi, CPU and probes (no SSH/HTTP).

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.
"""

import glob
import os
import tempfile
import unittest
from datetime import timedelta

from _helpers import OfflineTestCase, load_module

scaler = load_module("02-scaler-poc/scaler_daemon.py", "scaler_daemon")

CHECKS = list(scaler.READINESS_MILESTONES)


class FakeProbe:
    def __init__(self, *results):
        self.results = list(results)
        self.calls = 0

    def check(self):
        result = self.results[min(self.calls, len(self.results) - 1)]
        self.calls += 1
        return result


class FakeConnectorApi:
    """Returns ConnectorStatus values built by `factory(clock)` on every call."""
    def __init__(self, factory):
        self.factory = factory
        self.clock = None

    def get_status(self):
        return self.factory(self.clock)


def api_status(status, offset_sec=None, raw=None, tz_assumed=False, error=""):
    def factory(clock):
        if error:
            return scaler.ConnectorStatus(error=error)
        check_time = None if offset_sec is None else clock.start_wall + timedelta(seconds=offset_sec)
        raw_value = raw if raw is not None else (check_time.isoformat() if check_time else "")
        return scaler.ConnectorStatus(status, check_time, raw_value, tz_assumed)
    return FakeConnectorApi(factory)


def cfg(**overrides):
    base = dict(c1_ip="192.0.2.11", esxi_host="esxi.test.invalid", c2_vmid=12,
                scale_out_pct=80.0, scale_in_pct=30.0, window_sec=15.0, poll_sec=5.0,
                cooldown_sec=60.0, min_c2_uptime_sec=0.0, power_on_timeout_sec=60.0,
                power_state_poll_sec=1.0, shutdown_timeout_sec=10.0, readiness_timeout_sec=600.0)
    base.update(overrides)
    return scaler.ScalerConfig(**base)


def make(config, c1_profile, esxi_kwargs=None, c2_profile=None, **probes):
    clock = scaler.SimClock()
    if isinstance(probes.get("connector_api"), FakeConnectorApi):
        probes["connector_api"].clock = clock
    esxi = scaler.SimulatedESXi(clock, **(esxi_kwargs or {}))
    recorder = scaler.MemoryRecorder()
    daemon = scaler.ScalerDaemon(config, scaler.ScalerController(config), esxi, scaler.SimCpuSampler(c1_profile),
                                 clock, recorder,
                                 c2_cpu=scaler.SimCpuSampler(c2_profile) if c2_profile else None, **probes)
    return daemon, esxi, recorder, clock


def _with_latency(method, clock, seconds):
    """Wraps a simulated call so that it takes `seconds` of simulated time."""
    def wrapped(*args, **kwargs):
        clock.sleep(seconds)
        return method(*args, **kwargs)
    return wrapped


def event_names(recorder):
    return [e["event"] for e in recorder.events]


def first_event(recorder, name):
    return next(e for e in recorder.events if e["event"] == name)


def summary(recorder):
    return [e for e in recorder.events if e["event"] == "ACTIVATION_SUMMARY"][-1]["detail"]


def check_statuses(recorder):
    """{check: status} from the last set of ACTIVATION_CHECK events."""
    result = {}
    for e in recorder.events:
        if e["event"] == "ACTIVATION_CHECK":
            fields = dict(part.split("=", 1) for part in e["detail"].split("; ")[:2])
            result[fields["check"]] = fields["status"]
    return result


class ActivationTimelineTests(OfflineTestCase):
    def test_delayed_vm_start_is_timed_from_power_on_sent(self):
        daemon, esxi, rec, _ = make(cfg(), [90.0], {"boot_delay_sec": 7.0})
        daemon.run(max_cycles=6)
        sent = first_event(rec, "POWER_ON_SENT")
        self.assertEqual(sent["monotonic_s"], "15.000")
        self.assertTrue(sent["detail"].startswith("exit_code=0; "))
        powered = first_event(rec, "VM_POWERED_ON")
        self.assertEqual(powered["monotonic_s"], "22.000")
        self.assertTrue(powered["detail"].startswith("+7.000s after POWER_ON_SENT"))
        self.assertEqual(esxi.commands.count("power.on"), 1)
        self.assertIn("VM_POWERED_ON=verified(+7.000s; attribution=confirmed_within_power_on_timeout)", summary(rec))

    def test_threshold_and_power_on_times_are_recorded_separately(self):
        # Every ESXi state query costs 0.4 s, so POWER_ON_SENT happens 0.4 s after the C1 sample
        # that met the threshold; the summary must show the real gap, not assume zero.
        daemon, esxi, rec, clock = make(cfg(), [90.0], {"boot_delay_sec": 7.0})
        esxi.get_power_state = _with_latency(esxi.get_power_state, clock, 0.4)
        daemon.run(max_cycles=5)
        threshold = first_event(rec, "THRESHOLD_MET")
        sent = first_event(rec, "POWER_ON_SENT")
        self.assertEqual(threshold["monotonic_s"], "15.000")
        self.assertEqual(sent["monotonic_s"], "15.400")
        self.assertNotEqual(threshold["timestamp_utc"], sent["timestamp_utc"])
        self.assertIn("+0.400s after THRESHOLD_MET", sent["detail"])
        text = summary(rec)
        self.assertIn("THRESHOLD_MET=verified(t=15.000s, -0.400s vs POWER_ON_SENT)", text)
        self.assertIn("SCALE_OUT_DECISION=verified(t=15.400s, +0.400s after THRESHOLD_MET)", text)
        self.assertIn("POWER_ON_SENT=verified(t=15.400s, +0.400s after THRESHOLD_MET, exit_code=0)", text)
        # readiness offsets stay relative to POWER_ON_SENT, not to THRESHOLD_MET
        powered = float(first_event(rec, "VM_POWERED_ON")["monotonic_s"])
        self.assertIn(f"VM_POWERED_ON=verified(+{powered - 15.4:.3f}s; attribution=", text)

    def test_all_events_are_kept_in_order(self):
        daemon, _, rec, _ = make(cfg(), [90.0], {"boot_delay_sec": 3.0})
        daemon.run(max_cycles=5)
        # The power-on cycle ends after POWER_ON_SENT (no blocking poll). "Powered on" is seen by a
        # power-state poll between cycles; those events go into the next row. Only VM_POWERED_ON
        # is configured, so the activation is closed then; the other checks are reported
        # individually and none of them as verified.
        trigger = ["THRESHOLD_MET", "SCALE_OUT_DECISION", "POWER_ON_SENT"]
        after = ["VM_POWERED_ON"] + ["ACTIVATION_CHECK"] * len(CHECKS) + ["ACTIVATION_SUMMARY"]
        self.assertEqual(rec.rows[3]["events"], ";".join(trigger))
        self.assertEqual(rec.rows[4]["events"], ";".join(after))
        self.assertEqual(event_names(rec), trigger + after)
        self.assertIn("power-state poll between cycles", first_event(rec, "VM_POWERED_ON")["detail"])
        self.assertIn(f"reason={scaler.REASON_ALL_VERIFIED}", summary(rec))
        statuses = check_statuses(rec)
        self.assertEqual(statuses.pop("VM_POWERED_ON"), "verified")
        self.assertEqual(set(statuses.values()), {"not_checked"})

    def test_power_on_failure_is_logged_with_separate_error_output(self):
        daemon, esxi, rec, _ = make(cfg(power_on_timeout_sec=10.0), [90.0], {"power_on_exit_code": 1})
        daemon.run(max_cycles=5)
        self.assertTrue(first_event(rec, "POWER_ON_SENT")["detail"].startswith("exit_code=1; "))
        # a failed power.on starts no in-progress tracking: no timeout, no polls between cycles
        self.assertIn("POWER_ON_FAILED", event_names(rec))
        self.assertNotIn("POWER_ON_TIMEOUT", event_names(rec))
        self.assertEqual(esxi.commands.count("power.getstate"), 5)  # one per cycle only
        self.assertFalse(daemon.controller.activated_by_controller)
        self.assertNotIn("VM_POWERED_ON", event_names(rec))
        sources = [e["source"] for e in rec.errors]
        self.assertEqual(sources.count("esxi_power_on"), 1)  # the exit code
        self.assertEqual(check_statuses(rec)["VM_POWERED_ON"], "failed")
        # no simulated latency in this test, so the measured gap is genuinely zero
        self.assertIn("POWER_ON_SENT=verified(t=15.000s, +0.000s after THRESHOLD_MET, exit_code=1)", summary(rec))

    def test_late_power_on_is_still_recorded(self):
        daemon, _, rec, _ = make(cfg(power_on_timeout_sec=5.0), [90.0], {"boot_delay_sec": 20.0})
        daemon.run(max_cycles=10)
        names = event_names(rec)
        self.assertLess(names.index("POWER_ON_TIMEOUT"), names.index("VM_POWERED_ON"))
        powered = first_event(rec, "VM_POWERED_ON")
        self.assertIn("regular power-state poll", powered["detail"])
        self.assertGreaterEqual(float(powered["monotonic_s"]) - 15.0, 20.0)
        self.assertEqual(check_statuses(rec)["VM_POWERED_ON"], "verified")

    def test_vm_that_never_runs_ends_in_timeout(self):
        daemon, _, rec, _ = make(cfg(power_on_timeout_sec=5.0), [90.0], {"never_boots": True}, c2_profile=[5.0])
        daemon.run(max_cycles=6)
        statuses = check_statuses(rec)
        self.assertEqual(statuses["VM_POWERED_ON"], "timeout")
        # the guest check needs a running VM, so it was never attempted
        self.assertEqual(statuses["GUEST_REACHABLE"], "not_checked")
        self.assertIn("GUEST_REACHABLE=not_checked(not attempted (prerequisite not met))", summary(rec))

    def test_telemetry_error_prevents_activation(self):
        daemon, esxi, rec, _ = make(cfg(), [90.0, 90.0, None, 90.0, 90.0, 90.0])
        daemon.run(max_cycles=6)
        self.assertNotIn("power.on", esxi.commands)
        self.assertIn("TELEMETRY_ERROR_C1", event_names(rec))
        self.assertIn("c1_cpu", [e["source"] for e in rec.errors])
        self.assertEqual(rec.rows[2]["c1_cpu_pct"], "")

    def test_unknown_power_state_blocks_activation(self):
        daemon, esxi, rec, _ = make(cfg(), [90.0], {"initial_state": scaler.UNKNOWN})
        daemon.run(max_cycles=8)
        self.assertNotIn("power.on", esxi.commands)
        self.assertEqual(event_names(rec).count("SCALE_OUT_BLOCKED_C2_STATE"), 1)
        self.assertIn("esxi_getstate", [e["source"] for e in rec.errors])

    def test_cooldown_defers_second_power_on(self):
        daemon, esxi, rec, _ = make(cfg(power_on_timeout_sec=5.0), [90.0], {"never_boots": True})
        daemon.run(max_cycles=20)
        sent = [float(e["monotonic_s"]) for e in rec.events if e["event"] == "POWER_ON_SENT"]
        self.assertGreaterEqual(len(sent), 2)
        self.assertGreaterEqual(sent[1] - sent[0], 60.0)
        self.assertIn("SCALE_OUT_DEFERRED_COOLDOWN", event_names(rec))
        first_summary = first_event(rec, "ACTIVATION_SUMMARY")["detail"]
        self.assertIn("reason=superseded by a new power-on", first_summary)
        self.assertIn("VM_POWERED_ON=timeout(", first_summary)


class CheckStatusTests(OfflineTestCase):
    def test_each_check_keeps_its_own_final_status_on_timeout(self):
        daemon, _, rec, _ = make(
            cfg(readiness_timeout_sec=30.0), [90.0], {"boot_delay_sec": 3.0}, c2_profile=[10.0],
            connector_api=api_status(None, error="connector status HTTP 401"),        # every attempt errors
            app_probe=FakeProbe((False, "HTTP 503")),                                  # valid negative answers
            connection_probe=FakeProbe((None, "ss: not found")),                          # check cannot run
        )
        daemon.run(max_cycles=12)
        self.assertIn("READINESS_TIMEOUT", event_names(rec))
        self.assertIn(f"reason={scaler.REASON_READINESS_TIMEOUT}", summary(rec))
        self.assertEqual(check_statuses(rec), {
            "VM_POWERED_ON": "verified",
            "GUEST_REACHABLE": "verified",
            "CONNECTOR_API_REPORTED_AVAILABLE": "failed",
            "APPLICATION_REACHABLE": "timeout",
            "C2_MATCHING_CONNECTION_OBSERVED": "failed",
            "C2_TRAFFIC_OBSERVED": "not_checked",
        })
        self.assertIn("connector_api", [e["source"] for e in rec.errors])
        self.assertIn("c2_connection_probe", [e["source"] for e in rec.errors])

    def test_stopping_the_daemon_leaves_open_checks_unverified(self):
        daemon, _, rec, _ = make(cfg(), [90.0], {"boot_delay_sec": 3.0},
                                 app_probe=FakeProbe((False, "HTTP 503")))
        daemon.run(max_cycles=6)
        self.assertIn("reason=daemon stopped", summary(rec))
        self.assertEqual(check_statuses(rec)["APPLICATION_REACHABLE"], "unverified")
        self.assertIn("APPLICATION_REACHABLE=unverified(attempts=", summary(rec))


class ObservedStateSeparationTests(OfflineTestCase):
    def test_application_reachable_is_not_c2_traffic(self):
        daemon, _, rec, _ = make(cfg(), [90.0], {"boot_delay_sec": 3.0}, app_probe=FakeProbe((True, "HTTP 200")))
        daemon.run(max_cycles=6)
        self.assertIn("not attributed to a connector", first_event(rec, "APPLICATION_REACHABLE")["detail"])
        self.assertNotIn("C2_TRAFFIC_OBSERVED", event_names(rec))
        statuses = check_statuses(rec)
        self.assertEqual(statuses["APPLICATION_REACHABLE"], "verified")
        self.assertEqual(statuses["C2_TRAFFIC_OBSERVED"], "not_checked")
        self.assertEqual(statuses["GUEST_REACHABLE"], "not_checked")

    def test_matching_connection_is_not_reported_as_c2_traffic(self):
        probe = FakeProbe((False, "0 established connection(s) to backend"),
                          (True, "2 established connection(s) to backend"))
        daemon, _, rec, _ = make(cfg(), [90.0], {"boot_delay_sec": 3.0}, c2_profile=[10.0],
                                 app_probe=FakeProbe((True, "HTTP 200")), connection_probe=probe)
        daemon.run(max_cycles=8)
        matching = first_event(rec, "C2_MATCHING_CONNECTION_OBSERVED")
        self.assertIn("not validated as application traffic", matching["detail"])
        self.assertNotIn("C2_TRAFFIC_OBSERVED", event_names(rec))
        statuses = check_statuses(rec)
        self.assertEqual(statuses["C2_MATCHING_CONNECTION_OBSERVED"], "verified")
        self.assertEqual(statuses["C2_TRAFFIC_OBSERVED"], "not_checked")
        self.assertIn("C2_TRAFFIC_OBSERVED=not_checked(no check configured)", summary(rec))
        self.assertEqual([r["c2_matching_connection"] for r in rec.rows if r["c2_matching_connection"]][:2],
                         ["no", "yes"])

    def test_matching_connection_without_evidence_times_out(self):
        probe = FakeProbe((False, "0 established connection(s) to backend"))
        daemon, _, rec, _ = make(cfg(readiness_timeout_sec=30.0), [90.0], {"boot_delay_sec": 3.0},
                                 c2_profile=[10.0], connection_probe=probe)
        daemon.run(max_cycles=12)
        self.assertNotIn("C2_MATCHING_CONNECTION_OBSERVED", event_names(rec))
        self.assertEqual(check_statuses(rec)["C2_MATCHING_CONNECTION_OBSERVED"], "timeout")


class ConnectorApiTests(OfflineTestCase):
    def test_fresh_ready_status_is_verified_as_control_plane_report(self):
        daemon, _, rec, _ = make(cfg(), [90.0], {"boot_delay_sec": 3.0}, connector_api=api_status("Available", 40))
        daemon.run(max_cycles=6)
        event = first_event(rec, "CONNECTOR_API_REPORTED_AVAILABLE")
        self.assertIn("control-plane report only", event["detail"])
        self.assertEqual(check_statuses(rec)["CONNECTOR_API_REPORTED_AVAILABLE"], "verified")

    def test_stale_or_not_ready_status_is_not_verified(self):
        for api in (api_status("Available", 0), api_status("Pending", 40)):  # power-on happens at +15 s
            with self.subTest():
                daemon, _, rec, _ = make(cfg(readiness_timeout_sec=30.0), [90.0], {"boot_delay_sec": 3.0},
                                         connector_api=api)
                daemon.run(max_cycles=12)
                self.assertNotIn("CONNECTOR_API_REPORTED_AVAILABLE", event_names(rec))
                self.assertEqual(check_statuses(rec)["CONNECTOR_API_REPORTED_AVAILABLE"], "timeout")

    def test_timestamp_without_offset_is_logged_and_not_counted_as_fresh(self):
        raw = "2026-01-01T00:00:40"
        api = api_status("Available", 40, raw=raw, tz_assumed=True)
        daemon, _, rec, _ = make(cfg(readiness_timeout_sec=30.0), [90.0], {"boot_delay_sec": 3.0},
                                 connector_api=api)
        daemon.run(max_cycles=12)
        notes = [e for e in rec.events if e["event"] == "CONNECTOR_API_TIMESTAMP_AMBIGUOUS"]
        self.assertEqual(len(notes), 1)  # logged once per distinct raw value
        self.assertIn(f"raw systemStatusCheckTime='{raw}'", notes[0]["detail"])
        self.assertIn("unverified UTC assumption", notes[0]["detail"])
        self.assertIn("not counted as fresh", notes[0]["detail"])
        self.assertNotIn("CONNECTOR_API_REPORTED_AVAILABLE", event_names(rec))
        self.assertEqual(check_statuses(rec)["CONNECTOR_API_REPORTED_AVAILABLE"], "timeout")
        self.assertRegex(summary(rec), r"CONNECTOR_API_REPORTED_AVAILABLE=timeout\(attempts=\d+ negative=0 "
                                       r"ambiguous=\d+ errors=0\)")
        self.assertIn(raw, [r["connector_api_check_time_raw"] for r in rec.rows])

    def test_unparseable_timestamp_is_logged(self):
        api = api_status("Available", None, raw="yesterday")
        daemon, _, rec, _ = make(cfg(readiness_timeout_sec=30.0), [90.0], {"boot_delay_sec": 3.0},
                                 connector_api=api)
        daemon.run(max_cycles=12)
        self.assertIn("missing or unparseable", first_event(rec, "CONNECTOR_API_TIMESTAMP_AMBIGUOUS")["detail"])
        self.assertNotIn("CONNECTOR_API_REPORTED_AVAILABLE", event_names(rec))


class ScaleInTests(OfflineTestCase):
    LOW_AFTER_HIGH = [90.0] * 4 + [5.0]

    def test_scale_in_disabled_by_default(self):
        daemon, esxi, _, _ = make(cfg(cooldown_sec=0), self.LOW_AFTER_HIGH, {"boot_delay_sec": 3.0},
                                  c2_profile=[5.0])
        daemon.run(max_cycles=200)
        self.assertNotIn("power.shutdown", esxi.commands)

    def test_scale_in_after_cooldown_and_min_uptime(self):
        config = cfg(enable_scale_in=True, cooldown_sec=60.0, min_c2_uptime_sec=120.0, c2_ip="192.0.2.12")
        daemon, esxi, rec, _ = make(config, self.LOW_AFTER_HIGH, {"boot_delay_sec": 7.0}, c2_profile=[5.0])
        daemon.run(max_cycles=60)
        shutdown_at = float(first_event(rec, "SHUTDOWN_SENT")["monotonic_s"])
        self.assertGreaterEqual(shutdown_at, 22.0 + 120.0)  # VM_POWERED_ON at 22s
        self.assertIn("VM_POWERED_OFF", event_names(rec))
        self.assertNotIn("power.off", esxi.commands)

    def test_scale_in_requires_c2_cpu(self):
        config = cfg(enable_scale_in=True, cooldown_sec=0, c2_ip="192.0.2.12")
        daemon, esxi, rec, _ = make(config, self.LOW_AFTER_HIGH, {"boot_delay_sec": 3.0}, c2_profile=[None])
        daemon.run(max_cycles=40)
        self.assertNotIn("power.shutdown", esxi.commands)
        self.assertIn("TELEMETRY_ERROR_C2", event_names(rec))

    def test_manually_started_c2_is_not_stopped(self):
        config = cfg(enable_scale_in=True, cooldown_sec=0, c2_ip="192.0.2.12")
        daemon, esxi, rec, _ = make(config, [5.0], {"initial_state": scaler.RUNNING}, c2_profile=[5.0])
        daemon.run(max_cycles=60)
        self.assertNotIn("power.shutdown", esxi.commands)
        self.assertEqual(event_names(rec).count("SCALE_IN_SKIPPED_NOT_CONTROLLER_ACTIVATED"), 1)

    def test_forced_power_off_is_disabled_by_default(self):
        config = cfg(enable_scale_in=True, cooldown_sec=0, allow_scale_in_manual_c2=True, c2_ip="192.0.2.12")
        daemon, esxi, rec, _ = make(config, [5.0], {"initial_state": scaler.RUNNING, "shutdown_hangs": True},
                                    c2_profile=[5.0])
        daemon.run(max_cycles=5)
        self.assertIn("power.shutdown", esxi.commands)
        self.assertNotIn("power.off", esxi.commands)
        self.assertIn("SHUTDOWN_TIMEOUT", event_names(rec))
        self.assertIn("esxi_shutdown", [e["source"] for e in rec.errors])

    def test_forced_power_off_when_explicitly_allowed(self):
        config = cfg(enable_scale_in=True, cooldown_sec=0, allow_scale_in_manual_c2=True,
                     allow_force_power_off=True, c2_ip="192.0.2.12")
        daemon, esxi, rec, _ = make(config, [5.0], {"initial_state": scaler.RUNNING, "shutdown_hangs": True},
                                    c2_profile=[5.0])
        daemon.run(max_cycles=5)
        self.assertIn("power.off", esxi.commands)
        self.assertIn("FORCED_POWER_OFF_SENT", event_names(rec))


class DryRunTests(OfflineTestCase):
    def _run(self, out_dir, *extra, environ=None):
        scaler.main(["--dry-run", "--output-dir", out_dir, *extra], environ=environ or {})
        contents = {}
        for kind in ("timeseries", "events", "errors"):
            path, = glob.glob(os.path.join(out_dir, f"scaler_dryrun_*_{kind}.csv"))
            with open(path, encoding="utf-8") as f:
                contents[kind] = f.read()
        return contents

    def test_dry_run_is_deterministic(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            with self.assertLogs("scaler", level="INFO"):
                first = self._run(a)
                second = self._run(b)
        self.assertEqual(first, second)
        self.assertIn("POWER_ON_SENT", first["events"])
        self.assertIn("VM_POWERED_ON", first["events"])
        self.assertNotIn("SHUTDOWN_SENT", first["events"])  # scale-in disabled by default

    def test_lab_flags_are_visible(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertLogs("scaler", level="WARNING") as logs:
                out = self._run(d, "--lab-insecure-ssh", "--lab-insecure-tls", "--max-cycles", "1")
        self.assertTrue(any("LAB MODE: SSH host key verification is DISABLED" in m for m in logs.output))
        self.assertTrue(any("LAB MODE: TLS certificate verification" in m for m in logs.output))
        self.assertIn("LAB_INSECURE_SSH", out["events"])
        self.assertIn("LAB_INSECURE_TLS", out["events"])

    def test_deprecated_cooldown_variable_warns(self):
        env = {"SCALER_COOLDOWN_SEC": "45", "SCALE_IN_COOLDOWN_SEC": "90"}
        with tempfile.TemporaryDirectory() as d:
            with self.assertLogs("scaler", level="WARNING") as logs:
                out = self._run(d, "--max-cycles", "1", environ=env)
        self.assertTrue(any("SCALE_IN_COOLDOWN_SEC=90 is deprecated and ignored" in m for m in logs.output))
        self.assertIn("CONFIG_DEPRECATED_VARIABLE", out["events"])


def _sampler_with_latency(sampler, clock, seconds):
    sampler.observe = _with_latency(sampler.observe, clock, seconds)
    return sampler


def run_cycles(daemon, n, before_cycle=None):
    """Runs n cycles like ScalerDaemon.run (incl. the waits between cycles); before_cycle(i) may
    change the simulated world, e.g. start C2 by hand."""
    for i in range(n):
        if before_cycle:
            before_cycle(i)
        start = daemon.clock.monotonic()
        daemon.run_cycle()
        daemon._wait_for_next_cycle(start + daemon.cfg.poll_sec)


class TimestampSeparationTests(OfflineTestCase):
    """C1 sampling, C2 state observation, C2 sampling, decision and POWER_ON_SENT are separate times."""

    def test_delayed_state_query_and_sampling(self):
        config = cfg(window_sec=10.0, c2_ip="192.0.2.12")
        daemon, esxi, rec, clock = make(config, [90.0], {"boot_delay_sec": 4.0}, c2_profile=[10.0])
        _sampler_with_latency(daemon.c1_cpu, clock, 1.2)        # C1 sampling takes 1.2 s
        _sampler_with_latency(daemon.c2_cpu, clock, 0.9)        # C2 sampling takes 0.9 s
        esxi.get_power_state = _with_latency(esxi.get_power_state, clock, 0.5)
        daemon.run(max_cycles=5)

        r0 = rec.rows[0]
        self.assertEqual((r0["c1_sample_start_s"], r0["c1_sample_end_s"], r0["c2_state_observed_s"],
                          r0["decision_s"]), ("0.000", "1.200", "1.700", "1.700"))
        self.assertEqual((r0["c2_sample_start_s"], r0["c2_sample_end_s"]), ("", ""))  # C2 not running

        # window on C1 sample times: samples at 1.2, 6.2, 11.2 -> threshold met by the sample at 11.2
        threshold = first_event(rec, "THRESHOLD_MET")
        decision = first_event(rec, "SCALE_OUT_DECISION")
        sent = first_event(rec, "POWER_ON_SENT")
        self.assertEqual(threshold["monotonic_s"], "11.200")
        self.assertIn("c1_sample_t=11.200s; decision_t=11.700s", threshold["detail"])
        self.assertEqual((decision["monotonic_s"], sent["monotonic_s"]), ("11.700", "11.700"))
        self.assertIn("+0.500s after THRESHOLD_MET", sent["detail"])

        # C2 running: its sampling happens after the state observation, before the decision
        running = [r for r in rec.rows if r["c2_power_state"] == scaler.RUNNING][0]
        times = [float(running[k]) for k in ("c1_sample_start_s", "c1_sample_end_s", "c2_state_observed_s",
                                             "c2_sample_start_s", "c2_sample_end_s", "decision_s")]
        self.assertEqual(times, sorted(times))
        self.assertEqual(round(times[4] - times[3], 3), 0.9)

        # C2 uptime starts at the power-state observation that saw "Powered on", not at a C1 time
        powered = first_event(rec, "VM_POWERED_ON")
        self.assertEqual(daemon.controller.c2_running_since, float(powered["monotonic_s"]))
        c1_ends = {float(r["c1_sample_end_s"]) for r in rec.rows}
        self.assertNotIn(daemon.controller.c2_running_since, c1_ends)


class PowerOnAttributionTests(OfflineTestCase):
    """Who started C2: only a confirmed power-on counts as the controller's."""

    def scale_in_cfg(self, **kw):
        base = dict(enable_scale_in=True, cooldown_sec=0, c2_ip="192.0.2.12", power_on_timeout_sec=10.0,
                    window_sec=10.0)
        base.update(kw)
        return cfg(**base)

    def test_failed_power_on_then_manual_start(self):
        daemon, esxi, rec, _ = make(self.scale_in_cfg(cooldown_sec=600.0), [90.0] * 3 + [5.0],
                                    {"power_on_exit_code": 1}, c2_profile=[5.0])

        def start_by_hand(i):
            if i == 4:
                esxi.state = scaler.RUNNING

        run_cycles(daemon, 30, start_by_hand)
        names = event_names(rec)
        self.assertIn("POWER_ON_FAILED", names)
        attribution = first_event(rec, "C2_RUNNING_NOT_ATTRIBUTED")
        self.assertIn("after a failed power.on", attribution["detail"])
        self.assertIn("attribution=not_attributed (observed after a failed power.on)",
                      first_event(rec, "VM_POWERED_ON")["detail"])
        self.assertFalse(daemon.controller.activated_by_controller)
        self.assertNotIn("power.shutdown", esxi.commands)
        self.assertEqual(names.count("SCALE_IN_SKIPPED_NOT_CONTROLLER_ACTIVATED"), 1)
        self.assertEqual(esxi.commands.count("power.on"), 1)

    def test_running_after_timeout_is_logged_but_not_attributed(self):
        daemon, esxi, rec, _ = make(self.scale_in_cfg(cooldown_sec=600.0), [90.0] * 3 + [5.0],
                                    {"boot_delay_sec": 25.0}, c2_profile=[5.0])
        daemon.run(max_cycles=40)
        names = event_names(rec)
        self.assertLess(names.index("POWER_ON_TIMEOUT"), names.index("VM_POWERED_ON"))
        self.assertIn("observed after the power-on timeout", first_event(rec, "VM_POWERED_ON")["detail"])
        self.assertIn("VM_POWERED_ON=verified(", summary(rec))
        self.assertIn("attribution=not_attributed (observed after the power-on timeout)", summary(rec))
        self.assertFalse(daemon.controller.activated_by_controller)
        self.assertNotIn("power.shutdown", esxi.commands)

    def test_confirmed_power_on_allows_scale_in(self):
        daemon, esxi, rec, _ = make(self.scale_in_cfg(), [90.0] * 3 + [5.0], {"boot_delay_sec": 4.0},
                                    c2_profile=[5.0])
        daemon.run(max_cycles=20)
        self.assertIn("attribution=confirmed_within_power_on_timeout", first_event(rec, "VM_POWERED_ON")["detail"])
        self.assertNotIn("C2_RUNNING_NOT_ATTRIBUTED", event_names(rec))
        self.assertIn("power.shutdown", esxi.commands)

    def test_manual_start_stopped_only_with_explicit_permission(self):
        for allowed in (False, True):
            with self.subTest(allowed=allowed):
                config = self.scale_in_cfg(allow_scale_in_manual_c2=allowed)
                daemon, esxi, rec, _ = make(config, [5.0], {"initial_state": scaler.RUNNING}, c2_profile=[5.0])
                daemon.run(max_cycles=10)
                self.assertIn("not started by this controller", first_event(rec, "C2_RUNNING_NOT_ATTRIBUTED")["detail"])
                self.assertEqual("power.shutdown" in esxi.commands, allowed)


class NonBlockingPowerOnTests(OfflineTestCase):
    def test_cycles_keep_running_while_power_on_is_in_progress(self):
        app = FakeProbe((False, "HTTP 503"))
        daemon, esxi, rec, _ = make(cfg(cooldown_sec=0, power_on_timeout_sec=60.0), [90.0],
                                    {"boot_delay_sec": 22.0}, app_probe=app)
        daemon.run(max_cycles=10)
        # cycle schedule unchanged: one row every poll_sec, C1 sampled in every cycle
        self.assertEqual([r["monotonic_s"] for r in rec.rows], [f"{5.0 * i:.3f}" for i in range(10)])
        self.assertEqual(daemon.c1_cpu.calls, 10)
        # the application probe ran in every cycle after POWER_ON_SENT (15 s) while the VM booted
        self.assertEqual(app.calls, 7)
        in_progress = [r["monotonic_s"] for r in rec.rows if r["power_on_in_progress"] == "yes"]
        self.assertEqual(in_progress, ["15.000", "20.000", "25.000", "30.000", "35.000"])  # VM on at 37 s
        # no second power.on although the cooldown is 0 and C1 stays high
        self.assertEqual(esxi.commands.count("power.on"), 1)
        self.assertIn("SCALE_OUT_WAITING_POWER_ON_IN_PROGRESS", event_names(rec))
        powered = first_event(rec, "VM_POWERED_ON")
        self.assertEqual(powered["monotonic_s"], "37.000")       # seen by a 1 s poll between cycles
        self.assertIn("power-state poll between cycles", powered["detail"])

    def test_no_polling_between_cycles_without_power_on_in_progress(self):
        daemon, esxi, _, _ = make(cfg(), [10.0])
        daemon.run(max_cycles=6)
        self.assertEqual(esxi.commands.count("power.getstate"), 6)

    def test_timeout_ends_in_progress_state_and_allows_a_new_attempt(self):
        daemon, esxi, rec, _ = make(cfg(cooldown_sec=0, power_on_timeout_sec=5.0), [90.0], {"never_boots": True})
        daemon.run(max_cycles=12)
        sent = [float(e["monotonic_s"]) for e in rec.events if e["event"] == "POWER_ON_SENT"]
        timeouts = [float(e["monotonic_s"]) for e in rec.events if e["event"] == "POWER_ON_TIMEOUT"]
        self.assertGreaterEqual(len(sent), 2)
        self.assertGreaterEqual(timeouts[0], sent[0] + 5.0)
        self.assertGreater(sent[1], timeouts[0])                 # retry only after the timeout


class GuestSshVersusCpuTests(OfflineTestCase):
    def test_ssh_ok_but_invalid_cpu_data(self):
        config = cfg(enable_scale_in=True, cooldown_sec=0, c2_ip="192.0.2.12")
        daemon, esxi, rec, _ = make(config, [90.0] * 4 + [5.0], {"boot_delay_sec": 3.0},
                                    c2_profile=[scaler.BAD_CPU_DATA])
        daemon.run(max_cycles=30)
        guest = first_event(rec, "GUEST_REACHABLE")
        self.assertIn("exited with 0; no valid CPU value", guest["detail"])
        running = [r for r in rec.rows if r["c2_power_state"] == scaler.RUNNING]
        self.assertTrue(all(r["guest_reachable"] == "yes" and r["c2_cpu_pct"] == "" for r in running))
        self.assertIn("TELEMETRY_ERROR_C2", event_names(rec))     # not usable for the scale-in decision
        self.assertNotIn("power.shutdown", esxi.commands)
        self.assertIn("ssh_command_ok=yes", [e for e in rec.errors if e["source"] == "c2_cpu"][0]["message"])

    def test_failed_ssh_is_not_guest_reachable(self):
        daemon, _, rec, _ = make(cfg(readiness_timeout_sec=30.0), [90.0], {"boot_delay_sec": 3.0},
                                 c2_profile=[None])
        daemon.run(max_cycles=12)
        self.assertNotIn("GUEST_REACHABLE", event_names(rec))
        self.assertEqual(check_statuses(rec)["GUEST_REACHABLE"], "timeout")
        running = [r for r in rec.rows if r["c2_power_state"] == scaler.RUNNING]
        self.assertTrue(all(r["guest_reachable"] == "no" for r in running))

    def test_c1_invalid_data_is_a_telemetry_error_with_ssh_ok(self):
        daemon, esxi, rec, _ = make(cfg(), [90.0, 90.0, scaler.BAD_CPU_DATA, 90.0, 90.0, 90.0])
        daemon.run(max_cycles=6)
        self.assertEqual((rec.rows[2]["c1_ssh_command_ok"], rec.rows[2]["c1_cpu_pct"]), ("yes", ""))
        self.assertIn("TELEMETRY_ERROR_C1", event_names(rec))
        self.assertNotIn("power.on", esxi.commands)


class MainConfigErrorTests(OfflineTestCase):
    def test_missing_known_hosts_is_a_configuration_error(self):
        with tempfile.TemporaryDirectory() as d:
            missing = os.path.join(d, "no_such_known_hosts")
            with self.assertLogs("scaler", level="ERROR") as logs:
                code = scaler.main(["--c1-ip", "192.0.2.11", "--esxi-host", "esxi.test.invalid", "--c2-vmid", "12",
                                    "--ssh-known-hosts", missing, "--output-dir", os.path.join(d, "out")],
                                   environ={})
            self.assertFalse(os.path.exists(os.path.join(d, "out")))   # nothing started, no files
        self.assertEqual(code, 2)
        self.assertTrue(any("SSH_KNOWN_HOSTS" in m and "stays enabled" in m for m in logs.output))


if __name__ == "__main__":
    unittest.main()
