"""Parsers, I/O adapters (with fake executors) and the pure ScalerController.

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.
"""

import unittest
from datetime import datetime, timezone

from _helpers import OfflineTestCase, load_module

scaler = load_module("02-scaler-poc/scaler_daemon.py", "scaler_daemon")

STOPPED, RUNNING, UNKNOWN = scaler.STOPPED, scaler.RUNNING, scaler.UNKNOWN


class FakeExecutor:
    def __init__(self, results, timeout=5.0):
        self.results = list(results)
        self.commands = []
        self.timeout = timeout

    def run(self, cmd, timeout=None):
        self.commands.append(cmd)
        return self.results.pop(0)


def cfg(**overrides):
    base = dict(c1_ip="192.0.2.11", esxi_host="esxi.test.invalid", c2_vmid=12,
                scale_out_pct=80.0, scale_in_pct=30.0, window_sec=15.0, poll_sec=5.0,
                cooldown_sec=60.0, min_c2_uptime_sec=0.0)
    base.update(overrides)
    return scaler.ScalerConfig(**base)


def names(decision):
    return [n for n, _ in decision.events]


class ParserTests(OfflineTestCase):
    def test_power_state(self):
        self.assertEqual(scaler.parse_power_state("Retrieved runtime info\nPowered on\n"), RUNNING)
        self.assertEqual(scaler.parse_power_state("Retrieved runtime info\nPowered off"), STOPPED)
        self.assertEqual(scaler.parse_power_state("Retrieved runtime info\nSuspended"), scaler.SUSPENDED)
        self.assertEqual(scaler.parse_power_state(""), UNKNOWN)
        self.assertEqual(scaler.parse_power_state("vim-cmd: not found"), UNKNOWN)

    def test_proc_stat_fields(self):
        # user nice system idle iowait irq softirq steal guest guest_nice
        line = "cpu  10 20 30 400 50 6 7 8 1000 2000"
        idle, total = scaler.parse_proc_stat_cpu(line)
        self.assertEqual(idle, 400 + 50)                            # idle + iowait
        self.assertEqual(total, 10 + 20 + 30 + 400 + 50 + 6 + 7 + 8)  # guest fields not added

    def test_cpu_pct_from_proc_stat(self):
        out = "cpu  100 0 100 800 0 0 0 0 0 0\ncpu  150 0 150 900 0 0 0 0 0 0\n"
        self.assertEqual(scaler.cpu_pct_from_proc_stat(out), 50.0)  # d_idle=100, d_total=200
        # iowait counts as idle
        out = "cpu  0 0 0 100 100 0 0 0\ncpu  0 0 0 150 150 0 0 0\n"
        self.assertEqual(scaler.cpu_pct_from_proc_stat(out), 0.0)
        # irq/softirq/steal count as busy
        out = "cpu  0 0 0 100 0 0 0 0\ncpu  0 0 0 130 0 30 20 20\n"
        self.assertEqual(scaler.cpu_pct_from_proc_stat(out), 70.0)  # 1 - 30/100

    def test_cpu_pct_rejects_bad_input(self):
        for out in ("", "cpu  1 2 3 4\n", "%Cpu(s): 1.0 us\n%Cpu(s): 2.0 us",
                    "cpu  1 1 1 1 0 0 0\ncpu  2 2 2 2 0 0 0",          # fewer than 8 counters
                    "cpu  1 1 1 1 0 0 0 0\ncpu  1 1 1 1 0 0 0 0",      # no time elapsed
                    "cpu  900 0 0 900 0 0 0 0\ncpu  10 0 0 1000 0 0 0 0",   # counter reset
                    "cpu  100 0 0 100 0 0 0 0\ncpu  50 0 0 300 0 0 0 0"):   # d_idle > d_total
            with self.subTest(out=out), self.assertRaises(ValueError):
                scaler.cpu_pct_from_proc_stat(out)

    def test_api_timestamp(self):
        utc = timezone.utc
        self.assertEqual(scaler.parse_api_timestamp("2026-10-26T10:00:00Z"),
                         (datetime(2026, 10, 26, 10, tzinfo=utc), False))
        self.assertEqual(scaler.parse_api_timestamp("2026-10-26T10:00:00.1234567+00:00"),
                         (datetime(2026, 10, 26, 10, 0, 0, 123456, tzinfo=utc), False))
        # no UTC offset: returned as UTC but flagged as an assumption
        self.assertEqual(scaler.parse_api_timestamp("2026-10-26T10:00:00.5"),
                         (datetime(2026, 10, 26, 10, 0, 0, 500000, tzinfo=utc), True))
        self.assertEqual(scaler.parse_api_timestamp("yesterday"), (None, False))
        self.assertEqual(scaler.parse_api_timestamp(None), (None, False))

    def test_legacy_cooldown_variable(self):
        self.assertEqual(scaler.resolve_cooldown({}), ("60.0", None))
        self.assertEqual(scaler.resolve_cooldown({"SCALER_COOLDOWN_SEC": "45"}), ("45", None))
        value, warning = scaler.resolve_cooldown({"SCALE_IN_COOLDOWN_SEC": "90"})
        self.assertEqual(value, "90")
        self.assertIn("deprecated", warning)
        value, warning = scaler.resolve_cooldown({"SCALER_COOLDOWN_SEC": "45", "SCALE_IN_COOLDOWN_SEC": "90"})
        self.assertEqual(value, "45")
        self.assertIn("ignored", warning)
        self.assertEqual(scaler.parse_args([], {"SCALE_IN_COOLDOWN_SEC": "90"}).cooldown_sec, 90.0)
        self.assertEqual(scaler.parse_args([], {"SCALER_COOLDOWN_SEC": "45", "SCALE_IN_COOLDOWN_SEC": "90"})
                         .cooldown_sec, 45.0)
        self.assertEqual(scaler.parse_args(["--cooldown-sec", "5"], {"SCALER_COOLDOWN_SEC": "45"}).cooldown_sec, 5.0)

    def test_cpu_profile(self):
        self.assertEqual(scaler.parse_cpu_profile("20, 85,err,x"), (20.0, 85.0, None, None))
        with self.assertRaises(ValueError):
            scaler.parse_cpu_profile(" , ")


class AdapterTests(OfflineTestCase):
    def test_esxi_commands_and_states(self):
        ex = FakeExecutor([scaler.CommandResult(0, "Retrieved runtime info\nPowered off", ""),
                           scaler.CommandResult(255, "", "connection refused"),
                           scaler.CommandResult(0, "garbage", ""),
                           scaler.CommandResult(0, "", "")])
        esxi = scaler.ESXiHost(ex, 12)
        self.assertEqual(esxi.get_power_state(), (STOPPED, ""))
        self.assertEqual(esxi.get_power_state(), (UNKNOWN, "connection refused"))
        state, err = esxi.get_power_state()
        self.assertEqual(state, UNKNOWN)
        self.assertIn("unrecognised", err)
        esxi.power_on()
        self.assertEqual(ex.commands[0], "vim-cmd vmsvc/power.getstate 12")
        self.assertEqual(ex.commands[-1], "vim-cmd vmsvc/power.on 12")

    def test_esxi_rejects_non_integer_vmid(self):
        for vmid in ("12; reboot", 0, -1, 1.5):
            with self.assertRaises(ValueError):
                scaler.ESXiHost(FakeExecutor([]), vmid)

    def test_guest_cpu_sampler(self):
        ok = scaler.CommandResult(0, "cpu  0 0 10 90 0 0 0 0\ncpu  0 0 20 180 0 0 0 0", "")
        sampler = scaler.GuestCpuSampler(FakeExecutor([ok, scaler.CommandResult(-1, "", "SSH error"),
                                                       scaler.CommandResult(0, "nonsense", "")]))
        self.assertEqual(sampler.sample(), (10.0, ""))
        self.assertEqual(sampler.sample(), (None, "SSH error"))
        value, err = sampler.sample()
        self.assertIsNone(value)
        self.assertIn("unparseable", err)
        self.assertIn("/proc/stat", sampler.executor.commands[0])

    def test_established_connection_probe(self):
        ex = FakeExecutor([scaler.CommandResult(0, "0 0 10.0.1.122:5000 10.0.1.123:443\n", ""),
                           scaler.CommandResult(0, "", ""),
                           scaler.CommandResult(1, "", "ss: not found")])
        probe = scaler.EstablishedConnectionProbe(ex, "10.0.1.123", 443)
        self.assertEqual(probe.check(), (True, "1 established connection(s) to backend"))
        self.assertEqual(probe.check()[0], False)
        self.assertEqual(probe.check(), (None, "ss: not found"))
        self.assertEqual(ex.commands[0], "ss -Htn state established dst 10.0.1.123:443")
        self.assertIn("[2001:db8::1]:443", scaler.EstablishedConnectionProbe(ex, "2001:db8::1", 443).cmd)
        for host in ("backend.local", "10.0.1.123; reboot"):
            with self.assertRaises(ValueError):
                scaler.EstablishedConnectionProbe(ex, host, 443)


class ConfigValidationTests(OfflineTestCase):
    def test_valid(self):
        scaler.validate_config(cfg())

    def test_invalid(self):
        bad = [
            dict(scale_in_pct=80.0),
            dict(window_sec=0),
            dict(cooldown_sec=-1),
            dict(c2_vmid=0),
            dict(esxi_host=""),
            dict(enable_scale_in=True, c2_ip=""),
            dict(c2_connection_check="ss-established", c2_ip="192.0.2.12", backend_host="backend.local"),
            dict(c2_connection_check="magic"),
        ]
        for overrides in bad:
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                scaler.validate_config(cfg(**overrides))

    def test_dry_run_needs_no_hosts(self):
        scaler.validate_config(scaler.ScalerConfig(dry_run=True))


class ControllerTests(OfflineTestCase):
    def test_power_on_only_after_sustained_window(self):
        c = scaler.ScalerController(cfg())
        for t in (0, 5, 10):
            self.assertEqual(c.observe(t, 90.0, None, STOPPED).action, "")
        d = c.observe(15, 90.0, None, STOPPED)
        self.assertEqual(d.action, scaler.POWER_ON)
        self.assertEqual(names(d), ["THRESHOLD_MET"])
        self.assertEqual(c.threshold_met_at, 15)

    def test_single_low_sample_resets_window(self):
        c = scaler.ScalerController(cfg())
        c.observe(0, 90.0, None, STOPPED)
        c.observe(5, 90.0, None, STOPPED)
        c.observe(10, 50.0, None, STOPPED)
        for t in (15, 20, 25):
            self.assertEqual(c.observe(t, 90.0, None, STOPPED).action, "")
        self.assertEqual(c.observe(30, 90.0, None, STOPPED).action, scaler.POWER_ON)

    def test_telemetry_error_resets_window(self):
        c = scaler.ScalerController(cfg())
        c.observe(0, 90.0, None, STOPPED)
        c.observe(5, 90.0, None, STOPPED)
        d = c.observe(10, None, None, STOPPED)
        self.assertEqual(names(d), ["TELEMETRY_ERROR_C1"])
        self.assertEqual(c.observe(15, 90.0, None, STOPPED).action, "")
        self.assertEqual(c.observe(25, 90.0, None, STOPPED).action, "")
        self.assertEqual(c.observe(30, 90.0, None, STOPPED).action, scaler.POWER_ON)

    def test_unknown_state_blocks_power_on(self):
        c = scaler.ScalerController(cfg())
        for t in (0, 5, 10):
            c.observe(t, 90.0, None, UNKNOWN)
        d = c.observe(15, 90.0, None, UNKNOWN)
        self.assertEqual(d.action, "")
        self.assertIn("C2_POWER_STATE_UNKNOWN", names(d))
        self.assertIn("SCALE_OUT_BLOCKED_C2_STATE", names(d))
        # reported once per window, not on every cycle
        self.assertNotIn("SCALE_OUT_BLOCKED_C2_STATE", names(c.observe(20, 90.0, None, UNKNOWN)))

    def test_running_c2_needs_no_power_on(self):
        c = scaler.ScalerController(cfg())
        for t in (0, 5, 10):
            c.observe(t, 90.0, None, RUNNING)
        d = c.observe(15, 90.0, None, RUNNING)
        self.assertEqual(d.action, "")
        self.assertIn("SCALE_OUT_NOT_NEEDED_C2_RUNNING", names(d))

    def test_cooldown_defers_retry(self):
        # power-on timeout (10 s) shorter than the cooldown, so the cooldown is what defers the retry
        c = scaler.ScalerController(cfg(cooldown_sec=60.0, power_on_timeout_sec=10.0))
        c.power_on_sent(15)
        actions = {}
        deferred = 0
        for t in range(20, 90, 5):
            d = c.observe(t, 90.0, None, STOPPED)  # VM never came up
            actions[t] = d.action
            deferred += names(d).count("SCALE_OUT_DEFERRED_COOLDOWN")
        self.assertEqual([t for t, a in actions.items() if a], [75, 80, 85])
        self.assertEqual(deferred, 1)

    def test_scale_in_disabled_by_default(self):
        c = scaler.ScalerController(cfg())
        c.power_on_sent(0)
        c.vm_powered_on(5)
        for t in range(100, 1000, 5):
            self.assertEqual(c.observe(t, 5.0, 5.0, RUNNING).action, "")

    def test_scale_in_requires_both_cpu_samples(self):
        c = scaler.ScalerController(cfg(enable_scale_in=True, cooldown_sec=0))
        c.power_on_sent(0)
        c.vm_powered_on(5)
        events = []
        for t in range(100, 200, 5):
            d = c.observe(t, 5.0, None, RUNNING)
            self.assertEqual(d.action, "")
            events += names(d)
        self.assertIn("TELEMETRY_ERROR_C2", events)
        c2_high = [c.observe(t, 5.0, 50.0, RUNNING).action for t in range(200, 300, 5)]
        self.assertEqual(set(c2_high), {""})

    def test_scale_in_respects_cooldown_and_min_uptime(self):
        c = scaler.ScalerController(cfg(enable_scale_in=True, cooldown_sec=60.0, min_c2_uptime_sec=120.0))
        c.power_on_sent(15)
        c.vm_powered_on(22)
        first = next(t for t in range(25, 400, 5) if c.observe(t, 5.0, 5.0, RUNNING).action == scaler.SHUTDOWN)
        self.assertGreaterEqual(first, 22 + 120)

    def test_manual_c2_is_not_stopped(self):
        c = scaler.ScalerController(cfg(enable_scale_in=True, cooldown_sec=0))
        events = []
        for t in range(0, 300, 5):
            d = c.observe(t, 5.0, 5.0, RUNNING)
            self.assertEqual(d.action, "")
            events += names(d)
        self.assertEqual(events.count("SCALE_IN_SKIPPED_NOT_CONTROLLER_ACTIVATED"), 1)

        allowed = scaler.ScalerController(cfg(enable_scale_in=True, cooldown_sec=0, allow_scale_in_manual_c2=True))
        actions = [allowed.observe(t, 5.0, 5.0, RUNNING).action for t in range(0, 30, 5)]
        self.assertIn(scaler.SHUTDOWN, actions)


def stat(user=0, nice=0, system=0, idle=0, iowait=0, irq=0, softirq=0, steal=0, guest=0, guest_nice=0):
    return f"cpu  {user} {nice} {system} {idle} {iowait} {irq} {softirq} {steal} {guest} {guest_nice}"


def two(a, b):
    return f"{a}\n{b}\n"


class ProcStatRuleTests(OfflineTestCase):
    """The documented per-field rules of cpu_stats_from_proc_stat."""

    def test_deltas_and_derived_percentages(self):
        st = scaler.cpu_stats_from_proc_stat(two(stat(100, 10, 50, 1000, 20, 5, 5, 10, guest=40),
                                                 stat(130, 10, 60, 1040, 30, 6, 7, 17, guest=90)))
        self.assertEqual(st["deltas"], {"user": 30, "nice": 0, "system": 10, "idle": 40, "iowait": 10,
                                        "irq": 1, "softirq": 2, "steal": 7})
        self.assertEqual(st["d_total"], 100)               # guest delta (50) is not added
        self.assertEqual(st["busy_pct"], 50.0)             # 1 - (40 + 10) / 100
        self.assertEqual((st["iowait_pct"], st["steal_pct"]), (10.0, 7.0))

    def test_iowait_is_idle_and_steal_is_busy(self):
        only_iowait = two(stat(idle=100), stat(idle=100, iowait=100))
        only_steal = two(stat(idle=100), stat(idle=100, steal=100))
        self.assertEqual(scaler.cpu_pct_from_proc_stat(only_iowait), 0.0)
        self.assertEqual(scaler.cpu_pct_from_proc_stat(only_steal), 100.0)

    def test_iowait_may_decrease_when_idle_absorbs_it(self):
        st = scaler.cpu_stats_from_proc_stat(two(stat(user=10, idle=100, iowait=50),
                                                 stat(user=20, idle=180, iowait=40)))
        self.assertEqual(st["busy_pct"], 12.5)             # d(idle+iowait) = 70 of 80
        self.assertIsNone(st["iowait_pct"])                # a negative share is not reported

    def test_idle_may_decrease_when_iowait_absorbs_it(self):
        st = scaler.cpu_stats_from_proc_stat(two(stat(user=10, idle=100, iowait=0),
                                                 stat(user=20, idle=95, iowait=75)))
        self.assertEqual(st["busy_pct"], 12.5)
        self.assertEqual(st["deltas"]["idle"], -5)

    def test_combined_idle_decrease_is_a_reset(self):
        with self.assertRaisesRegex(ValueError, r"idle\+iowait decreased"):
            scaler.cpu_stats_from_proc_stat(two(stat(user=10, idle=100, iowait=50),
                                                stat(user=500, idle=90, iowait=40)))

    def test_every_monotonic_counter_decrease_is_rejected_by_name(self):
        for name in scaler.PROC_STAT_MONOTONIC:
            before = dict.fromkeys(scaler.PROC_STAT_FIELDS, 100)
            after = dict.fromkeys(scaler.PROC_STAT_FIELDS, 200)
            after[name] = 99
            with self.subTest(field=name), self.assertRaisesRegex(ValueError, f"'{name}' decreased by 1"):
                scaler.cpu_stats_from_proc_stat(two(stat(**before), stat(**after)))

    def test_reboot_between_snapshots_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "counter reset"):
            scaler.cpu_stats_from_proc_stat(two(stat(9000, 10, 3000, 90000, 500, 10, 20, 5),
                                                stat(12, 0, 8, 150, 1, 0, 0, 0)))

    def test_zero_interval_is_rejected(self):
        same = stat(100, 0, 100, 800, 10, 1, 1, 1)
        with self.assertRaisesRegex(ValueError, "no CPU time elapsed"):
            scaler.cpu_stats_from_proc_stat(two(same, same))

    def test_malformed_counters_are_rejected(self):
        for line in ("cpu  1 2 3 x 5 6 7 8", "cpu  1 2 3 -4 5 6 7 8", "cpu0 1 2 3 4 5 6 7 8"):
            with self.subTest(line=line), self.assertRaises(ValueError):
                scaler.parse_proc_stat_counters(line)

    def test_sampler_rejects_non_positive_interval(self):
        for sec in (0, -1.0):
            with self.subTest(sec=sec), self.assertRaises(ValueError):
                scaler.GuestCpuSampler(FakeExecutor([]), sample_sec=sec)


class GuestObservationTests(OfflineTestCase):
    """SSH command success and CPU validity are two separate observations."""

    def test_observations(self):
        ok_out = "cpu  0 0 10 90 0 0 0 0\ncpu  0 0 20 180 0 0 0 0"
        sampler = scaler.GuestCpuSampler(FakeExecutor([
            scaler.CommandResult(0, ok_out, ""),
            scaler.CommandResult(0, "cpu  1 1 1 1 0 0 0 0\ncpu  1 1 1 1 0 0 0 0", ""),   # zero interval
            scaler.CommandResult(0, "garbage", ""),
            scaler.CommandResult(1, "", "head: cannot open '/proc/stat'"),
            scaler.CommandResult(-1, "", "SSH error (192.0.2.12): timeout"),
        ]))
        self.assertEqual(sampler.observe(), (10.0, "", True))
        for expected_error in ("no CPU time elapsed", "unparseable"):
            reading = sampler.observe()
            self.assertEqual((reading.value, reading.ssh_command_ok), (None, True))   # SSH ok, no CPU value
            self.assertIn(expected_error, reading.error)
        reading = sampler.observe()
        self.assertEqual((reading.value, reading.ssh_command_ok), (None, False))
        self.assertIn("command exit code 1", reading.error)
        self.assertEqual(sampler.observe(), (None, "SSH error (192.0.2.12): timeout", False))

    def test_simulated_profile_tokens(self):
        sim = scaler.SimCpuSampler(scaler.parse_cpu_profile("50,err,bad"))
        self.assertEqual([tuple(sim.observe()) for _ in range(3)],
                         [(50.0, "", True), (None, "simulated SSH failure", False),
                          (None, "simulated unparseable /proc/stat output", True)])


class ControllerTimingTests(OfflineTestCase):
    """Windows use C1 sample times; cooldown, uptime and in-progress checks use the decision time."""

    def test_window_measured_on_c1_sample_times(self):
        c = scaler.ScalerController(cfg(window_sec=15.0))
        for sample in (0, 5, 10):
            d = c.observe(sample + 3, 90.0, None, STOPPED, sample_t=sample, c2_state_t=sample + 1)
            self.assertEqual(d.action, "")
        d = c.observe(18, 90.0, None, STOPPED, sample_t=15, c2_state_t=16)
        self.assertEqual(d.action, scaler.POWER_ON)
        self.assertEqual((c.threshold_met_at, c.decided_at), (15, 18))
        self.assertIn("for 15.0s of C1 sample time", dict(d.events)["THRESHOLD_MET"])

    def test_late_decisions_do_not_shorten_the_window(self):
        c = scaler.ScalerController(cfg(window_sec=15.0))
        c.observe(1, 90.0, None, STOPPED, sample_t=0)
        # decision 15 s after the first decision, but the sample only 14 s after the first sample
        self.assertEqual(c.observe(16, 90.0, None, STOPPED, sample_t=14).action, "")
        self.assertEqual(c.observe(21, 90.0, None, STOPPED, sample_t=19).action, scaler.POWER_ON)

    def test_cooldown_evaluated_at_decision_time(self):
        c = scaler.ScalerController(cfg(cooldown_sec=60.0, power_on_timeout_sec=5.0))
        c.power_on_sent(0)
        c.c2_state_observed(6, STOPPED)                       # timeout -> no longer in progress
        for sample in range(10, 55, 5):
            c.observe(sample + 0.5, 90.0, None, STOPPED, sample_t=sample)
        self.assertEqual(c.observe(59.9, 90.0, None, STOPPED, sample_t=55).action, "")
        # the C1 sample is 55.5 s after the command, the decision 60 s: the decision time counts
        self.assertEqual(c.observe(60.0, 90.0, None, STOPPED, sample_t=55.5).action, scaler.POWER_ON)

    def test_c2_uptime_starts_at_the_power_state_observation(self):
        c = scaler.ScalerController(cfg(enable_scale_in=True, cooldown_sec=0, min_c2_uptime_sec=100.0,
                                        power_on_timeout_sec=60.0))
        c.power_on_sent(0)
        c.observe(13, 90.0, None, RUNNING, sample_t=10, c2_state_t=12)
        self.assertEqual(c.c2_running_since, 12)              # not the C1 time 10, not the decision 13
        actions = {t: c.observe(t + 2, 5.0, 5.0, RUNNING, sample_t=t, c2_state_t=t + 1).action
                   for t in range(20, 140, 5)}
        first = min(t for t, a in actions.items() if a == scaler.SHUTDOWN)
        self.assertEqual(first + 2, 112)                      # first decision time with 112 - 12 >= 100


class ControllerOwnershipTests(OfflineTestCase):
    """Only a confirmed power-on grants scale-in; an in-progress power-on is not repeated."""

    def low_cycle(self, c, start, n=40):
        actions, events = [], []
        for t in range(start, start + 5 * n, 5):
            d = c.observe(t, 5.0, 5.0, RUNNING)
            actions.append(d.action)
            events += names(d)
        return actions, events

    def scale_in_cfg(self, **kw):
        return cfg(enable_scale_in=True, cooldown_sec=0, power_on_timeout_sec=30.0, **kw)

    def test_no_second_power_on_while_in_progress(self):
        c = scaler.ScalerController(cfg(cooldown_sec=0, power_on_timeout_sec=30.0))
        c.power_on_sent(15)
        actions, events = [], []
        for t in range(20, 80, 5):
            d = c.observe(t, 90.0, None, STOPPED)
            actions.append((t, d.action))
            events += names(d)
        # in progress until 45 (timeout); the window restarted at 20, so the next power-on is at 45
        self.assertEqual([t for t, a in actions if a][:1], [45])
        self.assertEqual(events.count("SCALE_OUT_WAITING_POWER_ON_IN_PROGRESS"), 1)
        self.assertEqual(events.count("POWER_ON_TIMEOUT"), 1)
        self.assertLess(events.index("SCALE_OUT_WAITING_POWER_ON_IN_PROGRESS"), events.index("POWER_ON_TIMEOUT"))

    def test_confirmed_power_on_allows_scale_in(self):
        c = scaler.ScalerController(self.scale_in_cfg())
        c.power_on_sent(15)
        self.assertEqual(c.c2_state_observed(45, RUNNING), [])   # exactly at the deadline: confirmed
        self.assertTrue(c.activated_by_controller)
        self.assertEqual(c.attribution, scaler.ATTRIBUTION_CONFIRMED)
        actions, _ = self.low_cycle(c, 50)
        self.assertIn(scaler.SHUTDOWN, actions)

    def test_failed_power_on_then_manual_start_is_not_stopped(self):
        c = scaler.ScalerController(self.scale_in_cfg())
        c.power_on_sent(15, exit_code=1)
        self.assertFalse(c.power_on_pending)
        events = c.c2_state_observed(20, RUNNING)                # someone started C2 by hand
        self.assertEqual([n for n, _ in events], ["C2_RUNNING_NOT_ATTRIBUTED"])
        self.assertIn("after a failed power.on", events[0][1])
        self.assertFalse(c.activated_by_controller)
        actions, ev = self.low_cycle(c, 25)
        self.assertNotIn(scaler.SHUTDOWN, actions)
        self.assertEqual(ev.count("SCALE_IN_SKIPPED_NOT_CONTROLLER_ACTIVATED"), 1)

    def test_running_after_timeout_is_not_attributed(self):
        c = scaler.ScalerController(self.scale_in_cfg())
        c.power_on_sent(15)
        self.assertEqual(c.c2_state_observed(40, STOPPED), [])
        events = c.c2_state_observed(46, RUNNING)                # 31 s after POWER_ON_SENT
        self.assertEqual([n for n, _ in events], ["POWER_ON_TIMEOUT", "C2_RUNNING_NOT_ATTRIBUTED"])
        self.assertIn("after the power-on timeout", c.attribution)
        actions, _ = self.low_cycle(c, 50)
        self.assertNotIn(scaler.SHUTDOWN, actions)

    def test_manual_c2_needs_explicit_permission(self):
        allowed = scaler.ScalerController(self.scale_in_cfg(allow_scale_in_manual_c2=True))
        allowed.power_on_sent(15, exit_code=1)
        allowed.c2_state_observed(20, RUNNING)
        actions, _ = self.low_cycle(allowed, 25)
        self.assertIn(scaler.SHUTDOWN, actions)

    def test_stop_clears_ownership(self):
        c = scaler.ScalerController(self.scale_in_cfg())
        c.power_on_sent(15)
        c.c2_state_observed(20, RUNNING)
        self.assertTrue(c.activated_by_controller)
        self.assertEqual([n for n, _ in c.c2_state_observed(30, STOPPED)], ["C2_STOPPED_OBSERVED"])
        events = c.c2_state_observed(40, RUNNING)                # restarted outside the controller
        self.assertFalse(c.activated_by_controller)
        self.assertEqual(events[0][0], "C2_RUNNING_NOT_ATTRIBUTED")


if __name__ == "__main__":
    unittest.main()
