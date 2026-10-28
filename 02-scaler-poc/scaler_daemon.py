#!/usr/bin/env python3
"""
Pillar 2: CPU-threshold activation of a pre-configured secondary Connector VM (VMware ESXi testbed)

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

- Samples SR-CONN01 guest CPU over SSH (two /proc/stat snapshots).
- Powers on SR-CONN02 on its ESXi host via `vim-cmd` once the scale-out threshold
  has been held for the trigger window.
- Records every activation milestone as a separately observed state:

    THRESHOLD_MET                     scale-out condition held for the trigger window (time of the
                                      C1 sample that completed the window)
    SCALE_OUT_DECISION                the controller decided to power on (decision time, after all
                                      inputs of the cycle were collected)
    POWER_ON_SENT                     `vim-cmd vmsvc/power.on` dispatched (logged with its exit code,
                                      even if the VM never reaches the running state)
    VM_POWERED_ON                     ESXi reports "Powered on", with its attribution:
                                      confirmed_within_power_on_timeout only if the power.on returned
                                      exit code 0 and "Powered on" was observed before the power-on
                                      timeout; otherwise not_attributed (failed power.on, observed
                                      after the timeout, or C2 already running / started by someone else)
    GUEST_REACHABLE                   an authenticated SSH command on the SR-CONN02 guest exited with 0
                                      (a valid CPU value is a separate observation; an open TCP port
                                      is not enough)
    CONNECTOR_API_REPORTED_AVAILABLE  Atmos Admin API status of SR-CONN02, refreshed after POWER_ON_SENT
                                      (control-plane report only)
    APPLICATION_REACHABLE             the target application answered; NOT attributed to any connector
    C2_MATCHING_CONNECTION_OBSERVED   optional `ss` check: an established TCP connection from SR-CONN02
                                      to BACKEND_HOST:BACKEND_PORT (not yet validated as app traffic)
    C2_TRAFFIC_OBSERVED               application traffic carried by SR-CONN02; no validated evidence
                                      source exists yet, so this is always reported as not_checked

  Every check ends with its own status in ACTIVATION_CHECK / ACTIVATION_SUMMARY:
    verified      positive evidence was observed (offset given)
    unverified    attempted, no evidence (or only ambiguous evidence), activation closed for another reason
    not_checked   no check configured, or never attempted because its prerequisite was not met
    failed        every attempt errored, or (VM_POWERED_ON) the power.on command returned non-zero
    timeout       attempted with valid negative answers until the readiness / power-on timeout
  Closing an activation never marks a check as verified, and no readiness time is derived
  from another check. Offsets are measured on the monotonic clock from POWER_ON_SENT, i.e. from
  the moment immediately before the power.on SSH call is made.

Times recorded per cycle (monotonic seconds, also in the time series):
  c1_sample_start_s / c1_sample_end_s   C1 CPU sampling command (the value covers the /proc/stat
                                        interval inside it; it is available at c1_sample_end_s)
  c2_state_observed_s                   C2 power state returned by ESXi
  c2_sample_start_s / c2_sample_end_s   C2 CPU sampling, only if C2 is running
  decision_s                            controller decision, after all inputs were collected
The trigger windows are measured between C1 sample times. Cooldown, minimum C2 uptime and the
in-progress check are evaluated at the decision time. C2 uptime starts at the C2 power-state
observation that first reported "Powered on" (never at an earlier C1 time).

Power-on tracking does not block the main loop: after POWER_ON_SENT the daemon keeps running its
cycles (CPU sampling, probes); between cycles, while a power-on is in progress, it only queries the
C2 power state every POWER_STATE_POLL_SEC (one bounded command per query). No second power.on is
sent while one is in progress. POWER_ON_TIMEOUT closes the in-progress state.

Validation status: the offline unit tests and the --dry-run mode use simulated ESXi, CPU, API and
probe components and a simulated clock. They check the decision logic and the logging, NOT the
behaviour of a real ESXi host, connector VM, Atmos Admin API or SSE data path; those still have to
be validated by measurements on the testbed.

- Scale-in (ACPI shutdown of SR-CONN02) is disabled by default. When enabled it requires valid CPU
  samples from both connectors, never stops a C2 whose power-on by this controller was not
  confirmed (failed or timed-out power.on, manual start) unless explicitly allowed with
  --allow-scale-in-manual-c2, and never forces a power-off unless explicitly allowed. The shutdown
  itself is still followed by bounded polling (up to SHUTDOWN_TIMEOUT_SEC).

Secrets (SSH/ESXi passwords, Atmos API key) are read from the environment only, never from the
command line. Nothing is loaded from .env and no connection is opened at import time.
"""

import os
import sys
import re
import csv
import time
import argparse
import ipaddress
import logging
from collections import namedtuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import requests

log = logging.getLogger("scaler")

RUNNING = "running"
STOPPED = "stopped"
SUSPENDED = "suspended"
UNKNOWN = "unknown"

POWER_ON = "power_on"
SHUTDOWN = "shutdown"

CONNECTION_CHECK_NONE = "none"
CONNECTION_CHECK_SS = "ss-established"

READINESS_MILESTONES = (
    "VM_POWERED_ON",
    "GUEST_REACHABLE",
    "CONNECTOR_API_REPORTED_AVAILABLE",
    "APPLICATION_REACHABLE",
    "C2_MATCHING_CONNECTION_OBSERVED",
    "C2_TRAFFIC_OBSERVED",
)

VERIFIED = "verified"
UNVERIFIED = "unverified"
NOT_CHECKED = "not_checked"
FAILED = "failed"
TIMEOUT = "timeout"

REASON_ALL_VERIFIED = "all configured checks verified"
REASON_READINESS_TIMEOUT = "readiness timeout"

ATTRIBUTION_CONFIRMED = "confirmed_within_power_on_timeout"
ATTRIBUTION_NONE = "not_attributed"

# Simulated CPU profile entry: the SSH command succeeded but /proc/stat was unusable
BAD_CPU_DATA = "bad"

CommandResult = namedtuple("CommandResult", ["code", "out", "err"])
ConnectorStatus = namedtuple("ConnectorStatus", ["status", "check_time", "raw_check_time", "tz_assumed", "error"],
                             defaults=(None, None, "", False, ""))
# One guest CPU sampling attempt. ssh_command_ok: an authenticated SSH session ran the command and it
# exited with 0 (True), the SSH layer or the command failed (False). value is None unless the output
# was a valid sample; a valid SSH command with unusable output therefore gives (None, error, True).
CpuReading = namedtuple("CpuReading", ["value", "error", "ssh_command_ok"])
# CpuReading plus the monotonic start/end of the sampling call, filled in by the daemon
CpuObservation = namedtuple("CpuObservation", ["value", "error", "ssh_command_ok", "start", "end"])


class KnownHostsError(ValueError):
    """A configured known_hosts file is missing, unreadable or holds no usable host key."""


# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------

@dataclass
class ScalerConfig:
    # Primary connector guest (CPU telemetry)
    c1_ip: str = ""
    c1_user: str = ""
    c1_password: str = field(default="", repr=False)
    # Secondary connector guest (CPU telemetry for scale-in, guest reachability, connection check)
    c2_ip: str = ""
    c2_user: str = ""
    c2_password: str = field(default="", repr=False)
    # Secondary connector hypervisor
    esxi_host: str = ""
    esxi_user: str = "root"
    esxi_password: str = field(default="", repr=False)
    c2_vmid: int = 0

    # Decision logic
    scale_out_pct: float = 80.0
    scale_in_pct: float = 30.0
    window_sec: float = 15.0
    poll_sec: float = 5.0
    cpu_sample_sec: float = 1.0
    enable_scale_in: bool = False
    cooldown_sec: float = 60.0
    min_c2_uptime_sec: float = 300.0
    allow_scale_in_manual_c2: bool = False
    allow_force_power_off: bool = False

    # Power-state polling and readiness tracking
    power_on_timeout_sec: float = 60.0
    power_state_poll_sec: float = 1.0
    shutdown_timeout_sec: float = 120.0
    readiness_timeout_sec: float = 600.0

    # Application reachability (target app through SSE)
    target_url: str = ""
    app_expected_status: int = 200
    http_timeout_sec: float = 5.0
    http_ca_bundle: str = ""

    # Atmos Admin API (read-only connector status)
    atmos_base_url: str = "https://admin-api.axissecurity.com/api/v1.0"
    atmos_api_key: str = field(default="", repr=False)
    c2_connector_id: str = ""
    connector_ready_statuses: tuple = ("Available",)
    api_status_skew_sec: float = 0.0

    # Optional C2 connection check (C2_MATCHING_CONNECTION_OBSERVED; not app-traffic proof)
    c2_connection_check: str = CONNECTION_CHECK_NONE
    backend_host: str = ""
    backend_port: int = 443

    # Security
    ssh_known_hosts: str = ""
    lab_insecure_ssh: bool = False
    lab_insecure_tls: bool = False

    # Run mode
    dry_run: bool = False
    sim_c1_cpu: tuple = (20.0, 85.0, 90.0, 90.0, 90.0, 90.0, 90.0, 25.0)
    sim_c2_cpu: tuple = (10.0,)
    sim_boot_delay_sec: float = 8.0
    sim_initial_c2_state: str = STOPPED
    max_cycles: int = 0
    output_dir: str = ""

    def secrets(self):
        return [s for s in (self.c1_password, self.c2_password, self.esxi_password, self.atmos_api_key) if s]


def validate_config(cfg):
    """Raises ValueError for inconsistent or unsafe settings."""
    if not 0.0 <= cfg.scale_in_pct < cfg.scale_out_pct <= 100.0:
        raise ValueError("thresholds must satisfy 0 <= scale-in < scale-out <= 100")
    for name in ("window_sec", "poll_sec", "cpu_sample_sec", "power_on_timeout_sec",
                 "power_state_poll_sec", "shutdown_timeout_sec", "readiness_timeout_sec", "http_timeout_sec"):
        if getattr(cfg, name) <= 0:
            raise ValueError(f"{name} must be positive")
    for name in ("cooldown_sec", "min_c2_uptime_sec", "api_status_skew_sec"):
        if getattr(cfg, name) < 0:
            raise ValueError(f"{name} must not be negative")
    if cfg.c2_connection_check not in (CONNECTION_CHECK_NONE, CONNECTION_CHECK_SS):
        raise ValueError(f"unknown c2_connection_check: {cfg.c2_connection_check}")
    if cfg.dry_run:
        return
    if not isinstance(cfg.c2_vmid, int) or cfg.c2_vmid <= 0:
        raise ValueError("CONNECTOR_2_VMID must be a positive integer")
    if not cfg.c1_ip or not cfg.esxi_host:
        raise ValueError("CONNECTOR_1_IP and ESXI_HOST are required")
    if cfg.enable_scale_in and not cfg.c2_ip:
        raise ValueError("scale-in requires CONNECTOR_2_IP (C2 CPU telemetry)")
    if cfg.c2_connection_check == CONNECTION_CHECK_SS:
        if not cfg.c2_ip:
            raise ValueError("the ss-established connection check requires CONNECTOR_2_IP")
        ipaddress.ip_address(cfg.backend_host)  # raises ValueError for non-IP values
        if not 0 < int(cfg.backend_port) < 65536:
            raise ValueError("BACKEND_PORT out of range")


# ------------------------------------------------------------------------------
# Parsers (pure functions)
# ------------------------------------------------------------------------------

def parse_power_state(output):
    """Maps `vim-cmd vmsvc/power.getstate` output (state on the last line) to a state name."""
    lines = [line.strip() for line in (output or "").splitlines() if line.strip()]
    if not lines:
        return UNKNOWN
    return {"Powered on": RUNNING, "Powered off": STOPPED, "Suspended": SUSPENDED}.get(lines[-1], UNKNOWN)


PROC_STAT_FIELDS = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")
# Counters that must never decrease between two snapshots of one boot (see cpu_stats_from_proc_stat)
PROC_STAT_MONOTONIC = ("user", "nice", "system", "irq", "softirq", "steal")


def parse_proc_stat_counters(line):
    """{field: jiffies} for fields 1-8 of the aggregate 'cpu ' line of /proc/stat.

    guest and guest_nice (fields 9-10) are ignored because the kernel already counts them in
    user and nice; adding them would count that time twice."""
    parts = line.split()
    if parts[:1] != ["cpu"] or len(parts) < 9:
        raise ValueError(f"expected an aggregate 'cpu' line with at least 8 counters: {line!r}")
    try:
        values = [int(v) for v in parts[1:9]]
    except ValueError:
        raise ValueError(f"non-integer counter in cpu line: {line!r}") from None
    if any(v < 0 for v in values):
        raise ValueError(f"negative counter in cpu line: {line!r}")
    return dict(zip(PROC_STAT_FIELDS, values))


def parse_proc_stat_cpu(line):
    """Returns (idle, total) jiffies from the aggregate 'cpu ' line of /proc/stat.

    Fields 1-8 of the line are used: user nice system idle iowait irq softirq steal.
      idle  = idle + iowait
      total = user + nice + system + idle + iowait + irq + softirq + steal
    """
    c = parse_proc_stat_counters(line)
    return c["idle"] + c["iowait"], sum(c.values())


def cpu_stats_from_proc_stat(output):
    """CPU statistics over the interval between two /proc/stat snapshots.

    Returns {"busy_pct", "iowait_pct", "steal_pct", "d_total", "deltas"}:
      busy_pct    100 * (1 - d(idle + iowait) / d_total), rounded to 0.1
      iowait_pct  100 * d_iowait / d_total (None if iowait decreased, see below)
      steal_pct   100 * d_steal / d_total
    Treatment of the fields:
      iowait  counted as idle: the CPU had nothing to run (the task waits for I/O elsewhere).
      steal   counted as busy: time the hypervisor gave to others while this vCPU was runnable,
              i.e. CPU capacity the connector VM could not use (consistent with 100 - %idle of
              mpstat; steal_pct is reported separately for interpretation).
    Validity rules (a violation raises ValueError; nothing is clamped):
      - exactly two aggregate 'cpu' lines with 8 non-negative integer counters each;
      - d_total > 0, otherwise no CPU time elapsed (zero or broken sampling interval);
      - user, nice, system, irq, softirq and steal must not decrease. They are cumulative 64-bit
        counters since boot, so a decrease means a counter reset (reboot, VM restore) between the
        snapshots, not a wrap;
      - idle and iowait MAY decrease individually: the kernel documentation states that iowait can
        decrease, and with NO_HZ idle accounting the ongoing idle period of a CPU is reported as
        idle or iowait depending on pending I/O at read time, so time can move between the two;
      - their sum idle + iowait must not decrease (that would again mean a reset).
    """
    lines = [line for line in (output or "").splitlines() if line.startswith("cpu ")]
    if len(lines) != 2:
        raise ValueError(f"expected 2 aggregate cpu lines, got {len(lines)}")
    first, second = parse_proc_stat_counters(lines[0]), parse_proc_stat_counters(lines[1])
    deltas = {f: second[f] - first[f] for f in PROC_STAT_FIELDS}
    d_total = sum(deltas.values())
    for f in PROC_STAT_MONOTONIC:
        if deltas[f] < 0:
            raise ValueError(f"counter '{f}' decreased by {-deltas[f]}: counter reset between the snapshots")
    d_idle = deltas["idle"] + deltas["iowait"]
    if d_idle < 0:
        raise ValueError(f"idle+iowait decreased by {-d_idle}: counter reset between the snapshots")
    if d_total <= 0:
        raise ValueError("no CPU time elapsed between samples")
    return {
        "busy_pct": round(100.0 * (1.0 - d_idle / d_total), 1),
        "iowait_pct": round(100.0 * deltas["iowait"] / d_total, 1) if deltas["iowait"] >= 0 else None,
        "steal_pct": round(100.0 * deltas["steal"] / d_total, 1),
        "d_total": d_total,
        "deltas": deltas,
    }


def cpu_pct_from_proc_stat(output):
    """Busy CPU % over the interval between two /proc/stat snapshots (see cpu_stats_from_proc_stat)."""
    return cpu_stats_from_proc_stat(output)["busy_pct"]


def parse_api_timestamp(value):
    """Parses an ISO 8601 date-time. Returns (datetime | None, timezone_assumed).

    The Swagger does not define the time zone of values without a UTC offset. Such values are
    returned as UTC with timezone_assumed=True; callers must not treat them as verified times.
    """
    if not isinstance(value, str) or not value.strip():
        return None, False
    text = value.strip().replace("Z", "+00:00")
    # .NET may emit 7 fractional digits; normalise to the 6 that datetime accepts
    m = re.match(r"^(.*T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(.*)$", text)
    if m and m.group(2):
        text = f"{m.group(1)}.{(m.group(2) + '000000')[:6]}{m.group(3)}"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None, False
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc), True
    return parsed, False


def parse_cpu_profile(text):
    """'20,85,err,bad,90' -> (20.0, 85.0, None, 'bad', 90.0).
    'err'/'x'/'-' simulate a failed SSH command; 'bad' a successful SSH command with unusable output."""
    values = []
    for token in (t.strip() for t in text.split(",")):
        if not token:
            continue
        if token.lower() == BAD_CPU_DATA:
            values.append(BAD_CPU_DATA)
            continue
        values.append(None if token.lower() in ("err", "x", "-") else float(token))
    if not values:
        raise ValueError("empty CPU profile")
    return tuple(values)


# ------------------------------------------------------------------------------
# Clocks
# ------------------------------------------------------------------------------

class RealClock:
    def monotonic(self):
        return time.monotonic()

    def wall(self):
        return datetime.now(timezone.utc)

    def sleep(self, seconds):
        time.sleep(max(0.0, seconds))


class SimClock:
    """Deterministic clock for dry-run and tests: sleep() only advances simulated time."""
    def __init__(self, start_wall=datetime(2026, 1, 1, tzinfo=timezone.utc)):
        self.t = 0.0
        self.start_wall = start_wall

    def monotonic(self):
        return self.t

    def wall(self):
        return self.start_wall + timedelta(seconds=self.t)

    def sleep(self, seconds):
        self.t += max(0.0, seconds)


# ------------------------------------------------------------------------------
# SSH, ESXi and guest telemetry
# ------------------------------------------------------------------------------

def _host_key_load_errors():
    import paramiko
    from paramiko.hostkeys import InvalidHostKey  # not a subclass of SSHException
    return (OSError, UnicodeDecodeError, paramiko.SSHException, InvalidHostKey)


def load_known_hosts(path):
    """Validates an explicitly configured known_hosts file and returns its paramiko.HostKeys.

    Raises KnownHostsError if the file is missing, unreadable, has an invalid entry or holds no
    usable host key. The file is only read; it is never written. The error message names the
    file and the exception type, not the file content."""
    import paramiko
    if not os.path.isfile(path):
        raise KnownHostsError(f"known_hosts file not found or not a regular file: {path}")
    keys = paramiko.HostKeys()
    try:
        keys.load(path)
    except _host_key_load_errors() as exc:
        raise KnownHostsError(f"known_hosts file {path} could not be loaded: {type(exc).__name__}") from None
    if not keys.keys():
        raise KnownHostsError(f"known_hosts file {path} contains no usable host key entry")
    return keys


class SSHExecutor:
    """Runs one command per SSH session. Host keys are verified unless lab mode is requested.

    A missing or broken explicit known_hosts file, or a broken system known_hosts file, is reported
    as a known_hosts error result (code -1); it never falls back to a permissive host key policy.
    Nothing is opened or loaded before run() is called."""
    def __init__(self, host, user, password="", timeout=5.0, known_hosts="", insecure_host_keys=False):
        self.host = host
        self.user = user
        self._password = password
        self.timeout = timeout
        self.known_hosts = known_hosts
        self.insecure_host_keys = insecure_host_keys

    def _client(self):
        import paramiko
        client = paramiko.SSHClient()
        try:
            client.load_system_host_keys()  # a missing system file is ignored by paramiko itself
        except _host_key_load_errors() as exc:
            client.close()
            raise KnownHostsError(f"system known_hosts could not be loaded: {type(exc).__name__}") from None
        if self.known_hosts:
            try:
                load_known_hosts(self.known_hosts)
                client.load_host_keys(self.known_hosts)
            except KnownHostsError:
                client.close()
                raise
            except _host_key_load_errors() as exc:
                client.close()
                raise KnownHostsError(f"known_hosts file {self.known_hosts} could not be loaded: "
                                      f"{type(exc).__name__}") from None
        if self.insecure_host_keys:
            client.set_missing_host_key_policy(paramiko.WarningPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        return client

    def run(self, cmd, timeout=None):
        try:
            client = self._client()
        except KnownHostsError as exc:
            return CommandResult(-1, "", f"known_hosts error ({self.host}): {exc}")
        try:
            client.connect(hostname=self.host, username=self.user,
                           password=self._password or None, timeout=self.timeout)
            _, stdout, stderr = client.exec_command(cmd, timeout=timeout or self.timeout)
            out = stdout.read().decode(errors="replace").strip()
            err = stderr.read().decode(errors="replace").strip()
            return CommandResult(stdout.channel.recv_exit_status(), out, err)
        except Exception as exc:
            return CommandResult(-1, "", f"SSH error ({self.host}): {type(exc).__name__}: {exc}")
        finally:
            client.close()


class ESXiHost:
    """Controls SR-CONN02 on its ESXi host via vim-cmd."""
    def __init__(self, executor, vmid):
        if not isinstance(vmid, int) or vmid <= 0:
            raise ValueError("vmid must be a positive integer")
        self.executor = executor
        self.vmid = vmid

    def get_power_state(self):
        res = self.executor.run(f"vim-cmd vmsvc/power.getstate {self.vmid}")
        if res.code != 0:
            return UNKNOWN, res.err or f"power.getstate exit code {res.code}"
        state = parse_power_state(res.out)
        return state, ("" if state != UNKNOWN else f"unrecognised power.getstate output: {res.out!r}")

    def power_on(self):
        return self.executor.run(f"vim-cmd vmsvc/power.on {self.vmid}")

    def shutdown(self):
        return self.executor.run(f"vim-cmd vmsvc/power.shutdown {self.vmid}")

    def power_off(self):
        return self.executor.run(f"vim-cmd vmsvc/power.off {self.vmid}")


class SimulatedESXi:
    """Deterministic stand-in for ESXiHost (dry-run and tests). No SSH is used."""
    def __init__(self, clock, initial_state=STOPPED, boot_delay_sec=8.0, shutdown_delay_sec=5.0,
                 power_on_exit_code=0, never_boots=False, shutdown_hangs=False):
        self.clock = clock
        self.state = initial_state
        self.boot_delay_sec = boot_delay_sec
        self.shutdown_delay_sec = shutdown_delay_sec
        self.power_on_exit_code = power_on_exit_code
        self.never_boots = never_boots
        self.shutdown_hangs = shutdown_hangs
        self.commands = []
        self._pending = None  # (target_state, at_monotonic)

    def _settle(self):
        if self._pending and self.clock.monotonic() >= self._pending[1]:
            self.state = self._pending[0]
            self._pending = None

    def get_power_state(self):
        self.commands.append("power.getstate")
        self._settle()
        return self.state, ("" if self.state != UNKNOWN else "simulated unknown state")

    def power_on(self):
        self.commands.append("power.on")
        if self.power_on_exit_code != 0:
            return CommandResult(self.power_on_exit_code, "", "simulated power.on failure")
        if self.state == STOPPED and not self.never_boots:
            self._pending = (RUNNING, self.clock.monotonic() + self.boot_delay_sec)
        return CommandResult(0, "", "")

    def shutdown(self):
        self.commands.append("power.shutdown")
        if self.state == RUNNING and not self.shutdown_hangs:
            self._pending = (STOPPED, self.clock.monotonic() + self.shutdown_delay_sec)
        return CommandResult(0, "", "")

    def power_off(self):
        self.commands.append("power.off")
        self.state = STOPPED
        self._pending = None
        return CommandResult(0, "", "")


class GuestCpuSampler:
    """Busy CPU % of a Linux guest from two /proc/stat snapshots taken `sample_sec` apart.

    observe() keeps two observations apart: whether the authenticated SSH command succeeded
    (exit code 0) and whether its output was a valid CPU sample."""
    def __init__(self, executor, sample_sec=1.0):
        if not sample_sec > 0:
            raise ValueError("sample_sec must be positive")
        self.executor = executor
        self.sample_sec = sample_sec

    def observe(self):
        cmd = f"head -n1 /proc/stat; sleep {self.sample_sec:g}; head -n1 /proc/stat"
        res = self.executor.run(cmd, timeout=self.executor.timeout + self.sample_sec)
        if res.code == -1:
            return CpuReading(None, res.err or "SSH error", False)
        if res.code != 0:
            return CpuReading(None, f"command exit code {res.code}: {res.err}".rstrip(": "), False)
        try:
            return CpuReading(cpu_pct_from_proc_stat(res.out), "", True)
        except ValueError as exc:
            return CpuReading(None, f"unparseable /proc/stat output: {exc}", True)

    def sample(self):
        """(value, error) - kept for callers that do not need the SSH observation."""
        return self.observe()[:2]


class SimCpuSampler:
    """Replays a fixed CPU profile (one value per call, last value repeats).
    None = failed SSH command; BAD_CPU_DATA = SSH command succeeded, output unusable."""
    def __init__(self, profile):
        self.profile = tuple(profile)
        self.calls = 0

    def observe(self):
        value = self.profile[min(self.calls, len(self.profile) - 1)]
        self.calls += 1
        if value is None:
            return CpuReading(None, "simulated SSH failure", False)
        if value == BAD_CPU_DATA:
            return CpuReading(None, "simulated unparseable /proc/stat output", True)
        return CpuReading(value, "", True)

    def sample(self):
        return self.observe()[:2]


# ------------------------------------------------------------------------------
# Readiness checks (each returns (True | False | None, detail); None = check failed)
# ------------------------------------------------------------------------------

class ConnectorStatusClient:
    """Read-only GET /api/v1.0/Connectors/{id}/status (Swagger operation Connectors_Status).
    The reported status is a control-plane view; it is not proof of data-plane readiness."""
    def __init__(self, base_url, api_key, connector_id, timeout=5.0, session=None):
        self.url = f"{base_url.rstrip('/')}/Connectors/{connector_id}/status"
        self._api_key = api_key
        self.timeout = timeout
        self.session = session or requests.Session()

    def get_status(self):
        try:
            resp = self.session.get(self.url, headers={"Authorization": f"Bearer {self._api_key}"},
                                    timeout=self.timeout)
        except requests.RequestException as exc:
            return ConnectorStatus(error=f"connector status request failed: {type(exc).__name__}")
        if resp.status_code != 200:
            return ConnectorStatus(error=f"connector status HTTP {resp.status_code}")
        try:
            body = resp.json()
        except ValueError:
            return ConnectorStatus(error="connector status response is not JSON")
        raw = body.get("systemStatusCheckTime")
        check_time, tz_assumed = parse_api_timestamp(raw)
        return ConnectorStatus(body.get("status"), check_time, "" if raw is None else str(raw), tz_assumed)


class ApplicationProbe:
    """GET on the target URL. Success shows the application is reachable through SSE,
    not which connector carried the request."""
    def __init__(self, url, expected_status=200, timeout=5.0, verify=True, session=None):
        self.url = url
        self.expected_status = expected_status
        self.timeout = timeout
        self.verify = verify
        self.session = session or requests.Session()

    def check(self):
        try:
            resp = self.session.get(self.url, timeout=self.timeout, verify=self.verify)
        except requests.RequestException as exc:
            return None, f"{type(exc).__name__}"
        return resp.status_code == self.expected_status, f"HTTP {resp.status_code}"


class EstablishedConnectionProbe:
    """Reports C2_MATCHING_CONNECTION_OBSERVED: established TCP connections from the SR-CONN02 guest
    to BACKEND_HOST:BACKEND_PORT (`ss`). This is NOT proof of application traffic through C2:
    connector health checks or idle pooled connections would match as well. It may only be
    promoted to C2_TRAFFIC_OBSERVED after it has been validated against the test application."""
    def __init__(self, executor, backend_host, backend_port):
        addr = ipaddress.ip_address(backend_host)
        port = int(backend_port)
        if not 0 < port < 65536:
            raise ValueError("backend port out of range")
        host = f"[{addr}]" if addr.version == 6 else str(addr)
        self.cmd = f"ss -Htn state established dst {host}:{port}"
        self.executor = executor

    def check(self):
        res = self.executor.run(self.cmd)
        if res.code != 0:
            return None, res.err or f"exit code {res.code}"
        count = len([line for line in res.out.splitlines() if line.strip()])
        return count > 0, f"{count} established connection(s) to backend"


# ------------------------------------------------------------------------------
# Decision logic (pure; no I/O)
# ------------------------------------------------------------------------------

@dataclass
class Decision:
    action: str = ""
    events: list = field(default_factory=list)  # [(name, detail)]


class ScalerController:
    """Threshold/window/cooldown logic and C2 ownership. Pure: all times are monotonic seconds
    supplied by the caller.

    Times passed to observe():
      now         decision time (after all inputs of the cycle were collected)
      sample_t    time the C1 CPU sample became available; trigger windows are measured between
                  C1 sample times
      c2_state_t  time the C2 power state was observed

    - The trigger window starts at the first qualifying C1 sample; any non-qualifying or missing
      sample resets it. With a poll interval P the effective hold time is the first multiple of P
      that is >= window_sec.
    - Cooldown starts when a power-on or shutdown command is dispatched (a failed one included) and
      is evaluated at the decision time.
    - A power-on is in progress from a power.on with exit code 0 until "Powered on" is observed or
      the power-on timeout passes; meanwhile no further power-on is decided.
    - C2 counts as activated by this controller only if "Powered on" was observed within the
      power-on timeout of such a power.on. Only then is scale-in allowed (unless
      allow_scale_in_manual_c2). A failed power.on, a timeout or a manual start never grant it.
    - Minimum C2 uptime starts at the first C2 power-state observation reporting "Powered on".
    """
    # Events derived from a C2 power-state observation (logged at the observation time)
    STATE_EVENTS = ("C2_POWER_STATE_UNKNOWN", "C2_STOPPED_OBSERVED", "POWER_ON_TIMEOUT",
                    "C2_RUNNING_NOT_ATTRIBUTED")

    def __init__(self, cfg):
        self.cfg = cfg
        self.high_since = None          # C1 sample time of the first qualifying sample
        self.low_since = None
        self.threshold_met_at = None    # C1 sample time that completed the scale-out window
        self.decided_at = None          # decision time of the last POWER_ON decision
        self.last_action_at = None
        self.activated_by_controller = False
        self.power_on_pending = False
        self.power_on_deadline = None
        self.last_power_on_outcome = ""  # "", in_progress, failed, timeout, confirmed
        self.c2_running_since = None
        self.attribution = ""            # attribution of the current C2 running period
        self._reported = set()

    def _once(self, events, name, detail=""):
        if name not in self._reported:
            self._reported.add(name)
            events.append((name, detail))

    def _cooldown_ok(self, now):
        return self.last_action_at is None or now - self.last_action_at >= self.cfg.cooldown_sec

    def _reset_high(self):
        self.high_since = None
        self.threshold_met_at = None
        self._reported -= {"THRESHOLD_MET", "SCALE_OUT_DEFERRED_COOLDOWN", "SCALE_OUT_BLOCKED_C2_STATE",
                           "SCALE_OUT_NOT_NEEDED_C2_RUNNING", "SCALE_OUT_WAITING_POWER_ON_IN_PROGRESS"}

    def _reset_low(self):
        self.low_since = None
        self._reported -= {"SCALE_IN_SKIPPED_NOT_CONTROLLER_ACTIVATED", "SCALE_IN_DEFERRED_COOLDOWN",
                           "SCALE_IN_DEFERRED_MIN_UPTIME"}

    # Notifications from the daemon
    def power_on_sent(self, now, exit_code=0):
        self.last_action_at = now
        self._reset_high()
        if exit_code == 0:
            self.power_on_pending = True
            self.power_on_deadline = now + self.cfg.power_on_timeout_sec
            self.last_power_on_outcome = "in_progress"
        else:
            self.power_on_pending = False
            self.power_on_deadline = None
            self.last_power_on_outcome = "failed"

    def c2_state_observed(self, t, state):
        """Updates the in-progress power-on, the ownership and the uptime start from one C2
        power-state observation made at time t. Returns [(event, detail)]."""
        events = []
        if state == UNKNOWN:
            events.append(("C2_POWER_STATE_UNKNOWN", ""))
        if self.power_on_pending:
            if state == RUNNING and t <= self.power_on_deadline:
                self.power_on_pending = False
                self.activated_by_controller = True
                self.last_power_on_outcome = "confirmed"
                self.attribution = ATTRIBUTION_CONFIRMED
            elif t >= self.power_on_deadline:
                self.power_on_pending = False
                self.last_power_on_outcome = "timeout"
                events.append(("POWER_ON_TIMEOUT", f"no 'Powered on' observed within "
                                                   f"{self.cfg.power_on_timeout_sec}s of POWER_ON_SENT"))
        if state == RUNNING:
            if self.c2_running_since is None:
                self.c2_running_since = t
                if not self.activated_by_controller:
                    reason = {"failed": "observed after a failed power.on",
                              "timeout": "observed after the power-on timeout"}.get(
                        self.last_power_on_outcome, "not started by this controller")
                    self.attribution = f"{ATTRIBUTION_NONE} ({reason})"
                    events.append(("C2_RUNNING_NOT_ATTRIBUTED", f"{reason}; scale-in not authorised"))
        elif state == STOPPED and self.c2_running_since is not None:
            # C2 was running and is now off (our shutdown completed or someone stopped it)
            events.append(("C2_STOPPED_OBSERVED", ""))
            self.c2_stopped()
        return events

    def vm_powered_on(self, now):
        """Shortcut for a 'Powered on' observation at `now`."""
        return self.c2_state_observed(now, RUNNING)

    def shutdown_sent(self, now):
        self.last_action_at = now
        self._reset_low()

    def c2_stopped(self):
        self.activated_by_controller = False
        self.c2_running_since = None
        self.attribution = ""

    def observe(self, now, c1_cpu, c2_cpu, c2_state, sample_t=None, c2_state_t=None):
        sample_t = now if sample_t is None else sample_t
        c2_state_t = now if c2_state_t is None else c2_state_t
        d = Decision()
        d.events.extend(self.c2_state_observed(c2_state_t, c2_state))

        if c1_cpu is None:
            d.events.append(("TELEMETRY_ERROR_C1", ""))
            self._reset_high()
            self._reset_low()
            return d

        # Scale-out: window on C1 sample times, conditions at the decision time
        if c1_cpu >= self.cfg.scale_out_pct:
            self._reset_low()
            if self.high_since is None:
                self.high_since = sample_t
            held = sample_t - self.high_since
            if held >= self.cfg.window_sec:
                if self.threshold_met_at is None:
                    self.threshold_met_at = sample_t
                self._once(d.events, "THRESHOLD_MET",
                           f"c1_cpu={c1_cpu:.1f}% >= {self.cfg.scale_out_pct}% for {held:.1f}s of C1 sample time")
                if c2_state == RUNNING:
                    self._once(d.events, "SCALE_OUT_NOT_NEEDED_C2_RUNNING")
                elif self.power_on_pending:
                    self._once(d.events, "SCALE_OUT_WAITING_POWER_ON_IN_PROGRESS",
                               f"{self.power_on_deadline - now:.1f}s until the power-on timeout")
                elif c2_state != STOPPED:
                    self._once(d.events, "SCALE_OUT_BLOCKED_C2_STATE", f"c2_state={c2_state}")
                elif not self._cooldown_ok(now):
                    self._once(d.events, "SCALE_OUT_DEFERRED_COOLDOWN",
                               f"{self.cfg.cooldown_sec - (now - self.last_action_at):.1f}s left")
                else:
                    d.action = POWER_ON
                    self.decided_at = now
            return d
        self._reset_high()

        # Scale-in
        if not self.cfg.enable_scale_in or c2_state != RUNNING:
            self._reset_low()
            return d
        if c2_cpu is None:
            d.events.append(("TELEMETRY_ERROR_C2", ""))
            self._reset_low()
            return d
        if c1_cpu > self.cfg.scale_in_pct or c2_cpu > self.cfg.scale_in_pct:
            self._reset_low()
            return d
        if self.low_since is None:
            self.low_since = sample_t
        if sample_t - self.low_since < self.cfg.window_sec:
            return d
        if not self.activated_by_controller and not self.cfg.allow_scale_in_manual_c2:
            self._once(d.events, "SCALE_IN_SKIPPED_NOT_CONTROLLER_ACTIVATED", self.attribution)
        elif not self._cooldown_ok(now):
            self._once(d.events, "SCALE_IN_DEFERRED_COOLDOWN",
                       f"{self.cfg.cooldown_sec - (now - self.last_action_at):.1f}s left")
        elif now - self.c2_running_since < self.cfg.min_c2_uptime_sec:
            self._once(d.events, "SCALE_IN_DEFERRED_MIN_UPTIME",
                       f"uptime {now - self.c2_running_since:.1f}s < {self.cfg.min_c2_uptime_sec}s")
        else:
            d.action = SHUTDOWN
        return d


class Activation:
    """One scale-out activation: when each check was first verified (monotonic time) and how many
    attempts it took. Attempts are counted only until the check is verified."""
    TRIGGER_STEPS = ("THRESHOLD_MET", "SCALE_OUT_DECISION", "POWER_ON_SENT")

    def __init__(self, threshold_met_at, decided_at, power_on_sent_at, power_on_sent_wall, power_on_exit_code=0):
        self.times = {"THRESHOLD_MET": threshold_met_at, "SCALE_OUT_DECISION": decided_at,
                      "POWER_ON_SENT": power_on_sent_at}
        self.power_on_sent_wall = power_on_sent_wall
        self.power_on_exit_code = power_on_exit_code
        self.power_on_timed_out = False
        self.attribution = ""
        self.attempts = {name: {"positive": 0, "negative": 0, "ambiguous": 0, "error": 0}
                         for name in READINESS_MILESTONES}
        self.closed = False
        self.close_reason = ""

    @property
    def t0(self):
        return self.times["POWER_ON_SENT"]

    def record(self, name, outcome):
        """Counts one 'negative', 'ambiguous' or 'error' attempt of a check that is not yet verified."""
        if name not in self.times:
            self.attempts[name][outcome] += 1

    def mark(self, name, now):
        """Records the first positive observation. Returns False if the check was already verified."""
        if name in self.times:
            return False
        self.attempts[name]["positive"] += 1
        self.times[name] = now
        return True

    def check_status(self, name, configured):
        """Returns (status, detail) for one readiness check; see the module docstring for the statuses."""
        if name in self.times:
            offset = f"{self.times[name] - self.t0:+.3f}s"
            if name == "VM_POWERED_ON" and self.attribution:
                return VERIFIED, f"{offset}; attribution={self.attribution}"
            return VERIFIED, offset
        if not configured:
            return NOT_CHECKED, "no check configured"
        counts = self.attempts[name]
        total = sum(counts.values())
        if total == 0:
            return NOT_CHECKED, "not attempted (prerequisite not met)"
        detail = (f"attempts={total} negative={counts['negative']} "
                  f"ambiguous={counts['ambiguous']} errors={counts['error']}")
        if name == "VM_POWERED_ON" and self.power_on_exit_code != 0:
            return FAILED, f"power.on exit code {self.power_on_exit_code}; {detail}"
        if counts["error"] == total:
            return FAILED, detail
        if self.close_reason == REASON_READINESS_TIMEOUT or (name == "VM_POWERED_ON" and self.power_on_timed_out):
            return TIMEOUT, detail
        return UNVERIFIED, detail

    def results(self, configured):
        """[(name, status, detail)] for the trigger steps and every readiness check.
        Each trigger step carries its own recorded monotonic time; differences are computed,
        never assumed to be zero."""
        threshold, decision = self.times["THRESHOLD_MET"], self.times["SCALE_OUT_DECISION"]
        rows = [("THRESHOLD_MET", VERIFIED, f"t={threshold:.3f}s, {threshold - self.t0:+.3f}s vs POWER_ON_SENT"),
                ("SCALE_OUT_DECISION", VERIFIED, f"t={decision:.3f}s, {decision - threshold:+.3f}s after THRESHOLD_MET"),
                ("POWER_ON_SENT", VERIFIED, f"t={self.t0:.3f}s, {self.t0 - threshold:+.3f}s after THRESHOLD_MET, "
                                            f"exit_code={self.power_on_exit_code}")]
        for name in READINESS_MILESTONES:
            rows.append((name,) + self.check_status(name, configured.get(name, False)))
        return rows

    def summary(self, configured):
        return "; ".join(f"{name}={status}({detail})" for name, status, detail in self.results(configured))


# ------------------------------------------------------------------------------
# Recording
# ------------------------------------------------------------------------------

ROW_FIELDS = [
    "timestamp_utc", "monotonic_s", "cycle_duration_s",
    "c1_sample_start_s", "c1_sample_end_s", "c1_ssh_command_ok", "c1_cpu_pct",
    "c2_state_observed_s", "c2_power_state", "power_on_in_progress",
    "c2_sample_start_s", "c2_sample_end_s", "c2_cpu_pct", "guest_reachable", "decision_s",
    "connector_api_status", "connector_api_check_time_raw", "application_reachable",
    "c2_matching_connection", "events",
]
EVENT_FIELDS = ["timestamp_utc", "monotonic_s", "event", "detail"]
ERROR_FIELDS = ["timestamp_utc", "monotonic_s", "source", "message"]


class MemoryRecorder:
    def __init__(self):
        self.rows, self.events, self.errors = [], [], []

    def row(self, rec):
        self.rows.append(rec)

    def event(self, rec):
        self.events.append(rec)

    def error(self, rec):
        self.errors.append(rec)

    def close(self):
        pass


class CsvRecorder:
    """Writes the cycle time series, the event log and the error log to separate CSV files."""
    def __init__(self, output_dir, prefix):
        os.makedirs(output_dir, exist_ok=True)
        self.paths = {k: os.path.join(output_dir, f"{prefix}_{k}.csv") for k in ("timeseries", "events", "errors")}
        self._files, self._writers = {}, {}
        for key, fields in (("timeseries", ROW_FIELDS), ("events", EVENT_FIELDS), ("errors", ERROR_FIELDS)):
            f = open(self.paths[key], mode="w", newline="", encoding="utf-8")
            self._files[key] = f
            self._writers[key] = csv.DictWriter(f, fieldnames=fields)
            self._writers[key].writeheader()

    def _write(self, key, rec):
        self._writers[key].writerow(rec)
        self._files[key].flush()

    def row(self, rec):
        self._write("timeseries", rec)

    def event(self, rec):
        self._write("events", rec)

    def error(self, rec):
        self._write("errors", rec)

    def close(self):
        for f in self._files.values():
            f.close()


def _iso(dt):
    return dt.isoformat(timespec="milliseconds")


def _tri(value):
    return "" if value is None else ("yes" if value else "no")


# ------------------------------------------------------------------------------
# Daemon (I/O orchestration)
# ------------------------------------------------------------------------------

class ScalerDaemon:
    def __init__(self, cfg, controller, esxi, c1_cpu, clock, recorder,
                 c2_cpu=None, connector_api=None, app_probe=None, connection_probe=None):
        self.cfg = cfg
        self.controller = controller
        self.esxi = esxi
        self.c1_cpu = c1_cpu
        self.c2_cpu = c2_cpu
        self.connector_api = connector_api
        self.app_probe = app_probe
        self.connection_probe = connection_probe
        self.clock = clock
        self.recorder = recorder
        self.activation = None
        self._secrets = cfg.secrets()
        self._cycle_events = []  # events since the last time-series row (incl. those between cycles)
        self._last_api_time_note = None

    # --- logging helpers -------------------------------------------------------
    def _redact(self, text):
        for secret in self._secrets:
            text = text.replace(secret, "***")
        return text

    def _event(self, name, detail="", mono=None, wall=None):
        mono = self.clock.monotonic() if mono is None else mono
        wall = self.clock.wall() if wall is None else wall
        detail = self._redact(detail)
        self._cycle_events.append(name)
        self.recorder.event({"timestamp_utc": _iso(wall), "monotonic_s": f"{mono:.3f}",
                             "event": name, "detail": detail})
        log.info("%s %s", name, detail)

    def _error(self, source, message):
        message = self._redact(message)
        self.recorder.error({"timestamp_utc": _iso(self.clock.wall()),
                             "monotonic_s": f"{self.clock.monotonic():.3f}",
                             "source": source, "message": message})
        log.error("[%s] %s", source, message)

    def configured_milestones(self):
        return {
            "VM_POWERED_ON": True,
            "GUEST_REACHABLE": self.c2_cpu is not None,
            "CONNECTOR_API_REPORTED_AVAILABLE": self.connector_api is not None,
            "APPLICATION_REACHABLE": self.app_probe is not None,
            "C2_MATCHING_CONNECTION_OBSERVED": self.connection_probe is not None,
            # No validated C2 application-traffic evidence source exists yet
            "C2_TRAFFIC_OBSERVED": False,
        }

    # --- observations ------------------------------------------------------------
    def _sample_cpu(self, sampler, source):
        start = self.clock.monotonic()
        reading = sampler.observe()
        end, end_wall = self.clock.monotonic(), self.clock.wall()
        if reading.error:
            self._error(source, f"{reading.error} (ssh_command_ok={_tri(reading.ssh_command_ok)})")
        return CpuObservation(reading.value, reading.error, reading.ssh_command_ok, start, end), end_wall

    def _observe_c2_state(self):
        state, err = self.esxi.get_power_state()
        t, wall = self.clock.monotonic(), self.clock.wall()
        if err:
            self._error("esxi_getstate", err)
        return state, err, t, wall

    def _handle_state(self, state, err, t, wall, events, how):
        """Logs the controller's events for one C2 power-state observation at the observation time
        and updates VM_POWERED_ON of the open activation."""
        a = self.activation
        for name, detail in events:
            if name == "POWER_ON_TIMEOUT":
                detail = f"{detail}; last_state={state}"
                if a is not None and not a.closed:
                    a.power_on_timed_out = True
            self._event(name, detail, mono=t, wall=wall)
            if name == "POWER_ON_TIMEOUT":
                self._error("esxi_power_on", f"VM not running within {self.cfg.power_on_timeout_sec}s "
                                             f"(last state: {state}); a later 'Powered on' is logged "
                                             "but not attributed to this power.on")
        if a is None or a.closed:
            return
        if state == RUNNING:
            if "VM_POWERED_ON" not in a.times:
                a.attribution = self.controller.attribution
            self._mark("VM_POWERED_ON", t, f"{how}; attribution={self.controller.attribution}")
        else:
            a.record("VM_POWERED_ON", "error" if err else "negative")

    def _poll_between_cycles(self):
        """One C2 power-state query while a power-on is in progress (no CPU sampling, no probes)."""
        state, err, t, wall = self._observe_c2_state()
        events = self.controller.c2_state_observed(t, state)
        self._handle_state(state, err, t, wall, events, "power-state poll between cycles")
        self._maybe_close_activation()

    # --- power actions ---------------------------------------------------------
    def _poll_power_state(self, target, deadline):
        """Polls until `target` is reported or the deadline passes (used for scale-in only).
        Returns (state, reached)."""
        while True:
            state, err = self.esxi.get_power_state()
            if err:
                self._error("esxi_getstate", err)
            if state == target:
                return state, True
            remaining = deadline - self.clock.monotonic()
            if remaining <= 0:
                return state, False
            self.clock.sleep(min(self.cfg.power_state_poll_sec, remaining))

    def _power_on(self, decision_t):
        """Sends power.on and returns at once; the outcome is followed by the main loop."""
        self._close_activation("superseded by a new power-on")
        t0, wall0 = self.clock.monotonic(), self.clock.wall()
        res = self.esxi.power_on()
        t1 = self.clock.monotonic()
        self.activation = Activation(self.controller.threshold_met_at, decision_t, t0, wall0, res.code)
        self.controller.power_on_sent(t0, res.code)
        self._event("POWER_ON_SENT", f"exit_code={res.code}; "
                                     f"{t0 - self.activation.times['THRESHOLD_MET']:+.3f}s after THRESHOLD_MET; "
                                     f"{t0 - decision_t:+.3f}s after SCALE_OUT_DECISION; "
                                     f"command returned after {t1 - t0:.3f}s", mono=t0, wall=wall0)
        if res.code != 0:
            self._error("esxi_power_on", f"power.on exit code {res.code}: {res.err}")
            self._event("POWER_ON_FAILED", f"exit_code={res.code}; no power-on in progress; C2 is not treated "
                                           "as activated by this controller")

    def _shutdown(self):
        t0 = self.clock.monotonic()
        res = self.esxi.shutdown()
        self.controller.shutdown_sent(t0)
        self._event("SHUTDOWN_SENT", f"exit_code={res.code}", mono=t0)
        if res.code != 0:
            self._error("esxi_shutdown", f"power.shutdown exit code {res.code}: {res.err}")
        self._close_activation("scale-in")

        state, reached = self._poll_power_state(STOPPED, t0 + self.cfg.shutdown_timeout_sec)
        if not reached:
            if not self.cfg.allow_force_power_off:
                self._event("SHUTDOWN_TIMEOUT", f"last_state={state}; forced power-off disabled")
                self._error("esxi_shutdown", f"VM not stopped within {self.cfg.shutdown_timeout_sec}s "
                                             "and forced power-off is disabled (--allow-force-power-off)")
                return state
            t1 = self.clock.monotonic()
            res = self.esxi.power_off()
            self._event("FORCED_POWER_OFF_SENT", f"exit_code={res.code}", mono=t1)
            if res.code != 0:
                self._error("esxi_power_off", f"power.off exit code {res.code}: {res.err}")
            state, reached = self._poll_power_state(STOPPED, t1 + self.cfg.power_on_timeout_sec)
            if not reached:
                self._error("esxi_power_off", f"VM still not stopped (last state: {state})")
                return state
        self._event("VM_POWERED_OFF")
        self.controller.c2_stopped()
        return state

    # --- activation tracking ---------------------------------------------------
    def _mark(self, name, now, detail=""):
        if self.activation is None or self.activation.closed or not self.activation.mark(name, now):
            return
        offset = f"+{now - self.activation.t0:.3f}s after POWER_ON_SENT"
        self._event(name, f"{offset}; {detail}" if detail else offset, mono=now)

    def _close_activation(self, reason):
        """Reports the final status of every check. Closing never marks a check as verified."""
        a = self.activation
        if a is None or a.closed:
            return
        a.closed = True
        a.close_reason = reason
        configured = self.configured_milestones()
        for name, status, detail in a.results(configured)[len(Activation.TRIGGER_STEPS):]:
            self._event("ACTIVATION_CHECK", f"check={name}; status={status}; {detail}")
        self._event("ACTIVATION_SUMMARY", f"reason={reason}; " + a.summary(configured))

    def _maybe_close_activation(self):
        a = self.activation
        if a is None or a.closed:
            return
        configured = self.configured_milestones()
        if all(name in a.times for name in READINESS_MILESTONES if configured[name]):
            self._close_activation(REASON_ALL_VERIFIED)
        elif self.clock.monotonic() - a.t0 >= self.cfg.readiness_timeout_sec:
            self._event("READINESS_TIMEOUT", f"{self.cfg.readiness_timeout_sec}s after POWER_ON_SENT")
            self._close_activation(REASON_READINESS_TIMEOUT)

    def _record_probe(self, name, ok, now, detail, error_source, positive_detail):
        """Maps a probe result (True / False / None = check failed) onto the activation check."""
        if ok is None:
            self._error(error_source, detail)
            self.activation.record(name, "error")
        elif ok:
            self._mark(name, now, positive_detail)
        else:
            self.activation.record(name, "negative")

    def _check_connector_api(self, a, obs):
        name = "CONNECTOR_API_REPORTED_AVAILABLE"
        st = self.connector_api.get_status()
        now = self.clock.monotonic()
        if st.error:
            self._error("connector_api", st.error)
            a.record(name, "error")
            return
        obs["connector_api_status"] = st.status or ""
        obs["connector_api_check_time_raw"] = st.raw_check_time

        ambiguous = st.check_time is None or st.tz_assumed
        if ambiguous and st.raw_check_time != self._last_api_time_note:
            self._last_api_time_note = st.raw_check_time
            if st.check_time is None:
                note = f"raw systemStatusCheckTime={st.raw_check_time!r} is missing or unparseable"
            else:
                note = (f"raw systemStatusCheckTime={st.raw_check_time!r} has no UTC offset; "
                        f"read as {_iso(st.check_time)} only under an unverified UTC assumption")
            self._event("CONNECTOR_API_TIMESTAMP_AMBIGUOUS", f"{note}; not counted as fresh after POWER_ON_SENT")

        if st.status not in self.cfg.connector_ready_statuses:
            a.record(name, "negative")
        elif ambiguous:
            a.record(name, "ambiguous")
        elif st.check_time >= a.power_on_sent_wall - timedelta(seconds=self.cfg.api_status_skew_sec):
            self._mark(name, now, f"status={st.status}; systemStatusCheckTime={st.raw_check_time}; "
                                  "control-plane report only")
        else:
            a.record(name, "negative")  # stale: last status check predates POWER_ON_SENT

    def _track_activation(self, c2_state, c2_obs, obs):
        """Guest, API and probe checks of the open activation (VM_POWERED_ON is handled per
        power-state observation in _handle_state)."""
        a = self.activation
        if a is None or a.closed:
            return
        if c2_obs is not None and c2_obs.ssh_command_ok is not None:
            if c2_obs.ssh_command_ok:
                cpu = "valid CPU value" if c2_obs.value is not None else "no valid CPU value (separate observation)"
                self._mark("GUEST_REACHABLE", c2_obs.end, f"authenticated SSH command on SR-CONN02 exited with 0; {cpu}")
            else:
                a.record("GUEST_REACHABLE", "negative")

        if self.connector_api is not None:
            self._check_connector_api(a, obs)

        if self.app_probe is not None:
            ok, detail = self.app_probe.check()
            obs["application_reachable"] = _tri(ok)
            self._record_probe("APPLICATION_REACHABLE", ok, self.clock.monotonic(), detail, "application_probe",
                               f"{detail}; not attributed to a connector")

        if self.connection_probe is not None and c2_state == RUNNING:
            ok, detail = self.connection_probe.check()
            obs["c2_matching_connection"] = _tri(ok)
            self._record_probe("C2_MATCHING_CONNECTION_OBSERVED", ok, self.clock.monotonic(), detail,
                               "c2_connection_probe",
                               f"{detail}; not validated as application traffic through SR-CONN02")

        self._maybe_close_activation()

    # --- main loop ---------------------------------------------------------------
    def run_cycle(self):
        start, wall = self.clock.monotonic(), self.clock.wall()

        c1, c1_end_wall = self._sample_cpu(self.c1_cpu, "c1_cpu")
        c2_state, state_err, state_t, state_wall = self._observe_c2_state()
        c2 = None
        if c2_state == RUNNING and self.c2_cpu is not None:
            c2, _ = self._sample_cpu(self.c2_cpu, "c2_cpu")

        # Decision time: all inputs of this cycle are available now
        decision_t, decision_wall = self.clock.monotonic(), self.clock.wall()
        decision = self.controller.observe(decision_t, c1.value, None if c2 is None else c2.value, c2_state,
                                           sample_t=c1.end, c2_state_t=state_t)
        state_events = [e for e in decision.events if e[0] in ScalerController.STATE_EVENTS]
        self._handle_state(c2_state, state_err, state_t, state_wall, state_events, "regular power-state poll")
        for name, detail in decision.events:
            if name in ScalerController.STATE_EVENTS:
                continue
            if name == "THRESHOLD_MET":
                self._event(name, f"{detail}; c1_sample_t={c1.end:.3f}s; decision_t={decision_t:.3f}s",
                            mono=c1.end, wall=c1_end_wall)
            else:
                self._event(name, detail, mono=decision_t, wall=decision_wall)
        if decision.action == POWER_ON:
            self._event("SCALE_OUT_DECISION", f"decision_t={decision_t:.3f}s; "
                                              f"{decision_t - self.controller.threshold_met_at:+.3f}s after THRESHOLD_MET",
                        mono=decision_t, wall=decision_wall)
            self._power_on(decision_t)
        elif decision.action == SHUTDOWN:
            self._shutdown()

        obs = {"connector_api_status": "", "connector_api_check_time_raw": "",
               "application_reachable": "", "c2_matching_connection": ""}
        self._track_activation(c2_state, c2, obs)

        def t(value):
            return "" if value is None else f"{value:.3f}"

        row = {
            "timestamp_utc": _iso(wall),
            "monotonic_s": f"{start:.3f}",
            "cycle_duration_s": f"{self.clock.monotonic() - start:.3f}",
            "c1_sample_start_s": t(c1.start),
            "c1_sample_end_s": t(c1.end),
            "c1_ssh_command_ok": _tri(c1.ssh_command_ok),
            "c1_cpu_pct": "" if c1.value is None else c1.value,
            "c2_state_observed_s": t(state_t),
            "c2_power_state": c2_state,
            "power_on_in_progress": _tri(self.controller.power_on_pending),
            "c2_sample_start_s": "" if c2 is None else t(c2.start),
            "c2_sample_end_s": "" if c2 is None else t(c2.end),
            "c2_cpu_pct": "" if c2 is None or c2.value is None else c2.value,
            "guest_reachable": "" if c2 is None else _tri(c2.ssh_command_ok),
            "decision_s": t(decision_t),
            "events": ";".join(self._cycle_events),
        }
        row.update(obs)
        self._cycle_events = []
        self.recorder.row(row)
        c1_str = "ERR" if c1.value is None else f"{c1.value:.1f}%"
        log.info("C1 CPU: %s | C2: %s | Events: %s", c1_str, c2_state, row["events"] or "-")
        return row

    def _wait_for_next_cycle(self, next_start):
        """Sleeps until the next cycle. While a power-on is in progress, only the C2 power state is
        queried every power_state_poll_sec; each query is one bounded command, so the cycle
        schedule (CPU sampling and probes) is kept."""
        poll = self.cfg.power_state_poll_sec
        while self.controller.power_on_pending and self.clock.monotonic() + poll < next_start:
            self.clock.sleep(poll)
            self._poll_between_cycles()
        self.clock.sleep(max(0.1, next_start - self.clock.monotonic()))

    def run(self, max_cycles=0):
        cycles = 0
        try:
            while not max_cycles or cycles < max_cycles:
                start = self.clock.monotonic()
                self.run_cycle()
                cycles += 1
                self._wait_for_next_cycle(start + self.cfg.poll_sec)
        except KeyboardInterrupt:
            log.info("Autoscaler daemon stopped by user.")
        finally:
            self._close_activation("daemon stopped")
            self.recorder.close()


# ------------------------------------------------------------------------------
# Wiring and CLI
# ------------------------------------------------------------------------------

def build_daemon(cfg, clock=None, recorder=None):
    """Builds the daemon from a validated config. Dry-run uses only simulated components."""
    if cfg.dry_run:
        clock = clock or SimClock()
        esxi = SimulatedESXi(clock, initial_state=cfg.sim_initial_c2_state, boot_delay_sec=cfg.sim_boot_delay_sec)
        return ScalerDaemon(cfg, ScalerController(cfg), esxi, SimCpuSampler(cfg.sim_c1_cpu), clock, recorder,
                            c2_cpu=SimCpuSampler(cfg.sim_c2_cpu))

    clock = clock or RealClock()
    if cfg.ssh_known_hosts:
        load_known_hosts(cfg.ssh_known_hosts)  # raises KnownHostsError; read only, opens no connection
    ssh = dict(known_hosts=cfg.ssh_known_hosts, insecure_host_keys=cfg.lab_insecure_ssh)
    esxi = ESXiHost(SSHExecutor(cfg.esxi_host, cfg.esxi_user, cfg.esxi_password, **ssh), cfg.c2_vmid)
    c1 = GuestCpuSampler(SSHExecutor(cfg.c1_ip, cfg.c1_user, cfg.c1_password, **ssh), cfg.cpu_sample_sec)
    c2_exec = SSHExecutor(cfg.c2_ip, cfg.c2_user, cfg.c2_password, **ssh) if cfg.c2_ip else None
    c2 = GuestCpuSampler(c2_exec, cfg.cpu_sample_sec) if c2_exec else None

    api = None
    if cfg.atmos_api_key and cfg.c2_connector_id:
        api = ConnectorStatusClient(cfg.atmos_base_url, cfg.atmos_api_key, cfg.c2_connector_id, cfg.http_timeout_sec)
    app = None
    if cfg.target_url:
        verify = False if cfg.lab_insecure_tls else (cfg.http_ca_bundle or True)
        app = ApplicationProbe(cfg.target_url, cfg.app_expected_status, cfg.http_timeout_sec, verify)
    connection = None
    if cfg.c2_connection_check == CONNECTION_CHECK_SS:
        connection = EstablishedConnectionProbe(c2_exec, cfg.backend_host, cfg.backend_port)

    return ScalerDaemon(cfg, ScalerController(cfg), esxi, c1, clock, recorder,
                        c2_cpu=c2, connector_api=api, app_probe=app, connection_probe=connection)


def _env(env, key, default=""):
    """Empty values (e.g. `KEY=` in .env) fall back to the default."""
    value = env.get(key)
    return default if value is None or not value.strip() else value.strip()


def _env_bool(env, key, default=False):
    value = _env(env, key)
    return default if not value else value.lower() in ("1", "true", "yes", "on")


def resolve_cooldown(env):
    """Returns (value, warning). SCALER_COOLDOWN_SEC takes precedence over the deprecated
    SCALE_IN_COOLDOWN_SEC, which is still honoured on its own for backward compatibility."""
    new = _env(env, "SCALER_COOLDOWN_SEC")
    old = _env(env, "SCALE_IN_COOLDOWN_SEC")
    if new and old:
        return new, (f"SCALE_IN_COOLDOWN_SEC={old} is deprecated and ignored; "
                     f"SCALER_COOLDOWN_SEC={new} takes precedence")
    if old:
        return old, f"SCALE_IN_COOLDOWN_SEC is deprecated; its value {old} is used - rename it to SCALER_COOLDOWN_SEC"
    return new or "60.0", None


def parse_args(argv, env):
    """Non-secret options only; defaults come from `env`. Secrets are read in build_config()."""
    def g(key, default=""):
        return _env(env, key, default)

    p = argparse.ArgumentParser(description="CPU-threshold activation of the secondary HPE SSE Connector VM")
    p.add_argument("--c1-ip", default=g("CONNECTOR_1_IP", ""), help="SR-CONN01 guest IP")
    p.add_argument("--c1-user", default=g("CONNECTOR_SSH_USER", ""), help="SR-CONN01 SSH user")
    p.add_argument("--c2-ip", default=g("CONNECTOR_2_IP", ""), help="SR-CONN02 guest IP")
    p.add_argument("--c2-user", default=g("CONNECTOR_2_SSH_USER", g("CONNECTOR_SSH_USER", "")))
    p.add_argument("--esxi-host", default=g("ESXI_HOST", ""), help="ESXi host of SR-CONN02")
    p.add_argument("--esxi-user", default=g("ESXI_USER", "root"))
    p.add_argument("--c2-vmid", type=int, default=g("CONNECTOR_2_VMID", "0"))

    p.add_argument("--scale-out-pct", type=float, default=g("CPU_SCALE_OUT_THRESHOLD", "80.0"))
    p.add_argument("--scale-in-pct", type=float, default=g("CPU_SCALE_IN_THRESHOLD", "30.0"))
    p.add_argument("--window-sec", type=float, default=g("TRIGGER_WINDOW_SEC", "15.0"))
    p.add_argument("--poll-sec", type=float, default=g("POLL_INTERVAL_SEC", "5.0"))
    p.add_argument("--cpu-sample-sec", type=float, default=g("CPU_SAMPLE_SEC", "1.0"))
    p.add_argument("--enable-scale-in", action="store_true", default=_env_bool(env, "ENABLE_SCALE_IN"),
                   help="Allow ACPI shutdown of SR-CONN02 (default: disabled)")
    p.add_argument("--cooldown-sec", type=float, default=resolve_cooldown(env)[0],
                   help="Minimum time between power commands, from the last dispatched command "
                        "(env: SCALER_COOLDOWN_SEC; deprecated alias: SCALE_IN_COOLDOWN_SEC)")
    p.add_argument("--min-c2-uptime-sec", type=float, default=g("MIN_C2_UPTIME_SEC", "300.0"),
                   help="Minimum C2 uptime before scale-in, from the first observed 'Powered on'")
    p.add_argument("--allow-scale-in-manual-c2", action="store_true",
                   help="Also stop a C2 that this controller did not power on")
    p.add_argument("--allow-force-power-off", action="store_true",
                   help="Hard power-off if the ACPI shutdown times out")
    p.add_argument("--power-on-timeout-sec", type=float, default=g("POWER_ON_TIMEOUT_SEC", "60.0"))
    p.add_argument("--power-state-poll-sec", type=float, default=g("POWER_STATE_POLL_SEC", "1.0"))
    p.add_argument("--shutdown-timeout-sec", type=float, default=g("SHUTDOWN_TIMEOUT_SEC", "120.0"))
    p.add_argument("--readiness-timeout-sec", type=float, default=g("READINESS_TIMEOUT_SEC", "600.0"))

    p.add_argument("--target-url", default=g("TARGET_APP_URL", ""))
    p.add_argument("--app-expected-status", type=int, default=g("APP_EXPECTED_STATUS", "200"))
    p.add_argument("--http-timeout-sec", type=float, default=g("HTTP_TIMEOUT_SEC", "5.0"))
    p.add_argument("--http-ca-bundle", default=g("HTTP_CA_BUNDLE", ""), help="CA bundle for the target app")
    p.add_argument("--atmos-base-url", default=g("ATMOS_BASE_URL", "https://admin-api.axissecurity.com/api/v1.0"))
    p.add_argument("--c2-connector-id", default=g("ATMOS_CONNECTOR_2_ID", ""), help="SR-CONN02 connector GUID")
    p.add_argument("--connector-ready-statuses", default=g("CONNECTOR_READY_STATUSES", "Available"))
    p.add_argument("--api-status-skew-sec", type=float, default=g("API_STATUS_SKEW_SEC", "0"))
    p.add_argument("--c2-connection-check", choices=[CONNECTION_CHECK_NONE, CONNECTION_CHECK_SS],
                   default=g("C2_CONNECTION_CHECK", CONNECTION_CHECK_NONE))
    p.add_argument("--backend-host", default=g("BACKEND_HOST", ""))
    p.add_argument("--backend-port", type=int, default=g("BACKEND_PORT", "443"))

    p.add_argument("--ssh-known-hosts", default=g("SSH_KNOWN_HOSTS", ""), help="Extra known_hosts file")
    p.add_argument("--lab-insecure-ssh", action="store_true", help="LAB ONLY: accept unknown SSH host keys")
    p.add_argument("--lab-insecure-tls", action="store_true", help="LAB ONLY: skip TLS verification of the target app")

    p.add_argument("--dry-run", action="store_true", help="Simulated ESXi/CPU and clock; no SSH or HTTP")
    p.add_argument("--sim-c1-cpu", default="20,85,90,90,90,90,90,25", help="Dry-run C1 CPU profile")
    p.add_argument("--sim-c2-cpu", default="10", help="Dry-run C2 CPU profile")
    p.add_argument("--sim-boot-delay-sec", type=float, default=8.0)
    p.add_argument("--sim-initial-c2-state", choices=[STOPPED, RUNNING, UNKNOWN], default=STOPPED)
    p.add_argument("--max-cycles", type=int, default=0, help="Stop after N cycles (dry-run default: 40)")
    p.add_argument("--output-dir", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "results"))
    return p.parse_args(argv)


def build_config(args, env):
    c1_password = _env(env, "CONNECTOR_SSH_PASSWORD")
    return ScalerConfig(
        c1_ip=args.c1_ip, c1_user=args.c1_user, c1_password=c1_password,
        c2_ip=args.c2_ip, c2_user=args.c2_user, c2_password=_env(env, "CONNECTOR_2_SSH_PASSWORD", c1_password),
        esxi_host=args.esxi_host, esxi_user=args.esxi_user, esxi_password=_env(env, "ESXI_PASSWORD"),
        c2_vmid=args.c2_vmid,
        scale_out_pct=args.scale_out_pct, scale_in_pct=args.scale_in_pct, window_sec=args.window_sec,
        poll_sec=args.poll_sec, cpu_sample_sec=args.cpu_sample_sec, enable_scale_in=args.enable_scale_in,
        cooldown_sec=args.cooldown_sec, min_c2_uptime_sec=args.min_c2_uptime_sec,
        allow_scale_in_manual_c2=args.allow_scale_in_manual_c2, allow_force_power_off=args.allow_force_power_off,
        power_on_timeout_sec=args.power_on_timeout_sec, power_state_poll_sec=args.power_state_poll_sec,
        shutdown_timeout_sec=args.shutdown_timeout_sec, readiness_timeout_sec=args.readiness_timeout_sec,
        target_url=args.target_url, app_expected_status=args.app_expected_status,
        http_timeout_sec=args.http_timeout_sec, http_ca_bundle=args.http_ca_bundle,
        atmos_base_url=args.atmos_base_url, atmos_api_key=_env(env, "ATMOS_API_KEY"),
        c2_connector_id=args.c2_connector_id,
        connector_ready_statuses=tuple(s.strip() for s in args.connector_ready_statuses.split(",") if s.strip()),
        api_status_skew_sec=args.api_status_skew_sec,
        c2_connection_check=args.c2_connection_check, backend_host=args.backend_host, backend_port=args.backend_port,
        ssh_known_hosts=args.ssh_known_hosts, lab_insecure_ssh=args.lab_insecure_ssh,
        lab_insecure_tls=args.lab_insecure_tls,
        dry_run=args.dry_run, sim_c1_cpu=parse_cpu_profile(args.sim_c1_cpu),
        sim_c2_cpu=parse_cpu_profile(args.sim_c2_cpu), sim_boot_delay_sec=args.sim_boot_delay_sec,
        sim_initial_c2_state=args.sim_initial_c2_state,
        max_cycles=args.max_cycles or (40 if args.dry_run else 0),
        output_dir=args.output_dir,
    )


def _runtime_environ(argv):
    """Configuration source for a command-line start. --help and --dry-run never read .env or the
    process environment: they run on an empty, synthetic configuration, so a broken or incomplete
    live configuration cannot block them. Only the live modes load .env (python-dotenv)."""
    if any(a in ("-h", "--help", "--dry-run") for a in argv):
        return {}
    from dotenv import load_dotenv
    load_dotenv()
    return os.environ


def main(argv=None, environ=None):
    """Returns 0 after a run, 2 on a configuration error (nothing is started then)."""
    if environ is None:
        environ = _runtime_environ(sys.argv[1:] if argv is None else argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    try:
        cfg = build_config(parse_args(argv, environ), environ)
        validate_config(cfg)
        if not cfg.dry_run and cfg.ssh_known_hosts:
            load_known_hosts(cfg.ssh_known_hosts)
    except KnownHostsError as exc:
        log.error("configuration error (SSH_KNOWN_HOSTS): %s; host key verification stays enabled, "
                  "nothing was started", exc)
        return 2
    except ValueError as exc:
        log.error("configuration error: %s; nothing was started", exc)
        return 2
    if cfg.lab_insecure_ssh:
        log.warning("LAB MODE: SSH host key verification is DISABLED (--lab-insecure-ssh)")
    if cfg.lab_insecure_tls:
        log.warning("LAB MODE: TLS certificate verification of the target app is DISABLED (--lab-insecure-tls)")

    prefix = ("scaler_dryrun" if cfg.dry_run else "scaler") + "_" + datetime.now().strftime("%Y%m%d_%H%M%S")
    recorder = CsvRecorder(cfg.output_dir, prefix)
    daemon = build_daemon(cfg, recorder=recorder)
    if cfg.lab_insecure_ssh:
        daemon._event("LAB_INSECURE_SSH", "SSH host key verification disabled")
    if cfg.lab_insecure_tls:
        daemon._event("LAB_INSECURE_TLS", "TLS verification of the target app disabled")
    cooldown_warning = resolve_cooldown(environ)[1]
    if cooldown_warning:
        log.warning(cooldown_warning)
        daemon._event("CONFIG_DEPRECATED_VARIABLE", cooldown_warning)

    print(f"[*] Mode          : {'DRY-RUN (simulated, no SSH/HTTP)' if cfg.dry_run else 'LIVE'}")
    print(f"[*] Primary Node  : SR-CONN01 ({cfg.c1_ip or '-'})")
    print(f"[*] Standby Node  : SR-CONN02 (VMID {cfg.c2_vmid} on {cfg.esxi_host or '-'})")
    print(f"[*] Scale-in      : {'enabled' if cfg.enable_scale_in else 'disabled'}")
    print(f"[*] Milestones    : {', '.join(n for n, on in daemon.configured_milestones().items() if on)}")
    print(f"[*] Logging to    : {', '.join(recorder.paths.values())}\n")
    daemon.run(max_cycles=cfg.max_cycles)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
