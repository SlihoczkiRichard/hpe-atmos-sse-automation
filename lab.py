#!/usr/bin/env python3
"""
lab.py - optional menu and one-command runners for the four experiments.

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

A convenience layer, nothing more. Every step calls the existing, tested scripts with explicit
arguments, in the order docs/measurement-guide.md gives for the manual procedure; the manual
procedure stays valid and produces the same files. Nothing here changes how a measurement is made,
validated or evaluated, and no result is overwritten (every tool keeps its own no-overwrite rule).

  python3 lab.py                     interactive menu
  python3 lab.py check               tools, .env keys, SSH key login to the connector (read only)
  python3 lab.py settings            view / change the non-secret .env parameters
  python3 lab.py preflight           00-preflight/preflight_check.py --run (read only)
  python3 lab.py e1 [--run-id ID] [--yes] [--dry-run]
  python3 lab.py e2 [--run-id ID] [--yes]
  python3 lab.py e3 [--run-id ID] [--duration-sec 720] [--yes]
  python3 lab.py e4 {plan,validate-signature,canary,restore} [--run-id ID]
  python3 lab.py process --run-id ID [--run-id ID ...] [--processing-id P] [--yes]
  python3 lab.py figures --spec FILE [--diagnostic]

Where it runs: the load-generator / control host (Linux with bash, OpenSSH client, sysstat, hey;
tmux recommended so a dropped SSH/VPN session does not stop a run). The connector VM is reached with
the system ssh/scp client: key login only (BatchMode), host key checked against known_hosts
(StrictHostKeyChecking=yes, SSH_KNOWN_HOSTS is used when set). No password is asked for or stored.

Configuration: the same .env as the scripts (they read it themselves), plus optional LAB_* keys
(see .env.example). Every run writes lab_run.json next to its results: git commit, parameters,
exact command lines, telemetry script hash, time-sync readings and timings.
"""

import argparse
import csv
import getpass
import glob
import hashlib
import io
import json
import math
import os
import re
import select
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import threading
import time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.abspath(__file__))
RUN_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
REMOTE_DIR_RE = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")

LOAD_DIR = os.path.join(ROOT, "01-load-test")
LOAD_RESULTS = os.path.join(LOAD_DIR, "results")
TELEMETRY_SCRIPT = os.path.join(LOAD_DIR, "collect_connector_telemetry.sh")
HEY_SCRIPT = os.path.join(LOAD_DIR, "run_hey_stepped.py")
SCALER_SCRIPT = os.path.join(ROOT, "02-scaler-poc", "scaler_daemon.py")
FAILOVER_SCRIPT = os.path.join(ROOT, "03-failover", "failover_probe.py")
FAILOVER_RESULTS = os.path.join(ROOT, "03-failover", "results")
THREAT_DIR = os.path.join(ROOT, "04-threat-intel")
THREAT_RESULTS = os.path.join(THREAT_DIR, "results")
PREFLIGHT_SCRIPT = os.path.join(ROOT, "00-preflight", "preflight_check.py")
PROCESS_SCRIPT = os.path.join(ROOT, "05-results", "process_results.py")
PROCESSED = os.path.join(ROOT, "05-results", "processed")
SPECS = os.path.join(ROOT, "05-results", "specs")
RESULT_DIRS = (LOAD_RESULTS, FAILOVER_RESULTS, THREAT_RESULTS)
PROBES = ("persistent", "http", "tcp")

# hey defaults: identical to run_hey_stepped.py (used only when .env leaves a key empty)
HEY_DEFAULTS = {"LOAD_CONCURRENCY_STEPS": "10,25,50,100,150,200,300,400,500,600,700,800,1000",
                "LOAD_SWEEPS": "3", "LOAD_STEP_DURATION": "30s", "LOAD_COOLDOWN_SEC": "5",
                "LOAD_RATE_LIMIT_QPS": "0"}
TIME_SYNC_UNCERTAINTY = ("inter-host clock difference not measured directly; both hosts NTP-synchronised "
                         "with the offsets listed in source; conservative bound about 30 ms, small against "
                         "the 1 s sar interval and the hey run length")


class LabError(Exception):
    """A precondition failed; nothing more is started."""


# ------------------------------------------------------------------------------
# Pure helpers (tested offline)
# ------------------------------------------------------------------------------

def utc_now():
    return datetime.now(timezone.utc)


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def env_value(env, key, default=""):
    value = env.get(key)
    return default if value is None or not str(value).strip() else str(value).strip()


def target_http_status(url, timeout=15):
    """One GET with TLS verification (redirects followed, as hey does); the HTTP status or the error text."""
    import urllib.error
    import urllib.request
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "lab.py-check"}),
                                    timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return f"no response ({type(exc).__name__}: {getattr(exc, 'reason', exc)})"


def check_run_id(run_id):
    if not RUN_ID_RE.match(run_id or ""):
        raise LabError(f"invalid RUN_ID {run_id!r}: letters, digits, '.', '_' and '-' only")
    return run_id


def parse_duration(text):
    m = re.match(r"^(\d+(?:\.\d+)?)(ms|s|m|h)$", str(text).strip())
    if not m:
        raise LabError(f"unsupported duration {text!r} (use e.g. 30s or 1m)")
    return float(m.group(1)) * {"ms": 0.001, "s": 1, "m": 60, "h": 3600}[m.group(2)]


def parse_steps(text):
    try:
        steps = [int(s) for s in str(text).split(",") if s.strip()]
    except ValueError:
        raise LabError(f"concurrency steps must be integers: {text!r}") from None
    if not steps or steps != sorted(set(steps)) or steps[0] <= 0:
        raise LabError(f"concurrency steps must be distinct positive integers in ascending order: {text!r}")
    return steps


def hey_plan(env, prefix="LOAD"):
    """The hey parameters of a run, from .env with run_hey_stepped.py's own defaults."""
    g = lambda key: env_value(env, f"{prefix}_{key}", HEY_DEFAULTS.get(f"LOAD_{key}", ""))  # noqa: E731
    plan = {"steps": g("CONCURRENCY_STEPS"), "sweeps": g("SWEEPS"), "duration": g("STEP_DURATION"),
            "cooldown": g("COOLDOWN_SEC"), "qps": g("RATE_LIMIT_QPS")}
    if not plan["steps"]:
        raise LabError(f"{prefix}_CONCURRENCY_STEPS is empty in .env")
    plan["levels"] = parse_steps(plan["steps"])
    plan["duration_sec"] = parse_duration(plan["duration"])
    try:
        plan["sweeps_n"] = int(plan["sweeps"])
        plan["cooldown_sec"] = float(plan["cooldown"])
        int(plan["qps"])
    except ValueError:
        raise LabError("LOAD_SWEEPS / LOAD_COOLDOWN_SEC / LOAD_RATE_LIMIT_QPS must be numbers") from None
    plan["estimate_sec"] = len(plan["levels"]) * plan["sweeps_n"] * (plan["duration_sec"] + plan["cooldown_sec"])
    return plan


def telemetry_seconds(estimate_sec, lead_sec, tail_sec=180, round_to=300):
    """Telemetry length that covers the lead time, the load run (+10 % for hey's own overhead) and a
    tail, rounded up to whole 5 minutes. E1 (6 levels x 3 sweeps x (60 s + 5 s), 60 s lead) -> 1800."""
    raw = lead_sec + estimate_sec * 1.1 + tail_sec
    return int(math.ceil(raw / round_to) * round_to)


def hey_command(python, run_id, plan, dry_run=False):
    cmd = [python, HEY_SCRIPT, "--run-id", run_id, "--steps", plan["steps"], "--sweeps", str(plan["sweeps"]),
           "--duration", plan["duration"], "--cooldown", str(plan["cooldown"]), "--qps", str(plan["qps"])]
    return cmd + (["--dry-run"] if dry_run else [])


def suggest_run_id(experiment, existing, today):
    """Next free <EXP>-<YYYYMMDD>-NN (for E3: <EXP>-<YYYYMMDD>-01-rNN) not in `existing`."""
    base = f"{experiment}-{today.strftime('%Y%m%d')}"
    for n in range(1, 100):
        rid = f"{base}-01-r{n:02d}" if experiment.endswith("E3") else f"{base}-{n:02d}"
        if rid not in existing and not any(e.startswith(rid + ".") for e in existing):
            return rid
    raise LabError("no free RUN_ID for today")


def existing_run_ids():
    ids = set()
    for d in RESULT_DIRS:
        if os.path.isdir(d):
            ids.update(os.listdir(d))
    if os.path.isdir(PROCESSED):
        ids.update(n.split("-P")[0] for n in os.listdir(PROCESSED))
    return ids


def remote_telemetry_start(remote_dir, run_id, role, seconds, tolerance):
    """Shell command (run on the connector) that starts collect_connector_telemetry.sh detached from
    the SSH session (setsid nohup) and prints its PID. RUN_START_EPOCH is taken on the connector."""
    q = shlex.quote
    out = f"{remote_dir}/{run_id}"
    return (f"set -e; test ! -e {q(out)} || {{ echo 'remote directory already exists: {out}' >&2; exit 2; }}; "
            f"RUN_ID={q(run_id)} ROLE={q(role)} RUN_START_EPOCH=$(date -u +%s) "
            f"COVERAGE_TOLERANCE_SEC={int(tolerance)} setsid nohup bash {q(remote_dir + '/collect_connector_telemetry.sh')} "
            f"{int(seconds)} 1 {q(out)} > {q(out + '.collector.log')} 2>&1 < /dev/null & echo $!")


def remote_sadf_export(remote_dir, run_id, role):
    """Shell command (run on the connector) that writes the CPU and memory sadf exports next to the
    binary sar file, records the sysstat version and prints the file names and the coverage."""
    q = shlex.quote
    out = f"{remote_dir}/{run_id}"
    return (f"set -e; cd {q(out)}; f=$(ls telemetry_{run_id}_{role}_*.sa); b=${{f%.sa}}; "
            f"sadf -d \"$f\" -- -u ALL > \"${{b}}_cpu_sadf.csv\"; sadf -d \"$f\" -- -r > \"${{b}}_mem_sadf.csv\"; "
            f"sadf -V > \"${{b}}_sadf_version.txt\" 2>&1 || true; ls -1 telemetry_{run_id}_*; "
            f"grep -ho '\"coverage\": *\"[^\"]*\"' *_meta.json")


TIMESYNC_COMMAND = "hostname; timedatectl show -p NTPSynchronized; timedatectl timesync-status 2>/dev/null || true"


def parse_timesync(text):
    lines = text.strip().splitlines()
    host = lines[0].strip() if lines else ""
    synced = re.search(r"NTPSynchronized=(\w+)", text)
    server = re.search(r"^\s*Server:\s*(.+?)\s*$", text, re.M)
    offset = re.search(r"^\s*Offset:\s*(\S+)", text, re.M)
    return {"host": host, "ntp_synchronized": synced.group(1) if synced else "unknown",
            "server": server.group(1) if server else "unknown", "offset": offset.group(1) if offset else "unknown"}


def time_sync_statement(readings, when):
    """spec.time_sync from timedatectl readings of every host; None if a host is not synchronised."""
    if not readings or any(r["ntp_synchronized"] != "yes" for r in readings):
        return None
    hosts = " and ".join(r["host"] for r in readings)
    return {"statement": f"{hosts} NTP-synchronised (timedatectl NTPSynchronized=yes) at the end of the run",
            "source": f"timedatectl right after the run ({iso(when)}): " +
                      "; ".join(f"{r['host']}: server {r['server']}, offset {r['offset']}" for r in readings),
            "known_uncertainty": TIME_SYNC_UNCERTAINTY}


def resolve_provenance(datasets, provenance=None):
    """The one provenance of a processing run. Explicit value: used for every dataset. Otherwise the
    tool metadata the scan found ('real' / 'simulated'); datasets without metadata ('unknown', e.g. sadf
    exports) take it only if all datasets with metadata agree. Mixed or no metadata -> LabError."""
    if provenance:
        if provenance not in ("real", "simulated"):
            raise LabError(f"provenance must be real or simulated, not {provenance!r}")
        return provenance
    claimed = {ds.get("provenance") for ds in datasets} - {"unknown", None, ""}
    if len(claimed) != 1:
        raise LabError(f"cannot derive one provenance from the tool metadata ({sorted(claimed) or 'none'}); "
                       "process these runs separately or give --provenance after checking them")
    return claimed.pop()


def build_reviewed_spec(draft, processing_id, provenance, time_sync, run_ids=()):
    """Reviewed spec from a scan draft: provenance, time_sync and the groups the run supports.
    m1_resources: exactly one hey, sar_cpu and sar_mem dataset and a time_sync statement.
    m2: one scaler dataset (its run_id is set to the run's RUN_ID: the scaler writes none)."""
    spec = json.loads(json.dumps(draft))
    provenance = resolve_provenance(spec["datasets"], provenance)
    by_kind = {}
    for ds in spec["datasets"]:
        by_kind.setdefault(ds["kind"], []).append(ds["id"])
        ds["provenance"] = provenance
        if ds["kind"] == "scaler" and not ds.get("run_id") and len(run_ids) == 1:
            ds["run_id"] = run_ids[0]
    spec.update(processing_id=processing_id, reviewed_by_operator=True, time_sync=time_sync)
    groups = {"m2": [], "m1_resources": []}
    one = lambda k: len(by_kind.get(k, [])) == 1  # noqa: E731
    if one("scaler"):
        if time_sync:
            groups["m2"].append({"scaler": by_kind["scaler"][0], "app": by_kind.get("hey", []),
                                 "sar": by_kind.get("sar_cpu", [])})
    elif one("hey") and one("sar_cpu") and time_sync:
        groups["m1_resources"].append({"hey": by_kind["hey"][0], "sar_cpu": by_kind["sar_cpu"][0],
                                       **({"sar_mem": by_kind["sar_mem"][0]} if one("sar_mem") else {}),
                                       "warmup_sec": 0, "min_coverage": 0.9})
    spec["groups"] = groups
    spec.setdefault("notes", []).append("reviewed with lab.py: the operator confirmed the dataset list, "
                                        f"provenance {provenance!r} and the groups before processing")
    return spec, by_kind


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


class ProbeTail:
    """Reads the new lines of a growing probes_<type>.csv (failover_probe.py output)."""

    def __init__(self, path):
        self.path, self.offset, self.header, self.buf = path, 0, None, ""
        self.ok = self.failed = 0
        self.last_ok = None

    def poll(self):
        if not os.path.exists(self.path):
            return
        with open(self.path, encoding="utf-8", newline="") as f:
            f.seek(self.offset)
            data = f.read()
            self.offset = f.tell()
        self.buf += data
        *lines, self.buf = self.buf.split("\n")
        for line in lines:
            if not line.strip():
                continue
            row = next(csv.reader([line]))
            if self.header is None:
                self.header = row
                continue
            rec = dict(zip(self.header, row))
            if rec.get("event") in ("probe", "exchange"):
                ok = rec.get("ok") == "True"
                self.ok += ok
                self.failed += not ok
                self.last_ok = ok

    def status(self):
        if self.header is None:
            return "starting"
        last = {None: "-", True: "ok", False: "FAIL"}[self.last_ok]
        return f"{last} (ok {self.ok}, failed {self.failed})"


class ManualActionWatcher:
    """Follows the scaler console log in a background thread and repeats every MANUAL ACTION
    line (with a terminal bell) on the lab console, so the operator sees it during the load."""

    def __init__(self, path, out, poll_sec=0.5):
        self.path = path
        self.out = out
        self.poll_sec = poll_sec
        self.alerts = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._pos = 0

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=5)
        self.scan()  # a request logged just before the stop is still counted

    def scan(self):
        try:
            with open(self.path, "rb") as f:
                f.seek(self._pos)
                chunk = f.read()
        except OSError:
            return
        complete = chunk[:chunk.rfind(b"\n") + 1]
        self._pos += len(complete)
        for line in complete.decode("utf-8", errors="replace").splitlines():
            if "MANUAL ACTION" in line:
                self.alerts += 1
                self.out("\a\n" + "!" * 72 + f"\n{line.strip()}\n" + "!" * 72)

    def _run(self):
        while not self._stop.wait(self.poll_sec):
            self.scan()


# ------------------------------------------------------------------------------
# Settings (.env editing for the non-secret keys)
# ------------------------------------------------------------------------------

SECRET_RE = re.compile(r"PASSWORD|API_KEY|TOKEN|SECRET", re.I)
SETTINGS_GROUPS = [
    ("E1 load (hey)", ["TARGET_APP_URL", "LOAD_CONCURRENCY_STEPS", "LOAD_SWEEPS", "LOAD_STEP_DURATION",
                       "LOAD_COOLDOWN_SEC", "LOAD_RATE_LIMIT_QPS", "ACCEPT_MAX_ERROR_RATE"]),
    ("Menu (lab.py)", ["LAB_LEAD_SEC", "LAB_TELEMETRY_SEC", "LAB_REMOTE_DIR", "LAB_COPY_DEST",
                       "CONNECTOR_1_IP", "CONNECTOR_SSH_USER"]),
    ("E2 scaling", ["E2_CONCURRENCY_STEPS", "E2_SWEEPS", "E2_STEP_DURATION", "E2_COOLDOWN_SEC",
                    "E2_OBSERVE_AFTER_SEC", "CPU_SCALE_OUT_THRESHOLD", "TRIGGER_WINDOW_SEC", "ENABLE_SCALE_IN"]),
    ("E2 C2 power-on", ["C2_POWER_BACKEND", "VCENTER_HOST", "VCENTER_USER", "VCENTER_VM_NAME", "VCENTER_CA_BUNDLE",
                        "VCENTER_API", "CONNECTOR_2_IP", "ESXI_HOST", "CONNECTOR_2_VMID", "ATMOS_CONNECTOR_2_ID"]),
    ("E3 failover", ["FAILOVER_HTTP_URL", "FAILOVER_HTTP_EXPECT_BODY", "FAILOVER_TCP_HOST", "FAILOVER_TCP_PORT",
                     "FAILOVER_HTTP_TIMEOUT_MS", "FAILOVER_DURATION_SEC", "FAILOVER_BASELINE_SEC",
                     "FAILOVER_RECOVERY_N"]),
    ("E4 threat intel", ["THREAT_MAX_HOSTS", "CANARY_URL", "CANARY_CATEGORY_NAME", "SWG_REFERENCE_URL"]),
]
C2_POWER_BACKENDS = ("esxi-ssh", "vcenter-api", "manual")
# Keys a live E2 run needs per C2 power backend (the scaler validates the same set)
E2_BACKEND_KEYS = {"esxi-ssh": ("ESXI_HOST", "ESXI_PASSWORD", "CONNECTOR_2_VMID"),
                   "vcenter-api": ("VCENTER_HOST", "VCENTER_USER", "VCENTER_PASSWORD"),
                   "manual": ("CONNECTOR_2_IP",)}
SETTINGS_KEYS = [k for _, keys in SETTINGS_GROUPS for k in keys]


def validate_setting(key, value):
    """Raises LabError for a value the tools would reject; returns the value unchanged."""
    if SECRET_RE.search(key) or key not in SETTINGS_KEYS:
        raise LabError(f"{key} cannot be changed here (secrets and other keys: edit .env by hand)")
    if "\n" in value or "\r" in value:
        raise LabError("the value must be one line")
    if value == "":
        return value
    if key.endswith("CONCURRENCY_STEPS"):
        parse_steps(value)
    elif key.endswith("STEP_DURATION"):
        parse_duration(value)
    elif key == "C2_POWER_BACKEND":
        if value not in C2_POWER_BACKENDS:
            raise LabError(f"C2_POWER_BACKEND must be one of {', '.join(C2_POWER_BACKENDS)}")
    elif key == "VCENTER_API":
        if value not in ("auto", "api", "rest"):
            raise LabError("VCENTER_API must be auto, api or rest")
    elif key == "ENABLE_SCALE_IN":
        if value.lower() not in ("true", "false"):
            raise LabError("ENABLE_SCALE_IN must be true or false")
    elif key == "LAB_REMOTE_DIR":
        if not REMOTE_DIR_RE.match(value) or ".." in value.split("/"):
            raise LabError("LAB_REMOTE_DIR: letters, digits, '.', '_', '-', '/' only")
    elif re.search(r"(_SEC|_MS|_N|_SWEEPS|_PORT|_QPS|_VMID|_HOSTS|THRESHOLD|_RATE)$", key):
        try:
            number = float(value)
        except ValueError:
            raise LabError(f"{key} must be a number") from None
        if number < 0:
            raise LabError(f"{key} must not be negative")
    return value


def set_env_line(text, key, value):
    """New .env text with KEY=value replaced (first occurrence) or appended; keeps line endings."""
    newline = "\r\n" if "\r\n" in text else "\n"
    quoted = f'"{value}"' if re.search(r"[\s#\"']", value) else value
    line = f"{key}={quoted}"
    pattern = re.compile(rf"^{re.escape(key)}=[^\r\n]*", re.M)
    if pattern.search(text):
        return pattern.sub(lambda _m: line, text, count=1)
    if text and not text.endswith(("\n", "\r\n")):
        text += newline
    return text + line + newline


def write_env(path, text):
    """Writes .env atomically with mode 0600; the previous version is kept as .env.bak (0600)."""
    if os.path.exists(path):
        shutil.copyfile(path, path + ".bak")
        os.chmod(path + ".bak", 0o600)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


# ------------------------------------------------------------------------------
# Process and SSH wrappers
# ------------------------------------------------------------------------------

class Shell:
    """subprocess wrapper (tests replace it); every command runs from the repository root."""

    def run(self, cmd, check=False, capture=True, timeout=None):
        p = subprocess.run(cmd, cwd=ROOT, capture_output=capture, text=True, timeout=timeout)
        if check and p.returncode != 0:
            detail = (p.stderr or p.stdout or "").strip() if capture else ""
            raise LabError(f"command failed (exit {p.returncode}): {shlex.join(cmd)}" + (f"\n{detail}" if detail else ""))
        return p

    def popen(self, cmd, **kwargs):
        return subprocess.Popen(cmd, cwd=ROOT, **kwargs)


class Remote:
    def __init__(self, shell, user, host, known_hosts=""):
        if not user or not host:
            raise LabError("CONNECTOR_1_IP and CONNECTOR_SSH_USER must be set in .env")
        self.shell, self.target = shell, f"{user}@{host}"
        self.opts = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=yes",
                     "-o", "ServerAliveInterval=15"]
        if known_hosts:
            self.opts += ["-o", f"UserKnownHostsFile={known_hosts}"]

    def ssh(self, command, check=True, timeout=60):
        return self.shell.run(["ssh", *self.opts, self.target, command], check=check, timeout=timeout)

    def put(self, local, remote_path):
        return self.shell.run(["scp", "-q", *self.opts, local, f"{self.target}:{remote_path}"], check=True, timeout=120)

    def get(self, remote_paths, local_dir):
        srcs = [f"{self.target}:{p}" for p in remote_paths]
        return self.shell.run(["scp", "-q", *self.opts, *srcs, local_dir], check=True, timeout=600)


# ------------------------------------------------------------------------------
# The lab
# ------------------------------------------------------------------------------

class Lab:
    def __init__(self, env, shell=None, out=print, ask=input, sleep=time.sleep, clock=time.time, now=utc_now,
                 http_status=None):
        self.env, self.shell = env, shell or Shell()
        self.http_status = http_status or target_http_status
        self.out, self._ask, self.sleep, self.clock, self.now = out, ask, sleep, clock, now
        self.python = sys.executable
        self.assume_yes = False

    # -- interaction -------------------------------------------------------------
    def ask(self, prompt, default=""):
        if self.assume_yes and default:
            self.out(f"{prompt}: {default} (--yes)")
            return default
        try:
            answer = self._ask(f"{prompt}{f' [{default}]' if default else ''}: ").strip()
        except EOFError:  # input closed: take the default (menu: exit, confirmations: no)
            return default
        return answer or default

    def confirm(self, prompt, default=False):
        if self.assume_yes:
            self.out(f"{prompt} -> yes (--yes)")
            return True
        answer = self.ask(f"{prompt} (y/n)", "y" if default else "n").lower()
        return answer in ("y", "yes", "i", "igen")

    def g(self, key, default=""):
        return env_value(self.env, key, default)

    def remote(self):
        return Remote(self.shell, self.g("CONNECTOR_SSH_USER"), self.g("CONNECTOR_1_IP"), self.g("SSH_KNOWN_HOSTS"))

    def remote_dir(self):
        d = self.g("LAB_REMOTE_DIR", "sse-lab")
        if not REMOTE_DIR_RE.match(d) or ".." in d.split("/"):
            raise LabError(f"invalid LAB_REMOTE_DIR {d!r}")
        return d.rstrip("/")

    def git_state(self):
        head = self.shell.run(["git", "rev-parse", "HEAD"])
        dirty = self.shell.run(["git", "status", "--porcelain"])
        return {"commit": head.stdout.strip() if head.returncode == 0 else "unknown",
                "uncommitted_changes": [l for l in (dirty.stdout or "").splitlines() if l.strip()]
                if dirty.returncode == 0 else ["unknown"]}

    def run_id(self, experiment, given):
        if given:
            return check_run_id(given)
        suggestion = suggest_run_id(experiment, existing_run_ids(), self.now())
        if self.assume_yes:
            return suggestion
        return check_run_id(self.ask(f"RUN_ID for {experiment}", suggestion))

    # -- check ---------------------------------------------------------------------
    def check(self, need_remote=True, tools=("hey", "sar", "sadf", "ssh", "scp"), need_env=True):
        """Read-only readiness check. Returns a list of problems (empty = ready)."""
        problems = []
        for tool in tools:
            name = self.g("HEY_PATH", "hey") if tool == "hey" else tool
            if shutil.which(name) is None:
                problems.append(f"'{name}' not found on this host")
        if need_env and not os.path.exists(os.path.join(ROOT, ".env")):
            problems.append(".env missing: cp .env.example .env and fill it in")
        elif need_env and not self.g("TARGET_APP_URL"):
            problems.append("TARGET_APP_URL is empty in .env")
        if not os.environ.get("TMUX"):
            self.out("[i] not inside tmux: a dropped SSH/VPN session would stop a running measurement")
        if need_remote and need_env and not problems:
            url = self.g("TARGET_APP_URL")
            status = self.http_status(url)
            if status == 200:
                self.out(f"[+] target answers 200 through SSE: {url}")
            else:
                problems.append(f"target {url} answered {status} instead of 200: the application path is broken "
                                "before any load (502 = the connector cannot reach the backend; is the backend VM "
                                "and its web server running?)")
        if need_remote and not problems:
            try:
                r = self.remote().ssh("command -v sar sadf setsid >/dev/null && hostname", check=False, timeout=30)
            except (LabError, subprocess.TimeoutExpired) as exc:
                problems.append(f"connector SSH: {exc}")
            else:
                if r.returncode != 0:
                    problems.append(self._ssh_hint(r))
                else:
                    self.out(f"[+] connector SSH ok: {self.remote().target} ({r.stdout.strip()}), sar/sadf present")
        git = self.git_state()
        self.out(f"[i] repository commit {git['commit'][:12]}"
                 + (f", {len(git['uncommitted_changes'])} uncommitted change(s)" if git["uncommitted_changes"] else ", clean"))
        for p in problems:
            self.out(f"[!] {p}")
        if not problems:
            self.out("[+] ready")
        return problems

    def _ssh_hint(self, r):
        err = (r.stderr or "").strip()
        target = self.remote().target
        if "Host key verification failed" in err or "No ED25519 host key" in err or "host key" in err.lower():
            return (f"connector SSH: host key of {target} is not in known_hosts. Log in once by hand "
                    f"(ssh {target}), compare the fingerprint with the VM console, then run lab.py again")
        if "Permission denied" in err:
            return (f"connector SSH: key login to {target} is not set up (lab.py never uses passwords). "
                    f"Run once: ssh-keygen -t ed25519 (if you have no key) and ssh-copy-id {target}")
        if r.returncode == 1 or "not found" in err:
            return f"connector SSH works but sar/sadf/setsid is missing on {target} (install sysstat)"
        return f"connector SSH to {target} failed: {err or 'exit ' + str(r.returncode)}"

    # -- E1 / E2 building blocks ---------------------------------------------------------
    def start_telemetry(self, run_id, seconds):
        rem, rdir = self.remote(), self.remote_dir()
        rem.ssh(f"mkdir -p {shlex.quote(rdir)}")
        rem.put(TELEMETRY_SCRIPT, f"{rdir}/collect_connector_telemetry.sh")
        remote_hash = rem.ssh(f"sha256sum {shlex.quote(rdir + '/collect_connector_telemetry.sh')}").stdout.split()[0]
        local_hash = sha256_file(TELEMETRY_SCRIPT)
        if remote_hash != local_hash:
            raise LabError("telemetry script on the connector differs from the repository copy (sha256)")
        tolerance = int(self.g("COVERAGE_TOLERANCE_SEC", "5"))
        pid = rem.ssh(remote_telemetry_start(rdir, run_id, "c1", seconds, tolerance)).stdout.strip().splitlines()[-1]
        started = self.clock()
        log = f"{rdir}/{run_id}.collector.log"
        for _ in range(20):
            self.sleep(1)
            text = rem.ssh(f"cat {shlex.quote(log)} 2>/dev/null || true", check=False).stdout
            if "[!]" in text:
                raise LabError(f"connector telemetry did not start:\n{text.strip()}")
            if "[*]" in text:
                self.out(f"[+] connector telemetry running on {rem.target} (pid {pid}, {seconds} s): "
                         f"{text.strip().splitlines()[-1]}")
                return {"remote": rem.target, "remote_dir": f"{rdir}/{run_id}", "pid": pid, "seconds": seconds,
                        "started_epoch": started, "script_sha256": local_hash, "coverage_tolerance_sec": tolerance}
        raise LabError(f"no start message from the connector telemetry within 20 s; check {rem.target}:{log}")

    def telemetry_running(self, tele):
        r = self.remote().ssh(f"ps -p {int(tele['pid'])} -o args= || true", check=False)
        return "collect_connector_telemetry" in (r.stdout or "")

    def stop_telemetry(self, tele):
        self.remote().ssh(f"kill -INT {int(tele['pid'])} 2>/dev/null || true", check=False)

    def wait_telemetry(self, tele):
        end = tele["started_epoch"] + tele["seconds"]
        while self.clock() < end:
            left = end - self.clock()
            self.out(f"[*] waiting for the connector telemetry to finish: {int(left // 60)} min {int(left % 60)} s left")
            self.sleep(min(60, max(1, left)))
        for _ in range(60):
            if not self.telemetry_running(tele):
                return
            self.sleep(5)
        raise LabError("connector telemetry still running 5 min after its planned end; check it by hand")

    def collect_telemetry(self, run_id, tele, run_dir):
        rem, rdir = self.remote(), self.remote_dir()
        out = rem.ssh(remote_sadf_export(rdir, run_id, "c1")).stdout
        names = [l.strip() for l in out.splitlines() if l.startswith("telemetry_")]
        coverage = re.findall(r'"coverage": *"([^"]*)"', out)
        dest = os.path.join(run_dir, "telemetry")
        os.makedirs(dest, exist_ok=True)
        clash = [n for n in names if os.path.exists(os.path.join(dest, n))]
        if clash:
            raise LabError(f"telemetry files already present locally, not overwritten: {clash}")
        rem.get([f"{rdir}/{run_id}/{n}" for n in names], dest)
        tele.update(files=names, coverage=coverage[0] if coverage else "unknown")
        self.out(f"[+] connector telemetry copied ({len(names)} files), coverage: {tele['coverage']}")
        if tele["coverage"] != "full_from_run_start":
            self.out("[!] telemetry coverage is not full_from_run_start: the resource figures will say so")

    def start_client_sar(self, run_dir, seconds):
        os.makedirs(os.path.join(run_dir, "client_sar"), exist_ok=True)
        path = os.path.join(run_dir, "client_sar", "client.sa")
        if os.path.exists(path):
            raise LabError(f"{path} exists (sar would append to it)")
        proc = self.shell.popen(["sar", "-u", "1", str(int(seconds)), "-o", path], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, start_new_session=True)
        self.out(f"[+] client CPU recording (sar, 1 s, {seconds} s) -> {os.path.relpath(path, ROOT)}")
        return proc, path

    def export_client_sar(self, proc, path):
        try:
            proc.wait(timeout=600)
        except subprocess.TimeoutExpired:
            proc.send_signal(signal.SIGINT)
            proc.wait(timeout=30)
        csv_path = os.path.join(os.path.dirname(path), "client_cpu.csv")
        r = self.shell.run(["sadf", "-d", path, "--", "-u", "ALL"], check=True)
        with open(csv_path, "x", encoding="utf-8") as f:
            f.write(r.stdout)
        self.out(f"[+] client CPU export -> {os.path.relpath(csv_path, ROOT)}")

    def raise_nofile(self, wanted=8192):
        try:
            import resource
        except ImportError:
            return "unknown"
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = wanted if hard == resource.RLIM_INFINITY else min(wanted, hard)
        if soft < target:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
        soft = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        if soft < wanted:
            self.out(f"[!] open-file limit is {soft} (< {wanted}): high concurrency levels may fail with "
                     "'too many open files' (raise the hard limit in /etc/security/limits.conf)")
        return soft

    def run_foreground(self, cmd):
        """Runs a measurement script in the foreground. Ctrl+C reaches the script too (same process
        group); this waits until it has written its partial results instead of killing it."""
        self.out(f"[*] {shlex.join(os.path.relpath(c, ROOT) if c.startswith(ROOT) else c for c in cmd)}")
        proc = self.shell.popen(cmd)
        while True:
            try:
                return proc.wait()
            except KeyboardInterrupt:
                self.out("[!] interrupted: waiting for the script to write its partial results ...")

    def time_sync(self, remote=True):
        readings = [parse_timesync(self.shell.run(["bash", "-c", TIMESYNC_COMMAND]).stdout)]
        if remote:
            readings.append(parse_timesync(self.remote().ssh(TIMESYNC_COMMAND, check=False).stdout))
        for r in readings:
            self.out(f"[i] time sync {r['host']}: NTPSynchronized={r['ntp_synchronized']}, "
                     f"server {r['server']}, offset {r['offset']}")
        return readings

    def check_hey_result(self, run_dir):
        with open(os.path.join(run_dir, "manifest.json"), encoding="utf-8") as f:
            manifest = json.load(f)
        by_status = manifest.get("validity", {}).get("levels_by_status", {})
        too_many = [os.path.basename(p) for p in glob.glob(os.path.join(run_dir, "raw", "*.txt"))
                    if "too many open files" in open(p, encoding="utf-8", errors="replace").read()]
        self.out(f"[i] hey: status {manifest['status']}, validity {manifest['validity']['status']}, "
                 f"levels by status {by_status}")
        if too_many:
            self.out(f"[!] 'too many open files' in {len(too_many)} raw file(s): those runs are invalid "
                     "(client limit, not the connector)")
        return manifest, too_many

    def write_record(self, run_dir, record):
        os.makedirs(run_dir, exist_ok=True)
        path = os.path.join(run_dir, "lab_run.json")
        if os.path.exists(path):
            path = os.path.join(run_dir, f"lab_run_{self.now().strftime('%Y%m%dT%H%M%SZ')}.json")
        with open(path, "x", encoding="utf-8") as f:
            json.dump(record, f, indent=2)
        return path

    def _stop_background(self, tele, sar_proc):
        if tele and self.confirm("Stop the connector telemetry now (its data is then marked partial)?", True):
            self.stop_telemetry(tele)
        if sar_proc and sar_proc.poll() is None:
            sar_proc.send_signal(signal.SIGINT)

    # -- E1 ------------------------------------------------------------------------------
    def e1(self, run_id=None, dry_run=False, process=True):
        plan = hey_plan(self.env)
        lead = 0 if dry_run else int(self.g("LAB_LEAD_SEC", "60"))
        seconds = int(self.g("LAB_TELEMETRY_SEC", "0")) or telemetry_seconds(plan["estimate_sec"], lead)
        if self.check(need_remote=not dry_run, tools=() if dry_run else ("hey", "sar", "sadf", "ssh", "scp"),
                      need_env=not dry_run):
            raise LabError("fix the problems above first (nothing was started)")
        run_id = self.run_id("DRY-E1" if dry_run else "E1", run_id)
        run_dir = os.path.join(LOAD_RESULTS, run_id)
        if os.path.exists(run_dir):
            raise LabError(f"{os.path.relpath(run_dir, ROOT)} already exists: use a new RUN_ID")
        git = self.git_state()
        self.out("\nE1 capacity run" + ("  (DRY RUN: synthetic hey output, no traffic, not a measurement)" if dry_run else ""))
        self.out(f"  RUN_ID      {run_id}\n  target      {self.g('TARGET_APP_URL') or '(dry run)'}\n"
                 f"  levels      {plan['steps']}\n  sweeps      {plan['sweeps']} x {plan['duration']}, "
                 f"cooldown {plan['cooldown']} s, qps {plan['qps']}\n"
                 f"  load time   about {round(plan['estimate_sec'] / 60)} min")
        if not dry_run:
            self.out(f"  telemetry   {self.remote().target}, {seconds} s at 1 s (starts {lead} s before the load)\n"
                     f"  client CPU  sar on this host, {seconds} s at 1 s")
        self.out(f"  code        {git['commit'][:12]}" + ("  UNCOMMITTED CHANGES: " + ", ".join(git["uncommitted_changes"])
                                                         if git["uncommitted_changes"] else ""))
        if not self.confirm("Start?"):
            self.out("[i] nothing started")
            return 1
        record = {"tool": "lab.py", "experiment": "E1", "run_id": run_id, "dry_run": dry_run, "git": git,
                  "host": socket.gethostname(), "python": sys.version.split()[0], "started_utc": iso(self.now()),
                  "hey_plan": {k: plan[k] for k in ("steps", "sweeps", "duration", "cooldown", "qps")},
                  "lead_sec": lead, "nofile_limit": self.raise_nofile(), "commands": []}
        tele = sar_proc = None
        try:
            if not dry_run:
                tele = self.start_telemetry(run_id, seconds)
                record["telemetry"] = tele
                sar_proc, sar_path = self.start_client_sar(run_dir, seconds)
                self.out(f"[*] idle baseline: the load starts in {lead} s")
                self.sleep(lead)
            cmd = hey_command(self.python, run_id, plan, dry_run)
            record["commands"].append(shlex.join(cmd))
            record["load_started_utc"] = iso(self.now())
            rc = self.run_foreground(cmd)
            record["load_ended_utc"], record["hey_exit_code"] = iso(self.now()), rc
        except (KeyboardInterrupt, LabError):
            self._stop_background(tele, sar_proc)
            raise
        if rc != 0 or not os.path.exists(os.path.join(run_dir, "manifest.json")):
            self._stop_background(tele, sar_proc)
            record["outcome"] = "load run did not complete"
            if os.path.isdir(run_dir):
                self.write_record(run_dir, record)
            raise LabError(f"hey run ended with exit code {rc}; the run is not usable as a capacity result")
        manifest, too_many = self.check_hey_result(run_dir)
        record["hey_status"], record["too_many_open_files"] = manifest["validity"], too_many
        if not dry_run:
            if self.clock() > tele["started_epoch"] + tele["seconds"]:
                self.out("[!] the load ran longer than the telemetry: the end of the run is not covered")
            self.wait_telemetry(tele)
            self.collect_telemetry(run_id, tele, run_dir)
            self.export_client_sar(sar_proc, sar_path)
            record["time_sync_readings"] = self.time_sync()
            record["time_sync"] = time_sync_statement(record["time_sync_readings"], self.now())
        record["ended_utc"] = iso(self.now())
        path = self.write_record(run_dir, record)
        self.out(f"[+] run record -> {os.path.relpath(path, ROOT)}")
        if process:
            return self.process([run_id])
        return 0

    # -- E2 ------------------------------------------------------------------------------
    def c2_power_text(self, backend):
        if backend == "vcenter-api":
            return (f"vCenter API, VM '{self.g('VCENTER_VM_NAME', 'SR-CONN02')}' via {self.g('VCENTER_HOST')} "
                    f"as {self.g('VCENTER_USER')}")
        if backend == "manual":
            return ("MANUAL: when the scaler console shows MANUAL ACTION, press Power On on SR-CONN02 in the "
                    "vSphere client; watch the scaler log with: tail -f <run>/scaler/scaler_console.log")
        return f"ESXi SSH, VMID {self.g('CONNECTOR_2_VMID')} on {self.g('ESXI_HOST')}"

    def e2(self, run_id=None, process=True):
        if not self.g("E2_CONCURRENCY_STEPS"):
            raise LabError("E2_CONCURRENCY_STEPS is empty in .env: the E2 load profile is a methodology decision "
                           "(docs/measurement-guide.md, Experiment 2); set it before an E2 run")
        plan = hey_plan(self.env, prefix="E2")
        backend = self.g("C2_POWER_BACKEND", "esxi-ssh")
        if backend not in E2_BACKEND_KEYS:
            raise LabError(f"C2_POWER_BACKEND={backend} is not one of {', '.join(C2_POWER_BACKENDS)}")
        for key in ("CONNECTOR_1_IP",) + E2_BACKEND_KEYS[backend]:
            if not self.g(key):
                raise LabError(f"{key} is empty in .env (needed for C2_POWER_BACKEND={backend})")
        if backend == "manual" and self.g("ENABLE_SCALE_IN", "false").lower() == "true":
            raise LabError("ENABLE_SCALE_IN=true is not possible with C2_POWER_BACKEND=manual")
        lead = int(self.g("LAB_LEAD_SEC", "60"))
        observe = int(self.g("E2_OBSERVE_AFTER_SEC", "120"))
        seconds = telemetry_seconds(plan["estimate_sec"] + observe, lead)
        if self.check():
            raise LabError("fix the problems above first (nothing was started)")
        run_id = self.run_id("E2", run_id)
        run_dir = os.path.join(LOAD_RESULTS, run_id)
        if os.path.exists(run_dir):
            raise LabError(f"{os.path.relpath(run_dir, ROOT)} already exists: use a new RUN_ID")
        self.out("\nDry run of the scaler configuration first (simulated, no SSH/HTTP):")
        if self.shell.run([self.python, SCALER_SCRIPT, "--dry-run", "--max-cycles", "3"], capture=False).returncode:
            raise LabError("scaler dry run failed")
        git = self.git_state()
        self.out(f"\nE2 scaling run  RUN_ID {run_id}\n"
                 f"  LIVE scaler: may POWER ON SR-CONN02 ({self.c2_power_text(backend)}) "
                 f"when C1 CPU >= {self.g('CPU_SCALE_OUT_THRESHOLD', '80.0')} % for {self.g('TRIGGER_WINDOW_SEC', '15.0')} s; "
                 f"scale-in {'ENABLED' if self.g('ENABLE_SCALE_IN', 'false').lower() == 'true' else 'disabled'}\n"
                 f"  C2 must be powered off and Unavailable in the portal before the start\n"
                 f"  load        {plan['steps']} x {plan['sweeps']} sweeps x {plan['duration']}, then {observe} s observation\n"
                 f"  telemetry   C1, {seconds} s\n  code        {git['commit'][:12]}")
        if not self.confirm("C2 is powered off, Unavailable, and the live run may power it on. Start?"):
            self.out("[i] nothing started")
            return 1
        record = {"tool": "lab.py", "experiment": "E2", "run_id": run_id, "git": git, "host": socket.gethostname(),
                  "started_utc": iso(self.now()), "nofile_limit": self.raise_nofile(), "commands": [],
                  "hey_plan": {k: plan[k] for k in ("steps", "sweeps", "duration", "cooldown", "qps")},
                  "lead_sec": lead, "observe_after_sec": observe}
        tele = sar_proc = scaler = watcher = None
        scaler_dir = os.path.join(run_dir, "scaler")
        try:
            tele = self.start_telemetry(run_id, seconds)
            record["telemetry"] = tele
            sar_proc, sar_path = self.start_client_sar(run_dir, seconds)
            os.makedirs(scaler_dir, exist_ok=True)
            scmd = [self.python, SCALER_SCRIPT, "--output-dir", scaler_dir]
            record["commands"].append(shlex.join(scmd))
            log = open(os.path.join(scaler_dir, "scaler_console.log"), "x", encoding="utf-8")
            scaler = self.shell.popen(scmd, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            record["scaler_started_utc"] = iso(self.now())
            self.out(f"[+] scaler running (pid {scaler.pid}), log {os.path.relpath(log.name, ROOT)}")
            if backend == "manual":
                watcher = ManualActionWatcher(log.name, self.out)
                watcher.start()
                self.out("[i] MANUAL backend: this console will beep and show MANUAL ACTION when SR-CONN02 "
                         "must be powered on in the vSphere client")
            self.sleep(lead)
            if scaler.poll() is not None:
                raise LabError(f"scaler exited early (code {scaler.returncode}); see {log.name}")
            cmd = hey_command(self.python, run_id, plan)
            record["commands"].append(shlex.join(cmd))
            record["load_started_utc"] = iso(self.now())
            record["hey_exit_code"] = self.run_foreground(cmd)
            record["load_ended_utc"] = iso(self.now())
            self.out(f"[*] observing for {observe} s after the load")
            self.sleep(observe)
        except (KeyboardInterrupt, LabError):
            self._stop_background(tele, sar_proc)
            raise
        finally:
            if watcher is not None:
                watcher.stop()
                record["manual_power_on_requests"] = watcher.alerts
            if scaler is not None and scaler.poll() is None:
                os.killpg(scaler.pid, signal.SIGINT)
                try:
                    scaler.wait(timeout=120)
                except subprocess.TimeoutExpired:
                    self.out("[!] scaler did not stop within 120 s after SIGINT; stop it by hand")
                record["scaler_stopped_utc"] = iso(self.now())
        self.check_hey_result(run_dir)
        self.wait_telemetry(tele)
        self.collect_telemetry(run_id, tele, run_dir)
        self.export_client_sar(sar_proc, sar_path)
        record["time_sync_readings"] = self.time_sync()
        record["time_sync"] = time_sync_statement(record["time_sync_readings"], self.now())
        record["note"] = "C2 telemetry is not collected (C2 is powered off at the start); C2 power state comes from the scaler"
        record["ended_utc"] = iso(self.now())
        self.write_record(run_dir, record)
        self.out("[i] after the run: shut C2 down by hand (Guest OS shutdown) if the next experiment needs it off")
        return self.process([run_id]) if process else 0

    # -- E3 ------------------------------------------------------------------------------
    def e3(self, run_id=None, duration=None, dry_run=False):
        for key in () if dry_run else ("FAILOVER_HTTP_URL", "FAILOVER_TCP_HOST"):
            if not self.g(key):
                raise LabError(f"{key} is empty in .env (docs/measurement-guide.md, Experiment 3)")
        if not dry_run and not (self.g("FAILOVER_HTTP_EXPECT_BODY") or self.g("FAILOVER_HTTP_EXPECT_REGEX")):
            raise LabError("FAILOVER_HTTP_EXPECT_BODY or FAILOVER_HTTP_EXPECT_REGEX must be set (content check)")
        duration = int(duration or self.g("FAILOVER_DURATION_SEC", "720"))
        run_id = self.run_id("DRY-E3" if dry_run else "E3", run_id)
        run_dir = os.path.join(FAILOVER_RESULTS, run_id)
        if os.path.exists(run_dir):
            raise LabError(f"{os.path.relpath(run_dir, ROOT)} already exists: every repetition needs a new RUN_ID")
        git = self.git_state()
        self.out(f"\nE3 failover repetition  RUN_ID {run_id}, {duration} s, probes: {', '.join(PROBES)}"
                 + ("  (DRY RUN: simulated probes, not a measurement)" if dry_run else "") + "\n"
                 f"  HTTP {self.g('FAILOVER_HTTP_URL')}   TCP {self.g('FAILOVER_TCP_HOST')}:{self.g('FAILOVER_TCP_PORT', '443')}\n"
                 f"  code {git['commit'][:12]}\n"
                 "  Before: both connectors Available in the portal, C1 NIC connected, >= 5 min since the last repetition.\n"
                 "  Keys while running (type, then Enter):\n"
                 "    f      fault marker - press IMMEDIATELY BEFORE you click Save in the Host Client\n"
                 "    c      fault cleared marker - IMMEDIATELY BEFORE the reconnect Save\n"
                 "    n TEXT note marker      q  abort (the files are kept, the run is then not valid)")
        if not self.confirm("Start the probes?"):
            self.out("[i] nothing started")
            return 1
        logs = os.path.join(run_dir, "lab_logs")
        os.makedirs(logs)
        record = {"tool": "lab.py", "experiment": "E3", "run_id": run_id, "git": git, "host": socket.gethostname(),
                  "dry_run": dry_run, "duration_sec": duration, "started_utc": iso(self.now()), "commands": [], "markers": []}
        procs = {}
        for p in PROBES:
            cmd = [self.python, "-u", FAILOVER_SCRIPT, "run", "--probe", p, "--run-id", run_id,
                   "--duration-sec", str(duration)] + (["--dry-run"] if dry_run else [])
            record["commands"].append(shlex.join(cmd))
            log = open(os.path.join(logs, f"{p}.log"), "x", encoding="utf-8")
            procs[p] = self.shell.popen(cmd, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        tails = {p: ProbeTail(os.path.join(run_dir, f"probes_{p}.csv")) for p in PROBES}
        t0, last_print, faulted = self.clock(), 0.0, False
        while any(pr.poll() is None for pr in procs.values()):
            for t in tails.values():
                t.poll()
            elapsed = self.clock() - t0
            if elapsed - last_print >= 5:
                last_print = elapsed
                self.out(f"t={int(elapsed):4d}s/{duration}  " + "  ".join(f"{p}: {tails[p].status()}" for p in PROBES))
            line = self._read_line(1.0)
            if line is None:
                continue
            cmd, _, text = line.strip().partition(" ")
            kind = {"f": "fault_injected", "c": "fault_cleared", "n": "note"}.get(cmd.lower())
            if kind:
                if kind == "fault_injected" and faulted:
                    self.out("[!] a fault marker already exists; only the first one is evaluated. Use n for a note.")
                    continue
                note = text or {"fault_injected": "C1 vNIC disconnect; marker immediately BEFORE Save",
                                "fault_cleared": "C1 vNIC reconnect; marker immediately BEFORE Save"}.get(kind, "")
                r = self.shell.run([self.python, FAILOVER_SCRIPT, "mark", "--run-id", run_id, "--kind", kind,
                                    "--note", note])
                faulted |= kind == "fault_injected" and r.returncode == 0
                record["markers"].append({"kind": kind, "note": note, "lab_utc": iso(self.now()), "exit": r.returncode})
                self.out(f"[{'+' if r.returncode == 0 else '!'}] marker {kind} written" + ("" if r.returncode == 0 else f": {r.stderr.strip()}"))
            elif cmd.lower() == "q" and self.confirm("Abort this repetition?"):
                for pr in procs.values():
                    if pr.poll() is None:
                        os.killpg(pr.pid, signal.SIGINT)
                record["aborted_utc"] = iso(self.now())
        record["exit_codes"] = {p: pr.returncode for p, pr in procs.items()}
        record["ended_utc"] = iso(self.now())
        self.write_record(run_dir, record)
        self.out("\nAnalysis (failover_probe.py analyze):")
        for p in PROBES:
            self.shell.run([self.python, FAILOVER_SCRIPT, "analyze", "--run-id", run_id, "--probe", p], capture=False)
        self.out(f"[i] files: {os.path.relpath(run_dir, ROOT)}. Figures for several repetitions: menu 'Process results'.")
        return 0

    def _read_line(self, timeout):
        """One line from stdin if available within `timeout` seconds (Linux terminals)."""
        try:
            ready, _, _ = select.select([sys.stdin], [], [], timeout)
        except (ValueError, OSError):
            self.sleep(timeout)
            return None
        return sys.stdin.readline() if ready else None

    # -- E4 ------------------------------------------------------------------------------
    def e4(self, action, run_id=None):
        run_id = self.run_id("E4", run_id)
        sync = os.path.join(THREAT_DIR, "sync_threat_intel.py")
        canary = os.path.join(THREAT_DIR, "canary_block_test.py")
        if action == "plan":
            cmd = [self.python, sync, "plan", "--run-id", run_id, "--fetch", "--read-api"]
            note = "read only: downloads the URLhaus feed and compares it with the category (no write)"
        elif action == "validate-signature":
            cmd = [self.python, canary, "validate-signature", "--run-id", run_id]
            note = "read only: probes SWG_REFERENCE_URL to validate the block signature"
        elif action == "canary":
            commit = self.ask("Commit mode after the category update (none / after-update)", "none")
            if commit not in ("none", "after-update"):
                raise LabError("commit mode must be none or after-update")
            cmd = [self.python, canary, "run", "--run-id", run_id, "--commit", commit]
            sig = self.ask("Signature file from validate-signature (empty = settings from .env)", "")
            if sig:
                cmd += ["--signature-file", sig]
            note = "WRITES the test category in Atmos (adds the canary host, then restores it)"
        elif action == "restore":
            cmd = [self.python, canary, "restore", "--run-id", run_id,
                   "--snapshot", self.ask("category_snapshot.json of the canary run"),
                   "--category-id", self.ask("category id"), "--category-name", self.ask("category name"),
                   "--commit", self.ask("Commit mode (none / after-update)", "none")]
            note = "WRITES the test category back from the snapshot"
        else:
            raise LabError(f"unknown E4 action {action!r}")
        self.out(f"\nE4 {action}  RUN_ID {run_id}\n  {note}\n  {shlex.join(cmd)}")
        if not self.confirm("Run?"):
            return 1
        return self.run_foreground(cmd)

    # -- settings --------------------------------------------------------------------------
    def settings(self, env_path=None):
        env_path = env_path or os.path.join(ROOT, ".env")
        if not os.path.exists(env_path):
            raise LabError(".env missing: cp .env.example .env first")
        while True:
            with open(env_path, encoding="utf-8", newline="") as f:
                text = f.read()
            file_values = {m.group(1): m.group(2).strip().strip('"').strip("'")
                           for m in re.finditer(r"^([A-Z0-9_]+)=(.*?)\r?$", text, re.M)}
            self.out("\nSettings in .env (secrets are not shown; edit those by hand)")
            for title, keys in SETTINGS_GROUPS:
                self.out(f"  {title}")
                for key in keys:
                    shown = file_values.get(key, "") or "(empty: default)"
                    note = "   [overridden by the shell environment]" if key in os.environ and \
                        os.environ[key] != file_values.get(key, "") else ""
                    self.out(f"    {key:<26} {shown}{note}")
            key = self.ask("Key to change (empty = back)", "").strip().upper()
            if not key:
                return 0
            if SECRET_RE.search(key) or key not in SETTINGS_KEYS:
                self.out(f"[!] {key} cannot be changed here (secrets and other keys: edit .env by hand)")
                continue
            try:
                value = validate_setting(key, self.ask(f"New value for {key} (empty = default)",
                                                       file_values.get(key, "")).strip())
            except LabError as exc:
                self.out(f"[!] {exc}")
                continue
            if value == file_values.get(key, "") and key in file_values:
                self.out("[i] unchanged")
                continue
            write_env(env_path, set_env_line(text, key, value))
            self.env[key] = os.environ.get(key, value)
            self.out(f"[+] {key}={value} saved (previous .env kept as .env.bak)")

    # -- processing ------------------------------------------------------------------------
    def find_run_dir(self, run_id):
        hits = [os.path.join(d, run_id) for d in RESULT_DIRS if os.path.isdir(os.path.join(d, run_id))]
        if len(hits) != 1:
            raise LabError(f"results of {run_id} not found (or found twice) under the results folders: {hits}")
        return hits[0]

    def process(self, run_ids, processing_id=None, provenance=None, diagnostic=False):
        roots = [self.find_run_dir(check_run_id(r)) for r in run_ids]
        if not processing_id:
            base = run_ids[0] if len(run_ids) == 1 else self.ask("processing_id prefix", f"{run_ids[0]}-group")
            processing_id = f"{base}-P1"
        check_run_id(processing_id)
        os.makedirs(SPECS, exist_ok=True)
        draft_path = os.path.join(SPECS, f"spec_draft_{processing_id}.json")
        reviewed_path = os.path.join(SPECS, f"spec_reviewed_{processing_id}.json")
        if os.path.exists(reviewed_path):
            self.out(f"[i] {os.path.relpath(reviewed_path, ROOT)} exists: regenerating figures from it")
            return self.figures(reviewed_path, diagnostic)
        if not os.path.exists(draft_path):
            cmd = [self.python, PROCESS_SCRIPT, "scan", *sum((["--root", r] for r in roots), []), "--out", draft_path]
            self.shell.run(cmd, check=True)
        with open(draft_path, encoding="utf-8") as f:
            draft = json.load(f)
        time_sync = None
        for root in roots:
            for rec in sorted(glob.glob(os.path.join(root, "lab_run*.json"))):
                with open(rec, encoding="utf-8") as f:
                    time_sync = json.load(f).get("time_sync") or time_sync
        spec, by_kind = build_reviewed_spec(draft, processing_id, provenance, time_sync, run_ids)
        provenance = spec["datasets"][0]["provenance"] if spec["datasets"] else provenance
        self.out(f"\nProcessing {processing_id}  (provenance: {provenance})")
        for ds in spec["datasets"]:
            self.out(f"  {ds['id']:<18} {os.path.relpath(ds['path'], ROOT)}")
        self.out(f"  groups: {json.dumps(spec['groups'])}")
        self.out(f"  time_sync: {time_sync['source'] if time_sync else 'none (cross-host figures will be skipped)'}")
        if provenance == "real" and any(k in by_kind for k in ("hey", "scaler")) and not time_sync:
            self.out("[!] no time_sync statement in lab_run.json: resource figures need one (see the measurement guide)")
        if not self.confirm("Is this list right (operator review)? Process"):
            self.out(f"[i] not processed; the draft is in {os.path.relpath(draft_path, ROOT)}")
            return 1
        with open(reviewed_path, "x", encoding="utf-8") as f:
            json.dump(spec, f, indent=2)
        try:
            return self.figures(reviewed_path, diagnostic, roots)
        except LabError:
            # keep the failed spec for the record, but do not reuse it next time
            failed = reviewed_path[:-5] + f".failed-{self.now().strftime('%Y%m%dT%H%M%SZ')}.json"
            os.replace(reviewed_path, failed)
            self.out(f"[i] spec kept as {os.path.relpath(failed, ROOT)}")
            raise

    def figures(self, spec_path, diagnostic=False, roots=None):
        cmd = [self.python, PROCESS_SCRIPT, "process", "--spec", spec_path] + (["--diagnostic"] if diagnostic else [])
        r = self.shell.run(cmd, capture=True)
        self.out((r.stdout or "").rstrip())
        if r.stderr:
            self.out(r.stderr.rstrip())
        m = re.search(r"-> (.+?)\s*$", r.stdout or "", re.M)
        if r.returncode != 0 or not m:
            raise LabError("processing failed (see above); the processing_manifest.json lists the issues")
        out_dir = m.group(1)
        if roots is None:
            with open(spec_path, encoding="utf-8") as f:
                roots = sorted({self._run_root(ds["path"]) for ds in json.load(f)["datasets"]})
        self.bundle(out_dir, spec_path, roots)
        return 0

    @staticmethod
    def _run_root(path):
        for d in RESULT_DIRS:
            rel = os.path.relpath(path, d)
            if not rel.startswith(".."):
                return os.path.join(d, rel.split(os.sep)[0])
        return os.path.dirname(path)

    def bundle(self, out_dir, spec_path, roots):
        """One tar.gz with the raw run folder(s), the figures and the spec, plus its sha256."""
        path = out_dir.rstrip("/") + ".tar.gz"
        with tarfile.open(path, "x:gz") as tar:
            for r in roots:
                tar.add(r, arcname=os.path.basename(r))
            tar.add(out_dir, arcname=os.path.basename(out_dir))
            tar.add(spec_path, arcname=os.path.basename(spec_path))
        digest = sha256_file(path)
        with open(path + ".sha256", "x", encoding="utf-8") as f:
            f.write(f"{digest}  {os.path.basename(path)}\n")
        rel = os.path.relpath(path, os.path.expanduser("~"))
        remote_path = f"~/{rel}" if not rel.startswith("..") else path
        host = self.shell.run(["hostname", "-I"]).stdout.split()
        dest = self.g("LAB_COPY_DEST", r"$HOME\sse-results")
        self.out(f"\n[+] figures: {os.path.relpath(out_dir, ROOT)}\n[+] bundle:  {os.path.relpath(path, ROOT)} (sha256 {digest[:16]}...)\n"
                 f"\nCopy to your computer (PowerShell):\n"
                 f"  mkdir -Force {dest}; cd {dest}\n"
                 f"  scp {getpass.getuser()}@{host[0] if host else socket.gethostname()}:{remote_path} .\n"
                 f"  tar -xzf {os.path.basename(path)}")


# ------------------------------------------------------------------------------
# Menu and command line
# ------------------------------------------------------------------------------

MENU = """
HPE Aruba SSE lab  ({host}, code {commit})
  1  Check setup (read only)
  2  Testbed preflight (read only)
  3  E1  capacity run: load + connector telemetry + figures
  4  E2  scaling run (live scaler; may power on C2)
  5  E3  failover: one repetition
  6  E4  threat intel / canary
  7  Process results or regenerate figures
  8  Practice offline: E1 or E3 dry run (simulated data)
  9  Settings (.env parameters, without secrets)
  0  Exit"""


def menu(lab):
    while True:
        git = lab.git_state()
        lab.out(MENU.format(host=socket.gethostname(), commit=git["commit"][:12]
                            + (" +changes" if git["uncommitted_changes"] else "")))
        choice = lab.ask("Choose", "0")
        try:
            if choice == "0":
                return 0
            elif choice == "1":
                lab.check()
            elif choice == "2":
                lab.run_foreground([lab.python, PREFLIGHT_SCRIPT, "--run"])
            elif choice == "3":
                lab.e1()
            elif choice == "4":
                lab.e2()
            elif choice == "5":
                lab.e3()
            elif choice == "6":
                action = lab.ask("plan / validate-signature / canary / restore", "plan")
                lab.e4(action)
            elif choice == "7":
                spec = lab.ask("RUN_ID(s) separated by spaces, or the path of a reviewed spec")
                if spec.endswith(".json"):
                    lab.figures(spec, lab.confirm("Diagnostic figure set (titles, run ids)?"))
                else:
                    lab.process(spec.split())
            elif choice == "9":
                lab.settings()
            elif choice == "8":
                if lab.ask("E1 or E3", "E1").upper() == "E3":
                    lab.e3(duration=120, dry_run=True)
                else:
                    lab.e1(dry_run=True)
        except LabError as exc:
            lab.out(f"[!] {exc}")
        except KeyboardInterrupt:
            lab.out("\n[!] interrupted")


def load_env():
    env = {}
    path = os.path.join(ROOT, ".env")
    if os.path.exists(path):
        try:
            from dotenv import dotenv_values
        except ImportError:
            raise LabError("python-dotenv is missing: pip install -r requirements.txt") from None
        env.update({k: v for k, v in dotenv_values(path).items() if v is not None})
    env.update(os.environ)  # like load_dotenv(): the process environment wins
    return env


def maybe_reexec_in_venv(argv):
    venv_python = os.path.join(ROOT, ".venv", "bin", "python")
    if sys.prefix == sys.base_prefix and os.path.exists(venv_python) and not os.environ.get("LAB_NO_VENV"):
        os.execv(venv_python, [venv_python, os.path.abspath(__file__), *argv])


def maybe_tmux(argv, lab):
    """Offers to restart inside tmux, so a dropped SSH/VPN session does not stop a measurement."""
    if os.environ.get("TMUX") or not shutil.which("tmux") or not sys.stdin.isatty():
        return
    if lab.confirm("Not inside tmux. Restart this inside a tmux session named 'lab' (recommended)?", True):
        os.execvp("tmux", ["tmux", "new-session", "-A", "-s", "lab", sys.executable, os.path.abspath(__file__), *argv])


def parse_args(argv):
    p = argparse.ArgumentParser(description="Optional menu / one-command runners for the four experiments")
    sub = p.add_subparsers(dest="command")
    sub.add_parser("check")
    sub.add_parser("settings")
    sub.add_parser("preflight")
    for name in ("e1", "e2", "e3"):
        s = sub.add_parser(name)
        s.add_argument("--run-id")
        s.add_argument("--yes", action="store_true", help="answer yes to every confirmation (scripted use)")
        if name == "e1":
            s.add_argument("--dry-run", action="store_true", help="synthetic hey output; no traffic, no SSH")
            s.add_argument("--no-process", action="store_true")
        if name == "e2":
            s.add_argument("--no-process", action="store_true")
        if name == "e3":
            s.add_argument("--duration-sec", type=int)
            s.add_argument("--dry-run", action="store_true", help="simulated probes with a scripted outage (finishes in seconds; no traffic)")
    s = sub.add_parser("e4")
    s.add_argument("action", choices=("plan", "validate-signature", "canary", "restore"))
    s.add_argument("--run-id")
    s = sub.add_parser("process")
    s.add_argument("--run-id", action="append", required=True)
    s.add_argument("--processing-id")
    s.add_argument("--provenance", choices=("real", "simulated"),
                   help="default: from the tool metadata (real/simulated); needed only if it cannot be derived")
    s.add_argument("--diagnostic", action="store_true")
    s.add_argument("--yes", action="store_true")
    s = sub.add_parser("figures")
    s.add_argument("--spec", required=True)
    s.add_argument("--diagnostic", action="store_true")
    return p.parse_args(argv)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    args = parse_args(argv)
    maybe_reexec_in_venv(argv)
    os.chdir(ROOT)
    try:
        lab = Lab(load_env())
        lab.assume_yes = getattr(args, "yes", False)
        if args.command in (None, "e1", "e2", "e3") and not getattr(args, "dry_run", False):
            maybe_tmux(argv, lab)
        if args.command is None:
            return menu(lab)
        if args.command == "check":
            return 1 if lab.check() else 0
        if args.command == "settings":
            return lab.settings()
        if args.command == "preflight":
            return lab.run_foreground([lab.python, PREFLIGHT_SCRIPT, "--run"])
        if args.command == "e1":
            return lab.e1(args.run_id, dry_run=args.dry_run, process=not args.no_process)
        if args.command == "e2":
            return lab.e2(args.run_id, process=not args.no_process)
        if args.command == "e3":
            return lab.e3(args.run_id, args.duration_sec, dry_run=args.dry_run)
        if args.command == "e4":
            return lab.e4(args.action, args.run_id)
        if args.command == "process":
            return lab.process(args.run_id, args.processing_id, args.provenance, args.diagnostic)
        if args.command == "figures":
            return lab.figures(args.spec, args.diagnostic)
    except LabError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
