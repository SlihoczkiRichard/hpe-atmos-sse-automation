#!/usr/bin/env python3
"""
Pillar 3: availability probes during a manually injected connector failure.

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

Subcommands
  run      one probe type per process; start several processes with the same RUN_ID
             tcp         a NEW TCP connection per probe (DNS + connect + close)
             http        a NEW HTTP(S) connection per probe; success = expected status AND expected
                         content (substring and/or regex); TLS verified by default; no redirects
             persistent  ONE keep-alive HTTP(S) connection opened before the fault; never reconnects
  mark     records an operator marker (fault_injected / fault_cleared / note) for a RUN_ID
  analyze  evaluates the records of one probe type (failover_analysis.py)

The fault is injected by hand (e.g. the operator stops the C1 connector); this script never
powers VMs off, never changes vNICs and never touches SSE configuration. A marker is an
operator_signal: it says when the operator acted, not when the network failure happened.

Timing: probes are scheduled on a monotonic grid (start + k * interval). The interval is a target,
not a guaranteed resolution: a failing probe lasts up to its timeout, and slots that pass during
a probe are skipped and counted. Every record has scheduled, start and end monotonic times and
start/end UTC. Markers carry the clock domain (host, OS, boot id or boot time estimate) of the
machine that wrote them; the analysis aligns markers on the monotonic clock only within the same
clock domain and the same RUN_ID.

Persistent probe: the connection is opened once; http.client's automatic reconnect is disabled
(auto_open = 0) and connect() is guarded so that a second connect() raises. Each response must
announce a Content-Length within the body limit and is read completely before the next request;
otherwise the exchange fails and the probe ends (no unread data stays on the connection). A
"Connection: close" response is logged as server_connection_close; EOF or reset are logged as
such, with the cause left unknown.

Outputs (results/<RUN_ID>/): probes_<type>.csv, manifest_<type>.json, markers.csv,
analysis_<type>.json, outages_<type>.csv. Existing files are never overwritten: a repeated run
of the same type gets an .attemptN suffix (announced on stdout and in the manifest), a repeated
analysis of the same records a .revN suffix. markers.csv gets its header only when it is created
and refuses rows of another RUN_ID.

Nothing is loaded from .env and no connection is opened at import time.
"""

import os
import re
import ssl
import csv
import sys
import json
import math
import time
import errno
import socket
import argparse
import platform
import http.client
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import importlib.util

RUN_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
PROBE_TYPES = ("tcp", "http", "persistent")
MARKER_KINDS = ("fault_injected", "fault_cleared", "note")
SIMULATED = "SIMULATED - NOT A REAL MEASUREMENT"

RECORD_FIELDS = ["run_id", "probe_type", "attempt", "seq", "event", "scheduled_mono_s", "start_mono_s",
                 "end_mono_s", "start_utc", "end_utc", "lag_ms", "duration_ms", "skipped_slots_after",
                 "ok", "error_class", "detail", "http_status"]
MARKER_FIELDS = ["run_id", "marker_seq", "kind", "note", "source", "utc", "monotonic_s", "host", "system",
                 "boot_id", "boot_epoch_estimate", "simulated"]
OUTAGE_FIELDS = ["outage_index", "first_failed_seq", "last_failed_seq", "failed_probes", "isolated_failure",
                 "error_classes", "first_failure_start_mono_s", "last_failure_end_mono_s", "failure_span_ms",
                 "bracket_interval_ms", "bracket_interval_reason"]

ProbeResult = namedtuple("ProbeResult", ["ok", "error_class", "detail", "http_status", "ended"],
                         defaults=("", "", None, False))

_UNREACHABLE = {errno.ENETUNREACH, errno.EHOSTUNREACH, 10051, 10065}  # 10051/10065: WSAENETUNREACH/WSAEHOSTUNREACH


def _load_analysis():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "failover_analysis.py")
    spec = importlib.util.spec_from_file_location("failover_analysis", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


analysis = _load_analysis()


# ------------------------------------------------------------------------------
# Clocks and clock domain
# ------------------------------------------------------------------------------

class RealClock:
    simulated = False

    def monotonic(self):
        return time.monotonic()

    def wall(self):
        return datetime.now(timezone.utc)

    def sleep(self, seconds):
        time.sleep(max(0.0, seconds))


class SimClock:
    simulated = True

    def __init__(self, start_wall=datetime(2026, 1, 1, tzinfo=timezone.utc)):
        self.t = 0.0
        self.start_wall = start_wall

    def monotonic(self):
        return self.t

    def wall(self):
        return self.start_wall + timedelta(seconds=self.t)

    def sleep(self, seconds):
        self.t += max(0.0, seconds)


def _read_boot_id():
    try:
        with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as f:
            return f.read().strip()
    except OSError:
        return ""


def clock_domain(clock, read_boot_id=_read_boot_id):
    """Identifies the monotonic clock: host, OS and boot (Linux boot_id, else UTC - monotonic)."""
    if clock.simulated:
        return {"host": "simulated", "system": "simulated", "boot_id": "", "boot_epoch_estimate": None,
                "simulated": True}
    mono, wall = clock.monotonic(), clock.wall().timestamp()
    return {"host": socket.gethostname(), "system": platform.system(), "boot_id": read_boot_id(),
            "boot_epoch_estimate": round(wall - mono, 3), "simulated": False}


def _iso(dt):
    return dt.isoformat(timespec="milliseconds")


# ------------------------------------------------------------------------------
# Probes
# ------------------------------------------------------------------------------

def classify_error(exc):
    """Maps an exception to an error class; nothing is inferred about its cause."""
    if isinstance(exc, socket.gaierror):
        return "dns_error"
    if isinstance(exc, (ssl.SSLEOFError, ssl.SSLZeroReturnError)):
        return "eof"
    if isinstance(exc, ssl.SSLError):
        return "tls_error"
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, (http.client.RemoteDisconnected, http.client.IncompleteRead)):
        return "eof"
    if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return "reset"
    if isinstance(exc, http.client.HTTPException):
        return "http_protocol_error"
    if isinstance(exc, OSError) and exc.errno in _UNREACHABLE:
        return "unreachable"
    return "other"


def _detail(exc):
    return f"{type(exc).__name__}: {exc}"[:200]


class TcpProbe:
    """New TCP connection per probe (name resolution included), closed immediately."""
    def __init__(self, host, port, timeout_sec, connect=socket.create_connection):
        self.host, self.port, self.timeout_sec = host, int(port), timeout_sec
        self._connect = connect

    def probe(self):
        try:
            sock = self._connect((self.host, self.port), timeout=self.timeout_sec)
        except Exception as exc:
            return ProbeResult(False, classify_error(exc), _detail(exc))
        try:
            sock.close()
        except OSError:
            pass
        return ProbeResult(True)


class ContentCheck:
    def __init__(self, expect_status=200, expect_body="", expect_regex="", max_body_bytes=4096):
        if not expect_body and not expect_regex:
            raise ValueError("a content check is required: --expect-body and/or --expect-regex")
        self.expect_status = int(expect_status)
        self.expect_body = expect_body.encode("utf-8") if expect_body else b""
        self.regex = re.compile(expect_regex.encode("utf-8")) if expect_regex else None
        self.max_body_bytes = int(max_body_bytes)

    def evaluate(self, status, body):
        if status != self.expect_status:
            return ProbeResult(False, "status_mismatch", f"HTTP {status} != {self.expect_status}", status)
        if self.expect_body and self.expect_body not in body:
            return ProbeResult(False, "content_mismatch", "expected body text not found", status)
        if self.regex and not self.regex.search(body):
            return ProbeResult(False, "content_mismatch", "expected body pattern not found", status)
        return ProbeResult(True, "", "", status)


def _target(url):
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"unsupported URL: {url!r}")
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    return parts.scheme, parts.hostname, parts.port or (443 if parts.scheme == "https" else 80), path


def default_connection_factory(scheme, host, port, timeout, ca_bundle=""):
    if scheme == "https":
        context = ssl.create_default_context(cafile=ca_bundle or None)  # certificate + hostname verified
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    return http.client.HTTPConnection(host, port, timeout=timeout)


class HttpProbe:
    """New HTTP(S) connection per probe (Connection: close); redirects are not followed."""
    def __init__(self, url, timeout_sec, check, ca_bundle="", connection_factory=default_connection_factory):
        self.scheme, self.host, self.port, self.path = _target(url)
        self.timeout_sec, self.check, self.ca_bundle = timeout_sec, check, ca_bundle
        self._factory = connection_factory

    def probe(self):
        conn = self._factory(self.scheme, self.host, self.port, self.timeout_sec, self.ca_bundle)
        try:
            conn.request("GET", self.path, headers={"Connection": "close", "User-Agent": "failover-probe"})
            resp = conn.getresponse()
            body = resp.read(self.check.max_body_bytes + 1)
            if len(body) > self.check.max_body_bytes:
                return ProbeResult(False, "body_too_large", f"body exceeds {self.check.max_body_bytes} bytes",
                                   resp.status)
            return self.check.evaluate(resp.status, body)
        except Exception as exc:
            return ProbeResult(False, classify_error(exc), _detail(exc))
        finally:
            conn.close()


class ReconnectRefused(ConnectionError):
    """Raised when the persistent probe would open a second connection."""


class PersistentHttpProbe:
    """One keep-alive HTTP(S) connection; never reconnects (see the module docstring)."""
    def __init__(self, url, timeout_sec, check, ca_bundle="", connection_factory=default_connection_factory):
        self.scheme, self.host, self.port, self.path = _target(url)
        self.timeout_sec, self.check, self.ca_bundle = timeout_sec, check, ca_bundle
        self._factory = connection_factory
        self.conn = None
        self.connect_calls = 0
        self.ended = False
        self.end_class = ""   # server_connection_close, or the error class that ended the connection

    def open(self):
        if self.conn is not None:
            raise ReconnectRefused("persistent probe already opened its connection")
        self.conn = self._factory(self.scheme, self.host, self.port, self.timeout_sec, self.ca_bundle)
        self.conn.auto_open = 0  # http.client: send() raises NotConnected instead of reconnecting
        original_connect = self.conn.connect

        def guarded_connect():
            self.connect_calls += 1
            if self.connect_calls > 1:
                raise ReconnectRefused("second connect() refused; the persistent probe never reconnects")
            return original_connect()

        self.conn.connect = guarded_connect
        try:
            self.conn.connect()
        except Exception as exc:
            self.ended = True
            self.end_class = classify_error(exc)
            return ProbeResult(False, self.end_class, _detail(exc), None, True)
        return ProbeResult(True)

    def _end(self, result, end_class=None):
        self.ended = True
        self.end_class = end_class or result.error_class
        try:
            self.conn.close()
        except Exception:
            pass
        return result._replace(ended=True)

    def probe(self):
        if self.ended or self.conn is None:
            return ProbeResult(False, "not_connected", "persistent connection already ended", None, True)
        try:
            self.conn.request("GET", self.path, headers={"Connection": "keep-alive", "User-Agent": "failover-probe"})
            resp = self.conn.getresponse()
        except Exception as exc:
            return self._end(ProbeResult(False, classify_error(exc), _detail(exc)))
        length = resp.getheader("Content-Length")
        chunked = "chunked" in (resp.getheader("Transfer-Encoding") or "").lower()
        if chunked or length is None or not length.strip().isdigit():
            return self._end(ProbeResult(False, "body_length_unknown",
                                         "no usable Content-Length; response cannot be read safely", resp.status))
        if int(length) > self.check.max_body_bytes:
            return self._end(ProbeResult(False, "body_too_large",
                                         f"Content-Length {length} exceeds {self.check.max_body_bytes} bytes",
                                         resp.status))
        try:
            body = resp.read(int(length))
        except Exception as exc:
            return self._end(ProbeResult(False, classify_error(exc), _detail(exc), resp.status))
        if len(body) != int(length) or not resp.isclosed():
            return self._end(ProbeResult(False, "eof", f"read {len(body)} of {length} body bytes", resp.status))
        result = self.check.evaluate(resp.status, body)
        if resp.will_close:
            # the server announced the end of the connection (Connection: close / HTTP/1.0)
            return self._end(result, "server_connection_close")
        return result


# ------------------------------------------------------------------------------
# Files (never overwritten)
# ------------------------------------------------------------------------------

def _suffix(attempt, label="attempt"):
    return "" if attempt == 1 else f".{label}{attempt}"


def create_exclusive(directory, stem, ext, attempt=None, max_attempts=99, label="attempt"):
    """Opens directory/stem[.<label>N].ext for writing, never replacing an existing file.
    With attempt=None the first free number is used. Returns (file, path, number)."""
    attempts = [attempt] if attempt else range(1, max_attempts + 1)
    for a in attempts:
        path = os.path.join(directory, f"{stem}{_suffix(a, label)}{ext}")
        try:
            return open(path, "x", newline="", encoding="utf-8"), path, a
        except FileExistsError:
            continue
    raise FileExistsError(f"{stem}{ext}: no free attempt slot in {directory}"
                          if attempt is None else f"{path} already exists; it is not overwritten")


def write_marker(results_dir, run_id, kind, note, clock, domain):
    """Appends one marker row; writes the header only when the file is created. Returns the row."""
    if kind not in MARKER_KINDS:
        raise ValueError(f"marker kind must be one of {MARKER_KINDS}")
    run_dir = os.path.join(results_dir, run_id)
    os.makedirs(run_dir, exist_ok=True)
    path = os.path.join(run_dir, "markers.csv")
    try:
        with open(path, "x", newline="", encoding="utf-8") as f:
            csv.DictWriter(f, fieldnames=MARKER_FIELDS).writeheader()
    except FileExistsError:
        pass
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    if not rows or rows[0] != MARKER_FIELDS:
        raise ValueError(f"{path} has an unexpected header; refusing to append")
    other = {r[0] for r in rows[1:] if r and r[0] != run_id}
    if other:
        raise ValueError(f"{path} contains markers of other runs {sorted(other)}; refusing to append")
    row = {"run_id": run_id, "marker_seq": len(rows), "kind": kind, "note": note,
           "source": analysis.OPERATOR_SIGNAL, "utc": _iso(clock.wall()), "monotonic_s": f"{clock.monotonic():.6f}",
           "host": domain["host"], "system": domain["system"], "boot_id": domain["boot_id"],
           "boot_epoch_estimate": "" if domain["boot_epoch_estimate"] is None else domain["boot_epoch_estimate"],
           "simulated": domain["simulated"]}
    with open(path, "a", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=MARKER_FIELDS).writerow(row)
    return row


def read_markers(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    markers = []
    for r in rows:
        est = r.get("boot_epoch_estimate")
        markers.append({"run_id": r["run_id"], "kind": r["kind"], "note": r.get("note", ""),
                        "utc": r.get("utc", ""), "monotonic_s": float(r["monotonic_s"]),
                        "clock_domain": {"host": r["host"], "system": r["system"], "boot_id": r.get("boot_id", ""),
                                         "boot_epoch_estimate": float(est) if est else None,
                                         "simulated": r.get("simulated") == "True"}})
    return markers


def read_records(path):
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["seq"] = int(r["seq"])
        r["ok"] = r["ok"] == "True"
        for k in ("scheduled_mono_s", "start_mono_s", "end_mono_s"):
            r[k] = float(r[k]) if r[k] else None
    return rows


# ------------------------------------------------------------------------------
# Probe loop
# ------------------------------------------------------------------------------

def run_probe(cfg, probe, clock, out_dir, attempt=None, stop=lambda: False):
    """Runs one probe type until duration_sec or until a persistent connection ends.
    Returns (manifest, records_path)."""
    os.makedirs(out_dir, exist_ok=True)
    f, path, attempt = create_exclusive(out_dir, f"probes_{cfg.probe}", ".csv", attempt)
    domain = clock_domain(clock)
    writer = csv.DictWriter(f, fieldnames=RECORD_FIELDS)
    writer.writeheader()
    started_mono, started_wall = clock.monotonic(), clock.wall()
    seq, ended_by, count = 0, "duration", {"ok": 0, "failed": 0}

    def record(event, sched, s_mono, s_wall, e_mono, e_wall, res, skipped):
        nonlocal seq
        seq += 1
        count["ok" if res.ok else "failed"] += 1
        writer.writerow({"run_id": cfg.run_id, "probe_type": cfg.probe, "attempt": attempt, "seq": seq,
                         "event": event, "scheduled_mono_s": "" if sched is None else f"{sched:.6f}",
                         "start_mono_s": f"{s_mono:.6f}", "end_mono_s": f"{e_mono:.6f}",
                         "start_utc": _iso(s_wall), "end_utc": _iso(e_wall),
                         "lag_ms": "" if sched is None else f"{(s_mono - sched) * 1000:.3f}",
                         "duration_ms": f"{(e_mono - s_mono) * 1000:.3f}", "skipped_slots_after": skipped,
                         "ok": res.ok, "error_class": res.error_class, "detail": res.detail,
                         "http_status": "" if res.http_status is None else res.http_status})
        f.flush()

    try:
        if cfg.probe == "persistent":
            s_mono, s_wall = clock.monotonic(), clock.wall()
            res = probe.open()
            record("connect", None, s_mono, s_wall, clock.monotonic(), clock.wall(), res, 0)
            if not res.ok:
                ended_by = f"connect failed: {res.error_class}"
        t0 = clock.monotonic()
        deadline = started_mono + cfg.duration_sec
        k = 0
        event = "exchange" if cfg.probe == "persistent" else "probe"
        while ended_by == "duration" and not stop():
            sched = t0 + k * cfg.interval_sec
            if sched >= deadline:
                break
            now = clock.monotonic()
            if now < sched:
                clock.sleep(sched - now)
            s_mono, s_wall = clock.monotonic(), clock.wall()
            res = probe.probe()
            e_mono, e_wall = clock.monotonic(), clock.wall()
            # first grid slot that starts after this probe ended; slots in between are skipped
            next_k = max(k + 1, math.ceil((e_mono - t0) / cfg.interval_sec - 1e-9))
            record(event, sched, s_mono, s_wall, e_mono, e_wall, res, next_k - k - 1)
            k = next_k
            if res.ended:
                end_class = getattr(probe, "end_class", "") or res.error_class or "other"
                detail = ("server sent Connection: close" if end_class == "server_connection_close"
                          else f"{res.detail}; cause unknown (no evidence)")
                record("end", None, e_mono, e_wall, e_mono, e_wall, ProbeResult(False, end_class, detail), 0)
                ended_by = f"connection ended: {end_class}"
        if cfg.probe == "persistent" and ended_by == "duration":
            if getattr(probe, "conn", None) is not None:
                probe.conn.close()
            now_mono, now_wall = clock.monotonic(), clock.wall()
            record("end", None, now_mono, now_wall, now_mono, now_wall,
                   ProbeResult(True, "probe_stopped", "duration reached; closed by the probe"), 0)
    except KeyboardInterrupt:
        ended_by = "keyboard_interrupt"
    finally:
        f.close()

    manifest = {
        "run_id": cfg.run_id, "probe_type": cfg.probe, "attempt": attempt,
        "mode": f"dry-run: {SIMULATED}" if cfg.dry_run else "measurement",
        "records_file": os.path.basename(path),
        "started_utc": _iso(started_wall), "started_mono_s": started_mono,
        "ended_utc": _iso(clock.wall()), "ended_mono_s": clock.monotonic(), "ended_by": ended_by,
        "probes_ok": count["ok"], "probes_failed": count["failed"],
        "clock_domain": domain,
        "config": cfg.describe(),
        "notes": ["the interval is a target, not a guaranteed resolution",
                  "a failed probe ratio is not packet loss",
                  "the fault is injected manually; markers are operator signals",
                  "this script never stops VMs, changes vNICs or changes SSE configuration"],
    }
    mf, mpath, _ = create_exclusive(out_dir, f"manifest_{cfg.probe}", ".json", attempt)
    with mf:
        json.dump(manifest, mf, indent=2)
    return manifest, path


# ------------------------------------------------------------------------------
# Dry-run (synthetic, scripted outage)
# ------------------------------------------------------------------------------

class ScriptedProbe:
    """SIMULATED probe: fails between fail_from and fail_until (monotonic s), with optional flaps."""
    def __init__(self, clock, fail_from, fail_until, flaps=(), latency=0.004, fail_latency=0.25,
                 error_class="timeout", persistent=False):
        self.clock, self.fail_from, self.fail_until = clock, fail_from, fail_until
        self.flaps, self.latency, self.fail_latency = tuple(flaps), latency, fail_latency
        self.error_class, self.persistent = error_class, persistent
        self.conn = None
        self.end_class = ""

    def open(self):
        self.clock.sleep(self.latency)
        return ProbeResult(True)

    def probe(self):
        t = self.clock.monotonic()
        failing = self.fail_from <= t < self.fail_until or any(a <= t < b for a, b in self.flaps)
        if failing:
            self.clock.sleep(self.fail_latency)
            if self.persistent:
                self.end_class = self.error_class
            return ProbeResult(False, self.error_class, f"simulated {self.error_class}", None, self.persistent)
        self.clock.sleep(self.latency)
        return ProbeResult(True, "", "", 200 if self.persistent else None)


# ------------------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------------------

def _env(env, key, default=""):
    value = env.get(key)
    return default if value is None or not value.strip() else value.strip()


class RunConfig:
    def __init__(self, args, env):
        self.probe = args.probe
        self.run_id = args.run_id
        self.dry_run = args.dry_run
        self.duration_sec = args.duration_sec
        if self.probe == "persistent":
            self.interval_sec = args.persistent_interval_ms / 1000.0
        else:
            self.interval_sec = args.interval_ms / 1000.0
        self.timeout_sec = (args.tcp_timeout_ms if self.probe == "tcp" else args.http_timeout_ms) / 1000.0
        self.tcp_host, self.tcp_port = args.tcp_host, args.tcp_port
        self.http_url, self.ca_bundle = args.http_url, args.http_ca_bundle
        self.expect_status, self.expect_body = args.expect_status, args.expect_body
        self.expect_regex, self.max_body_bytes = args.expect_regex, args.max_body_bytes
        if not self.run_id or not RUN_ID_RE.match(self.run_id):
            raise ValueError("RUN_ID is required (letters, digits, '.', '_', '-')")
        if self.interval_sec <= 0 or self.timeout_sec <= 0 or self.duration_sec <= 0:
            raise ValueError("interval, timeout and duration must be positive")
        if not self.dry_run:
            if self.probe == "tcp" and not self.tcp_host:
                raise ValueError("tcp probe needs --tcp-host (FAILOVER_TCP_HOST)")
            if self.probe in ("http", "persistent"):
                if not self.http_url:
                    raise ValueError("http/persistent probe needs --http-url (FAILOVER_HTTP_URL)")
                _target(self.http_url)
                ContentCheck(self.expect_status, self.expect_body, self.expect_regex, self.max_body_bytes)

    def describe(self):
        d = {"probe": self.probe, "interval_ms": self.interval_sec * 1000, "timeout_ms": self.timeout_sec * 1000,
             "duration_sec": self.duration_sec}
        if self.probe == "tcp":
            d.update({"target": f"{self.tcp_host}:{self.tcp_port}", "new_connection_per_probe": True,
                      "includes": "name resolution + TCP connect"})
        else:
            d.update({"url": self.http_url, "expect_status": self.expect_status, "expect_body": self.expect_body,
                      "expect_regex": self.expect_regex, "max_body_bytes": self.max_body_bytes,
                      "tls_verification": "certificate and hostname verified" if self.http_url.startswith("https")
                      else "plain HTTP (no TLS)", "ca_bundle": self.ca_bundle or "system default",
                      "redirects": "not followed",
                      "new_connection_per_probe": self.probe == "http"})
        return d


def parse_args(argv, env):
    p = argparse.ArgumentParser(description="Failover availability probes (manual fault injection)")
    sub = p.add_subparsers(dest="command", required=True)
    default_out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")

    r = sub.add_parser("run", help="run one probe type")
    r.add_argument("--probe", choices=PROBE_TYPES, required=True)
    r.add_argument("--run-id", default=_env(env, "RUN_ID"))
    r.add_argument("--tcp-host", default=_env(env, "FAILOVER_TCP_HOST"))
    r.add_argument("--tcp-port", type=int, default=_env(env, "FAILOVER_TCP_PORT", "443"))
    r.add_argument("--http-url", default=_env(env, "FAILOVER_HTTP_URL"))
    r.add_argument("--http-ca-bundle", default=_env(env, "HTTP_CA_BUNDLE"))
    r.add_argument("--expect-status", type=int, default=_env(env, "FAILOVER_HTTP_EXPECT_STATUS", "200"))
    r.add_argument("--expect-body", default=_env(env, "FAILOVER_HTTP_EXPECT_BODY"))
    r.add_argument("--expect-regex", default=_env(env, "FAILOVER_HTTP_EXPECT_REGEX"))
    r.add_argument("--max-body-bytes", type=int, default=_env(env, "FAILOVER_HTTP_MAX_BODY_BYTES", "4096"))
    r.add_argument("--interval-ms", type=float, default=_env(env, "FAILOVER_INTERVAL_MS", "50"))
    r.add_argument("--persistent-interval-ms", type=float,
                   default=_env(env, "FAILOVER_PERSISTENT_INTERVAL_MS", "200"))
    r.add_argument("--tcp-timeout-ms", type=float, default=_env(env, "FAILOVER_TCP_TIMEOUT_MS", "250"))
    r.add_argument("--http-timeout-ms", type=float, default=_env(env, "FAILOVER_HTTP_TIMEOUT_MS", "1000"))
    r.add_argument("--duration-sec", type=float, default=_env(env, "FAILOVER_DURATION_SEC", "180"))
    r.add_argument("--output-dir", default=default_out)
    r.add_argument("--dry-run", action="store_true", help=f"scripted outage, no traffic ({SIMULATED})")

    m = sub.add_parser("mark", help="record an operator marker")
    m.add_argument("--run-id", default=_env(env, "RUN_ID"))
    m.add_argument("--kind", choices=MARKER_KINDS, required=True)
    m.add_argument("--note", default="")
    m.add_argument("--output-dir", default=default_out)

    a = sub.add_parser("analyze", help="evaluate one probe type")
    a.add_argument("--run-id", default=_env(env, "RUN_ID"))
    a.add_argument("--probe", choices=PROBE_TYPES, required=True)
    a.add_argument("--attempt", type=int, default=1)
    a.add_argument("--recovery-n", type=int, default=_env(env, "FAILOVER_RECOVERY_N", "10"))
    a.add_argument("--baseline-sec", type=float, default=_env(env, "FAILOVER_BASELINE_SEC", "30"))
    a.add_argument("--baseline-max-failures", type=int,
                   default=_env(env, "FAILOVER_BASELINE_MAX_FAILURES", "0"))
    a.add_argument("--baseline-max-gap-ms", type=float,
                   default=_env(env, "FAILOVER_BASELINE_MAX_GAP_MS", "1000"))
    a.add_argument("--output-dir", default=default_out)
    return p.parse_args(argv)


def build_probe(cfg, clock):
    if cfg.dry_run:
        persistent = cfg.probe == "persistent"
        return ScriptedProbe(clock, 40.0, 42.3 if not persistent else 1e9, flaps=((43.0, 43.2),) if not persistent else (),
                             fail_latency=cfg.timeout_sec if cfg.probe == "tcp" else 0.3,
                             error_class="eof" if persistent else "timeout", persistent=persistent)
    if cfg.probe == "tcp":
        return TcpProbe(cfg.tcp_host, cfg.tcp_port, cfg.timeout_sec)
    check = ContentCheck(cfg.expect_status, cfg.expect_body, cfg.expect_regex, cfg.max_body_bytes)
    cls = HttpProbe if cfg.probe == "http" else PersistentHttpProbe
    return cls(cfg.http_url, cfg.timeout_sec, check, cfg.ca_bundle)


def cmd_run(args, env, clock=None):
    cfg = RunConfig(args, env)
    clock = clock or (SimClock() if cfg.dry_run else RealClock())
    out_dir = os.path.join(args.output_dir, cfg.run_id)
    probe = build_probe(cfg, clock)
    if cfg.dry_run:
        print(f"[*] DRY-RUN ({SIMULATED}): scripted outage, no traffic")
        markers = read_markers(os.path.join(out_dir, "markers.csv"))
        if not any(m["kind"] == "fault_injected" for m in markers):   # one simulated marker per run
            sim_clock = SimClock()
            sim_clock.t = 35.0
            write_marker(args.output_dir, cfg.run_id, "fault_injected", f"{SIMULATED} (dry-run marker)",
                         sim_clock, clock_domain(sim_clock))
    print(f"[*] {cfg.probe} probe, run {cfg.run_id}: {json.dumps(cfg.describe())}")
    print("[*] Inject the fault by hand and record it with: failover_probe.py mark --kind fault_injected "
          f"--run-id {cfg.run_id}")
    manifest, path = run_probe(cfg, probe, clock, out_dir)
    if manifest["attempt"] != 1:
        print(f"[!] earlier files exist; this run was written as attempt {manifest['attempt']}")
    print(f"[+] {manifest['probes_ok']} ok / {manifest['probes_failed']} failed records -> {path}")
    return 0


def cmd_mark(args, clock=None):
    if not args.run_id or not RUN_ID_RE.match(args.run_id):
        raise ValueError("RUN_ID is required (letters, digits, '.', '_', '-')")
    clock = clock or RealClock()
    row = write_marker(args.output_dir, args.run_id, args.kind, args.note, clock, clock_domain(clock))
    print(f"[+] marker {row['marker_seq']} ({row['kind']}, {analysis.OPERATOR_SIGNAL}) at monotonic "
          f"{row['monotonic_s']} / {row['utc']}")
    return 0


def cmd_analyze(args):
    run_dir = os.path.join(args.output_dir, args.run_id)
    suffix = _suffix(args.attempt)
    records = read_records(os.path.join(run_dir, f"probes_{args.probe}{suffix}.csv"))
    with open(os.path.join(run_dir, f"manifest_{args.probe}{suffix}.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    markers = read_markers(os.path.join(run_dir, "markers.csv"))
    options = {"recovery_n": args.recovery_n, "baseline_sec": args.baseline_sec,
               "baseline_max_failures": args.baseline_max_failures,
               "baseline_max_gap_sec": args.baseline_max_gap_ms / 1000.0}
    if args.probe == "persistent":
        summary, outages = analysis.analyze_persistent(records, markers, args.run_id, manifest["clock_domain"],
                                                       **options), []
    else:
        probes = [r for r in records if r["event"] == "probe"]
        summary, outages = analysis.analyze_new_connection(probes, markers, args.run_id, manifest["clock_domain"],
                                                           manifest["config"]["interval_ms"] / 1000.0, **options)
    summary["source_records"] = manifest["records_file"]
    summary["mode"] = manifest["mode"]
    # a repeated analysis of the same records gets a .revN suffix; nothing is overwritten
    jf, jpath, rev = create_exclusive(run_dir, f"analysis_{args.probe}{suffix}", ".json", label="rev")
    with jf:
        json.dump(summary, jf, indent=2)
    if args.probe != "persistent":
        of, _, _ = create_exclusive(run_dir, f"outages_{args.probe}{suffix}", ".csv", rev, label="rev")
        with of:
            w = csv.DictWriter(of, fieldnames=OUTAGE_FIELDS, extrasaction="ignore")
            w.writeheader()
            for o in outages:
                w.writerow({**o, "error_classes": json.dumps(o["error_classes"], sort_keys=True),
                            "bracket_interval_ms": "" if o["bracket_interval_ms"] is None else o["bracket_interval_ms"]})
    print(f"[+] {args.probe}: run_validity={summary['run_validity']} -> {jpath}")
    for reason in summary["validity_reasons"]:
        print(f"    - {reason}")
    return 0


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
    """Returns 0 on success, 2 on a configuration or file error (nothing overwritten)."""
    if environ is None:
        environ = _runtime_environ(sys.argv[1:] if argv is None else argv)
    args = parse_args(argv, environ)
    try:
        if args.command == "run":
            return cmd_run(args, environ)
        if args.command == "mark":
            return cmd_mark(args)
        return cmd_analyze(args)
    except (ValueError, FileExistsError, FileNotFoundError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
