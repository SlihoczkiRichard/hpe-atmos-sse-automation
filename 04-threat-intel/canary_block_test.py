#!/usr/bin/env python3
"""
Pillar 4: canary experiment for the PERCEIVED SWG blocking latency of a custom web category change.

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

Independent of the indicator sync (sync_threat_intel.py). Only the operator's own, harmless
canary host and reference host are contacted; no live malware target is ever probed.

Prerequisites (documented, not checked by this script): a dedicated test category exists and was
assigned BY HAND to a blocking SWG rule (the Swagger has no rule operation); the reference host is
permanently blocked by such a rule; the canary host serves the canary token through the SSE/SWG
path; the TLS chain used by the SWG is trusted (HTTP_CA_BUNDLE) if it inspects TLS.

Commands
  validate-signature  probes the reference host and accepts the block signature only if every
                      probe matches it (a REAL network operation; in this round only tested offline)
  run                 baseline -> add canary to the test category -> optional Commit -> observe
                      blocking -> restore -> check stable access again
                      --commit none|after-update is mandatory; a validated signature file is required.
  restore             puts the test category back to a canary run's category_snapshot.json (e.g. after
                      an interrupted run): category id and name must match the snapshot, and it writes
                      only if the category still equals what the run wrote (otherwise restore_conflict,
                      nothing written); uncertain outcomes stop with manual recovery information.

Run sequence (probes every INTERVAL on the main thread; one API worker thread does the API steps)
  1. pre-check (GET): category id and name match, canary not yet in the category, snapshot of the
     writable fields; canary host != reference host and not in a given feed snapshot
  2. baseline: BASELINE_SEC of reachable probes -> BASELINE_OK -> worker: GET (unchanged since the
     pre-check?) -> category_snapshot.json written, fsync'ed and closed (pre-check state + the exact
     payload about to be sent) -> update (+ Commit). If the snapshot cannot be saved, nothing is written.
  3. observation until STABLE_N consecutive blocked probes or MAX_WAIT after UPDATE_SENT
  4. the restore starts only after the worker has finished the apply job; it GETs the current
     state first and writes nothing on a foreign change (RESTORE_CONFLICT)
  5. access check after RESTORE_RESPONSE: STABLE_N consecutive reachable probes or timeout
  Category restore and access restore are logged as separate results.
  Uncertain writes (timeout / connection error) are reconciled with GET only, never re-sent.
  Reported separately: execution exceptions of an API job (execution_errors, redacted: type and
  message, no traceback or headers), raw write outcomes and GET reconciliation (api_outcomes), and the
  restoration result (restore_state). If finalisation cannot finish, the run is reported incomplete.
  Whether the API accepts an empty test category (restore of an originally empty category) is not
  verified; a refusal is reported as RESTORE_REJECTED and left for manual handling.

Outputs: results/<RUN_ID>/canary[.attemptN]/ probes.csv, events.csv, api_log.jsonl,
category_snapshot.json, summary.json, manifest.json; results/<RUN_ID>/signature[.attemptN]/.
Dry-run: simulated clock, simulated API and scripted target (SIMULATED - NOT A REAL MEASUREMENT);
the dry-run executes API steps inline, so it does not model probes running during an API call.
"""

import os
import ssl
import copy
import csv
import sys
import json
import time
import signal
import socket
import argparse
import threading
import http.client
import importlib.util
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
SIMULATED = "SIMULATED - NOT A REAL MEASUREMENT"


def _load(name):
    spec = importlib.util.spec_from_file_location(f"ti_{name}", os.path.join(HERE, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ba = _load("block_analysis")
api = _load("atmos_categories")
files = _load("run_files")
feed = _load("threat_feed")

PROBE_FIELDS = ["run_id", "repetition", "seq", "phase", "scheduled_mono_s", "start_mono_s", "end_mono_s",
                "start_utc", "end_utc", "class", "http_status", "error_class", "location", "detail"]
EVENT_FIELDS = ["seq", "event", "mono_s", "utc", "detail"]
SNAPSHOT_DURABILITY_NOTE = (
    "written, fsync'ed and closed before the first category write; if it cannot be saved, nothing is "
    "written. It protects against an interruption, exception or process kill AFTER it was saved. Not "
    "guaranteed: survival of the directory entry after a power loss or OS crash (file-system dependent), "
    "storage failure, and the outcome of a write that was in flight when the process died (restore then "
    "stops on its conflict/uncertainty checks).")


# ------------------------------------------------------------------------------
# Clocks
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
        self._lock = threading.Lock()

    def monotonic(self):
        return self.t

    def wall(self):
        return self.start_wall + timedelta(seconds=self.t)

    def sleep(self, seconds):
        with self._lock:
            self.t += max(0.0, seconds)


# ------------------------------------------------------------------------------
# Canary HTTP probe (new connection per probe, no redirects)
# ------------------------------------------------------------------------------

def classify_error(exc):
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
    return "other"


def default_connection_factory(scheme, host, port, timeout, ca_bundle=""):
    if scheme == "https":
        return http.client.HTTPSConnection(host, port, timeout=timeout,
                                           context=ssl.create_default_context(cafile=ca_bundle or None))
    return http.client.HTTPConnection(host, port, timeout=timeout)


class HttpProbe:
    def __init__(self, url, timeout_sec, max_body_bytes=65536, ca_bundle="", factory=default_connection_factory):
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(f"unsupported URL {url!r}")
        self.scheme, self.host = parts.scheme, parts.hostname
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        self.timeout, self.max_body, self.ca_bundle, self._factory = timeout_sec, max_body_bytes, ca_bundle, factory

    def probe(self):
        conn = self._factory(self.scheme, self.host, self.port, self.timeout, self.ca_bundle)
        try:
            conn.request("GET", self.path, headers={"Connection": "close", "User-Agent": "canary-block-probe"})
            resp = conn.getresponse()
            body = resp.read(self.max_body + 1)[:self.max_body]
            return {"status": resp.status, "body": body, "location": resp.getheader("Location") or "",
                    "error_class": "", "detail": ""}
        except Exception as exc:
            return {"status": None, "body": b"", "location": "", "error_class": classify_error(exc),
                    "detail": f"{type(exc).__name__}: {exc}"[:200]}
        finally:
            conn.close()


# ------------------------------------------------------------------------------
# API worker
# ------------------------------------------------------------------------------

def _error_record(job, exc):
    """Structured execution error: job name, exception type and message (no traceback, no headers).
    The message is redacted by the Recorder before it is written anywhere."""
    return {"job": getattr(job, "__name__", "job"), "type": type(exc).__name__, "message": str(exc)[:500]}


class ThreadWorker:
    """Runs one job at a time on a single background thread. Execution exceptions are kept in
    `errors` (one structured record per failed job) and reported by the runner."""
    def __init__(self):
        self._thread = None
        self.errors = []

    def submit(self, job):
        if self.busy():
            raise RuntimeError("API worker is busy; jobs never overlap")

        def target():
            try:
                job()
            except Exception as exc:  # recorded, reported by the runner
                self.errors.append(_error_record(job, exc))

        self._thread = threading.Thread(target=target, name="api-worker", daemon=True)
        self._thread.start()

    def busy(self):
        return self._thread is not None and self._thread.is_alive()

    def join(self, timeout=None):
        if self._thread is not None:
            self._thread.join(timeout)
        return not self.busy()


class InlineWorker:
    """Executes the job immediately (dry-run and tests). Probes do not run during the job."""
    def __init__(self):
        self.errors = []

    def submit(self, job):
        try:
            job()
        except Exception as exc:
            self.errors.append(_error_record(job, exc))

    def busy(self):
        return False

    def join(self, timeout=None):
        return True


# ------------------------------------------------------------------------------
# Experiment
# ------------------------------------------------------------------------------

class Recorder:
    def __init__(self, directory, run_id, repetition, clock, secrets=()):
        self.clock, self.run_id, self.repetition = clock, run_id, repetition
        self._lock = threading.Lock()
        self._secrets = [s for s in secrets if s]
        self._pf = open(os.path.join(directory, "probes.csv"), "x", newline="", encoding="utf-8")
        self._ef = open(os.path.join(directory, "events.csv"), "x", newline="", encoding="utf-8")
        self._pw = csv.DictWriter(self._pf, fieldnames=PROBE_FIELDS)
        self._ew = csv.DictWriter(self._ef, fieldnames=EVENT_FIELDS)
        self._pw.writeheader()
        self._ew.writeheader()
        self.api_log = files.JsonLines(os.path.join(directory, "api_log.jsonl"))
        self.events, self.probes = {}, []
        self._event_seq = 0

    def _redact(self, text):
        for s in self._secrets:
            text = text.replace(s, "***")
        return text

    def redact_record(self, record):
        """A JSON-safe copy of record with every secret replaced by ***."""
        return json.loads(self._redact(json.dumps(record, default=str)))

    def event(self, name, mono=None, utc=None, detail=""):
        with self._lock:
            mono = self.clock.monotonic() if mono is None else mono
            utc = self.clock.wall() if utc is None else utc
            self._event_seq += 1
            rec = {"seq": self._event_seq, "event": name, "mono_s": f"{mono:.6f}", "utc": utc.isoformat(),
                   "detail": self._redact(detail)}
            self._ew.writerow(rec)
            self._ef.flush()
            self.events.setdefault(name, {"mono": mono, "utc": utc.isoformat(), "detail": rec["detail"],
                                          "seq": self._event_seq})
            print(f"    {mono:9.3f}s {name} {rec['detail']}")

    def api(self, record):
        with self._lock:
            self.api_log.write(json.loads(self._redact(json.dumps(record, default=str))))

    def probe(self, rec):
        self.probes.append(rec)
        row = {k: rec.get(k, "") for k in PROBE_FIELDS}
        row["start_mono_s"], row["end_mono_s"] = f"{rec['start_mono_s']:.6f}", f"{rec['end_mono_s']:.6f}"
        row["scheduled_mono_s"] = f"{rec['scheduled_mono_s']:.6f}"
        self._pw.writerow(row)
        self._pf.flush()

    def close(self):
        self._pf.close()
        self._ef.close()
        self.api_log.close()


class CanaryExperiment:
    def __init__(self, cfg, probe, client, clock, worker, recorder, canary, signature, snapshot_path=None):
        self.cfg, self.probe_target, self.client, self.clock = cfg, probe, client, clock
        self.worker, self.rec, self.canary, self.signature = worker, recorder, canary, signature
        self.snapshot_path = snapshot_path
        self.snapshot_state = ""     # "" (no write attempted) / saved / failed
        self.snapshot_before = None
        self.sent_payload = None
        # apply_state: applied / failed / applied_after_reconcile / not_applied / unknown /
        #   not_started_category_changed / not_started_snapshot_failed /
        #   execution_error_before_update / execution_error_after_update_attempt
        self.apply_state = ""
        self.restore_state = ""      # ... / execution_error
        self.outcome_hint = ""
        # API outcomes kept apart from execution exceptions (which the worker records)
        self.api_outcomes = {"update_raw": "not_sent", "update_reconciled": "not_needed", "commit_raw": "not_sent",
                             "restore_raw": "not_sent", "restore_verified": "not_checked",
                             "restore_commit_raw": "not_sent"}
        self._update_attempted = False
        self._apply_done = threading.Event()
        self._restore_done = threading.Event()

    def save_snapshot(self, written):
        """Writes, fsyncs and closes category_snapshot.json BEFORE the first category write. It holds
        the identity (id, name), the pre-check state and the exact payload about to be sent, which is
        what `restore` needs for its identity and conflict checks. Raises on failure."""
        if not self.snapshot_path:
            raise RuntimeError("no snapshot path configured; refusing to modify the category")
        files.write_json_durable(self.snapshot_path, {
            "schema_version": 2, "category_id": self.cfg.category_id, "run_id": self.cfg.run_id,
            "repetition": self.cfg.repetition, "before": self.snapshot_before, "written": written,
            "written_role": "intended_payload_saved_before_update", "saved_before_first_write": True,
            "saved_utc": self.clock.wall().isoformat(), "durability_note": SNAPSHOT_DURABILITY_NOTE})
        self.snapshot_state = "saved"

    def _job_failed(self, job, exc):
        """Logs an execution exception of an API job (redacted); the worker keeps the record."""
        try:
            self.rec.event("WORKER_EXCEPTION", detail=f"{job}: {type(exc).__name__}: {exc}"[:500])
        except Exception:
            pass   # the worker record still carries the error

    # --- API jobs (run on the worker) --------------------------------------------
    def _api_event(self, prefix, res):
        self.rec.event(f"{prefix}_SENT", res.sent_mono, res.sent_utc)
        self.rec.event(f"{prefix}_RESPONSE", res.response_mono, res.response_utc,
                       f"status={res.status}; uncertain={res.uncertain}; {res.error}".strip("; "))

    def precheck(self):
        current, _ = self.client.get(self.cfg.category_id)
        if current.get("name") != self.cfg.category_name:
            raise ValueError(f"category {self.cfg.category_id} is named {current.get('name')!r}, "
                             f"not {self.cfg.category_name!r}")
        included = [x.lower() for x in current.get("includedDomainsOrUrls") or []]
        self.snapshot_before = api.writable_state(current)
        return self.cfg.canary_host.lower() not in included

    def apply_job(self):
        try:
            current, _ = self.client.get(self.cfg.category_id)
            if api.writable_state(current) != self.snapshot_before:
                self.apply_state = "not_started_category_changed"
                self.rec.event("APPLY_ABORTED", detail="category changed since the pre-check; nothing written")
                return
            included = list(self.snapshot_before.get("includedDomainsOrUrls") or []) + [self.cfg.canary_host]
            payload = api.payload_from_state(self.snapshot_before, included)
            try:
                self.save_snapshot(payload)
            except Exception as exc:
                self.snapshot_state = "failed"
                self.apply_state = "not_started_snapshot_failed"
                self.rec.event("SNAPSHOT_FAILED", detail=f"{type(exc).__name__}: {exc}; nothing written"[:500])
                raise
            self.rec.event("SNAPSHOT_SAVED", detail="category_snapshot.json written and closed before the update")
            self.sent_payload = payload
            self._update_attempted = True
            res = self.client.update(self.cfg.category_id, self.sent_payload)
            self._api_event("UPDATE", res)
            state = api.write_outcome(res, 200)
            self.api_outcomes["update_raw"] = state
            if state == "uncertain":
                found, detail = api.reconcile_update(self.client, self.cfg.category_id, included)
                self.api_outcomes["update_reconciled"] = found
                state = {"applied": "applied_after_reconcile", "not_applied": "not_applied"}.get(found, "unknown")
                self.rec.event("UPDATE_RECONCILED", detail=f"{state}: {detail} (GET only, no new write)")
            self.apply_state = state
            if state not in ("applied", "applied_after_reconcile"):
                return
            if self.cfg.commit == "after-update":
                c = self.client.commit()
                self._api_event("COMMIT", c)
                self.api_outcomes["commit_raw"] = api.write_outcome(c, 204)
                if self.api_outcomes["commit_raw"] != "applied":
                    self.outcome_hint = "commit_outcome_unknown" if c.uncertain else "commit_failed"
            else:
                self.api_outcomes["commit_raw"] = "skipped"
                self.rec.event("COMMIT_SKIPPED", detail="--commit none")
        except Exception as exc:
            if self.apply_state != "not_started_snapshot_failed":
                self.apply_state = "execution_error_after_update_attempt" if self._update_attempted \
                    else "execution_error_before_update"
            self._job_failed("apply_job", exc)
            raise
        finally:
            self._apply_done.set()

    def restore_job(self):
        try:
            self._restore()
        except Exception as exc:
            self.restore_state = "execution_error"
            self._job_failed("restore_job", exc)
            raise
        finally:
            self._restore_done.set()

    def _restore(self):
        try:
            current, _ = self.client.get(self.cfg.category_id)
        except api.ApiError as exc:
            self.restore_state = "unknown"
            self.rec.event("RESTORE_STATE_UNKNOWN", detail=str(exc))
            return
        now = api.writable_state(current)
        if now == self.snapshot_before:
            self.restore_state = "not_needed"
            self.rec.event("RESTORE_NOT_NEEDED", detail="category equals the pre-check snapshot")
            return
        expected = dict(self.snapshot_before)
        if self.sent_payload:
            expected.update(self.sent_payload)
        same = all((now.get(k) or None) == (expected.get(k) or None)
                   for k in ("name", "description", "excludedDomainsOrUrls", "connectorZoneId")) and \
            api.same_entries(now.get("includedDomainsOrUrls"), expected.get("includedDomainsOrUrls"))
        if not same:
            self.restore_state = "conflict"
            self.rec.event("RESTORE_CONFLICT", detail=json.dumps({"snapshot_before": self.snapshot_before,
                                                                  "written": self.sent_payload, "current": now},
                                                                 default=str))
            return
        target = api.payload_from_state(self.snapshot_before)
        res = self.client.update(self.cfg.category_id, target)
        self._api_event("RESTORE", res)
        self.api_outcomes["restore_raw"] = api.write_outcome(res, 200)
        if res.status == 400 and not target["includedDomainsOrUrls"]:
            self.restore_state = "rejected"
            self.rec.event("RESTORE_REJECTED", detail="API refused the empty category; open point, resolve by hand")
            return
        found, detail = api.reconcile_update(self.client, self.cfg.category_id, target["includedDomainsOrUrls"])
        self.api_outcomes["restore_verified"] = found
        if found == "applied":
            self.restore_state = "restored"
            self.rec.event("CATEGORY_RESTORED", detail=detail)
        else:
            self.restore_state = "failed"
            self.rec.event("CATEGORY_RESTORE_FAILED", detail=f"{found}: {detail}")
            return
        if self.cfg.commit == "after-update":
            c = self.client.commit()
            self._api_event("RESTORE_COMMIT", c)
            self.api_outcomes["restore_commit_raw"] = api.write_outcome(c, 204)
        else:
            self.api_outcomes["restore_commit_raw"] = "skipped"

    # --- probe loop (main thread) ---------------------------------------------------
    def _probe_once(self, seq, sched, phase):
        s_mono, s_wall = self.clock.monotonic(), self.clock.wall()
        raw = self.probe_target.probe()
        e_mono, e_wall = self.clock.monotonic(), self.clock.wall()
        cls = ba.classify(raw, self.canary, self.signature)
        rec = {"run_id": self.cfg.run_id, "repetition": self.cfg.repetition, "seq": seq, "phase": phase,
               "scheduled_mono_s": sched, "start_mono_s": s_mono, "end_mono_s": e_mono,
               "start_utc": s_wall.isoformat(), "end_utc": e_wall.isoformat(), "class": cls,
               "http_status": raw.get("status") or "", "error_class": raw.get("error_class", ""),
               "location": raw.get("location", ""), "detail": raw.get("detail", "")}
        self.rec.probe(rec)
        return rec

    def run(self):
        cfg, clock = self.cfg, self.clock
        if not self.precheck():
            self.rec.event("PREVIOUSLY_BLOCKED", detail="canary host already in the test category; nothing written")
            return "previously_blocked"
        t0 = clock.monotonic()
        phase, seq, k = "baseline", 0, 0
        update_sent_at = restore_resp_at = None
        result = ""
        while True:
            sched = t0 + k * cfg.interval_sec
            now = clock.monotonic()
            if now < sched:
                clock.sleep(sched - now)
            seq += 1
            rec = self._probe_once(seq, sched, phase)
            k = max(k + 1, int((clock.monotonic() - t0) / cfg.interval_sec + 1 - 1e-9))
            now = clock.monotonic()
            probes = self.rec.probes

            if phase == "baseline":
                if rec["class"] == ba.BLOCKED:
                    self.rec.event("PREVIOUSLY_BLOCKED", detail="blocked during the baseline; nothing written")
                    return "previously_blocked"
                met, _ = ba.baseline_met(probes, rec["end_mono_s"] + 1e-9, cfg.baseline_sec, cfg.max_gap_sec)
                if met:
                    self.rec.event("BASELINE_OK", rec["end_mono_s"], datetime.fromisoformat(rec["end_utc"]),
                                   f"{cfg.baseline_sec}s reachable")
                    phase = "observe"
                    self.worker.submit(self.apply_job)
                elif now - t0 > cfg.baseline_max_wait_sec:
                    self.rec.event("BASELINE_FAILED", detail=f"no valid baseline within {cfg.baseline_max_wait_sec}s")
                    return "baseline_failed"
            elif phase == "observe":
                if update_sent_at is None and "UPDATE_SENT" in self.rec.events:
                    update_sent_at = self.rec.events["UPDATE_SENT"]["mono"]
                apply_finished = self._apply_done.is_set() and not self.worker.busy()
                if apply_finished and self.apply_state not in ("applied", "applied_after_reconcile"):
                    result = {"failed": "update_failed", "not_applied": "update_not_applied",
                              "not_started_category_changed": "update_not_started",
                              "not_started_snapshot_failed": "update_not_started_snapshot_failed",
                              "execution_error_before_update": "update_not_started_execution_error",
                              "execution_error_after_update_attempt": "update_execution_error"
                              }.get(self.apply_state, "update_uncertain")
                    phase = "restore"
                else:
                    after = [p for p in probes if update_sent_at is not None and p["start_mono_s"] >= update_sent_at]
                    _, confirmed, _ = ba.first_run(after, ba.BLOCKED, cfg.stable_n)
                    if confirmed is not None:
                        self.rec.event("STABLE_BLOCKED_CONFIRMED", confirmed["end_mono_s"],
                                       datetime.fromisoformat(confirmed["end_utc"]), f"{cfg.stable_n} consecutive")
                        phase = "restore"
                    elif update_sent_at is not None and now - update_sent_at >= cfg.max_wait_sec:
                        self.rec.event("BLOCK_WAIT_TIMEOUT", detail=f"{cfg.max_wait_sec}s after UPDATE_SENT")
                        result = "not_blocked_within_timeout"
                        phase = "restore"
            if phase == "restore":
                if self.worker.busy() or not self._apply_done.is_set():
                    continue   # never start a restore that competes with the apply job
                if not self._restore_done.is_set() and not getattr(self, "_restore_submitted", False):
                    self._restore_submitted = True
                    self.worker.submit(self.restore_job)
                if self._restore_done.is_set() and not self.worker.busy():
                    if self.restore_state not in ("restored", "not_needed"):
                        return result or f"restore_{self.restore_state}"
                    restore_resp_at = self.rec.events.get("RESTORE_RESPONSE", {}).get("mono", now)
                    phase = "recover"
            elif phase == "recover":
                after = [p for p in probes if p["start_mono_s"] >= restore_resp_at]
                _, confirmed, _ = ba.first_run(after, ba.REACHABLE, cfg.stable_n)
                if confirmed is not None:
                    self.rec.event("ACCESS_RESTORED_STABLE", confirmed["end_mono_s"],
                                   datetime.fromisoformat(confirmed["end_utc"]), f"{cfg.stable_n} consecutive reachable")
                    return result or self.outcome_hint or ""
                if now - restore_resp_at >= cfg.restore_max_wait_sec:
                    self.rec.event("ACCESS_NOT_RESTORED", detail=f"{cfg.restore_max_wait_sec}s after RESTORE_RESPONSE")
                    return result or "access_not_restored"


# ------------------------------------------------------------------------------
# Simulation (dry-run only)
# ------------------------------------------------------------------------------

class _SimResponse:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = body
        self.content = b"" if body is None else json.dumps(body).encode()

    def json(self):
        if self._body is None:
            raise ValueError("no body")
        return self._body


class SimulatedAtmosSession:
    """In-memory WebCategories/Commit for the dry-run (SIMULATED). Each request costs latency."""
    def __init__(self, clock, categories, latency=0.3):
        self.clock, self.latency = clock, latency
        self.categories = {c["id"]: copy.deepcopy(c) for c in categories}  # no shared lists, as with real JSON
        self.changes = []   # (mono, category_id, included)

    def request(self, method, url, headers=None, params=None, json=None, timeout=None):
        self.clock.sleep(self.latency)
        path = url.split("/api/v1.0", 1)[-1]
        parts = path.strip("/").split("/")
        if parts[0] == "Commit" and method == "POST":
            return _SimResponse(204)
        if parts[0] != "WebCategories":
            return _SimResponse(404, {"status": "NotFound"})
        if len(parts) == 2 and method == "GET":
            cat = self.categories.get(parts[1])
            return _SimResponse(200, copy.deepcopy(cat)) if cat else _SimResponse(404, {"status": "NotFound"})
        if len(parts) == 2 and method == "PUT":
            cat = self.categories.get(parts[1])
            if not cat:
                return _SimResponse(404, {"status": "NotFound"})
            cat.update(copy.deepcopy(json))
            self.changes.append((self.clock.monotonic(), parts[1], list(json["includedDomainsOrUrls"])))
            return _SimResponse(200, copy.deepcopy(cat))
        return _SimResponse(400, {"status": "BadRequest"})


class ScriptedCanaryTarget:
    """SIMULATED canary: blocked `effect_delay` after the canary entered the category, reachable
    `effect_delay` after it left it; a timeout and an unclassified 403 occur once at the transition."""
    def __init__(self, clock, session, category_id, canary_host, token, block_body, effect_delay=4.0):
        self.clock, self.session, self.category_id = clock, session, category_id
        self.canary_host, self.token, self.block_body, self.delay = canary_host, token, block_body, effect_delay
        self._transient = ["timeout", "403"]

    def _blocked_now(self):
        state, now = False, self.clock.monotonic()
        for t, cid, included in self.session.changes:
            if cid == self.category_id and t + self.delay <= now:
                state = self.canary_host in included
        return state

    def probe(self):
        self.clock.sleep(0.03)
        if self._blocked_now():
            if self._transient:
                kind = self._transient.pop(0)
                if kind == "timeout":
                    self.clock.sleep(1.97)
                    return {"status": None, "body": b"", "location": "", "error_class": "timeout",
                            "detail": "simulated timeout"}
                return {"status": 403, "body": b"Forbidden", "location": "", "error_class": "", "detail": ""}
            return {"status": 403, "body": self.block_body.encode(), "location": "", "error_class": "", "detail": ""}
        return {"status": 200, "body": f"canary {self.token}".encode(), "location": "", "error_class": "",
                "detail": ""}


# ------------------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------------------

def _raise_interrupt(signum, frame):
    raise KeyboardInterrupt


def _sigterm_as_interrupt():
    """Best effort: treat SIGTERM like Ctrl+C where the platform delivers it to Python."""
    try:
        return signal.signal(signal.SIGTERM, _raise_interrupt)
    except (ValueError, OSError, AttributeError):   # not in the main thread / not supported
        return None


def _restore_sigterm(previous):
    if previous is not None:
        try:
            signal.signal(signal.SIGTERM, previous)
        except (ValueError, OSError):
            pass


def _env(env, key, default=""):
    value = env.get(key)
    return default if value is None or not value.strip() else value.strip()


def parse_args(argv, env):
    p = argparse.ArgumentParser(description="Canary experiment: perceived SWG blocking latency")
    sub = p.add_subparsers(dest="command", required=True)

    def common(s):
        s.add_argument("--run-id", default=_env(env, "RUN_ID"))
        s.add_argument("--output-dir", default=os.path.join(HERE, "results"))
        s.add_argument("--block-status", default=_env(env, "SWG_BLOCK_STATUS"))
        s.add_argument("--block-body-regex", default=_env(env, "SWG_BLOCK_BODY_REGEX"))
        s.add_argument("--block-location-regex", default=_env(env, "SWG_BLOCK_LOCATION_REGEX"))
        s.add_argument("--interval-ms", type=float, default=_env(env, "CANARY_INTERVAL_MS", "500"))
        s.add_argument("--http-timeout-ms", type=float, default=_env(env, "CANARY_HTTP_TIMEOUT_MS", "2000"))
        s.add_argument("--max-body-bytes", type=int, default=_env(env, "CANARY_MAX_BODY_BYTES", "65536"))
        s.add_argument("--http-ca-bundle", default=_env(env, "HTTP_CA_BUNDLE"))
        s.add_argument("--dry-run", action="store_true", help=SIMULATED)

    v = sub.add_parser("validate-signature")
    common(v)
    v.add_argument("--reference-url", default=_env(env, "SWG_REFERENCE_URL"))
    v.add_argument("--probes", type=int, default=_env(env, "SWG_SIGNATURE_PROBES", "5"))

    r = sub.add_parser("run")
    common(r)
    r.add_argument("--canary-url", default=_env(env, "CANARY_URL"))
    r.add_argument("--canary-token", default=_env(env, "CANARY_TOKEN"))
    r.add_argument("--canary-expect-status", type=int, default=_env(env, "CANARY_EXPECT_STATUS", "200"))
    r.add_argument("--category-id", default=_env(env, "CANARY_CATEGORY_ID"))
    r.add_argument("--category-name", default=_env(env, "CANARY_CATEGORY_NAME"))
    r.add_argument("--commit", choices=("none", "after-update"), required=True)
    r.add_argument("--signature-file", default="")
    r.add_argument("--feed-file", default="", help="optional feed snapshot; the canary must not be in it")
    r.add_argument("--repetition", type=int, default=1)
    r.add_argument("--baseline-sec", type=float, default=_env(env, "CANARY_BASELINE_SEC", "30"))
    r.add_argument("--baseline-max-wait-sec", type=float, default=_env(env, "CANARY_BASELINE_MAX_WAIT_SEC", "120"))
    r.add_argument("--max-gap-ms", type=float, default=_env(env, "CANARY_MAX_GAP_MS", "1500"))
    r.add_argument("--stable-n", type=int, default=_env(env, "CANARY_STABLE_N", "10"))
    r.add_argument("--max-wait-sec", type=float, default=_env(env, "CANARY_MAX_WAIT_SEC", "600"))
    r.add_argument("--restore-max-wait-sec", type=float, default=_env(env, "CANARY_RESTORE_MAX_WAIT_SEC", "600"))
    r.add_argument("--base-url", default=_env(env, "ATMOS_BASE_URL", "https://admin-api.axissecurity.com/api/v1.0"))
    r.add_argument("--api-timeout", type=float, default=_env(env, "ATMOS_API_TIMEOUT_SEC", "15"))
    x = sub.add_parser("restore", help="restore the test category from a canary run's category_snapshot.json")
    x.add_argument("--run-id", default=_env(env, "RUN_ID"))
    x.add_argument("--output-dir", default=os.path.join(HERE, "results"))
    x.add_argument("--snapshot", required=True, help="<canary run dir>/category_snapshot.json")
    x.add_argument("--category-id", required=True, help="must match the snapshot")
    x.add_argument("--category-name", required=True, help="must match the snapshot")
    x.add_argument("--commit", choices=("none", "after-update"), required=True)
    x.add_argument("--base-url", default=_env(env, "ATMOS_BASE_URL", "https://admin-api.axissecurity.com/api/v1.0"))
    x.add_argument("--api-timeout", type=float, default=_env(env, "ATMOS_API_TIMEOUT_SEC", "15"))
    return p.parse_args(argv)


def _signature(args):
    return ba.BlockSignature(args.block_status, args.block_body_regex, args.block_location_regex)


SIM_BLOCK_PAGE = "SIMULATED SWG block page: access denied by policy"


def cmd_validate(args, env, clock=None, probe=None):
    files.check_run_id(args.run_id)
    if args.dry_run:
        args.block_body_regex = args.block_body_regex or "access denied by policy"
        args.reference_url = args.reference_url or "https://reference.canary.invalid/"
    signature = _signature(args)
    if not args.reference_url:
        raise ValueError("--reference-url (SWG_REFERENCE_URL) is required")
    clock = clock or (SimClock() if args.dry_run else RealClock())
    if probe is None:
        if args.dry_run:
            class _Ref:
                def probe(self_inner):
                    clock.sleep(0.03)
                    return {"status": 403, "body": SIM_BLOCK_PAGE.encode(), "location": "", "error_class": ""}
            probe = _Ref()
        else:
            probe = HttpProbe(args.reference_url, args.http_timeout_ms / 1000, args.max_body_bytes, args.http_ca_bundle)
    out, attempt = files.make_run_dir(args.output_dir, args.run_id, "signature")
    classes, rows = [], []
    for i in range(args.probes):
        start = clock.monotonic()
        raw = probe.probe()
        cls = ba.classify(raw, None, signature)
        classes.append(cls)
        rows.append({"seq": i + 1, "start_mono_s": start, "end_mono_s": clock.monotonic(), "class": cls,
                     "http_status": raw.get("status"), "error_class": raw.get("error_class", "")})
        clock.sleep(max(0.0, args.interval_ms / 1000 - (clock.monotonic() - start)))
    result = ba.validate_signature(classes, args.probes)
    result.update({"signature": signature.describe(), "reference_url": args.reference_url,
                   "reference_host": urlsplit(args.reference_url).hostname,
                   "mode": f"dry-run: {SIMULATED}" if args.dry_run else "measurement-support",
                   "probes": rows, "note": ba.NOT_BLOCKING_NOTE})
    files.write_json(os.path.join(out, "signature_validation.json"), result)
    print(f"[{'+' if result['validated'] else '!'}] signature validated={result['validated']} -> {out}")
    return 0 if result["validated"] else 3


class RunConfig:
    def __init__(self, args):
        self.run_id = files.check_run_id(args.run_id)
        self.repetition, self.commit = args.repetition, args.commit
        self.category_id, self.category_name = args.category_id, args.category_name
        self.canary_url = args.canary_url
        self.canary_host = (urlsplit(args.canary_url).hostname or "").lower()
        self.interval_sec, self.baseline_sec = args.interval_ms / 1000, args.baseline_sec
        self.baseline_max_wait_sec, self.max_gap_sec = args.baseline_max_wait_sec, args.max_gap_ms / 1000
        self.stable_n, self.max_wait_sec, self.restore_max_wait_sec = args.stable_n, args.max_wait_sec, \
            args.restore_max_wait_sec
        if not (self.category_id and self.category_name and self.canary_host and args.canary_token):
            raise ValueError("canary URL, canary token, category id and category name are required")
        if min(self.interval_sec, self.baseline_sec, self.max_wait_sec, self.restore_max_wait_sec) <= 0 \
                or self.stable_n < 1:
            raise ValueError("intervals, waits and stable-n must be positive")

    def describe(self):
        return {k: v for k, v in vars(self).items()}


def _check_signature_file(args, cfg):
    if not args.signature_file:
        raise ValueError("--signature-file with a validated block signature is required")
    with open(args.signature_file, encoding="utf-8") as f:
        sig = json.load(f)
    if not sig.get("validated"):
        raise ValueError("the signature file is not validated")
    if sig.get("signature") != _signature(args).describe():
        raise ValueError("the block signature differs from the validated one")
    if (sig.get("reference_host") or "").lower() == cfg.canary_host:
        raise ValueError("canary host and reference host must differ")
    if not args.dry_run and "SIMULATED" in sig.get("mode", ""):
        raise ValueError("a simulated signature validation cannot be used for a real run")
    return sig


def cmd_run(args, env, clock=None, probe=None, session=None, worker=None):
    if args.dry_run:
        args.canary_url = args.canary_url or "https://canary.canary.invalid/canary.txt"
        args.canary_token = args.canary_token or "canary-token-SIM"
        args.category_id = args.category_id or "00000000-0000-0000-0000-00000000c0de"
        args.category_name = args.category_name or "Thesis_Canary_Test"
        args.block_body_regex = args.block_body_regex or "access denied by policy"
    cfg = RunConfig(args)
    sig = _check_signature_file(args, cfg)
    if args.feed_file:
        with open(args.feed_file, encoding="utf-8") as f:
            rows, _ = feed.parse_urlhaus_csv(f.read())
        if any(feed.normalize_host(r["url"])[1] == cfg.canary_host for r in rows):
            raise ValueError("the canary host appears in the threat feed snapshot; refusing to use it")
    key = _env(env, "ATMOS_API_KEY", "dry-run-key" if args.dry_run else "")
    if not key:
        raise ValueError("ATMOS_API_KEY is required in the environment")
    clock = clock or (SimClock() if args.dry_run else RealClock())
    if args.dry_run and session is None:
        session = SimulatedAtmosSession(clock, [{"id": cfg.category_id, "name": cfg.category_name, "type": "Custom",
                                                 "description": "SIMULATED test category",
                                                 "includedDomainsOrUrls": ["placeholder.canary.invalid"],
                                                 "excludedDomainsOrUrls": []}])
    out, attempt = files.make_run_dir(args.output_dir, cfg.run_id, "canary")
    rec = Recorder(out, cfg.run_id, cfg.repetition, clock, [key])
    client = api.AtmosCategoryClient(args.base_url, key, session=session, clock=clock.monotonic, wall=clock.wall,
                                     timeout=args.api_timeout, log=rec.api)
    if probe is None:
        probe = ScriptedCanaryTarget(clock, session, cfg.category_id, cfg.canary_host, args.canary_token,
                                     SIM_BLOCK_PAGE) if args.dry_run else \
            HttpProbe(cfg.canary_url, args.http_timeout_ms / 1000, args.max_body_bytes, args.http_ca_bundle)
    worker = worker or (InlineWorker() if args.dry_run else ThreadWorker())
    snapshot_path = os.path.join(out, "category_snapshot.json")
    exp = CanaryExperiment(cfg, probe, client, clock, worker, rec,
                           ba.CanaryCheck(args.canary_expect_status, args.canary_token), _signature(args),
                           snapshot_path=snapshot_path)
    print(f"[*] canary run {cfg.run_id} repetition {cfg.repetition}{' (' + SIMULATED + ')' if args.dry_run else ''}")
    run_exception = None
    previous = _sigterm_as_interrupt()
    try:
        hint = exp.run()
    except KeyboardInterrupt:
        hint = "interrupted"
        _attempt(rec.event, "INTERRUPTED", detail="stopped by the operator or SIGTERM; check the category state "
                                                  "by hand or use the restore command")
    except Exception as exc:
        hint = "run_exception"
        run_exception = rec.redact_record(dict(_error_record(exp.run, exc), job="run"))
        _attempt(rec.event, "RUN_EXCEPTION", detail=f"{run_exception['type']}: {run_exception['message']}")
    finally:
        _restore_sigterm(previous)
        # waits for a running apply/restore job; a timeout is reported as an incomplete finalisation
        worker_finished = worker.join(timeout=args.api_timeout * 3)
        rec.close()
    return _finalise_run(args, cfg, sig, out, attempt, rec, exp, worker, hint, run_exception, worker_finished)


def _attempt(fn, *a, **k):
    try:
        fn(*a, **k)
    except Exception:
        pass


def _finalise_run(args, cfg, sig, out, attempt, rec, exp, worker, hint, run_exception, worker_finished):
    """Writes the snapshot (only if no write was attempted), summary.json and manifest.json. Every step
    is attempted even if an earlier one fails; failures are listed as finalisation problems, the run is
    then reported as incomplete (exit code 3) and the available diagnostics are kept (stderr as the
    last resort)."""
    problems = []

    def step(name, fn):
        try:
            return fn()
        except Exception as exc:
            problems.append(rec.redact_record({"step": name, "type": type(exc).__name__, "message": str(exc)[:500]}))
            return None

    if not exp.snapshot_state:
        step("snapshot_without_write", lambda: files.write_json(os.path.join(out, "category_snapshot.json"), {
            "schema_version": 2, "category_id": cfg.category_id, "run_id": cfg.run_id, "repetition": cfg.repetition,
            "before": exp.snapshot_before, "written": None, "written_role": "no_write_attempted",
            "saved_before_first_write": False, "saved_utc": datetime.now(timezone.utc).isoformat()}))
    execution_errors = [rec.redact_record(e) for e in list(worker.errors)]
    mode = f"dry-run: {SIMULATED}" if args.dry_run else "measurement"
    summary = step("analysis", lambda: ba.analyze_canary(rec.probes, rec.events, cfg.stable_n, cfg.baseline_sec,
                                                         cfg.max_gap_sec, outcome_hint=hint or exp.outcome_hint))
    if summary is None:
        summary = {"outcome": hint or "unknown", "run_validity": "not_valid",
                   "validity_reasons": ["analysis could not finish (see finalisation.problems)"],
                   "restore": {"category_state": exp.restore_state or "unknown", "access": "not_evaluated"}}
    if not worker_finished:
        summary["run_validity"] = "not_valid"
        summary.setdefault("validity_reasons", []).append(
            "API worker still running at exit: the outcome of its call is unknown; check the category or use "
            "the restore command once this process has ended")
    if execution_errors or run_exception:
        summary["run_validity"] = "not_valid"
        summary.setdefault("validity_reasons", []).append("execution exception (see execution_errors / run_exception)")

    def finalisation():
        return {"status": "complete" if worker_finished and not problems else "incomplete",
                "api_worker_finished_at_exit": worker_finished, "problems": list(problems)}

    summary.update({"apply_state": exp.apply_state, "restore_state": exp.restore_state,
                    "api_outcomes": dict(exp.api_outcomes), "execution_errors": execution_errors,
                    "run_exception": run_exception,
                    "snapshot": {"state": exp.snapshot_state or "no_write_attempted",
                                 "file": "category_snapshot.json", "durability_note": SNAPSHOT_DURABILITY_NOTE},
                    "mode": mode, "finalisation": finalisation()})
    step("summary", lambda: files.write_json(os.path.join(out, "summary.json"), summary))
    manifest = {
        "run_id": cfg.run_id, "attempt": attempt, "repetition": cfg.repetition, "mode": mode,
        "config": cfg.describe(), "commit_note": api.COMMIT_NOTE, "type_field_note": api.TYPE_FIELD_NOTE,
        "signature": sig.get("signature"), "signature_reference_host": sig.get("reference_host"),
        "rule_assignment": "operator_asserted prerequisite (no rule/policy operation in the Swagger)",
        "empty_category_note": "API acceptance of an empty test category is not verified",
        "snapshot_policy": SNAPSHOT_DURABILITY_NOTE,
        "outcome_layers": {"execution_errors": "exceptions raised while executing an API job (worker records)",
                           "api_outcomes": "raw HTTP write outcomes and GET-only reconciliation, kept separate",
                           "restore_state": "restoration result of the run itself"},
        "apply_state": exp.apply_state, "restore_state": exp.restore_state,
        "execution_errors": execution_errors, "run_exception": run_exception,
        "dry_run_limitation": "API steps run inline in the dry-run; probes do not run during them"
        if args.dry_run else ""}
    manifest["finalisation"] = finalisation()
    step("manifest", lambda: files.write_json(os.path.join(out, "manifest.json"), manifest))
    if problems:
        print("[!] finalisation incomplete; diagnostics: "
              + json.dumps({"problems": problems, "execution_errors": execution_errors,
                            "run_exception": run_exception, "apply_state": exp.apply_state,
                            "restore_state": exp.restore_state}, default=str), file=sys.stderr)
    print(f"[+] outcome={summary['outcome']} validity={summary['run_validity']} "
          f"restore={summary['restore']} -> {out}")
    return 0 if summary["run_validity"] == "valid" and worker_finished and not problems else 3


# ------------------------------------------------------------------------------
# Restore from a canary run's own snapshot (separate command)
# ------------------------------------------------------------------------------

_COMPARED = ("name", "description", "excludedDomainsOrUrls", "connectorZoneId")


def _same_state(current, expected):
    """Writable fields equal (included entries compared as a set, case-insensitive)."""
    return all((current.get(k) or None) == (expected.get(k) or None) for k in _COMPARED) and \
        api.same_entries(current.get("includedDomainsOrUrls"), expected.get("includedDomainsOrUrls"))


def restore_from_snapshot(client, category_id, before, written, commit):
    """Puts the test category back to the canary run's pre-check snapshot.

    Writes only if the current category still equals what the canary run wrote; it never overwrites a
    change made by someone else, never retries a write and never deletes anything. Returns
    (result, exit_code): 0 restored or nothing to do, 3 refused/failed (nothing or nothing more
    written), 4 outcome uncertain (check by hand)."""
    manual = {"category_id": category_id, "snapshot_before": before, "written_by_canary_run": written}
    try:
        current, _ = client.get(category_id)
    except api.ApiError as exc:
        return {"state": "state_unknown", "detail": str(exc), "manual_recovery": manual}, 4
    now = api.writable_state(current)
    manual["current"] = now
    if now.get("name") != before.get("name"):
        return {"state": "restore_conflict", "detail": "the category name changed; identity not confirmed",
                "manual_recovery": manual}, 3
    if _same_state(now, before):
        return {"state": "restore_not_needed", "detail": "category already equals the snapshot"}, 0
    if not written or not _same_state(now, written):
        return {"state": "restore_conflict",
                "detail": "current category differs from what the canary run wrote; nothing was written",
                "manual_recovery": manual}, 3
    target = api.payload_from_state(before)
    res = client.update(category_id, target)
    result = {"write": {"status": res.status, "error": res.error, "outcome": api.write_outcome(res, 200),
                        "sent_utc": res.sent_utc.isoformat(), "response_utc": res.response_utc.isoformat()}}
    if res.status == 400 and not target["includedDomainsOrUrls"]:
        result.update({"state": "restore_rejected", "detail": "API refused the empty category; open point, "
                                                              "resolve by hand", "manual_recovery": manual})
        return result, 3
    found, detail = api.reconcile_update(client, category_id, target["includedDomainsOrUrls"])
    result["verification"] = {"state": found, "detail": detail + " (GET only; no new write)"}
    if found != "applied":
        uncertain = result["write"]["outcome"] == "uncertain" or found == "unknown"
        result.update({"state": "restore_uncertain" if uncertain else "restore_failed",
                       "manual_recovery": manual})
        return result, 4 if uncertain else 3
    result["category_restored"] = True
    if commit == "after-update":
        c = client.commit()
        result["commit"] = {"status": c.status, "error": c.error, "outcome": api.write_outcome(c, 204)}
        if result["commit"]["outcome"] != "applied":
            result["state"] = f"category_restored_commit_{result['commit']['outcome']}"
            return result, 4 if c.uncertain else 3
    else:
        result["commit"] = {"outcome": "skipped (--commit none)"}
    result["state"] = "category_restored"
    result["note"] = "category state restored; check stable access to the canary separately"
    return result, 0


def cmd_restore(args, env, session=None):
    run_id = files.check_run_id(args.run_id)
    with open(args.snapshot, encoding="utf-8") as f:
        snap = json.load(f)
    category_id, before, written = snap.get("category_id"), snap.get("before"), snap.get("written")
    if snap.get("schema_version", 1) not in (1, 2):
        raise ValueError(f"unsupported snapshot schema_version {snap.get('schema_version')!r}")
    if not category_id or not isinstance(before, dict) or not before.get("name"):
        raise ValueError("the file is not a canary category snapshot (category_id / before missing)")
    if args.category_id != category_id:
        raise ValueError(f"--category-id {args.category_id!r} does not match the snapshot ({category_id!r})")
    if args.category_name != before["name"]:
        raise ValueError(f"--category-name {args.category_name!r} does not match the snapshot ({before['name']!r})")
    key = _env(env, "ATMOS_API_KEY")
    if not key:
        raise ValueError("ATMOS_API_KEY is required in the environment")
    out, attempt = files.make_run_dir(args.output_dir, run_id, "canary_restore")
    log = files.JsonLines(os.path.join(out, "api_log.jsonl"))

    def api_log(record):
        log.write(json.loads(json.dumps(record, default=str).replace(key, "***")))

    try:
        client = api.AtmosCategoryClient(args.base_url, key, session=session, timeout=args.api_timeout, log=api_log)
        result, code = restore_from_snapshot(client, category_id, before, written, args.commit)
    finally:
        log.close()
    result.update({"snapshot": os.path.abspath(args.snapshot), "commit_mode": args.commit,
                   "snapshot_schema_version": snap.get("schema_version", 1),
                   "snapshot_written_role": snap.get("written_role", "written_payload (schema 1)")})
    files.write_json(os.path.join(out, "result.json"), result)
    files.write_json(os.path.join(out, "manifest.json"), {
        "run_id": run_id, "attempt": attempt, "command": "canary restore", "category_id": category_id,
        "commit_note": api.COMMIT_NOTE, "type_field_note": api.TYPE_FIELD_NOTE,
        "rules": ["writes only if the category equals what the canary run wrote", "no retry of a write",
                  "no DELETE", "uncertain outcomes stop with manual recovery information"]})
    print(f"[{'+' if code == 0 else '!'}] canary restore: {result['state']} -> {out}")
    return code


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
    if environ is None:
        environ = _runtime_environ(sys.argv[1:] if argv is None else argv)
    args = parse_args(argv, environ)
    try:
        if args.command == "validate-signature":
            return cmd_validate(args, environ)
        if args.command == "restore":
            return cmd_restore(args, environ)
        return cmd_run(args, environ)
    except (ValueError, FileExistsError, FileNotFoundError, api.ApiError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
