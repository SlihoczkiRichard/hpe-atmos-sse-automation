"""Canary blocking experiment: classification, signature validation, timeline, experiment flow (offline).

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

The experiment runs against a simulated Admin API and a scripted canary target; validate-signature
is only exercised with simulated reference probes. No real host, SWG or API is contacted.
"""

import contextlib
import csv
import glob
import io
import json
import json as _json
import os
import signal
import socket
import tempfile
import unittest
import unittest.mock

import requests

from _helpers import OfflineTestCase, load_module

cb = load_module("04-threat-intel/canary_block_test.py", "canary_block_test")
ba = cb.ba
SECRET = "jwt-canary-secret"
SIG = ba.BlockSignature(403, "access denied by policy")
CANARY = ba.CanaryCheck(200, "tok-1")


def probe(status=None, body=b"", location="", error_class=""):
    return {"status": status, "body": body, "location": location, "error_class": error_class}


class ClassificationTests(OfflineTestCase):
    def test_classes(self):
        cases = [
            (probe(200, b"canary tok-1"), ba.REACHABLE),
            (probe(403, b"<h1>access denied by policy</h1>"), ba.BLOCKED),
            (probe(403, b"Forbidden"), ba.UNCLASSIFIED_403),
            (probe(200, b"other content"), ba.UNEXPECTED),
            (probe(error_class="timeout"), "timeout"),
            (probe(error_class="tls_error"), "tls_error"),
            (probe(error_class="dns_error"), "dns_error"),
        ]
        for p, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(ba.classify(p, CANARY, SIG), expected)

    def test_signature_needs_a_pattern_and_location_matching(self):
        with self.assertRaises(ValueError):
            ba.BlockSignature(403)
        loc = ba.BlockSignature(None, "", r"^https://block\.example\.invalid/")
        self.assertEqual(ba.classify(probe(302, b"", "https://block.example.invalid/x"), CANARY, loc), ba.BLOCKED)
        self.assertEqual(ba.classify(probe(302, b"", "https://other.invalid/"), CANARY, loc), ba.UNEXPECTED)

    def test_signature_validation_rule(self):
        self.assertTrue(ba.validate_signature([ba.BLOCKED] * 5)["validated"])
        self.assertFalse(ba.validate_signature([ba.BLOCKED] * 4)["validated"])
        bad = ba.validate_signature([ba.BLOCKED] * 4 + [ba.UNCLASSIFIED_403])
        self.assertFalse(bad["validated"])
        self.assertIn("unclassified_403", json.dumps(bad["class_counts"]))


def rec(seq, t, cls, dur=0.03):
    return {"seq": seq, "start_mono_s": t, "end_mono_s": t + dur, "start_utc": "", "end_utc": "", "class": cls}


def events(**times):
    return {k: {"mono": v, "utc": "", "seq": i} for i, (k, v) in enumerate(times.items())}


class TimelineTests(OfflineTestCase):
    def series(self, classes, start=0.0, step=0.5):
        return [rec(i + 1, start + i * step, c) for i, c in enumerate(classes)]

    def test_negative_offsets_are_kept_and_order_preserved(self):
        # blocking is visible at 31.0 s although the update response only arrives at 31.4 s
        probes = self.series([ba.REACHABLE] * 62 + [ba.BLOCKED] * 12)
        ev = events(BASELINE_OK=30.03, UPDATE_SENT=30.5, UPDATE_RESPONSE=31.4, COMMIT_SENT=31.4, COMMIT_RESPONSE=31.7)
        s = ba.analyze_canary(probes, ev, stable_n=10)
        lat = s["observed_blocking_latency_ms"]
        self.assertEqual(lat["from_update_sent"]["first_blocked_start_ms"], 500.0)
        self.assertEqual(lat["from_update_response"]["first_blocked_start_ms"], -400.0)
        self.assertEqual(lat["from_commit_response"]["first_blocked_end_ms"], -670.0)
        order = s["event_order"]
        self.assertLess(order.index("FIRST_BLOCKED_PROBE_START"), order.index("UPDATE_RESPONSE"))
        self.assertLess(order.index("UPDATE_RESPONSE"), order.index("COMMIT_SENT"))   # tie keeps record order
        self.assertIn("negative values are kept", s["observed_blocking_latency_note"])

    def test_first_block_and_stable_run_are_separate(self):
        probes = self.series([ba.REACHABLE] * 62 + [ba.BLOCKED, ba.UNCLASSIFIED_403, "timeout"] + [ba.BLOCKED] * 10)
        s = ba.analyze_canary(probes, events(BASELINE_OK=30.03, UPDATE_SENT=30.5), stable_n=10)
        tl = s["timeline"]
        self.assertEqual(tl["T_first_blocked"]["seq"], 63)
        self.assertEqual(tl["stable_run_first"]["seq"], 66)
        self.assertEqual(tl["stable_run_confirmed"]["seq"], 75)
        self.assertEqual(s["outcome"], "blocked_stable")
        self.assertEqual(s["classes_before_first_block"], {ba.REACHABLE: 1})

    def test_outcomes(self):
        ev = events(BASELINE_OK=30.03, UPDATE_SENT=30.5)
        unstable = ba.analyze_canary(self.series([ba.REACHABLE] * 62 + [ba.BLOCKED, ba.REACHABLE] * 6), ev)
        self.assertEqual(unstable["outcome"], "blocked_unstable")
        only_403 = ba.analyze_canary(self.series([ba.REACHABLE] * 62 + [ba.UNCLASSIFIED_403] * 30), ev)
        self.assertEqual((only_403["outcome"], only_403["run_validity"]), ("not_blocked_within_timeout", "not_valid"))
        early = ba.analyze_canary(self.series([ba.REACHABLE] * 30 + [ba.BLOCKED] * 50), ev)
        self.assertEqual(early["outcome"], "previously_blocked")

    def test_restore_results_are_separate(self):
        classes = [ba.REACHABLE] * 62 + [ba.BLOCKED] * 10 + [ba.BLOCKED] * 4 + [ba.REACHABLE] * 10
        ev = events(BASELINE_OK=30.03, UPDATE_SENT=30.5, RESTORE_SENT=36.2, RESTORE_RESPONSE=36.5,
                    CATEGORY_RESTORED=36.8)
        r = ba.analyze_canary(self.series(classes), ev)["restore"]
        self.assertEqual((r["category_state"], r["access"]), ("CATEGORY_RESTORED", "restored_stable"))
        r2 = ba.analyze_canary(self.series(classes[:-5]), ev)["restore"]
        self.assertEqual((r2["category_state"], r2["access"]), ("CATEGORY_RESTORED", "not_restored_within_observation"))


class ExperimentTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name

    def quiet(self, fn, *a, **k):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            code = fn(*a, **k)
        return code, err.getvalue()

    def signature_file(self):
        args = cb.parse_args(["validate-signature", "--run-id", "R1", "--dry-run", "--output-dir", self.dir], {})
        self.assertEqual(self.quiet(cb.cmd_validate, args, {})[0], 0)
        return glob.glob(os.path.join(self.dir, "R1", "signature*", "signature_validation.json"))[-1]

    def run_exp(self, *extra, session=None, env=None, included=("placeholder.canary.invalid",), probe=None):
        args = cb.parse_args(["run", "--run-id", "R1", "--dry-run", "--signature-file", self.signature_file(),
                              "--output-dir", self.dir, *extra], {})
        clock = cb.SimClock()
        if session is None:
            session = cb.SimulatedAtmosSession(clock, [{
                "id": "00000000-0000-0000-0000-00000000c0de", "name": "Thesis_Canary_Test", "type": "Custom",
                "description": "SIMULATED", "includedDomainsOrUrls": list(included), "excludedDomainsOrUrls": []}])
        else:
            session.clock = clock
        code, err = self.quiet(cb.cmd_run, args, env or {"ATMOS_API_KEY": SECRET}, clock=clock, session=session,
                               probe=probe)
        out = sorted(glob.glob(os.path.join(self.dir, "R1", "canary*")))[-1]
        with open(os.path.join(out, "summary.json"), encoding="utf-8") as f:
            summary = json.load(f)
        with open(os.path.join(out, "events.csv"), encoding="utf-8") as f:
            names = [r["event"] for r in csv.DictReader(f)]
        api_log = []
        with open(os.path.join(out, "api_log.jsonl"), encoding="utf-8") as f:
            api_log = [json.loads(line) for line in f]
        return code, summary, names, api_log, session, out

    def test_full_sequence_with_commit(self):
        code, s, names, api_log, session, out = self.run_exp("--commit", "after-update")
        self.assertEqual((code, s["outcome"], s["run_validity"]), (0, "blocked_stable", "valid"))
        for a, b in (("BASELINE_OK", "UPDATE_SENT"), ("UPDATE_RESPONSE", "COMMIT_SENT"),
                     ("STABLE_BLOCKED_CONFIRMED", "RESTORE_SENT"), ("CATEGORY_RESTORED", "ACCESS_RESTORED_STABLE")):
            self.assertLess(names.index(a), names.index(b))
        self.assertEqual((s["restore"]["category_state"], s["restore"]["access"]), ("CATEGORY_RESTORED",
                                                                                   "restored_stable"))
        puts = [r for r in api_log if r["method"] == "PUT"]
        self.assertEqual([p["payload"]["includedDomainsOrUrls"] for p in puts],
                         [["placeholder.canary.invalid", "canary.canary.invalid"], ["placeholder.canary.invalid"]])
        self.assertTrue(all("type" not in p["payload"] for p in puts))
        self.assertNotIn("DELETE", [r["method"] for r in api_log])
        self.assertIn("SIMULATED", s["mode"])
        for path in glob.glob(os.path.join(out, "*")):
            with open(path, encoding="utf-8") as f:
                self.assertNotIn(SECRET, f.read())

    def test_commit_none_is_explicit(self):
        code, s, names, api_log, _, _ = self.run_exp("--commit", "none")
        self.assertIn("COMMIT_SKIPPED", names)
        self.assertNotIn("/Commit", [r["path"] for r in api_log])
        self.assertEqual(s["timeline"]["commit"], "skipped")
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cb.parse_args(["run", "--run-id", "R1"], {})

    def test_previously_blocked_writes_nothing(self):
        code, s, names, api_log, _, _ = self.run_exp("--commit", "none", included=("canary.canary.invalid",))
        self.assertEqual(code, 3)
        self.assertIn("PREVIOUSLY_BLOCKED", names)
        self.assertNotIn("PUT", [r["method"] for r in api_log])

    def test_restore_conflict_is_not_overwritten(self):
        class Foreign(cb.SimulatedAtmosSession):
            def request(self, method, url, **kw):
                resp = super().request(method, url, **kw)
                if method == "PUT" and not getattr(self, "_done", False):
                    self._done = True
                    next(iter(self.categories.values()))["includedDomainsOrUrls"].append("foreign.example.invalid")
                return resp
        session = Foreign(None, [{"id": "00000000-0000-0000-0000-00000000c0de", "name": "Thesis_Canary_Test",
                                  "description": "SIMULATED", "includedDomainsOrUrls": ["x.canary.invalid"],
                                  "excludedDomainsOrUrls": []}])
        code, s, names, api_log, _, _ = self.run_exp("--commit", "none", session=session)
        self.assertIn("RESTORE_CONFLICT", names)
        self.assertEqual(s["restore"]["category_state"], "RESTORE_CONFLICT")
        self.assertEqual(len([r for r in api_log if r["method"] == "PUT"]), 1)   # no restore write
        self.assertNotIn("ACCESS_RESTORED_STABLE", names)

    def test_uncertain_update_reconciled_without_second_write(self):
        class Flaky(cb.SimulatedAtmosSession):
            def request(self, method, url, **kw):
                resp = super().request(method, url, **kw)
                if method == "PUT" and not getattr(self, "_done", False):
                    self._done = True
                    raise requests.Timeout("timed out after the server applied it")
                return resp
        session = Flaky(None, [{"id": "00000000-0000-0000-0000-00000000c0de", "name": "Thesis_Canary_Test",
                                "description": "SIMULATED", "includedDomainsOrUrls": ["x.canary.invalid"],
                                "excludedDomainsOrUrls": []}])
        code, s, names, api_log, _, _ = self.run_exp("--commit", "none", session=session)
        self.assertIn("UPDATE_RECONCILED", names)
        self.assertEqual(s["apply_state"], "applied_after_reconcile")
        canary_puts = [r for r in api_log if r["method"] == "PUT" and
                       "canary.canary.invalid" in r["payload"]["includedDomainsOrUrls"]]
        self.assertEqual(len(canary_puts), 1)

    def test_empty_category_restore_refusal_stays_open(self):
        class RejectEmpty(cb.SimulatedAtmosSession):
            def request(self, method, url, headers=None, params=None, json=None, timeout=None):
                if method == "PUT" and not json["includedDomainsOrUrls"]:
                    self.clock.sleep(self.latency)
                    return cb._SimResponse(400, {"status": "BadRequest"})
                return super().request(method, url, headers=headers, params=params, json=json, timeout=timeout)
        session = RejectEmpty(None, [{"id": "00000000-0000-0000-0000-00000000c0de", "name": "Thesis_Canary_Test",
                                      "description": "SIMULATED", "includedDomainsOrUrls": [],
                                      "excludedDomainsOrUrls": []}])
        code, s, names, _, _, _ = self.run_exp("--commit", "none", session=session)
        self.assertIn("RESTORE_REJECTED", names)
        self.assertEqual(s["restore"]["category_state"], "RESTORE_REJECTED")

    def test_signature_and_target_preconditions(self):
        sig = self.signature_file()
        cases = [
            ([], "signature-file"),
            (["--signature-file", sig, "--block-body-regex", "different"], "differs"),
        ]
        for extra, text in cases:
            with self.subTest(text=text):
                code, err = self.quiet(cb.main, ["run", "--run-id", "R1", "--dry-run", "--commit", "none",
                                                 "--output-dir", self.dir, *extra], {"ATMOS_API_KEY": SECRET})
                self.assertEqual(code, 2)
                self.assertIn(text, err)
        # a simulated validation cannot be used for a real run (fails before any network use)
        code, err = self.quiet(cb.main, ["run", "--run-id", "R1", "--commit", "none", "--signature-file", sig,
                                         "--canary-url", "https://canary.example.invalid/c", "--canary-token", "t",
                                         "--category-id", "c", "--category-name", "n",
                                         "--block-body-regex", "access denied by policy", "--output-dir", self.dir],
                               {"ATMOS_API_KEY": SECRET})
        self.assertEqual(code, 2)
        self.assertIn("simulated signature", err)
        feed = os.path.join(self.dir, "feed.csv")
        with open(feed, "w", encoding="utf-8") as f:
            f.write('"1","2026-10-26 10:00:00","http://canary.canary.invalid/x","online","","","","",""\n')
        code, err = self.quiet(cb.main, ["run", "--run-id", "R1", "--dry-run", "--commit", "none", "--signature-file",
                                         sig, "--feed-file", feed, "--output-dir", self.dir], {"ATMOS_API_KEY": SECRET})
        self.assertEqual(code, 2)
        self.assertIn("appears in the threat feed", err)


class ThreadWorkerTests(OfflineTestCase):
    """Real threads and a real clock (about 3 s), all components simulated: probes continue while the
    API worker waits for a (simulated) slow API, and the restore never overlaps the apply job."""

    def test_probes_continue_during_api_calls(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        sig_path = os.path.join(tmp.name, "sig.json")
        with open(sig_path, "w", encoding="utf-8") as f:
            json.dump({"validated": True, "signature": SIG.describe(), "reference_host": "reference.canary.invalid",
                       "mode": "measurement-support (fixture)"}, f)
        args = cb.parse_args(["run", "--run-id", "RT", "--commit", "after-update", "--signature-file", sig_path,
                              "--canary-url", "https://canary.canary.invalid/c", "--canary-token", "tok-1",
                              "--category-id", "cat-1", "--category-name", "Thesis_Canary_Test",
                              "--block-status", "403", "--block-body-regex", "access denied by policy",
                              "--interval-ms", "20", "--baseline-sec", "0.2", "--max-gap-ms", "200",
                              "--stable-n", "3", "--max-wait-sec", "10", "--restore-max-wait-sec", "10",
                              "--output-dir", tmp.name], {})
        clock = cb.RealClock()
        session = cb.SimulatedAtmosSession(clock, [{"id": "cat-1", "name": "Thesis_Canary_Test", "description": "",
                                                    "includedDomainsOrUrls": ["x.canary.invalid"],
                                                    "excludedDomainsOrUrls": []}], latency=0.25)
        target = cb.ScriptedCanaryTarget(clock, session, "cat-1", "canary.canary.invalid", "tok-1",
                                         "access denied by policy", effect_delay=0.1)
        target._transient = []

        class Tick:
            def probe(self_inner):
                clock.sleep(0.01)
                r = target.probe()
                return r
        with contextlib.redirect_stdout(io.StringIO()):
            code = cb.cmd_run(args, {"ATMOS_API_KEY": SECRET}, clock=clock, session=session, probe=Tick(),
                              worker=cb.ThreadWorker())
        out = glob.glob(os.path.join(tmp.name, "RT", "canary*"))[0]
        with open(os.path.join(out, "summary.json"), encoding="utf-8") as f:
            s = json.load(f)
        with open(os.path.join(out, "events.csv"), encoding="utf-8") as f:
            ev = {r["event"]: float(r["mono_s"]) for r in csv.DictReader(f)}
        with open(os.path.join(out, "probes.csv"), encoding="utf-8") as f:
            starts = [float(r["start_mono_s"]) for r in csv.DictReader(f)]
        during_update = [t for t in starts if ev["UPDATE_SENT"] <= t <= ev["UPDATE_RESPONSE"]]
        self.assertGreaterEqual(len(during_update), 3, "probes must keep running during the API call")
        self.assertGreaterEqual(ev["RESTORE_SENT"], ev["COMMIT_RESPONSE"])     # restore after the apply job
        self.assertEqual((code, s["outcome"], s["restore"]["access"]), (0, "blocked_stable", "restored_stable"))


class HttpProbeTests(OfflineTestCase):
    def test_errors_and_location(self):
        class Conn:
            def __init__(self, exc=None, status=302, location="https://block.invalid/"):
                self.exc, self.status, self.location = exc, status, location

            def request(self, *a, **k):
                if self.exc:
                    raise self.exc

            def getresponse(self):
                conn = self

                class R:
                    status = conn.status

                    def read(self, n):
                        return b"x" * 10

                    def getheader(self, name):
                        return conn.location if name == "Location" else None
                return R()

            def close(self):
                pass

        for exc, cls in ((socket.gaierror(-2, "x"), "dns_error"), (socket.timeout(), "timeout"),
                         (ConnectionResetError(), "reset")):
            p = cb.HttpProbe("https://canary.invalid/", 2.0, factory=lambda *a, exc=exc: Conn(exc))
            self.assertEqual(p.probe()["error_class"], cls)
        r = cb.HttpProbe("https://canary.invalid/", 2.0, max_body_bytes=4, factory=lambda *a: Conn()).probe()
        self.assertEqual((r["status"], r["location"], r["body"]), (302, "https://block.invalid/", b"xxxx"))


class CanaryRestoreTests(OfflineTestCase):
    """restore command for a canary run's own category_snapshot.json (simulated API, no network)."""

    BEFORE = {"name": "Thesis_Canary_Test", "description": "test", "includedDomainsOrUrls": ["x.canary.invalid"],
              "excludedDomainsOrUrls": []}
    WRITTEN = dict(BEFORE, includedDomainsOrUrls=["x.canary.invalid", "canary.canary.invalid"])

    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name

    def snapshot(self, written="default"):
        path = os.path.join(self.dir, f"snap_{len(os.listdir(self.dir))}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"category_id": "cat-1", "before": self.BEFORE,
                       "written": self.WRITTEN if written == "default" else written}, f)
        return path

    def session(self, included, cls=None):
        clock = cb.SimClock()
        cat = dict(self.BEFORE, id="cat-1", type="Custom", includedDomainsOrUrls=list(included))
        return (cls or cb.SimulatedAtmosSession)(clock, [cat])

    def restore(self, session, snap, *extra, commit="after-update"):
        args = cb.parse_args(["restore", "--run-id", "RS-1", "--snapshot", snap, "--category-id", "cat-1",
                              "--category-name", "Thesis_Canary_Test", "--commit", commit, "--output-dir", self.dir,
                              *extra], {})
        with contextlib.redirect_stdout(io.StringIO()):
            code = cb.cmd_restore(args, {"ATMOS_API_KEY": SECRET}, session=session)
        out = sorted(glob.glob(os.path.join(self.dir, "RS-1", "canary_restore*")))[-1]
        with open(os.path.join(out, "result.json"), encoding="utf-8") as f:
            result = json.load(f)
        with open(os.path.join(out, "api_log.jsonl"), encoding="utf-8") as f:
            log = [json.loads(line) for line in f]
        return code, result, log

    def test_restores_the_state_written_by_the_run(self):
        session = self.session(self.WRITTEN["includedDomainsOrUrls"])
        code, result, log = self.restore(session, self.snapshot())
        self.assertEqual((code, result["state"], result["category_restored"]), (0, "category_restored", True))
        self.assertEqual(session.categories["cat-1"]["includedDomainsOrUrls"], ["x.canary.invalid"])
        puts = [r for r in log if r["method"] == "PUT"]
        self.assertEqual(len(puts), 1)
        self.assertNotIn("type", puts[0]["payload"])
        self.assertEqual([r["method"] for r in log].count("DELETE"), 0)
        self.assertEqual(log[-1]["path"], "/Commit")
        self.assertNotIn(SECRET, json.dumps(log))

    def test_nothing_to_do(self):
        code, result, log = self.restore(self.session(self.BEFORE["includedDomainsOrUrls"]), self.snapshot())
        self.assertEqual((code, result["state"]), (0, "restore_not_needed"))
        self.assertNotIn("PUT", [r["method"] for r in log])

    def test_foreign_change_is_never_overwritten(self):
        for included, written in ((["x.canary.invalid", "canary.canary.invalid", "foreign.example.invalid"],
                                   "default"),
                                  (["x.canary.invalid", "canary.canary.invalid"], None)):   # nothing known written
            with self.subTest(written=written):
                session = self.session(included)
                code, result, log = self.restore(session, self.snapshot(written))
                self.assertEqual((code, result["state"]), (3, "restore_conflict"))
                self.assertIn("manual_recovery", result)
                self.assertNotIn("PUT", [r["method"] for r in log])
                self.assertEqual(session.categories["cat-1"]["includedDomainsOrUrls"], included)

    def test_identity_must_match_the_snapshot(self):
        session = self.session(self.WRITTEN["includedDomainsOrUrls"])
        snap = self.snapshot()
        for extra in (["--category-id", "cat-2"], ["--category-name", "Other"]):
            args = cb.parse_args(["restore", "--run-id", "RS-1", "--snapshot", snap, "--category-id", "cat-1",
                                  "--category-name", "Thesis_Canary_Test", "--commit", "none",
                                  "--output-dir", self.dir, *extra], {})
            with self.subTest(extra=extra), self.assertRaisesRegex(ValueError, "does not match the snapshot"):
                cb.cmd_restore(args, {"ATMOS_API_KEY": SECRET}, session=session)
        self.assertEqual(session.changes, [])

    def test_uncertain_write_stops_with_manual_information(self):
        class TimeoutNotApplied(cb.SimulatedAtmosSession):
            def request(self, method, url, **kw):
                if method == "PUT":
                    raise requests.Timeout("timed out")
                return super().request(method, url, **kw)
        session = self.session(self.WRITTEN["includedDomainsOrUrls"], TimeoutNotApplied)
        code, result, log = self.restore(session, self.snapshot())
        self.assertEqual((code, result["state"]), (4, "restore_uncertain"))
        self.assertEqual(result["write"]["outcome"], "uncertain")
        self.assertIn("manual_recovery", result)
        self.assertEqual([r["method"] for r in log].count("PUT"), 1)        # never retried

    def test_empty_category_refusal_stays_open(self):
        class RejectEmpty(cb.SimulatedAtmosSession):
            def request(self, method, url, headers=None, params=None, json=None, timeout=None):
                if method == "PUT" and not json["includedDomainsOrUrls"]:
                    return cb._SimResponse(400, {"status": "BadRequest"})
                return super().request(method, url, headers=headers, params=params, json=json, timeout=timeout)
        before, written = dict(self.BEFORE, includedDomainsOrUrls=[]), dict(self.BEFORE,
                                                                             includedDomainsOrUrls=["canary.canary.invalid"])
        path = os.path.join(self.dir, "snap_empty.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"category_id": "cat-1", "before": before, "written": written}, f)
        code, result, _ = self.restore(self.session(["canary.canary.invalid"], RejectEmpty), path, commit="none")
        self.assertEqual((code, result["state"]), (3, "restore_rejected"))


CAT_ID = "00000000-0000-0000-0000-00000000c0de"


def _category(included=("x.canary.invalid",)):
    return [{"id": CAT_ID, "name": "Thesis_Canary_Test", "description": "SIMULATED",
             "includedDomainsOrUrls": list(included), "excludedDomainsOrUrls": []}]


def failing_session(fail_on):
    """Simulated API that raises fail_on(method, url, calls) when it returns an exception
    (calls counts the requests per method, including the failing one)."""
    class Failing(cb.SimulatedAtmosSession):
        def request(self, method, url, headers=None, params=None, json=None, timeout=None):
            self.calls = getattr(self, "calls", {})
            self.calls[method] = self.calls.get(method, 0) + 1
            exc = fail_on(method, url, self.calls)
            if exc is not None:
                raise exc
            return super().request(method, url, headers=headers, params=params, json=json, timeout=timeout)
    return Failing


class SnapshotAndWorkerErrorTests(OfflineTestCase):
    """G1: the restoration snapshot exists (closed) before the first category write, and a failed
    snapshot prevents the write. G2: execution exceptions of the API jobs are reported (redacted) apart
    from raw/reconciled API outcomes and the restoration result. Inline worker, simulated API."""

    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name

    quiet = ExperimentTests.quiet
    signature_file = ExperimentTests.signature_file
    run_exp = ExperimentTests.run_exp

    def read(self, out, name):
        with open(os.path.join(out, name), encoding="utf-8") as f:
            return json.load(f)

    def all_text(self, out):
        text = ""
        for name in os.listdir(out):
            with open(os.path.join(out, name), encoding="utf-8") as f:
                text += f.read()
        return text

    def restore_cmd(self, out, session):
        args = cb.parse_args(["restore", "--run-id", "RS-1", "--snapshot", os.path.join(out, "category_snapshot.json"),
                              "--category-id", CAT_ID, "--category-name", "Thesis_Canary_Test", "--commit", "none",
                              "--output-dir", self.dir], {})
        with contextlib.redirect_stdout(io.StringIO()):
            code = cb.cmd_restore(args, {"ATMOS_API_KEY": SECRET}, session=session)
        res_dir = sorted(glob.glob(os.path.join(self.dir, "RS-1", "canary_restore*")))[-1]
        return code, self.read(res_dir, "result.json")

    # --- G1 -------------------------------------------------------------------------
    def test_snapshot_is_saved_and_closed_before_the_update(self):
        seen = {}
        test_dir = self.dir

        class Check(cb.SimulatedAtmosSession):
            def request(self, method, url, headers=None, params=None, json=None, timeout=None):
                if method == "PUT" and "canary.canary.invalid" in json["includedDomainsOrUrls"]:
                    path = glob.glob(os.path.join(test_dir, "R1", "canary*", "category_snapshot.json"))
                    with open(path[0], encoding="utf-8") as f:
                        seen["snapshot"] = _json.load(f)      # complete, parseable file at PUT time
                    seen["payload"] = json
                return super().request(method, url, headers=headers, params=params, json=json, timeout=timeout)
        code, s, names, _, _, out = self.run_exp("--commit", "none", session=Check(None, _category()))
        snap = seen["snapshot"]
        self.assertEqual((snap["schema_version"], snap["category_id"], snap["saved_before_first_write"]),
                         (2, CAT_ID, True))
        self.assertEqual(snap["before"]["includedDomainsOrUrls"], ["x.canary.invalid"])
        self.assertEqual(snap["written"], seen["payload"])          # the exact payload sent afterwards
        self.assertLess(names.index("SNAPSHOT_SAVED"), names.index("UPDATE_SENT"))
        self.assertEqual((code, s["snapshot"]["state"], s["execution_errors"]), (0, "saved", []))
        self.assertEqual(s["finalisation"]["status"], "complete")

    def test_snapshot_failure_prevents_the_update(self):
        session = cb.SimulatedAtmosSession(None, _category())
        with unittest.mock.patch.object(cb.files, "write_json_durable", side_effect=OSError("disk full")):
            code, s, names, api_log, _, out = self.run_exp("--commit", "after-update", session=session)
        self.assertNotIn("PUT", [r["method"] for r in api_log])
        self.assertEqual(session.categories[CAT_ID]["includedDomainsOrUrls"], ["x.canary.invalid"])
        self.assertIn("SNAPSHOT_FAILED", names)
        self.assertNotIn("UPDATE_SENT", names)
        self.assertEqual((s["apply_state"], s["outcome"], s["snapshot"]["state"]),
                         ("not_started_snapshot_failed", "update_not_started_snapshot_failed", "failed"))
        self.assertEqual(s["api_outcomes"]["update_raw"], "not_sent")
        self.assertEqual([(e["job"], e["type"]) for e in s["execution_errors"]], [("apply_job", "OSError")])
        self.assertEqual((code, s["run_validity"], s["restore_state"]), (3, "not_valid", "not_needed"))
        self.assertFalse(os.path.exists(os.path.join(out, "category_snapshot.json")))

    def _crash_after_update(self, exc):
        session = cb.SimulatedAtmosSession(None, _category())

        class Crash:
            def probe(self):
                if session.changes:
                    raise exc
                return {"status": 200, "body": b"canary canary-token-SIM", "location": "", "error_class": "",
                        "detail": ""}
        code, s, names, _, _, out = self.run_exp("--commit", "none", session=session, probe=Crash())
        return code, s, names, out, session

    def test_unexpected_exception_after_update_keeps_a_usable_snapshot(self):
        code, s, names, out, session = self._crash_after_update(RuntimeError(f"probe crashed {SECRET}"))
        self.assertEqual((code, s["outcome"], s["run_validity"]), (3, "run_exception", "not_valid"))
        self.assertEqual(s["run_exception"]["type"], "RuntimeError")
        self.assertIn("RUN_EXCEPTION", names)
        self.assertNotIn(SECRET, self.all_text(out))
        self.assertEqual(self.read(out, "manifest.json")["run_exception"]["type"], "RuntimeError")
        self.assertIn("canary.canary.invalid", session.categories[CAT_ID]["includedDomainsOrUrls"])
        code, result = self.restore_cmd(out, session)                # recovery with the saved snapshot
        self.assertEqual((code, result["state"], result["snapshot_schema_version"]), (0, "category_restored", 2))
        self.assertEqual(session.categories[CAT_ID]["includedDomainsOrUrls"], ["x.canary.invalid"])

    def test_interrupt_after_update_keeps_a_usable_snapshot(self):
        code, s, names, out, session = self._crash_after_update(KeyboardInterrupt())
        self.assertEqual((code, s["outcome"], s["snapshot"]["state"]), (3, "interrupted", "saved"))
        self.assertIn("INTERRUPTED", names)
        self.assertEqual(self.restore_cmd(out, session)[1]["state"], "category_restored")

    def test_sigterm_is_handled_like_ctrl_c(self):
        if not hasattr(signal, "SIGTERM"):
            self.skipTest("no SIGTERM on this platform")
        before = signal.getsignal(signal.SIGTERM)
        previous = cb._sigterm_as_interrupt()
        try:
            self.assertIs(signal.getsignal(signal.SIGTERM), cb._raise_interrupt)
            with self.assertRaises(KeyboardInterrupt):
                cb._raise_interrupt(signal.SIGTERM, None)
        finally:
            cb._restore_sigterm(previous)
        self.assertEqual(signal.getsignal(signal.SIGTERM), before)

    def test_run_without_write_records_a_no_write_snapshot_once(self):
        code, s, names, api_log, _, out = self.run_exp("--commit", "none", included=("canary.canary.invalid",))
        snap = self.read(out, "category_snapshot.json")
        self.assertEqual((snap["written"], snap["written_role"], snap["saved_before_first_write"]),
                         (None, "no_write_attempted", False))
        self.assertEqual((s["snapshot"]["state"], s["finalisation"]["status"]), ("no_write_attempted", "complete"))

    def test_restore_refuses_an_unknown_snapshot_schema(self):
        path = os.path.join(self.dir, "snap.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"schema_version": 9, "category_id": CAT_ID, "before": {"name": "Thesis_Canary_Test"}}, f)
        args = cb.parse_args(["restore", "--run-id", "RS-1", "--snapshot", path, "--category-id", CAT_ID,
                              "--category-name", "Thesis_Canary_Test", "--commit", "none", "--output-dir", self.dir], {})
        with self.assertRaisesRegex(ValueError, "schema_version"):
            cb.cmd_restore(args, {"ATMOS_API_KEY": SECRET}, session=cb.SimulatedAtmosSession(cb.SimClock(), []))

    # --- G2 -------------------------------------------------------------------------
    def test_apply_exception_before_the_update_is_reported_not_reconciled(self):
        cls = failing_session(lambda m, u, c: ValueError(f"broken GET body {SECRET}")
                              if m == "GET" and c["GET"] == 2 else None)
        code, s, names, api_log, session, out = self.run_exp("--commit", "after-update", session=cls(None, _category()))
        self.assertEqual((s["apply_state"], s["outcome"]),
                         ("execution_error_before_update", "update_not_started_execution_error"))
        err = s["execution_errors"]
        self.assertEqual([(e["job"], e["type"]) for e in err], [("apply_job", "ValueError")])
        self.assertIn("***", err[0]["message"])
        self.assertEqual(self.read(out, "manifest.json")["execution_errors"], err)
        self.assertEqual((s["api_outcomes"]["update_raw"], s["api_outcomes"]["update_reconciled"]),
                         ("not_sent", "not_needed"))
        self.assertIn("WORKER_EXCEPTION", names)
        self.assertNotIn("PUT", [r["method"] for r in api_log])
        self.assertEqual((s["restore_state"], code), ("not_needed", 3))
        text = self.all_text(out)
        for secret_like in (SECRET, "Authorization", "Bearer"):
            self.assertNotIn(secret_like, text)

    def test_apply_exception_after_the_update_keeps_the_raw_outcome_and_restores(self):
        cls = failing_session(lambda m, u, c: RuntimeError("commit client crashed")
                              if m == "POST" and u.endswith("/Commit") and c["POST"] == 1 else None)
        code, s, names, api_log, session, out = self.run_exp("--commit", "after-update", session=cls(None, _category()))
        self.assertEqual((s["apply_state"], s["outcome"]),
                         ("execution_error_after_update_attempt", "update_execution_error"))
        self.assertEqual((s["api_outcomes"]["update_raw"], s["api_outcomes"]["commit_raw"]), ("applied", "not_sent"))
        self.assertEqual(s["restore_state"], "restored")             # restoration reported separately
        self.assertLess(names.index("WORKER_EXCEPTION"), names.index("RESTORE_SENT"))
        self.assertEqual(session.categories[CAT_ID]["includedDomainsOrUrls"], ["x.canary.invalid"])
        self.assertEqual(code, 3)

    def test_restore_exception_is_an_execution_error_not_a_restore_result(self):
        cls = failing_session(lambda m, u, c: RuntimeError("restore crashed") if m == "PUT" and c["PUT"] == 2
                              else None)
        code, s, names, _, session, _ = self.run_exp("--commit", "none", session=cls(None, _category()))
        self.assertEqual((s["restore_state"], s["outcome"]), ("execution_error", "restore_execution_error"))
        self.assertEqual([e["job"] for e in s["execution_errors"]], ["restore_job"])
        self.assertEqual(s["api_outcomes"]["restore_raw"], "not_sent")
        self.assertEqual(code, 3)

    def test_worker_not_finished_at_exit_is_reported_incomplete(self):
        class StillRunning(cb.InlineWorker):
            def join(self, timeout=None):
                return False
        args = cb.parse_args(["run", "--run-id", "R1", "--dry-run", "--signature-file", self.signature_file(),
                              "--commit", "none", "--output-dir", self.dir], {})
        code, _ = self.quiet(cb.cmd_run, args, {"ATMOS_API_KEY": SECRET}, worker=StillRunning())
        out = sorted(glob.glob(os.path.join(self.dir, "R1", "canary*")))[-1]
        s, m = self.read(out, "summary.json"), self.read(out, "manifest.json")
        self.assertEqual((code, s["run_validity"]), (3, "not_valid"))
        self.assertEqual((s["finalisation"]["status"], s["finalisation"]["api_worker_finished_at_exit"]),
                         ("incomplete", False))
        self.assertEqual(m["finalisation"]["status"], "incomplete")

    def test_finalisation_problem_keeps_diagnostics(self):
        args = cb.parse_args(["run", "--run-id", "R1", "--dry-run", "--signature-file", self.signature_file(),
                              "--commit", "none", "--output-dir", self.dir], {})
        with unittest.mock.patch.object(cb.ba, "analyze_canary", side_effect=KeyError("timeline")):
            code, err = self.quiet(cb.cmd_run, args, {"ATMOS_API_KEY": SECRET})
        out = sorted(glob.glob(os.path.join(self.dir, "R1", "canary*")))[-1]
        s = self.read(out, "summary.json")
        self.assertEqual((code, s["run_validity"], s["finalisation"]["status"]), (3, "not_valid", "incomplete"))
        self.assertEqual([p["step"] for p in s["finalisation"]["problems"]], ["analysis"])
        self.assertEqual(s["restore_state"], "restored")             # what is known is kept
        self.assertIn("finalisation incomplete", err)


class ThreadedWorkerErrorTests(OfflineTestCase):
    """G2 with a real API worker thread (real clock, simulated API, about 1-2 s per test)."""

    def run_threaded(self, fail_on):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        sig_path = os.path.join(tmp.name, "sig.json")
        with open(sig_path, "w", encoding="utf-8") as f:
            json.dump({"validated": True, "signature": SIG.describe(), "reference_host": "reference.canary.invalid",
                       "mode": "measurement-support (fixture)"}, f)
        args = cb.parse_args(["run", "--run-id", "RT", "--commit", "after-update", "--signature-file", sig_path,
                              "--canary-url", "https://canary.canary.invalid/c", "--canary-token", "tok-1",
                              "--category-id", "cat-1", "--category-name", "Thesis_Canary_Test",
                              "--block-status", "403", "--block-body-regex", "access denied by policy",
                              "--interval-ms", "20", "--baseline-sec", "0.2", "--max-gap-ms", "200",
                              "--stable-n", "3", "--max-wait-sec", "10", "--restore-max-wait-sec", "10",
                              "--output-dir", tmp.name], {})
        clock = cb.RealClock()
        session = failing_session(fail_on)(
            clock, [{"id": "cat-1", "name": "Thesis_Canary_Test", "description": "",
                     "includedDomainsOrUrls": ["x.canary.invalid"], "excludedDomainsOrUrls": []}], latency=0.1)
        target = cb.ScriptedCanaryTarget(clock, session, "cat-1", "canary.canary.invalid", "tok-1",
                                         "access denied by policy", effect_delay=0.1)
        target._transient = []
        with contextlib.redirect_stdout(io.StringIO()):
            code = cb.cmd_run(args, {"ATMOS_API_KEY": SECRET}, clock=clock, session=session, probe=target,
                              worker=cb.ThreadWorker())
        out = glob.glob(os.path.join(tmp.name, "RT", "canary*"))[0]
        with open(os.path.join(out, "summary.json"), encoding="utf-8") as f:
            s = json.load(f)
        with open(os.path.join(out, "events.csv"), encoding="utf-8") as f:
            ev = [(r["event"], float(r["mono_s"])) for r in csv.DictReader(f)]
        return code, s, ev, session

    def test_exception_before_update(self):
        code, s, ev, session = self.run_threaded(
            lambda m, u, c: ValueError(f"bad body {SECRET}") if m == "GET" and c["GET"] == 2 else None)
        self.assertEqual((s["apply_state"], [e["job"] for e in s["execution_errors"]]),
                         ("execution_error_before_update", ["apply_job"]))
        self.assertNotIn(SECRET, json.dumps(s))
        self.assertEqual(session.changes, [])
        self.assertEqual((code, s["finalisation"]["status"]), (3, "complete"))

    def test_exception_after_update_restore_waits_for_the_apply_job(self):
        code, s, ev, session = self.run_threaded(
            lambda m, u, c: RuntimeError("commit crashed") if m == "POST" and c["POST"] == 1 else None)
        names = [e for e, _ in ev]
        t = dict(ev)
        self.assertEqual(s["apply_state"], "execution_error_after_update_attempt")
        self.assertLess(names.index("WORKER_EXCEPTION"), names.index("RESTORE_SENT"))
        self.assertGreaterEqual(t["RESTORE_SENT"], t["WORKER_EXCEPTION"])      # no overlap with the apply job
        self.assertEqual((s["restore_state"], s["api_outcomes"]["update_raw"]), ("restored", "applied"))
        self.assertEqual(session.categories["cat-1"]["includedDomainsOrUrls"], ["x.canary.invalid"])
        self.assertEqual(code, 3)

if __name__ == "__main__":
    unittest.main()
