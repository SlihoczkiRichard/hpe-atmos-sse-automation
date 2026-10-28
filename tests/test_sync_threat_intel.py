"""sync_threat_intel.py: plan/apply/restore against an in-memory fake Admin API (no network).

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.
"""

import contextlib
import glob
import io
import json
import os
import tempfile
import unittest

import requests

from _helpers import OfflineTestCase, load_module

sync = load_module("04-threat-intel/sync_threat_intel.py", "sync_threat_intel")
api = sync.api
SECRET = "jwt-sync-secret"
ENV = {"ATMOS_API_KEY": SECRET}

FEED = "\n".join([
    "# comment",
    '"2","2026-10-26 10:00:00","http://bad-a.example.invalid/x","online","","","","",""',
    '"1","2026-10-26 09:00:00","http://bad-b.example.invalid/y","offline","","","","",""',
    '"0","2026-10-26 08:00:00","http://198.51.100.9/z","online","","","","",""',
]) + "\n"


class Resp:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = body
        self.content = b"" if body is None else json.dumps(body).encode()

    def json(self):
        if self._body is None:
            raise ValueError("no body")
        return self._body


class FakeApi:
    """In-memory WebCategories + Commit. hooks[(method, kind)] may override one call."""
    def __init__(self, categories=()):
        self.cats = {c["id"]: dict(c) for c in categories}
        self.calls = []
        self.hooks = {}
        self.next_id = 100

    def request(self, method, url, headers=None, params=None, json=None, timeout=None):
        path = url.split("/api/v1.0", 1)[1]
        kind = "item" if path.count("/") == 2 else path.strip("/")
        self.calls.append((method, path, json))
        hook = self.hooks.pop((method, kind), None)
        if hook:
            result = hook(self, path, json)
            if result is not None:
                return result
        if path == "/Commit":
            return Resp(204)
        if kind == "WebCategories" and method == "GET":
            data = sorted(self.cats.values(), key=lambda c: c["id"])
            return Resp(200, {"pageNumber": 1, "pageSize": 100, "totalPages": 1 if data else 0,
                              "totalRecords": len(data), "data": data})
        if kind == "WebCategories" and method == "POST":
            self.next_id += 1
            cat = dict(json, id=f"id-{self.next_id}", type="Custom")
            self.cats[cat["id"]] = cat
            return Resp(201, cat)
        cid = path.rsplit("/", 1)[1]
        if cid not in self.cats:
            return Resp(404, {"status": "NotFound"})
        if method == "GET":
            return Resp(200, dict(self.cats[cid]))
        if method == "PUT":
            if not json["includedDomainsOrUrls"] and getattr(self, "reject_empty", False):
                return Resp(400, {"status": "BadRequest", "details": "includedDomainsOrUrls must not be empty"})
            self.cats[cid].update(json)
            return Resp(200, dict(self.cats[cid]))
        raise AssertionError(f"unexpected call {method} {path}")

    def writes(self):
        """Category writes (POST/PUT/DELETE on /WebCategories); Commit calls are listed separately."""
        return [c for c in self.calls if c[0] in ("POST", "PUT", "DELETE") and c[1] != "/Commit"]


def managed(i=1, included=("old.example.invalid",), **extra):
    return {"id": f"id-{i}", "name": sync.DEFAULT_CATEGORY, "type": "Custom",
            "description": f"desc {api.managed_tag('urlhaus-sync')}", "includedDomainsOrUrls": list(included),
            "excludedDomainsOrUrls": ["keep.example.invalid"], "connectorZoneId": "zone-1", **extra}


class SyncTestCase(OfflineTestCase):
    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        self.feed = os.path.join(self.dir, "feed.csv")
        with open(self.feed, "w", encoding="utf-8") as f:
            f.write(FEED)

    def main(self, *argv, session=None, env=ENV):
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            code = sync.main(list(argv) + ["--run-id", "R1", "--output-dir", os.path.join(self.dir, "out")],
                             environ=env, session=session)
        return code, out.getvalue() + err.getvalue()

    def result(self, command, attempt=1):
        name = f"sync_{command}" + ("" if attempt == 1 else f".attempt{attempt}")
        with open(os.path.join(self.dir, "out", "R1", name, "result.json"), encoding="utf-8") as f:
            return json.load(f)

    def all_output(self):
        text = ""
        for path in glob.glob(os.path.join(self.dir, "out", "**", "*"), recursive=True):
            if os.path.isfile(path):
                with open(path, encoding="utf-8") as f:
                    text += f.read()
        return text


class PlanTests(SyncTestCase):
    def test_plan_needs_no_api_and_never_overwrites(self):
        code, _ = self.main("plan", "--feed-file", self.feed, env={})
        self.assertEqual(code, 0)
        self.assertEqual(self.main("plan", "--feed-file", self.feed, env={})[0], 0)
        run = os.path.join(self.dir, "out", "R1")
        self.assertEqual(sorted(os.listdir(run)), ["sync_plan", "sync_plan.attempt2"])
        with open(os.path.join(run, "sync_plan", "indicators.json"), encoding="utf-8") as f:
            ind = json.load(f)
        self.assertEqual(ind["hosts"], ["bad-a.example.invalid", "bad-b.example.invalid"])
        self.assertEqual(ind["ip_indicators"], ["198.51.100.9"])
        self.assertEqual(len(ind["source"]["sha256"]), 64)
        with open(os.path.join(run, "sync_plan", "manifest.json"), encoding="utf-8") as f:
            manifest = json.load(f)
        self.assertIn("not an API permission", manifest["managed_tag_note"])
        self.assertIn("not validated", manifest["commit_note"])

    def test_read_only_comparison(self):
        fake = FakeApi([managed()])
        self.assertEqual(self.main("plan", "--feed-file", self.feed, "--read-api", session=fake)[0], 0)
        self.assertEqual(fake.writes(), [])
        r = self.result("plan")
        self.assertEqual((r["to_add"], r["to_remove"]), (["bad-a.example.invalid", "bad-b.example.invalid"],
                                                         ["old.example.invalid"]))

    def test_url_status_filter(self):
        self.main("plan", "--feed-file", self.feed, "--url-status", "online", env={})
        self.assertEqual(self.result("plan")["indicators"], ["bad-a.example.invalid"])


class ApplyTests(SyncTestCase):
    def test_commit_choice_is_mandatory(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            sync.parse_args(["apply", "--feed-file", self.feed], {})
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            sync.parse_args(["restore", "--snapshot", "x"], {})

    def test_missing_key_writes_nothing(self):
        code, out = self.main("apply", "--feed-file", self.feed, "--commit", "none", env={})
        self.assertEqual(code, 2)
        self.assertIn("ATMOS_API_KEY", out)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "out", "R1")))

    def test_create_with_explicit_fields_verify_and_commit(self):
        fake = FakeApi()
        self.assertEqual(self.main("apply", "--feed-file", self.feed, "--commit", "after-update", session=fake)[0], 0)
        method, path, payload = fake.writes()[0]
        self.assertEqual((method, path), ("POST", "/WebCategories"))
        self.assertNotIn("type", payload)
        self.assertNotIn("id", payload)
        self.assertIn(api.managed_tag("urlhaus-sync"), payload["description"])
        r = self.result("apply")
        self.assertEqual((r["state"], r["verification"]["state"], r["commit"]["outcome"]),
                         ("applied", "applied", "applied"))
        self.assertIn("not a rule-enforcement delay", r["write"]["api_response_time_note"])
        self.assertEqual(fake.calls[-1][:2], ("POST", "/Commit"))
        self.assertNotIn(SECRET, self.all_output())

    def test_update_preserves_fields_and_never_deletes(self):
        fake = FakeApi([managed()])
        self.assertEqual(self.main("apply", "--feed-file", self.feed, "--commit", "none", session=fake)[0], 0)
        (method, path, payload), = fake.writes()
        self.assertEqual((method, path), ("PUT", "/WebCategories/id-1"))
        self.assertEqual(payload["excludedDomainsOrUrls"], ["keep.example.invalid"])
        self.assertEqual(payload["connectorZoneId"], "zone-1")
        self.assertNotIn("type", payload)
        self.assertNotIn("/Commit", [c[1] for c in fake.calls])
        self.assertEqual(self.result("apply")["commit"]["outcome"], "skipped (--commit none)")
        with open(glob.glob(os.path.join(self.dir, "out", "R1", "sync_apply", "category_snapshot.json"))[0],
                  encoding="utf-8") as f:
            snap = json.load(f)
        self.assertEqual(snap["before"]["includedDomainsOrUrls"], ["old.example.invalid"])

    def test_foreign_or_duplicate_category_is_not_touched(self):
        for cats in ([dict(managed(), description="someone else's")], [managed(1), managed(2)]):
            with self.subTest(cats=len(cats)):
                fake = FakeApi(cats)
                code, _ = self.main("apply", "--feed-file", self.feed, "--commit", "none", session=fake)
                self.assertEqual(code, 3)
                self.assertEqual(fake.writes(), [])

    def test_uncertain_update_is_reconciled_by_get_only(self):
        for attempt, (applied, state, code) in enumerate(((True, "applied", 0),
                                                          (False, "write_not_applied_at_check_time", 3)), 1):
            with self.subTest(applied=applied):
                fake = FakeApi([managed()])

                def timeout(f, path, payload, applied=applied):
                    if applied:
                        f.cats["id-1"].update(payload)
                    raise requests.Timeout("timed out")
                fake.hooks[("PUT", "item")] = timeout
                c, _ = self.main("apply", "--feed-file", self.feed, "--commit", "after-update", session=fake)
                self.assertEqual(c, code)
                self.assertEqual(len(fake.writes()), 1)                     # never re-sent
                result = self.result("apply", attempt)
                self.assertEqual(result["state"], state)
                self.assertEqual(result["write"]["outcome"], "uncertain")
                self.assertEqual(result["write"]["outcome_after_reconcile"], "applied_after_reconcile" if applied else
                                 "not_applied_at_check_time")
                if not applied:
                    self.assertNotIn("/Commit", [c[1] for c in fake.calls])

    def test_uncertain_commit(self):
        fake = FakeApi([managed()])
        fake.hooks[("POST", "Commit")] = lambda f, p, j: (_ for _ in ()).throw(requests.ConnectionError("reset"))
        code, _ = self.main("apply", "--feed-file", self.feed, "--commit", "after-update", session=fake)
        self.assertEqual(code, 4)
        self.assertEqual(self.result("apply")["state"], "commit_uncertain")


class RestoreTests(SyncTestCase):
    def apply(self, fake):
        self.assertEqual(self.main("apply", "--feed-file", self.feed, "--commit", "none", session=fake)[0], 0)
        return glob.glob(os.path.join(self.dir, "out", "R1", "sync_apply", "category_snapshot.json"))[0]

    def test_restore_after_checking_current_state(self):
        fake = FakeApi([managed()])
        snap = self.apply(fake)
        self.assertEqual(self.main("restore", "--snapshot", snap, "--commit", "after-update", session=fake)[0], 0)
        r = self.result("restore")
        self.assertEqual((r["state"], r["category_restored"]), ("category_restored", True))
        self.assertEqual(fake.cats["id-1"]["includedDomainsOrUrls"], ["old.example.invalid"])
        self.assertNotIn("type", fake.writes()[-1][2])
        self.assertNotIn("DELETE", [c[0] for c in fake.calls])

    def test_foreign_change_is_a_conflict_and_nothing_is_written(self):
        fake = FakeApi([managed()])
        snap = self.apply(fake)
        fake.cats["id-1"]["includedDomainsOrUrls"].append("someone-else.example.invalid")
        before = len(fake.writes())
        self.assertEqual(self.main("restore", "--snapshot", snap, "--commit", "none", session=fake)[0], 3)
        r = self.result("restore")
        self.assertEqual(r["state"], "restore_conflict")
        self.assertIn("includedDomainsOrUrls", r["changed_fields"])
        self.assertIn("restore by hand", r["manual_recovery"]["note"])
        self.assertEqual(len(fake.writes()), before)

    def test_created_category_is_emptied_and_refusal_stays_open(self):
        fake = FakeApi()
        snap = self.apply(fake)
        fake.reject_empty = True
        self.assertEqual(self.main("restore", "--snapshot", snap, "--commit", "none", session=fake)[0], 3)
        r = self.result("restore")
        self.assertEqual(r["state"], "restore_rejected")
        self.assertIn("not verified", r["empty_category_note"])
        self.assertEqual(fake.writes()[-1][2]["includedDomainsOrUrls"], [])
        self.assertNotIn("DELETE", [c[0] for c in fake.calls])


class ImportTests(OfflineTestCase):
    def test_imports_have_no_side_effects(self):
        from unittest import mock
        with mock.patch("dotenv.load_dotenv") as load_dotenv, mock.patch("requests.Session.request") as request:
            for rel in ("04-threat-intel/sync_threat_intel.py", "04-threat-intel/canary_block_test.py"):
                load_module(rel, "import_check_" + os.path.basename(rel)[:-3])
        load_dotenv.assert_not_called()
        request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
