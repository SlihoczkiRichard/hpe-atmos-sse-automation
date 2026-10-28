#!/usr/bin/env python3
"""
Pillar 4: URLhaus indicator synchronisation into one custom Atmos web category.

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

This is the SYNC mode; the canary blocking experiment (canary_block_test.py) is independent of it.

Commands
  plan     feed -> deterministic indicator list (threat_feed.py); with --read-api also a read-only
           comparison with the current category (GET only). No write.
  apply    plan + create/update of the managed category, verification by GET, optional Commit.
           --commit none|after-update is mandatory.
  restore  puts the category back to the snapshot taken by apply, after checking that the current
           state still equals what apply wrote (otherwise: restore_conflict, nothing is written).
           --commit none|after-update is mandatory.

Safety rules
  - Only the category whose name matches AND whose description carries the managed-by tag is
    modified (a project convention, not an API permission). A same-named category without the
    tag, or several same-named categories, stop the run without writing.
  - Payloads are built from the explicit writable field list (atmos_categories.WRITABLE_FIELDS);
    readOnly fields are never sent. DELETE is never used.
  - A timeout/connection error on a write is an UNCERTAIN outcome: it is reconciled by GET only.
  - A category created by apply is restored to an empty included list. Whether the API accepts an
    empty category is NOT verified; if it refuses, the restore stays open (restore_rejected) and
    has to be resolved by hand. No workaround is attempted.
  - Assigning the category to a blocking SWG rule is a manual prerequisite (no API in the Swagger).

Outputs: results/<RUN_ID>/sync_<command>[.attemptN]/ (never overwritten): manifest.json,
indicators.json (incl. the exact list sent), category_snapshot.json, api_log.jsonl, result.json,
feed_raw.csv (when fetched). The Bearer token never appears in any file or log line.
Nothing is loaded from .env and no connection is opened at import time.
"""

import os
import sys
import json
import hashlib
import argparse
import importlib.util
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
URLHAUS_RECENT_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
DEFAULT_CATEGORY = "URLhaus_Malware_Blocklist"
DEFAULT_DESCRIPTION = "Threat feed ingestion from abuse.ch URLhaus - BME BSc Thesis"


def _load(name):
    spec = importlib.util.spec_from_file_location(f"ti_{name}", os.path.join(HERE, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


feed = _load("threat_feed")
api = _load("atmos_categories")
files = _load("run_files")


def _env(env, key, default=""):
    value = env.get(key)
    return default if value is None or not value.strip() else value.strip()


def fetch_feed(session, url=URLHAUS_RECENT_URL, timeout=30.0):
    """Downloads the feed text (a real network operation; only with --fetch)."""
    resp = session.get(url, headers={"User-Agent": "BME-BSc-Thesis-ThreatSync/2.0"}, timeout=timeout)
    resp.raise_for_status()
    return resp.text


def build_indicators(args, session=None):
    if bool(args.feed_file) == bool(args.fetch):
        raise ValueError("give exactly one of --feed-file or --fetch")
    if args.feed_file:
        with open(args.feed_file, encoding="utf-8") as f:
            text = f.read()
        source = {"kind": "file", "path": os.path.abspath(args.feed_file)}
    else:
        import requests
        text = fetch_feed(session or requests.Session())
        source = {"kind": "download", "url": URLHAUS_RECENT_URL,
                  "downloaded_utc": datetime.now(timezone.utc).isoformat()}
    source["sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    rows, errors = feed.parse_urlhaus_csv(text)
    exclusions = []
    if args.exclude_file:
        with open(args.exclude_file, encoding="utf-8") as f:
            exclusions = [line.split("#", 1)[0].strip() for line in f]
    statuses = [s for s in (args.url_status or "").split(",") if s.strip()]
    selection = feed.select_indicators(rows, args.max_hosts, statuses or None, exclusions)
    selection["parse_errors"] = errors
    return text, source, selection


def make_client(args, env, log):
    key = _env(env, "ATMOS_API_KEY")
    if not key:
        raise ValueError("ATMOS_API_KEY is required in the environment (never on the command line)")
    return api.AtmosCategoryClient(args.base_url, key, session=getattr(args, "session", None),
                                   timeout=args.api_timeout, page_size=args.page_size, log=log), key


def _description(args):
    return f"{DEFAULT_DESCRIPTION} {api.managed_tag(args.category_key)}"


class Run:
    """One output directory with its manifest, api log and redaction."""
    def __init__(self, args, command, secrets=()):
        self.dir, self.attempt = files.make_run_dir(args.output_dir, args.run_id, f"sync_{command}")
        self.secrets = [s for s in secrets if s]
        self.api_log = files.JsonLines(os.path.join(self.dir, "api_log.jsonl"))

    def log(self, record):
        text = json.dumps(record, default=str)
        for s in self.secrets:
            text = text.replace(s, "***")
        self.api_log.write(json.loads(text))

    def save(self, name, data):
        files.write_json(os.path.join(self.dir, name), data)

    def close(self):
        self.api_log.close()


def _manifest(args, command, run, extra=None):
    m = {"run_id": args.run_id, "command": command, "attempt": run.attempt,
         "mode": "measurement-support (configuration change)" if command != "plan" else "plan (no write)",
         "category_name": args.category_name, "managed_tag": api.managed_tag(args.category_key),
         "managed_tag_note": api.MANAGED_TAG_NOTE, "commit_mode": getattr(args, "commit", None),
         "commit_note": api.COMMIT_NOTE, "type_field_note": api.TYPE_FIELD_NOTE,
         "writable_fields": list(api.WRITABLE_FIELDS),
         "rule_assignment": "operator_asserted prerequisite (no rule/policy operation in the Swagger)",
         "created_utc": datetime.now(timezone.utc).isoformat()}
    m.update(extra or {})
    return m


def cmd_plan(args, env):
    run = Run(args, "plan")
    try:
        text, source, selection = build_indicators(args, getattr(args, "session", None))
        if source["kind"] == "download":
            files.write_text(os.path.join(run.dir, "feed_raw.csv"), text)
        result = {"state": "planned", "indicators": selection["hosts"]}
        if args.read_api:
            client, key = make_client(args, env, run.log)
            run.secrets.append(key)
            items, consistency = client.list_categories()
            current, problem = api.find_by_name(items, args.category_name, args.category_key)
            now = (current or {}).get("includedDomainsOrUrls") or []
            result.update({"listing": consistency, "category_problem": problem,
                           "category_exists": current is not None,
                           "to_add": sorted(set(selection["hosts"]) - set(now)),
                           "to_remove": sorted(set(now) - set(selection["hosts"]))})
        run.save("indicators.json", {"source": source, **selection})
        run.save("result.json", result)
        run.save("manifest.json", _manifest(args, "plan", run, {"feed_source": source}))
        print(f"[+] planned {len(selection['hosts'])} hosts ({len(selection['ip_indicators'])} IP indicators saved "
              f"only) -> {run.dir}")
        return 0
    finally:
        run.close()


def _require_key(env):
    key = _env(env, "ATMOS_API_KEY")
    if not key:
        raise ValueError("ATMOS_API_KEY is required in the environment (never on the command line)")
    return key


def cmd_apply(args, env):
    run = Run(args, "apply", [_require_key(env)])
    try:
        text, source, selection = build_indicators(args, getattr(args, "session", None))
        if source["kind"] == "download":
            files.write_text(os.path.join(run.dir, "feed_raw.csv"), text)
        hosts = selection["hosts"]
        if not hosts:
            raise ValueError("no host indicators selected; nothing to apply")
        client, _ = make_client(args, env, run.log)
        result = {"commit_mode": args.commit}
        try:
            items, consistency = client.list_categories()
        except api.ApiError as exc:
            return _finish(run, args, result, "listing_failed", str(exc), source, selection, 3)
        result["listing"] = consistency
        current, problem = api.find_by_name(items, args.category_name, args.category_key)
        if problem:
            return _finish(run, args, result, "category_conflict", problem, source, selection, 3)

        if current is None:
            payload = api.build_payload(args.category_name, _description(args), hosts)
            res = client.create(payload)
            outcome = api.write_outcome(res, 201)
            category_id = res.body.get("id") if outcome == "applied" and isinstance(res.body, dict) else None
            if outcome == "uncertain":
                category_id, outcome = _reconcile_create(client, args, payload)
            # nothing existed before; the snapshot is written once the id is known (None if unresolved)
            run.save("category_snapshot.json", {"category_id": category_id, "created_by_tool": True,
                                                "before": None, "expected_after": payload})
        else:
            category_id = current["id"]
            try:
                fresh, _ = client.get(category_id)
            except api.ApiError as exc:
                return _finish(run, args, result, "category_state_unknown", str(exc), source, selection, 3)
            before = api.writable_state(fresh)
            payload = api.payload_from_state(before, hosts)
            snapshot = {"category_id": category_id, "created_by_tool": False, "before": before,
                        "expected_after": payload}
            run.save("category_snapshot.json", snapshot)
            res = client.update(category_id, payload)
            outcome = api.write_outcome(res, 200)
        run.save("indicators.json", {"source": source, **selection, "sent_included": payload["includedDomainsOrUrls"]})
        result.update({"write": {"method": res.method, "status": res.status, "error": res.error,
                                 "outcome": outcome, "sent_utc": res.sent_utc.isoformat(),
                                 "response_utc": res.response_utc.isoformat(),
                                 "api_response_time_ms": round((res.response_mono - res.sent_mono) * 1000, 3),
                                 "api_response_time_note": "API round trip; not a rule-enforcement delay"},
                       "category_id": category_id})
        if outcome in ("applied", "uncertain") and category_id:
            state, detail = api.reconcile_update(client, category_id, payload["includedDomainsOrUrls"])
            result["verification"] = {"state": state, "detail": detail + " (at the time of the GET)"}
            if outcome == "uncertain":
                outcome = {"applied": "applied_after_reconcile", "not_applied": "not_applied_at_check_time"}.get(
                    state, "uncertain")
                result["write"]["outcome_after_reconcile"] = outcome   # the raw outcome stays "uncertain"
        if outcome not in ("applied", "applied_after_reconcile"):
            return _finish(run, args, result, f"write_{outcome}", res.error, source, selection,
                           4 if "uncertain" in outcome else 3)
        if args.commit == "after-update":
            c = client.commit()
            result["commit"] = {"status": c.status, "error": c.error, "outcome": api.write_outcome(c, 204),
                                "sent_utc": c.sent_utc.isoformat(), "response_utc": c.response_utc.isoformat()}
            if result["commit"]["outcome"] != "applied":
                return _finish(run, args, result, f"commit_{result['commit']['outcome']}", c.error, source,
                               selection, 4 if c.uncertain else 3)
        else:
            result["commit"] = {"outcome": "skipped (--commit none)"}
        return _finish(run, args, result, "applied", "", source, selection, 0)
    finally:
        run.close()


def _reconcile_create(client, args, payload):
    try:
        items, _ = client.list_categories()
    except api.ApiError:
        return None, "uncertain"
    found, problem = api.find_by_name(items, args.category_name, args.category_key)
    if found and not problem:
        return found.get("id"), "applied_after_reconcile"
    return None, "not_applied_at_check_time" if not problem else "uncertain"


def _finish(run, args, result, state, detail, source, selection, code):
    result.update({"state": state, "detail": detail})
    run.save("result.json", result)
    if not os.path.exists(os.path.join(run.dir, "indicators.json")):
        run.save("indicators.json", {"source": source, **selection})
    run.save("manifest.json", _manifest(args, "apply", run, {"feed_source": source}))
    print(f"[{'+' if code == 0 else '!'}] apply: {state} {detail} -> {run.dir}")
    return code


def cmd_restore(args, env):
    run = Run(args, "restore", [_require_key(env)])
    try:
        with open(args.snapshot, encoding="utf-8") as f:
            snapshot = json.load(f)
        client, _ = make_client(args, env, run.log)
        result = {"commit_mode": args.commit, "snapshot": os.path.abspath(args.snapshot)}
        category_id = snapshot.get("category_id") or args.category_id
        if not category_id:
            result.update({"state": "restore_needs_category_id",
                           "detail": "the snapshot has no id (create outcome was uncertain); pass --category-id"})
            return _end_restore(run, args, result, 3)
        try:
            current, _ = client.get(category_id)
        except api.ApiError as exc:
            result.update({"state": "restore_state_unknown", "detail": str(exc)})
            return _end_restore(run, args, result, 3)
        expected = snapshot["expected_after"]
        now = api.writable_state(current)
        differs = [k for k in ("name", "description", "excludedDomainsOrUrls", "connectorZoneId")
                   if (now.get(k) or None) != (expected.get(k) or None)]
        if not api.same_entries(now.get("includedDomainsOrUrls"), expected["includedDomainsOrUrls"]):
            differs.append("includedDomainsOrUrls")
        if differs:
            result.update({"state": "restore_conflict", "changed_fields": differs,
                           "manual_recovery": {"category_id": category_id, "snapshot_before": snapshot.get("before"),
                                               "written_by_apply": expected, "current": now,
                                               "note": "the category changed after apply; nothing was written. "
                                                       "Compare and restore by hand."}})
            return _end_restore(run, args, result, 3)
        if snapshot.get("created_by_tool"):
            target = api.build_payload(expected["name"], expected.get("description", ""), [])
            result["empty_category_note"] = ("the category was created by apply; it is restored to an empty "
                                             "included list. API acceptance of an empty category is not verified.")
        else:
            target = api.payload_from_state(snapshot["before"])
        res = client.update(category_id, target)
        outcome = api.write_outcome(res, 200)
        result["write"] = {"status": res.status, "error": res.error, "outcome": outcome,
                           "sent_utc": res.sent_utc.isoformat(), "response_utc": res.response_utc.isoformat()}
        state, detail = api.reconcile_update(client, category_id, target["includedDomainsOrUrls"])
        result["category_restored"] = state == "applied"
        result["verification"] = {"state": state, "detail": detail + " (at the time of the GET)"}
        if outcome == "failed" and snapshot.get("created_by_tool") and res.status == 400:
            result.update({"state": "restore_rejected", "detail": "API refused the empty category; open point, "
                                                                  "resolve by hand"})
            return _end_restore(run, args, result, 3)
        if not result["category_restored"]:
            result.update({"state": "restore_unverified" if outcome != "failed" else "restore_failed",
                           "detail": res.error})
            return _end_restore(run, args, result, 4 if outcome == "uncertain" else 3)
        if args.commit == "after-update":
            c = client.commit()
            result["commit"] = {"status": c.status, "error": c.error, "outcome": api.write_outcome(c, 204)}
        else:
            result["commit"] = {"outcome": "skipped (--commit none)"}
        result["state"] = "category_restored"
        return _end_restore(run, args, result, 0 if result["commit"]["outcome"] in ("applied",
                                                                                     "skipped (--commit none)") else 3)
    finally:
        run.close()


def _end_restore(run, args, result, code):
    run.save("result.json", result)
    run.save("manifest.json", _manifest(args, "restore", run))
    print(f"[{'+' if code == 0 else '!'}] restore: {result['state']} -> {run.dir}")
    return code


def parse_args(argv, env):
    p = argparse.ArgumentParser(description="URLhaus -> Atmos custom web category (sync mode)")
    sub = p.add_subparsers(dest="command", required=True)
    for name in ("plan", "apply", "restore"):
        s = sub.add_parser(name)
        s.add_argument("--run-id", default=_env(env, "RUN_ID"))
        s.add_argument("--output-dir", default=os.path.join(HERE, "results"))
        s.add_argument("--base-url", default=_env(env, "ATMOS_BASE_URL", "https://admin-api.axissecurity.com/api/v1.0"))
        s.add_argument("--api-timeout", type=float, default=_env(env, "ATMOS_API_TIMEOUT_SEC", "15"))
        s.add_argument("--page-size", type=int, default=_env(env, "ATMOS_PAGE_SIZE", "100"))
        s.add_argument("--category-name", default=_env(env, "THREAT_CATEGORY_NAME", DEFAULT_CATEGORY))
        s.add_argument("--category-key", default=_env(env, "THREAT_CATEGORY_KEY", "urlhaus-sync"))
        if name in ("plan", "apply"):
            s.add_argument("--feed-file")
            s.add_argument("--fetch", action="store_true", help="download the URLhaus feed (network)")
            s.add_argument("--max-hosts", type=int, default=_env(env, "THREAT_MAX_HOSTS", "25"))
            s.add_argument("--url-status", default=_env(env, "THREAT_URL_STATUS_FILTER"),
                           help="comma list, e.g. online; default: no filter")
            s.add_argument("--exclude-file", default=_env(env, "THREAT_EXCLUDE_FILE"))
        if name == "plan":
            s.add_argument("--read-api", action="store_true", help="read-only comparison with the category")
        if name in ("apply", "restore"):
            s.add_argument("--commit", choices=("none", "after-update"), required=True)
        if name == "restore":
            s.add_argument("--snapshot", required=True)
            s.add_argument("--category-id", default="")
    return p.parse_args(argv)


def _runtime_environ(argv):
    """Configuration source for a command-line start. --help and --dry-run never read .env or the
    process environment: they run on an empty, synthetic configuration, so a broken or incomplete
    live configuration cannot block them. Only the live modes load .env (python-dotenv)."""
    if any(a in ("-h", "--help", "--dry-run") for a in argv):
        return {}
    from dotenv import load_dotenv
    load_dotenv()
    return os.environ


def main(argv=None, environ=None, session=None):
    """0 ok; 2 configuration error; 3 API/state problem (nothing or nothing more written);
    4 uncertain write outcome (reconcile by hand)."""
    if environ is None:
        environ = _runtime_environ(sys.argv[1:] if argv is None else argv)
    args = parse_args(argv, environ)
    args.session = session
    try:
        files.check_run_id(args.run_id)
        return {"plan": cmd_plan, "apply": cmd_apply, "restore": cmd_restore}[args.command](args, environ)
    except (ValueError, FileExistsError, FileNotFoundError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
