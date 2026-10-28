#!/usr/bin/env python3
"""
Pillar 4: Atmos Admin API client for custom web categories (Swagger operations only).

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

Operations used (04-threat-intel/atmos-swagger.json, Swagger 2.0, Bearer token in the
Authorization header):
  GET  /WebCategories?pageNumber=&pageSize=   WebCategory_Query   200 PagedApiResponse...
  GET  /WebCategories/{id}                    WebCategory_GetById 200
  POST /WebCategories                         WebCategory_Create  201
  PUT  /WebCategories/{id}                    WebCategory_Update  200
  POST /Commit                                Commit_CommitChanges 204
DELETE /WebCategories/{id} exists in the Swagger but is never called by this code.
The Swagger has no SWG rule/policy operation: assigning a category to a blocking rule is a manual,
documented prerequisite and cannot be verified through this API.

Write payloads are built from an explicit list of writable fields (WRITABLE_FIELDS); a GET
response or snapshot is never sent back as it is. Read-only fields (id, type) are never sent.
OPEN POINT (needs validation against the real API): WebCategoryModelV1 lists "type" as required
but also marks it readOnly. This code does not resolve the contradiction by guessing; it omits
"type", and whether the API accepts that has to be checked on the testbed.

Commit: POST /Commit is called only when the caller asks for it. Whether it is needed for a
category change to take effect, and whether it also applies OTHER pending changes of the tenant,
is not validated; that must be checked before the lab experiment.

Listing consistency: all pages 1..totalPages are read; totalRecords/totalPages must stay the same
on every page and the item count must equal totalRecords. Equal counts do NOT prove that the
listing did not change while paging (an item could be replaced by another); the result records
this limitation.

Writes are never retried. A timeout or connection error on a write leaves its outcome UNCERTAIN
(the server may or may not have applied it); callers reconcile with GET only, without writing again.

The managed-by tag in the description is this project's own naming/ownership convention. It is
not an API permission and does not prove exclusive ownership of a category.
"""

import time
from collections import namedtuple
from datetime import datetime, timezone

import requests

WRITABLE_FIELDS = ("name", "description", "includedDomainsOrUrls", "excludedDomainsOrUrls", "connectorZoneId")
READ_ONLY_FIELDS = ("id", "type")
TYPE_FIELD_NOTE = ("WebCategoryModelV1.type is both required and readOnly in the Swagger; it is not sent. "
                   "Whether the API accepts a write without it is an open point for real API validation.")
LISTING_NOTE = ("equal totalRecords on every page and a matching item count do not prove that the listing "
                "did not change during paging")
MANAGED_TAG = "[managed-by:hpe-atmos-sse-automation key={key}]"
MANAGED_TAG_NOTE = "project naming/ownership convention only; not an API permission or proof of exclusive ownership"
COMMIT_NOTE = ("necessity and scope of POST /Commit are not validated; it may also apply other pending changes "
               "of the tenant - check before the lab experiment")

ApiResult = namedtuple("ApiResult", ["method", "path", "status", "body", "error", "uncertain",
                                     "sent_mono", "response_mono", "sent_utc", "response_utc"])


class ApiError(Exception):
    def __init__(self, message, result=None):
        super().__init__(message)
        self.result = result


def _utc():
    return datetime.now(timezone.utc)


def managed_tag(key):
    if not key or any(c in key for c in "[]"):
        raise ValueError("invalid managed-by key")
    return MANAGED_TAG.format(key=key)


def build_payload(name, description, included, excluded=(), connector_zone_id=None):
    """Write payload from the explicit writable field list only."""
    payload = {"name": name, "description": description or "",
               "includedDomainsOrUrls": list(included), "excludedDomainsOrUrls": list(excluded)}
    if connector_zone_id:
        payload["connectorZoneId"] = connector_zone_id
    assert set(payload) <= set(WRITABLE_FIELDS)
    return payload


def writable_state(category):
    """The writable fields of a category as returned by GET (used for snapshots and comparisons)."""
    return {k: category.get(k) for k in WRITABLE_FIELDS if k in category}


def payload_from_state(state, included=None):
    """Write payload rebuilt from a writable-state dict; optionally with a new included list."""
    return build_payload(state["name"], state.get("description", ""),
                         state.get("includedDomainsOrUrls") or [] if included is None else included,
                         state.get("excludedDomainsOrUrls") or [], state.get("connectorZoneId"))


def same_entries(a, b):
    return sorted(x.strip().lower() for x in (a or [])) == sorted(x.strip().lower() for x in (b or []))


def find_by_name(items, name, key=None):
    """(category | None, problem). With key, the description must contain the managed-by tag."""
    matches = [c for c in items if c.get("name") == name]
    if len(matches) > 1:
        return None, f"duplicate_name: {len(matches)} categories named {name!r}"
    if not matches:
        return None, ""
    if key is not None and managed_tag(key) not in (matches[0].get("description") or ""):
        return None, f"foreign_category: {name!r} exists without the managed-by tag {managed_tag(key)!r}"
    return matches[0], ""


class AtmosCategoryClient:
    def __init__(self, base_url, api_key, session=None, clock=time.monotonic, wall=_utc, timeout=15.0,
                 page_size=100, max_pages=50, log=None):
        self.base = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        self._secret = api_key
        self.session = session or requests.Session()
        self.clock, self.wall, self.timeout = clock, wall, timeout
        self.page_size, self.max_pages = page_size, max_pages
        self.log = log  # callable(dict) or None; never receives the token

    def _redact(self, text):
        return text.replace(self._secret, "***") if self._secret else text

    def request(self, method, path, params=None, payload=None):
        sent_mono, sent_utc = self.clock(), self.wall()
        status, body, error, uncertain = None, None, "", False
        try:
            resp = self.session.request(method, f"{self.base}{path}", headers=self._headers, params=params,
                                        json=payload, timeout=self.timeout)
            status = resp.status_code
            try:
                body = resp.json() if resp.content else None
            except ValueError:
                body = None
            if status >= 400:
                detail = body.get("details") if isinstance(body, dict) else ""
                error = self._redact(f"HTTP {status}" + (f": {detail}" if detail else ""))[:300]
        except (requests.Timeout, requests.ConnectionError) as exc:
            error = self._redact(f"{type(exc).__name__}: {exc}")[:300]
            uncertain = method != "GET"  # a write may or may not have been applied
        except requests.RequestException as exc:
            error = self._redact(f"{type(exc).__name__}: {exc}")[:300]
            uncertain = method != "GET"
        result = ApiResult(method, path, status, body, error, uncertain, sent_mono, self.clock(),
                           sent_utc, self.wall())
        if self.log:
            self.log({"method": method, "path": path, "params": params, "status": status, "error": error,
                      "uncertain": uncertain, "sent_mono_s": result.sent_mono, "response_mono_s": result.response_mono,
                      "sent_utc": result.sent_utc.isoformat(), "response_utc": result.response_utc.isoformat(),
                      "payload": payload, "response_body": body})
        return result

    def list_categories(self):
        """(items, consistency). Raises ApiError on any error or inconsistency."""
        items, first, page = [], None, 1
        while True:
            res = self.request("GET", "/WebCategories", params={"pageNumber": page, "pageSize": self.page_size})
            if res.status != 200 or not isinstance(res.body, dict):
                raise ApiError(f"listing page {page} failed: {res.error or res.status}", res)
            body = res.body
            for key in ("pageNumber", "pageSize", "totalPages", "totalRecords"):
                if not isinstance(body.get(key), int):
                    raise ApiError(f"listing page {page}: required field {key!r} missing", res)
            if body["pageNumber"] != page:
                raise ApiError(f"listing returned page {body['pageNumber']} for requested page {page}", res)
            if first is None:
                first = (body["totalPages"], body["totalRecords"])
            elif (body["totalPages"], body["totalRecords"]) != first:
                raise ApiError(f"listing changed during paging: {first} -> "
                               f"{(body['totalPages'], body['totalRecords'])}", res)
            items.extend(body.get("data") or [])
            if page >= body["totalPages"] or body["totalPages"] == 0:
                break
            page += 1
            if page > self.max_pages:
                raise ApiError(f"more than {self.max_pages} pages; refusing to continue")
        ids = [c.get("id") for c in items]
        if len(items) != first[1]:
            raise ApiError(f"listing returned {len(items)} items, totalRecords={first[1]}")
        if len(set(ids)) != len(ids):
            raise ApiError("listing contains duplicate ids")
        return items, {"pages": page, "total_records": first[1], "page_size": self.page_size, "note": LISTING_NOTE}

    def get(self, category_id):
        res = self.request("GET", f"/WebCategories/{category_id}")
        if res.status != 200 or not isinstance(res.body, dict):
            raise ApiError(f"GET category {category_id} failed: {res.error or res.status}", res)
        return res.body, res

    def create(self, payload):
        assert set(payload) <= set(WRITABLE_FIELDS)
        return self.request("POST", "/WebCategories", payload=payload)

    def update(self, category_id, payload):
        assert set(payload) <= set(WRITABLE_FIELDS)
        return self.request("PUT", f"/WebCategories/{category_id}", payload=payload)

    def commit(self):
        return self.request("POST", "/Commit")


def write_outcome(res, expected_status):
    """'applied', 'failed' or 'uncertain' for one write result."""
    if res.uncertain:
        return "uncertain"
    return "applied" if res.status == expected_status else "failed"


def reconcile_update(client, category_id, expected_included):
    """After an uncertain or unverified update: GET only (no new write).
    Returns ('applied' | 'not_applied' | 'unknown', detail)."""
    try:
        current, _ = client.get(category_id)
    except ApiError as exc:
        return "unknown", f"GET failed: {exc}"
    if same_entries(current.get("includedDomainsOrUrls"), expected_included):
        return "applied", "current included list equals the sent list"
    return "not_applied", "current included list differs from the sent list"
