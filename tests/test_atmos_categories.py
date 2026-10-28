"""atmos_categories.py: Swagger contract, payload field list, paging checks, uncertain writes, redaction.

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

All HTTP traffic goes to a fake session; nothing reaches the real Admin API.
"""

import json
import os
import unittest

import requests

from _helpers import ROOT, OfflineTestCase, load_module

api = load_module("04-threat-intel/atmos_categories.py", "atmos_categories")
SECRET = "jwt-test-secret-value"


class Resp:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = body
        self.content = b"" if body is None else json.dumps(body).encode()

    def json(self):
        if self._body is None:
            raise ValueError("no body")
        return self._body


class FakeSession:
    """handler(method, path, params, json) -> Resp or raises."""
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def request(self, method, url, headers=None, params=None, json=None, timeout=None):
        path = url.split("/api/v1.0", 1)[1]
        self.calls.append({"method": method, "path": path, "params": params, "json": json, "headers": headers})
        return self.handler(method, path, params, json)


def page(n, total_pages, total_records, data, page_size=2):
    return Resp(200, {"pageNumber": n, "pageSize": page_size, "totalPages": total_pages,
                      "totalRecords": total_records, "data": data})


def client(handler, **kw):
    session = FakeSession(handler)
    log = []
    c = api.AtmosCategoryClient("https://api.test.invalid/api/v1.0", SECRET, session=session, log=log.append,
                                page_size=2, **kw)
    return c, session, log


def cat(i, name=None, **extra):
    return {"id": f"id-{i}", "name": name or f"cat-{i}", "type": "Custom", "description": "", **extra}


class SwaggerContractTests(OfflineTestCase):
    def test_used_operations_exist_and_type_is_read_only(self):
        with open(os.path.join(ROOT, "04-threat-intel", "atmos-swagger.json"), encoding="utf-8") as f:
            sw = json.load(f)
        paths = sw["paths"]
        self.assertEqual(paths["/api/v1.0/WebCategories"]["get"]["operationId"], "WebCategory_Query")
        self.assertEqual(paths["/api/v1.0/WebCategories"]["post"]["operationId"], "WebCategory_Create")
        self.assertEqual(paths["/api/v1.0/WebCategories/{id}"]["put"]["operationId"], "WebCategory_Update")
        self.assertEqual(paths["/api/v1.0/WebCategories/{id}"]["get"]["operationId"], "WebCategory_GetById")
        self.assertIn("204", paths["/api/v1.0/Commit"]["post"]["responses"])
        model = sw["definitions"]["WebCategoryModelV1"]["allOf"][1]
        self.assertTrue(model["properties"]["type"]["readOnly"])
        self.assertIn("type", model["required"])          # the documented contradiction
        writable = set(model["properties"]) - {"type"} | {"name", "description"}
        self.assertEqual(set(api.WRITABLE_FIELDS), writable)
        self.assertFalse(any("Polic" in p or "Rule" in p for p in paths))   # no rule API to assign the category

    def test_payload_never_contains_read_only_fields(self):
        state = api.writable_state(cat(1, includedDomainsOrUrls=["a.invalid"], excludedDomainsOrUrls=["b.invalid"],
                                       connectorZoneId="z-1", unknownField=1))
        payload = api.payload_from_state(state, ["c.invalid"])
        self.assertEqual(set(payload), {"name", "description", "includedDomainsOrUrls", "excludedDomainsOrUrls",
                                        "connectorZoneId"})
        self.assertEqual((payload["includedDomainsOrUrls"], payload["excludedDomainsOrUrls"]),
                         (["c.invalid"], ["b.invalid"]))
        self.assertNotIn("type", api.build_payload("n", "d", []))
        self.assertIn("required and readOnly", api.TYPE_FIELD_NOTE)


class ListingTests(OfflineTestCase):
    def test_all_pages_are_read(self):
        data = {1: [cat(1), cat(2)], 2: [cat(3), cat(4)], 3: [cat(5)]}
        c, session, _ = client(lambda m, p, params, j: page(params["pageNumber"], 3, 5, data[params["pageNumber"]]))
        items, info = c.list_categories()
        self.assertEqual([i["id"] for i in items], [f"id-{i}" for i in range(1, 6)])
        self.assertEqual([call["params"] for call in session.calls],
                         [{"pageNumber": n, "pageSize": 2} for n in (1, 2, 3)])
        self.assertIn("do not prove", info["note"])

    def test_empty_listing(self):
        c, _, _ = client(lambda m, p, params, j: page(1, 0, 0, []))
        self.assertEqual(c.list_categories()[0], [])

    def test_inconsistencies_raise(self):
        bad = {
            "totals changed": lambda n: page(n, 2, 4 if n == 1 else 5, [cat(n * 10), cat(n * 10 + 1)]),
            "count mismatch": lambda n: page(n, 2, 5, [cat(n * 10), cat(n * 10 + 1)]),
            "wrong page": lambda n: page(1, 2, 4, [cat(n * 10), cat(n * 10 + 1)]),
            "duplicate ids": lambda n: page(n, 2, 4, [cat(1), cat(2)]),
            "missing field": lambda n: Resp(200, {"pageNumber": n, "data": []}),
            "http error": lambda n: Resp(500, {"status": "InternalServerError", "details": "boom"}),
        }
        for name, fn in bad.items():
            with self.subTest(name=name), self.assertRaises(api.ApiError):
                client(lambda m, p, params, j, fn=fn: fn(params["pageNumber"]))[0].list_categories()

    def test_page_limit(self):
        c, _, _ = client(lambda m, p, params, j: page(params["pageNumber"], 100, 200,
                                                      [cat(params["pageNumber"] * 2), cat(params["pageNumber"] * 2 + 1)]),
                         max_pages=3)
        with self.assertRaisesRegex(api.ApiError, "more than 3 pages"):
            c.list_categories()


class OwnershipTests(OfflineTestCase):
    def test_find_by_name(self):
        tag = api.managed_tag("k1")
        managed = cat(1, "Feed", description=f"x {tag}")
        self.assertEqual(api.find_by_name([managed, cat(2)], "Feed", "k1"), (managed, ""))
        self.assertIn("foreign_category", api.find_by_name([cat(1, "Feed")], "Feed", "k1")[1])
        self.assertIn("foreign_category", api.find_by_name([cat(1, "Feed", description=api.managed_tag("other"))],
                                                           "Feed", "k1")[1])
        self.assertIn("duplicate_name", api.find_by_name([managed, cat(2, "Feed")], "Feed", "k1")[1])
        self.assertEqual(api.find_by_name([cat(2)], "Feed", "k1"), (None, ""))
        self.assertIn("not an API permission", api.MANAGED_TAG_NOTE)


class WriteTests(OfflineTestCase):
    def test_timeout_on_write_is_uncertain_on_read_is_not(self):
        def handler(m, p, params, j):
            raise requests.Timeout("read timed out")
        c, _, _ = client(handler)
        put = c.update("id-1", api.build_payload("n", "", ["a.invalid"]))
        self.assertTrue(put.uncertain)
        self.assertEqual(api.write_outcome(put, 200), "uncertain")
        self.assertFalse(c.request("GET", "/WebCategories/id-1").uncertain)
        self.assertTrue(c.commit().uncertain)

    def test_reconcile_is_get_only(self):
        state = {"included": ["a.invalid"]}

        def handler(m, p, params, j):
            if m != "GET":
                raise AssertionError("reconcile must not write")
            return Resp(200, cat(1, includedDomainsOrUrls=state["included"]))
        c, session, _ = client(handler)
        self.assertEqual(api.reconcile_update(c, "id-1", ["A.invalid"])[0], "applied")
        self.assertEqual(api.reconcile_update(c, "id-1", ["b.invalid"])[0], "not_applied")
        c2, _, _ = client(lambda m, p, params, j: Resp(404, {"status": "NotFound"}))
        self.assertEqual(api.reconcile_update(c2, "id-1", [])[0], "unknown")

    def test_token_only_in_header_and_redacted(self):
        def handler(m, p, params, j):
            raise requests.ConnectionError(f"failed with Authorization: Bearer {SECRET}")
        c, session, log = client(handler)
        res = c.update("id-1", api.build_payload("n", "", []))
        self.assertNotIn(SECRET, res.error)
        self.assertNotIn(SECRET, json.dumps(log, default=str))
        self.assertEqual(session.calls[0]["headers"]["Authorization"], f"Bearer {SECRET}")
        self.assertNotIn(SECRET, session.calls[0]["path"])

    def test_error_details_and_outcomes(self):
        c, _, _ = client(lambda m, p, params, j: Resp(409, {"status": "Conflict", "details": "Entity already exists"}))
        res = c.create(api.build_payload("n", "", []))
        self.assertEqual((res.status, api.write_outcome(res, 201)), (409, "failed"))
        self.assertIn("Entity already exists", res.error)


if __name__ == "__main__":
    unittest.main()
