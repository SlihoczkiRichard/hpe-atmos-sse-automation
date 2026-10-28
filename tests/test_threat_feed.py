"""threat_feed.py: URLhaus parsing, host normalisation and the deterministic selection rule.

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

Synthetic feed lines only (hosts under .invalid / .example / documentation IP ranges).
"""

import random
import unittest

from _helpers import OfflineTestCase, load_module

feed = load_module("04-threat-intel/threat_feed.py", "threat_feed")

FEED = """################################################################
# abuse.ch URLhaus Database Dump (CSV - recent URLs)          #
################################################################
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"3001","2026-10-26 10:00:00","http://Bad-One.example.invalid:8080/x.exe","online","2026-10-26 10:00:00","malware_download","exe","https://urlhaus.abuse.ch/url/3001/","r"
"3002","2026-10-26 10:00:00","http://bad-two.example.invalid./a","offline","","malware_download","","https://urlhaus.abuse.ch/url/3002/","r"
"3000","2026-10-26 09:00:00","http://user:pw@bad-one.example.invalid/other","online","","malware_download","","https://urlhaus.abuse.ch/url/3000/","r"
"2999","2026-10-25 09:00:00","http://198.51.100.7/bin","online","","malware_download","","https://urlhaus.abuse.ch/url/2999/","r"
"2998","2026-10-25 08:00:00","http://[2001:db8::7]/bin","online","","malware_download","","https://urlhaus.abuse.ch/url/2998/","r"
"2997","2026-10-25 07:00:00","http://bücher.example.invalid/z","online","","malware_download","","https://urlhaus.abuse.ch/url/2997/","r"
"2996","2026-10-25 06:00:00","http://files.shared-hosting.example/u/1","online","","malware_download","","https://urlhaus.abuse.ch/url/2996/","r"
"2995","2026-10-25 05:00:00","http://bad_host.example.invalid/","online","","malware_download","","https://urlhaus.abuse.ch/url/2995/","r"
"x","2026-10-25 05:00:00","http://broken.example.invalid/","online","","","","",""
"2994","yesterday","http://broken2.example.invalid/","online","","","","",""
"2993","2026-10-24 05:00:00"
"""


class ParseTests(OfflineTestCase):
    def test_comments_skipped_and_bad_rows_reported(self):
        rows, errors = feed.parse_urlhaus_csv(FEED)
        self.assertEqual(len(rows), 8)
        self.assertEqual([e["line"] for e in errors], [13, 14, 15])
        self.assertIn("bad id/dateadded", errors[0]["reason"])
        self.assertIn("expected >= 4 columns", errors[2]["reason"])


class NormalizeTests(OfflineTestCase):
    def test_hosts(self):
        cases = {
            "http://Bad-One.example.invalid:8080/x": ("host", "bad-one.example.invalid"),
            "http://user:pw@bad-one.example.invalid/": ("host", "bad-one.example.invalid"),
            "http://bad-two.example.invalid./a": ("host", "bad-two.example.invalid"),
            "http://bücher.example.invalid/": ("host", "xn--bcher-kva.example.invalid"),
            "http://198.51.100.7/": ("ip", "198.51.100.7"),
            "http://[2001:db8::7]/": ("ip", "2001:db8::7"),
        }
        for url, expected in cases.items():
            with self.subTest(url=url):
                self.assertEqual(feed.normalize_host(url)[:2], expected)

    def test_invalid(self):
        for url in ("http://bad_host.example.invalid/", "not a url", "http:///path", "http://localhost/"):
            with self.subTest(url=url):
                self.assertEqual(feed.normalize_host(url)[0], "invalid")


class SelectionTests(OfflineTestCase):
    def rows(self):
        return feed.parse_urlhaus_csv(FEED)[0]

    def test_rule_order_limit_and_alphabetical_result(self):
        sel = feed.select_indicators(self.rows(), max_hosts=2)
        # newest first: 3002 (id desc at equal time) then 3001 -> 2 hosts; result sorted
        self.assertEqual(sel["hosts"], ["bad-one.example.invalid", "bad-two.example.invalid"])
        self.assertEqual(sel["host_sources"]["bad-one.example.invalid"], [3000, 3001])

    def test_ips_saved_separately_and_invalid_rejected(self):
        sel = feed.select_indicators(self.rows())
        self.assertEqual(sel["ip_indicators"], ["198.51.100.7", "2001:db8::7"])
        self.assertNotIn("198.51.100.7", sel["hosts"])
        self.assertEqual([r["id"] for r in sel["rejected"]], [2995])
        self.assertIn("not synchronised", sel["ip_note"])

    def test_exclusion_list_and_notes(self):
        sel = feed.select_indicators(self.rows(), exclude_hosts=["shared-hosting.example"])
        self.assertNotIn("files.shared-hosting.example", sel["hosts"])
        self.assertEqual(sel["excluded"][0]["host"], "files.shared-hosting.example")
        self.assertIn("broader than blocking the listed URL", sel["scope_note"])
        self.assertIn("not a general over-blocking protection", sel["exclusion_note"])

    def test_url_status_filter_is_optional(self):
        all_rows = feed.select_indicators(self.rows())
        online = feed.select_indicators(self.rows(), url_status=["online"])
        self.assertIn("bad-two.example.invalid", all_rows["hosts"])          # default: no filter
        self.assertNotIn("bad-two.example.invalid", online["hosts"])
        self.assertEqual(online["filtered_by_url_status"], 1)
        self.assertIsNone(all_rows["selection_rule"]["url_status_filter"])

    def test_deterministic_for_any_input_order(self):
        rows = self.rows()
        expected = feed.select_indicators(rows, max_hosts=3)
        for seed in range(5):
            shuffled = rows[:]
            random.Random(seed).shuffle(shuffled)
            with self.subTest(seed=seed):
                self.assertEqual(feed.select_indicators(shuffled, max_hosts=3), expected)

    def test_max_hosts_validation(self):
        with self.assertRaises(ValueError):
            feed.select_indicators([], max_hosts=0)


if __name__ == "__main__":
    unittest.main()
