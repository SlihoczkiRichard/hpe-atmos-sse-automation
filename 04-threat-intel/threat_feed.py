#!/usr/bin/env python3
"""
Pillar 4: deterministic URLhaus feed processing (pure functions, no I/O).

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

Input: the text of the URLhaus "csv_recent" export (lines starting with '#' are comments). Expected
columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter.
Rows that cannot be parsed are counted with their line number and reason, never silently dropped.

Host extraction (documented scope reduction)
  Only the HOST of each URL is kept: lower-cased, trailing dot removed, port and userinfo removed,
  internationalised names converted to IDNA (punycode). Blocking a host is BROADER than blocking
  the listed URL: every path on that host is affected, including legitimate content on shared
  hosting. The optional exclusion list removes hosts the operator names; it is NOT a general
  protection against over-blocking.
  IP literals (IPv4/IPv6) are not put into the web category; they are only saved separately.

Selection rule (deterministic for a given input and configuration)
  1. optional url_status filter (default: no filter)
  2. order rows by dateadded descending, then id descending
  3. take hosts in that order, skipping excluded, invalid, IP and already taken hosts, until
     max_hosts unique hosts are collected (default 25)
  4. the resulting host list is sorted alphabetically
"""

import csv
import io
import re
import ipaddress
from datetime import datetime
from urllib.parse import urlsplit

URLHAUS_COLUMNS = ("id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link",
                   "reporter")
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

SCOPE_NOTE = ("indicators are reduced from URLs to hosts; blocking a host is broader than blocking the "
              "listed URL (all paths on the host, incl. shared hosting)")
EXCLUSION_NOTE = "the exclusion list only removes the named hosts; it is not a general over-blocking protection"
IP_NOTE = "IP indicators are saved separately and are not synchronised to any category"


def parse_urlhaus_csv(text):
    """Returns (rows, errors). rows: dicts with id (int), dateadded (datetime), url, url_status, line."""
    rows, errors = [], []
    for line_no, line in enumerate((text or "").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            fields = next(csv.reader(io.StringIO(line)))
        except (csv.Error, StopIteration) as exc:
            errors.append({"line": line_no, "reason": f"csv error: {exc}"})
            continue
        if len(fields) < 4:
            errors.append({"line": line_no, "reason": f"expected >= 4 columns, got {len(fields)}"})
            continue
        try:
            row_id = int(fields[0])
            added = datetime.strptime(fields[1].strip(), "%Y-%m-%d %H:%M:%S")
        except ValueError as exc:
            errors.append({"line": line_no, "reason": f"bad id/dateadded: {exc}"})
            continue
        rows.append({"id": row_id, "dateadded": added, "url": fields[2].strip(),
                     "url_status": fields[3].strip(), "line": line_no})
    return rows, errors


def normalize_host(url):
    """(kind, value, reason): kind is 'host', 'ip' or 'invalid'."""
    try:
        parts = urlsplit(url)
        host = parts.hostname  # lower-cased, without port/userinfo/brackets
    except ValueError as exc:
        return "invalid", None, f"unparseable URL: {exc}"
    if not host:
        return "invalid", None, "no host in URL"
    host = host.rstrip(".")
    try:
        return "ip", str(ipaddress.ip_address(host)), ""
    except ValueError:
        pass
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        return "invalid", None, f"IDNA conversion failed: {exc}"
    labels = ascii_host.split(".")
    if len(ascii_host) > 253 or len(labels) < 2 or not all(_LABEL.match(lbl) for lbl in labels):
        return "invalid", None, f"not a valid DNS host name: {ascii_host!r}"
    return "host", ascii_host, ""


def _excluded(host, exclusions):
    for entry in exclusions:
        if host == entry or host.endswith("." + entry):
            return entry
    return None


def select_indicators(rows, max_hosts=25, url_status=None, exclude_hosts=()):
    """Applies the selection rule of the module docstring. Returns a JSON-ready dict."""
    if max_hosts < 1:
        raise ValueError("max_hosts must be >= 1")
    allowed = {s.strip().lower() for s in url_status} if url_status else None
    exclusions = sorted({e.strip().lower().rstrip(".") for e in exclude_hosts if e.strip()})
    ordered = sorted(rows, key=lambda r: (r["dateadded"], r["id"]), reverse=True)
    hosts, sources, ips = [], {}, set()
    excluded, rejected, filtered = [], [], 0
    for row in ordered:
        if allowed is not None and row["url_status"].lower() not in allowed:
            filtered += 1
            continue
        kind, value, reason = normalize_host(row["url"])
        if kind == "invalid":
            rejected.append({"id": row["id"], "reason": reason})
            continue
        if kind == "ip":
            ips.add(value)
            continue
        entry = _excluded(value, exclusions)
        if entry:
            excluded.append({"id": row["id"], "host": value, "reason": f"exclusion list entry {entry!r}"})
            continue
        if value in sources:
            sources[value].append(row["id"])
            continue
        if len(hosts) >= max_hosts:
            continue
        hosts.append(value)
        sources[value] = [row["id"]]
    return {
        "hosts": sorted(hosts),
        "ip_indicators": sorted(ips),
        "host_sources": {h: sorted(sources[h]) for h in sorted(hosts)},
        "excluded": excluded,
        "rejected": rejected,
        "filtered_by_url_status": filtered,
        "rows_considered": len(rows),
        "selection_rule": {"url_status_filter": sorted(allowed) if allowed else None, "max_hosts": max_hosts,
                           "order": "dateadded desc, id desc; final host list sorted alphabetically",
                           "exclusions": exclusions},
        "scope_note": SCOPE_NOTE,
        "exclusion_note": EXCLUSION_NOTE,
        "ip_note": IP_NOTE,
    }
