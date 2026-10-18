import csv
import io
import ipaddress
import os
import time
from urllib.parse import urlparse
import requests
from dotenv import load_dotenv

load_dotenv()

ATMOS_BASE_URL = os.getenv("ATMOS_BASE_URL", "https://admin-api.axissecurity.com/api/v1.0")
ATMOS_API_KEY = os.getenv("ATMOS_API_KEY")

CATEGORY_NAME = "URLhaus_Malware_Blocklist"
CATEGORY_DESC = "Automated threat feed ingestion from abuse.ch URLhaus - BME BSc Thesis"
URLHAUS_RECENT_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
MAX_INDICATORS = 25

headers = {
    "Authorization": f"Bearer {ATMOS_API_KEY}",
    "Content-Type": "application/json"
}

def is_valid_domain(hostname):
    """Filters out raw IP addresses and validates domain format."""
    if not hostname or "." not in hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return False  # Raw IP addresses are rejected by WebCategory
    except ValueError:
        pass
    # Basic domain character validation
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-.")
    return set(hostname.lower()).issubset(allowed)

def fetch_urlhaus_indicators(limit=25):
    print("[*] 1/3: Fetching fresh threat intelligence feed (abuse.ch URLhaus)...")
    req_headers = {"User-Agent": "BME-BSc-Thesis-ThreatSync/1.0"}
    response = requests.get(URLHAUS_RECENT_URL, headers=req_headers, timeout=15)
    response.raise_for_status()

    # Filter out header comments (#) and parse CSV rows
    clean_lines = [line for line in response.text.splitlines() if not line.startswith("#") and line.strip()]
    reader = csv.reader(io.StringIO("\n".join(clean_lines)))

    domains = set()
    for row in reader:
        # URLhaus CSV columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
        if len(row) >= 3:
            raw_url = row[2].strip()
            parsed = urlparse(raw_url)
            host = parsed.hostname
            if host and is_valid_domain(host):
                domains.add(host.lower())
        if len(domains) >= limit:
            break

    indicator_list = list(domains)
    print(f"[+] 2/3: Successfully extracted and normalized {len(indicator_list)} unique malicious domains:")
    for d in indicator_list[:5]:
        print(f"    - {d}")
    if len(indicator_list) > 5:
        print(f"    ... and {len(indicator_list) - 5} more domains.")

    return indicator_list

def find_existing_category():
    url = f"{ATMOS_BASE_URL}/WebCategories"
    params = {"pageNumber": 1, "pageSize": 100}
    response = requests.get(url, headers=headers, params=params, timeout=15)
    response.raise_for_status()

    data = response.json().get("data", [])
    for item in data:
        if item.get("name") == CATEGORY_NAME:
            return item.get("id")
    return None

def sync_to_atmos(indicators):
    print("[*] 3/3: Synchronizing with Atmos REST API...")
    category_id = find_existing_category()
    start_time = time.perf_counter()

    payload = {
        "name": CATEGORY_NAME,
        "description": CATEGORY_DESC,
        "type": "Custom",
        "includedDomainsOrUrls": indicators,
        "excludedDomainsOrUrls": []
    }

    if category_id:
        print(f"[*] Updating existing WebCategory (ID: {category_id})...")
        target_url = f"{ATMOS_BASE_URL}/WebCategories/{category_id}"
        res = requests.put(target_url, headers=headers, json=payload, timeout=15)
    else:
        print(f"[*] Creating new WebCategory: '{CATEGORY_NAME}'...")
        target_url = f"{ATMOS_BASE_URL}/WebCategories"
        res = requests.post(target_url, headers=headers, json=payload, timeout=15)

    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
    print(f"[*] REST API response time: {latency_ms} ms (HTTP Status: {res.status_code})")

    if res.status_code in (200, 201):
        print(f"[SUCCESS] {len(indicators)} malicious domains successfully synchronized with Atmos SWG!")
        return res.json().get("id") or category_id
    else:
        print(f"[ERROR] Synchronization failed: {res.text}")
        return None

if __name__ == "__main__":
    domains = fetch_urlhaus_indicators(limit=MAX_INDICATORS)
    sync_to_atmos(domains)