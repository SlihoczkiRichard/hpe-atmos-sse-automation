#!/usr/bin/env python3
"""
Read-only pre-flight check of the testbed assumptions used by the measurement scripts.

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

Without --run the script only lists the checks and contacts nothing.
With --run it performs read-only operations:

  SSH (host keys are verified against EXISTING known_hosts files; an unknown key is
  reported and never added)
    ESXi : vmware -v | vim-cmd vmsvc/getallvms | vim-cmd vmsvc/power.getstate <vmid>
    C1/C2: head -n1 /proc/stat | command -v sar | command -v ss
           (C2 only if ESXi already reports it powered on; it is never powered on)
  Atmos Admin API (GET only): /Health, /Connectors, /Connectors/{id}/status
  Target application: one HTTPS GET with TLS verification

It never powers VMs on or off, never changes connector groups, applications or cloud
configuration, and never writes known_hosts. Every remote command must match a fixed
allow-list. The report contains derived facts only: no secrets, no full API responses,
no connector public IPs.

Check statuses: ok / warning / failed / not_checked (each with its reason).
A successful pre-flight is not a validation of the measurements themselves.
"""

import os
import re
import sys
import json
import argparse
import importlib.util
from datetime import datetime, timezone

import requests

OK = "ok"
WARNING = "warning"
FAILED = "failed"
NOT_CHECKED = "not_checked"

GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

ALLOWED_COMMANDS = (
    re.compile(r"^vmware -v$"),
    re.compile(r"^vim-cmd vmsvc/getallvms$"),
    re.compile(r"^vim-cmd vmsvc/power\.getstate \d+$"),
    re.compile(r"^head -n1 /proc/stat$"),
    re.compile(r"^command -v (sar|ss)$"),
)


def _load_scaler():
    """Reuses the scaler's own parsers and SSH executor, so the pre-flight checks exactly
    the assumptions the scaler relies on. Importing it has no side effects."""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "02-scaler-poc", "scaler_daemon.py")
    spec = importlib.util.spec_from_file_location("scaler_daemon_for_preflight", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scaler = _load_scaler()


class ReadOnlyExecutor:
    """Refuses any remote command that is not on the read-only allow-list."""
    def __init__(self, executor):
        self.executor = executor

    def run(self, cmd, timeout=None):
        if not any(p.match(cmd) for p in ALLOWED_COMMANDS):
            raise PermissionError(f"command not in the read-only allow-list: {cmd!r}")
        return self.executor.run(cmd, timeout=timeout)


class ReadOnlyHttp:
    """Exposes GET only."""
    def __init__(self, session=None):
        self._session = session or requests.Session()

    def get(self, url, **kwargs):
        return self._session.get(url, **kwargs)


def _env(env, key, default=""):
    value = env.get(key)
    return default if value is None or not value.strip() else value.strip()


def host_key_known(host, known_hosts_files):
    """True if `host` has an entry in one of the existing known_hosts files (read only)."""
    import paramiko
    keys = paramiko.HostKeys()
    for path in known_hosts_files:
        if path and os.path.isfile(path):
            try:
                keys.load(path)
            except (OSError, paramiko.SSHException):
                continue
    return keys.lookup(host) is not None


def default_known_hosts_files(env):
    files = [os.path.expanduser(os.path.join("~", ".ssh", "known_hosts"))]
    extra = _env(env, "SSH_KNOWN_HOSTS")
    if extra:
        files.append(extra)
    return files


def default_ssh_factory(env):
    def factory(host, user, password):
        # insecure_host_keys=False -> paramiko RejectPolicy: unknown keys fail, nothing is saved
        return scaler.SSHExecutor(host, user, password, timeout=10.0,
                                  known_hosts=_env(env, "SSH_KNOWN_HOSTS"), insecure_host_keys=False)
    return factory


class Preflight:
    def __init__(self, env, ssh_factory, http, known_hosts_files, http_timeout=10.0):
        self.env = env
        self.ssh_factory = ssh_factory
        self.http = http
        self.known_hosts_files = known_hosts_files
        self.http_timeout = http_timeout
        self.checks = []
        self._secrets = [s for s in (_env(env, "CONNECTOR_SSH_PASSWORD"), _env(env, "CONNECTOR_2_SSH_PASSWORD"),
                                     _env(env, "ESXI_PASSWORD"), _env(env, "ATMOS_API_KEY")) if s]

    # --- result helpers ------------------------------------------------------
    def _redact(self, value):
        if isinstance(value, str):
            for secret in self._secrets:
                value = value.replace(secret, "***")
        return value

    def add(self, name, status, detail, **data):
        self.checks.append({"check": name, "status": status, "detail": self._redact(detail),
                            "data": {k: self._redact(v) for k, v in data.items()}})

    def _ssh(self, role, host, user, password):
        """Returns a read-only executor, or None after recording why the host was not checked."""
        if not host:
            self.add(f"{role}.ssh", NOT_CHECKED, "host not configured")
            return None
        if not host_key_known(host, self.known_hosts_files):
            self.add(f"{role}.ssh_host_key", FAILED,
                     f"no known_hosts entry for {host}; not added automatically - verify the fingerprint "
                     "out of band and add it manually")
            return None
        self.add(f"{role}.ssh_host_key", OK, f"known_hosts entry present for {host}")
        return ReadOnlyExecutor(self.ssh_factory(host, user, password))

    # --- checks ----------------------------------------------------------------
    def check_config(self):
        required = ["CONNECTOR_1_IP", "CONNECTOR_SSH_USER", "ESXI_HOST", "ESXI_USER", "CONNECTOR_2_VMID",
                    "TARGET_APP_URL", "ATMOS_BASE_URL", "ATMOS_API_KEY"]
        optional = ["CONNECTOR_2_IP", "ATMOS_CONNECTOR_1_ID", "ATMOS_CONNECTOR_2_ID", "BACKEND_HOST",
                    "SSH_KNOWN_HOSTS", "HTTP_CA_BUNDLE"]
        missing = [k for k in required if not _env(self.env, k)]
        unset_optional = [k for k in optional if not _env(self.env, k)]
        self.add("config.variables", FAILED if missing else OK,
                 "missing required variables: " + ", ".join(missing) if missing else "all required variables set",
                 missing_required=missing, unset_optional=unset_optional)

    def check_esxi(self):
        """Returns the C2 power state reported by ESXi (or None if it could not be read)."""
        ex = self._ssh("esxi", _env(self.env, "ESXI_HOST"), _env(self.env, "ESXI_USER", "root"),
                       _env(self.env, "ESXI_PASSWORD"))
        if ex is None:
            for name in ("esxi.version", "esxi.c2_vm_inventory", "esxi.c2_power_state"):
                self.add(name, NOT_CHECKED, "ESXi SSH not available")
            return None

        res = ex.run("vmware -v")
        if res.code != 0:
            self.add("esxi.version", FAILED, res.err or f"exit code {res.code}")
            for name in ("esxi.c2_vm_inventory", "esxi.c2_power_state"):
                self.add(name, NOT_CHECKED, "ESXi command execution failed")
            return None
        self.add("esxi.version", OK, (res.out.splitlines() or [""])[0][:120])

        vmid_text = _env(self.env, "CONNECTOR_2_VMID")
        if not vmid_text.isdigit() or int(vmid_text) <= 0:
            self.add("esxi.c2_vm_inventory", NOT_CHECKED, "CONNECTOR_2_VMID missing or not a positive integer")
            self.add("esxi.c2_power_state", NOT_CHECKED, "CONNECTOR_2_VMID missing or not a positive integer")
            return None
        vmid = int(vmid_text)

        res = ex.run("vim-cmd vmsvc/getallvms")
        vms = {}
        for line in res.out.splitlines():
            cols = re.split(r"\s{2,}", line.strip())
            if len(cols) >= 2 and cols[0].isdigit():
                vms[int(cols[0])] = cols[1]
        if res.code != 0:
            self.add("esxi.c2_vm_inventory", FAILED, res.err or f"exit code {res.code}")
        elif vmid in vms:
            self.add("esxi.c2_vm_inventory", OK, f"VMID {vmid} exists ({vms[vmid]})",
                     vmid=vmid, vm_name=vms[vmid], vm_count=len(vms))
        else:
            self.add("esxi.c2_vm_inventory", FAILED, f"VMID {vmid} not found among {len(vms)} VMs",
                     vmid=vmid, vm_count=len(vms))

        res = ex.run(f"vim-cmd vmsvc/power.getstate {vmid}")
        state = scaler.parse_power_state(res.out) if res.code == 0 else scaler.UNKNOWN
        if res.code != 0:
            self.add("esxi.c2_power_state", FAILED, res.err or f"exit code {res.code}")
        elif state == scaler.UNKNOWN:
            self.add("esxi.c2_power_state", WARNING,
                     f"output not recognised by the scaler parser: {res.out[:120]!r}")
        else:
            self.add("esxi.c2_power_state", OK, f"parsed as '{state}' by the scaler parser", state=state)
        return state

    def check_guest(self, role, host, user, password, c2_state=None):
        names = [f"{role}.proc_stat", f"{role}.tool_sar", f"{role}.tool_ss"]
        if role == "c2" and c2_state != scaler.RUNNING:
            reason = (f"C2 power state is '{c2_state}'; the pre-flight never powers it on"
                      if c2_state else "C2 power state unknown")
            for name in names:
                self.add(name, NOT_CHECKED, reason)
            return
        ex = self._ssh(role, host, user, password)
        if ex is None:
            for name in names:
                self.add(name, NOT_CHECKED, "guest SSH not available")
            return

        res = ex.run("head -n1 /proc/stat")
        if res.code != 0:
            self.add(f"{role}.proc_stat", FAILED, res.err or f"exit code {res.code}")
            for name in names[1:]:
                self.add(name, NOT_CHECKED, "guest command execution failed")
            return
        try:
            scaler.parse_proc_stat_cpu(res.out.strip())
            counters = len(res.out.split()) - 1
            self.add(f"{role}.proc_stat", OK, f"aggregate cpu line with {counters} counters accepted by the scaler",
                     counters=counters)
        except ValueError as exc:
            self.add(f"{role}.proc_stat", FAILED, f"rejected by the scaler parser: {exc}")

        for tool, purpose in (("sar", "needed by collect_connector_telemetry.sh"),
                              ("ss", "needed only for the optional C2 connection check")):
            res = ex.run(f"command -v {tool}")
            if res.code == 0 and res.out.strip():
                self.add(f"{role}.tool_{tool}", OK, f"found at {res.out.strip()[:120]}")
            else:
                self.add(f"{role}.tool_{tool}", WARNING, f"'{tool}' not found ({purpose})")

    def _api_get(self, url, params=None):
        headers = {"Authorization": f"Bearer {_env(self.env, 'ATMOS_API_KEY')}"}
        try:
            return self.http.get(url, headers=headers, params=params, timeout=self.http_timeout), ""
        except requests.RequestException as exc:
            return None, f"request failed: {type(exc).__name__}"

    def check_api(self):
        base = _env(self.env, "ATMOS_BASE_URL", "https://admin-api.axissecurity.com/api/v1.0").rstrip("/")
        ids = {role: _env(self.env, f"ATMOS_CONNECTOR_{n}_ID") for role, n in (("c1", 1), ("c2", 2))}
        if not _env(self.env, "ATMOS_API_KEY"):
            for name in ["api.health", "api.connectors"] + [f"api.{r}_status" for r in ids]:
                self.add(name, NOT_CHECKED, "ATMOS_API_KEY not set")
            return

        resp, err = self._api_get(f"{base}/Health")
        if resp is None:
            self.add("api.health", FAILED, err)
        else:
            body = _json(resp)
            health = body.get("status") if isinstance(body, dict) else None
            status = OK if resp.status_code == 200 and health == "Healthy" else (
                WARNING if resp.status_code in (200, 503) else FAILED)
            self.add("api.health", status, f"HTTP {resp.status_code}; status={health}",
                     http_status=resp.status_code, health=health)

        resp, err = self._api_get(f"{base}/Connectors", params={"pageNumber": 1, "pageSize": 100})
        listed = {}
        if resp is None or resp.status_code != 200:
            self.add("api.connectors", FAILED, err or f"HTTP {resp.status_code}")
        else:
            body = _json(resp) or {}
            data = body.get("data") or []
            # names and ids only; primaryPublicIP and other fields are deliberately not reported
            listed = {str(c.get("id")): str(c.get("name")) for c in data if isinstance(c, dict)}
            more_pages = (body.get("totalPages") or 1) > 1
            unset = [r for r, i in ids.items() if not i]
            status = WARNING if more_pages or unset else OK
            notes = []
            if more_pages:
                notes.append("only the first page (100) was checked")
            if unset:
                notes.append("ATMOS_CONNECTOR_x_ID not set for: " + ", ".join(unset))
            self.add("api.connectors", status, f"{len(listed)} connector(s) listed" + ("; " + "; ".join(notes)
                                                                                      if notes else ""),
                     connectors=[{"id": i, "name": n} for i, n in sorted(listed.items(), key=lambda x: x[1])],
                     total_records=body.get("totalRecords"))

        for role, cid in ids.items():
            name = f"api.{role}_status"
            if not cid:
                self.add(name, NOT_CHECKED, f"ATMOS_CONNECTOR_{role[1]}_ID not set")
                continue
            if not GUID_RE.match(cid):
                self.add(name, FAILED, f"ATMOS_CONNECTOR_{role[1]}_ID is not a GUID")
                continue
            if listed and cid not in listed:
                self.add(f"api.{role}_listed", WARNING, "id not found on the first page of /Connectors")
            resp, err = self._api_get(f"{base}/Connectors/{cid}/status")
            if resp is None or resp.status_code != 200:
                self.add(name, FAILED, err or f"HTTP {resp.status_code}")
                continue
            body = _json(resp) or {}
            raw = body.get("systemStatusCheckTime")
            parsed, tz_assumed = scaler.parse_api_timestamp(raw)
            fields = sorted(k for k in body if k != "primaryPublicIP")
            cpu = body.get("cpuStatus") if isinstance(body.get("cpuStatus"), dict) else {}
            if parsed is None:
                status, note = WARNING, "systemStatusCheckTime missing or unparseable"
            elif tz_assumed:
                status, note = WARNING, "systemStatusCheckTime has no UTC offset (freshness cannot be verified)"
            else:
                status, note = OK, "systemStatusCheckTime has an explicit UTC offset"
            self.add(name, status, f"status={body.get('status')}; {note}",
                     connector_status=body.get("status"), system_status_check_time_raw=raw,
                     has_utc_offset=bool(parsed) and not tz_assumed, fields_present=fields,
                     cpu_total_used_percentage=cpu.get("totalUsedPercentage"))

    def check_app(self):
        url = _env(self.env, "TARGET_APP_URL")
        if not url:
            self.add("app.reachability", NOT_CHECKED, "TARGET_APP_URL not set")
            return
        expected = int(_env(self.env, "APP_EXPECTED_STATUS", "200"))
        verify = _env(self.env, "HTTP_CA_BUNDLE") or True
        try:
            resp = self.http.get(url, timeout=self.http_timeout, verify=verify)
        except requests.exceptions.SSLError:
            self.add("app.reachability", FAILED, "TLS verification failed (no lab override in the pre-flight)")
            return
        except requests.RequestException as exc:
            self.add("app.reachability", FAILED, f"request failed: {type(exc).__name__}")
            return
        status = OK if resp.status_code == expected else WARNING
        self.add("app.reachability", status,
                 f"HTTP {resp.status_code} (expected {expected}); reachable through the tested path, "
                 "not attributed to a connector", http_status=resp.status_code)

    def check_backend_logging(self):
        self.add("backend.source_ip_logging", NOT_CHECKED,
                 "not automated: inspect the backend access log manually and confirm whether requests "
                 "forwarded by SR-CONN01 and SR-CONN02 show distinguishable source addresses")

    def run(self):
        self.check_config()
        c2_state = self.check_esxi()
        self.check_guest("c1", _env(self.env, "CONNECTOR_1_IP"), _env(self.env, "CONNECTOR_SSH_USER"),
                         _env(self.env, "CONNECTOR_SSH_PASSWORD"))
        self.check_guest("c2", _env(self.env, "CONNECTOR_2_IP"),
                         _env(self.env, "CONNECTOR_2_SSH_USER", _env(self.env, "CONNECTOR_SSH_USER")),
                         _env(self.env, "CONNECTOR_2_SSH_PASSWORD", _env(self.env, "CONNECTOR_SSH_PASSWORD")),
                         c2_state=c2_state)
        self.check_api()
        self.check_app()
        self.check_backend_logging()
        return self.checks


def _json(resp):
    try:
        return resp.json()
    except ValueError:
        return None


def summarize(checks):
    counts = {s: sum(1 for c in checks if c["status"] == s) for s in (OK, WARNING, FAILED, NOT_CHECKED)}
    return {"counts": counts,
            "failed": [c["check"] for c in checks if c["status"] == FAILED],
            "not_checked": [{"check": c["check"], "reason": c["detail"]} for c in checks
                            if c["status"] == NOT_CHECKED]}


PLAN = """Pre-flight plan (nothing is contacted without --run):
  config.variables          presence of required/optional variables (names only)
  esxi.*                    host key present? vmware -v; vim-cmd vmsvc/getallvms; power.getstate <CONNECTOR_2_VMID>
  c1.* / c2.*               host key present? head -n1 /proc/stat; command -v sar; command -v ss
                            (C2 only if ESXi reports it powered on; it is never powered on)
  api.*                     GET /Health, GET /Connectors, GET /Connectors/{id}/status
  app.reachability          one HTTPS GET of TARGET_APP_URL with TLS verification
  backend.source_ip_logging not automated (manual inspection)"""


def main(argv=None, environ=None, ssh_factory=None, http=None):
    p = argparse.ArgumentParser(description="Read-only testbed pre-flight check")
    p.add_argument("--run", action="store_true", help="Actually contact the testbed (read-only operations)")
    p.add_argument("--output-dir", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "results"))
    args = p.parse_args(argv)
    if not args.run:
        print(PLAN)
        return 0

    if environ is None:
        from dotenv import load_dotenv
        load_dotenv()
        environ = os.environ
    pre = Preflight(environ, ssh_factory or default_ssh_factory(environ), http or ReadOnlyHttp(),
                    default_known_hosts_files(environ))
    checks = pre.run()
    report = {"generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "scope": "read-only pre-flight; not a validation of the measurements",
              "checks": checks, "summary": summarize(checks)}

    os.makedirs(args.output_dir, exist_ok=True)
    path = os.path.join(args.output_dir, f"preflight_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    for c in checks:
        print(f"[{c['status']:>11}] {c['check']:<32} {c['detail']}")
    s = report["summary"]["counts"]
    print(f"\nok={s[OK]} warning={s[WARNING]} failed={s[FAILED]} not_checked={s[NOT_CHECKED]}")
    print(f"Report: {path}")
    return 1 if s[FAILED] else 0


if __name__ == "__main__":
    sys.exit(main())
