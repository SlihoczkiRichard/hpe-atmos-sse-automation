"""Read-only pre-flight check: allow-list, no side effects, redaction and status reporting (offline)."""

import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from _helpers import OfflineTestCase, load_module

pre = load_module("00-preflight/preflight_check.py", "preflight_check")
CommandResult = pre.scaler.CommandResult

SECRET = "s3cr3t-test-value"
C1_ID = "00000000-0000-0000-0000-000000000001"
C2_ID = "00000000-0000-0000-0000-000000000002"

ENV = {
    "CONNECTOR_1_IP": "192.0.2.11", "CONNECTOR_2_IP": "192.0.2.12",
    "CONNECTOR_SSH_USER": "tester", "CONNECTOR_SSH_PASSWORD": SECRET,
    "ESXI_HOST": "esxi.test.invalid", "ESXI_USER": "root", "ESXI_PASSWORD": SECRET,
    "CONNECTOR_2_VMID": "12", "TARGET_APP_URL": "https://app.test.invalid/",
    "ATMOS_BASE_URL": "https://api.test.invalid/api/v1.0", "ATMOS_API_KEY": SECRET,
    "ATMOS_CONNECTOR_1_ID": C1_ID, "ATMOS_CONNECTOR_2_ID": C2_ID,
}

GUEST_OUTPUT = {
    "head -n1 /proc/stat": CommandResult(0, "cpu  10 20 30 400 50 6 7 8 0 0", ""),
    "command -v sar": CommandResult(0, "/usr/bin/sar", ""),
    "command -v ss": CommandResult(0, "/usr/bin/ss", ""),
}


def esxi_output(state="Powered on"):
    return {
        "vmware -v": CommandResult(0, "VMware ESXi 7.0.3 build-00000", ""),
        "vim-cmd vmsvc/getallvms": CommandResult(
            0, "Vmid   Name        File                         Guest OS      Version   Annotation\n"
               "11     SR-CONN01   [ds1] SR-CONN01/SR-CONN01.vmx  ubuntu64Guest vmx-19\n"
               "12     SR-CONN02   [ds1] SR-CONN02/SR-CONN02.vmx  ubuntu64Guest vmx-19   secret note", ""),
        "vim-cmd vmsvc/power.getstate 12": CommandResult(0, f"Retrieved runtime info\n{state}", ""),
    }


class FakeSSH:
    """Records every executed command per host."""
    def __init__(self, outputs_by_host):
        self.outputs_by_host = outputs_by_host
        self.executed = []

    def factory(self, host, user, password):
        outer = self

        class Exec:
            timeout = 10.0

            def run(self, cmd, timeout=None):
                outer.executed.append((host, cmd))
                return outer.outputs_by_host[host][cmd]
        return Exec()


class FakeResponse:
    def __init__(self, status_code, body=None):
        self.status_code = status_code
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class FakeHttp:
    """GET only; any other HTTP method would raise AttributeError."""
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.routes[url]


def api_routes(check_time="2026-10-26T10:00:00Z"):
    base = ENV["ATMOS_BASE_URL"]
    status_body = {"id": C2_ID, "status": "Available", "systemStatusCheckTime": check_time,
                   "primaryPublicIP": "198.51.100.7", "cpuStatus": {"numOfCpus": 2, "totalUsedPercentage": 12}}
    return {
        f"{base}/Health": FakeResponse(200, {"status": "Healthy", "timestamp": "2026-10-26T10:00:00Z"}),
        f"{base}/Connectors": FakeResponse(200, {"pageNumber": 1, "pageSize": 100, "totalPages": 1, "totalRecords": 2,
                                                 "data": [{"id": C1_ID, "name": "SR-CONN01", "primaryPublicIP": "198.51.100.7"},
                                                          {"id": C2_ID, "name": "SR-CONN02", "primaryPublicIP": "198.51.100.8"}]}),
        f"{base}/Connectors/{C1_ID}/status": FakeResponse(200, dict(status_body, id=C1_ID)),
        f"{base}/Connectors/{C2_ID}/status": FakeResponse(200, status_body),
        ENV["TARGET_APP_URL"]: FakeResponse(200),
    }


def statuses(checks):
    return {c["check"]: c["status"] for c in checks}


class PreflightTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        self.known_hosts = os.path.join(self.tmp, "known_hosts")
        with open(self.known_hosts, "w", encoding="utf-8") as f:
            for host in ("esxi.test.invalid", "192.0.2.11", "192.0.2.12"):
                f.write(f"{host} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n")

    def run_preflight(self, env=None, esxi_state="Powered on", routes=None, known_hosts=None):
        ssh = FakeSSH({"esxi.test.invalid": esxi_output(esxi_state),
                       "192.0.2.11": GUEST_OUTPUT, "192.0.2.12": GUEST_OUTPUT})
        http = FakeHttp(routes or api_routes())
        p = pre.Preflight(env or ENV, ssh.factory, http, known_hosts or [self.known_hosts])
        return p.run(), ssh, http

    def test_plan_mode_contacts_nothing(self):
        with mock.patch.object(pre, "Preflight", side_effect=AssertionError("must not run")), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(pre.main(["--output-dir", self.tmp], environ=ENV), 0)
        self.assertIn("nothing is contacted without --run", out.getvalue())
        self.assertEqual(os.listdir(self.tmp), ["known_hosts"])

    def test_allow_list_rejects_state_changing_commands(self):
        ex = pre.ReadOnlyExecutor(FakeSSH({}).factory("h", "u", "p"))
        for cmd in ("vim-cmd vmsvc/power.on 12", "vim-cmd vmsvc/power.off 12", "vim-cmd vmsvc/power.shutdown 12",
                    "head -n1 /proc/stat; reboot", "command -v sar && rm -rf /", "ssh-keyscan esxi"):
            with self.subTest(cmd=cmd), self.assertRaises(PermissionError):
                ex.run(cmd)

    def test_happy_path_uses_only_read_only_operations(self):
        checks, ssh, http = self.run_preflight()
        self.assertEqual({s for s in statuses(checks).values()} - {pre.OK, pre.NOT_CHECKED}, set())
        for _, cmd in ssh.executed:
            self.assertTrue(any(p.match(cmd) for p in pre.ALLOWED_COMMANDS), cmd)
        self.assertNotIn("power.on", " ".join(c for _, c in ssh.executed))
        self.assertEqual(statuses(checks)["backend.source_ip_logging"], pre.NOT_CHECKED)
        self.assertEqual(statuses(checks)["esxi.c2_power_state"], pre.OK)

    def test_report_contains_no_secrets_or_public_ips(self):
        checks, _, http = self.run_preflight()
        text = json.dumps(checks)
        self.assertNotIn(SECRET, text)
        self.assertNotIn("198.51.100.", text)
        self.assertNotIn("secret note", text)  # VM annotations are not reported
        api_calls = [kw for url, kw in http.calls if url.startswith(ENV["ATMOS_BASE_URL"])]
        self.assertTrue(all(kw["headers"]["Authorization"] == f"Bearer {SECRET}" for kw in api_calls))

    def test_unknown_host_key_is_reported_and_known_hosts_untouched(self):
        empty = os.path.join(self.tmp, "empty_known_hosts")
        open(empty, "w").close()
        checks, ssh, _ = self.run_preflight(known_hosts=[empty])
        st = statuses(checks)
        self.assertEqual(st["esxi.ssh_host_key"], pre.FAILED)
        self.assertEqual(st["esxi.version"], pre.NOT_CHECKED)
        self.assertEqual(st["c1.proc_stat"], pre.NOT_CHECKED)
        self.assertEqual(ssh.executed, [])
        self.assertEqual(os.path.getsize(empty), 0)

    def test_default_ssh_factory_rejects_unknown_keys(self):
        executor = pre.default_ssh_factory(ENV)("esxi.test.invalid", "root", SECRET)
        self.assertFalse(executor.insecure_host_keys)

    def test_powered_off_c2_is_not_checked_and_not_powered_on(self):
        checks, ssh, _ = self.run_preflight(esxi_state="Powered off")
        st = statuses(checks)
        for name in ("c2.proc_stat", "c2.tool_sar", "c2.tool_ss"):
            self.assertEqual(st[name], pre.NOT_CHECKED)
        self.assertNotIn("192.0.2.12", [h for h, _ in ssh.executed])
        reason = next(c["detail"] for c in checks if c["check"] == "c2.proc_stat")
        self.assertIn("never powers it on", reason)

    def test_timestamp_without_offset_is_a_warning(self):
        checks, _, _ = self.run_preflight(routes=api_routes(check_time="2026-10-26T10:00:00"))
        c2 = next(c for c in checks if c["check"] == "api.c2_status")
        self.assertEqual(c2["status"], pre.WARNING)
        self.assertFalse(c2["data"]["has_utc_offset"])
        self.assertEqual(c2["data"]["system_status_check_time_raw"], "2026-10-26T10:00:00")

    def test_missing_api_key_marks_api_checks_not_checked(self):
        env = dict(ENV, ATMOS_API_KEY="")
        checks, _, http = self.run_preflight(env=env)
        st = statuses(checks)
        for name in ("api.health", "api.connectors", "api.c1_status", "api.c2_status"):
            self.assertEqual(st[name], pre.NOT_CHECKED)
        self.assertEqual(st["config.variables"], pre.FAILED)
        self.assertFalse(any(url.startswith(ENV["ATMOS_BASE_URL"]) for url, _ in http.calls))

    def test_invalid_connector_id_is_not_put_into_url(self):
        env = dict(ENV, ATMOS_CONNECTOR_2_ID="../Connectors")
        checks, _, http = self.run_preflight(env=env)
        self.assertEqual(statuses(checks)["api.c2_status"], pre.FAILED)
        self.assertFalse(any("../" in url for url, _ in http.calls))

    def test_app_check_verifies_tls(self):
        _, _, http = self.run_preflight()
        app_call = next(kw for url, kw in http.calls if url == ENV["TARGET_APP_URL"])
        self.assertIs(app_call["verify"], True)

    def test_summary_lists_not_checked_separately(self):
        checks, _, _ = self.run_preflight(esxi_state="Powered off")
        summary = pre.summarize(checks)
        names = [n["check"] for n in summary["not_checked"]]
        self.assertIn("c2.proc_stat", names)
        self.assertIn("backend.source_ip_logging", names)
        self.assertTrue(all(n["reason"] for n in summary["not_checked"]))

    def test_main_run_writes_report_with_injected_fakes(self):
        ssh = FakeSSH({"esxi.test.invalid": esxi_output(), "192.0.2.11": GUEST_OUTPUT, "192.0.2.12": GUEST_OUTPUT})
        env = dict(ENV, SSH_KNOWN_HOSTS=self.known_hosts)
        out_dir = os.path.join(self.tmp, "out")
        with contextlib.redirect_stdout(io.StringIO()):
            code = pre.main(["--run", "--output-dir", out_dir], environ=env, ssh_factory=ssh.factory,
                            http=FakeHttp(api_routes()))
        self.assertEqual(code, 0)
        report_file, = os.listdir(out_dir)
        with open(os.path.join(out_dir, report_file), encoding="utf-8") as f:
            report = json.load(f)
        self.assertIn("not a validation", report["scope"])
        self.assertNotIn(SECRET, json.dumps(report))


if __name__ == "__main__":
    unittest.main()
