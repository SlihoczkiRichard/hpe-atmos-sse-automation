"""Security defaults, secret handling, known_hosts handling, import side effects and the Swagger contract.

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.
"""

import builtins
import contextlib
import io
import json
import os
import socket
import tempfile
import unittest
from unittest import mock

import _helpers
from _helpers import ROOT, NetworkBlocked, OfflineTestCase, load_module

# Recorded BEFORE the module under test is imported: the guard must already be active here.
GUARD_ACTIVE_BEFORE_IMPORT = _helpers.network_guard_active()
CREATE_CONNECTION_BEFORE_IMPORT = socket.create_connection

import paramiko  # noqa: E402

scaler = load_module("02-scaler-poc/scaler_daemon.py", "scaler_daemon")

# A syntactically valid public host key (generated locally, never used for a connection)
TEST_HOST_KEY = paramiko.RSAKey.generate(1024)

SECRET = "s3cr3t-test-value"


def live_cfg(**overrides):
    base = dict(c1_ip="192.0.2.11", c1_user="tester", c1_password=SECRET, esxi_host="esxi.test.invalid",
                esxi_password=SECRET, c2_vmid=12, atmos_api_key=SECRET)
    base.update(overrides)
    return scaler.ScalerConfig(**base)


class FakeResponse:
    def __init__(self, status_code, body=None):
        self.status_code = status_code
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response


class NetworkGuardTests(OfflineTestCase):
    def test_guard_was_active_before_the_module_under_test_was_imported(self):
        self.assertTrue(GUARD_ACTIVE_BEFORE_IMPORT)
        with self.assertRaises(NetworkBlocked):
            CREATE_CONNECTION_BEFORE_IMPORT(("192.0.2.1", 443), timeout=0.1)

    def test_load_module_refuses_without_guard(self):
        with mock.patch.object(_helpers, "network_guard_active", return_value=False), \
                self.assertRaisesRegex(RuntimeError, "network guard not active"):
            load_module("02-scaler-poc/scaler_daemon.py", "scaler_daemon_unguarded")

    def test_real_connections_are_blocked(self):
        with self.assertRaises(NetworkBlocked):
            socket.create_connection(("192.0.2.1", 443), timeout=0.1)
        with self.assertRaises(NetworkBlocked):
            paramiko.SSHClient().connect("192.0.2.1")


class SshHostKeyTests(OfflineTestCase):
    def _client_for(self, **kwargs):
        with mock.patch("paramiko.SSHClient") as client_cls:
            scaler.SSHExecutor("192.0.2.11", "tester", SECRET, **kwargs)._client()
        return client_cls.return_value

    def test_host_keys_are_verified_by_default(self):
        client = self._client_for()
        client.load_system_host_keys.assert_called_once()
        policy = client.set_missing_host_key_policy.call_args[0][0]
        self.assertIsInstance(policy, paramiko.RejectPolicy)

    def test_extra_known_hosts_file_is_loaded(self):
        path = write_known_hosts(self, f"esxi.test.invalid ssh-rsa {TEST_HOST_KEY.get_base64()}\n")
        client = self._client_for(known_hosts=path)
        client.load_host_keys.assert_called_once_with(path)
        self.assertIsInstance(client.set_missing_host_key_policy.call_args[0][0], paramiko.RejectPolicy)

    def test_lab_mode_accepts_unknown_keys_with_warning_policy(self):
        policy = self._client_for(insecure_host_keys=True).set_missing_host_key_policy.call_args[0][0]
        self.assertIsInstance(policy, paramiko.WarningPolicy)

    def test_ssh_failure_is_reported_not_raised(self):
        res = scaler.SSHExecutor("192.0.2.11", "tester", SECRET).run("true")
        self.assertEqual(res.code, -1)
        self.assertIn("SSH error", res.err)
        self.assertNotIn(SECRET, res.err)


def write_known_hosts(test, content, binary=False):
    tmp = tempfile.TemporaryDirectory()
    test.addCleanup(tmp.cleanup)
    path = os.path.join(tmp.name, "known_hosts")
    with open(path, "wb" if binary else "w", **({} if binary else {"encoding": "utf-8"})) as f:
        f.write(content)
    return path


class KnownHostsTests(OfflineTestCase):
    """Missing or broken explicit known_hosts: structured error, never a permissive fallback."""

    def bad_files(self):
        return {
            "missing": os.path.join(tempfile.gettempdir(), "definitely_missing_known_hosts_4711"),
            "invalid_base64": write_known_hosts(self, "esxi.test.invalid ssh-ed25519 !!!notbase64!!!\n"),
            "no_entries": write_known_hosts(self, "# only a comment\n\n"),
            "binary": write_known_hosts(self, b"\xff\xfe\x00garbage\n", binary=True),
            "directory": os.path.dirname(write_known_hosts(self, "")),
        }

    def test_load_known_hosts_errors_are_structured(self):
        for kind, path in self.bad_files().items():
            with self.subTest(kind=kind), self.assertRaises(scaler.KnownHostsError) as ctx:
                scaler.load_known_hosts(path)
            self.assertIn(path, str(ctx.exception))
            self.assertNotIn("notbase64", str(ctx.exception))   # file content is not echoed

    def test_valid_file_is_accepted(self):
        path = write_known_hosts(self, f"esxi.test.invalid ssh-rsa {TEST_HOST_KEY.get_base64()}\n")
        self.assertIn("esxi.test.invalid", scaler.load_known_hosts(path).keys())

    def test_executor_reports_error_and_never_connects_or_relaxes_policy(self):
        for insecure in (False, True):
            for kind, path in self.bad_files().items():
                with self.subTest(kind=kind, insecure=insecure), mock.patch("paramiko.SSHClient") as client_cls:
                    res = scaler.SSHExecutor("192.0.2.11", "tester", SECRET, known_hosts=path,
                                             insecure_host_keys=insecure).run("true")
                    client = client_cls.return_value
                    self.assertEqual(res.code, -1)
                    self.assertIn("known_hosts error", res.err)
                    client.connect.assert_not_called()
                    client.set_missing_host_key_policy.assert_not_called()
                    self.assertNotIn(SECRET, res.err)

    def test_broken_system_known_hosts_is_reported(self):
        from paramiko.hostkeys import InvalidHostKey
        with mock.patch("paramiko.SSHClient") as client_cls:
            client_cls.return_value.load_system_host_keys.side_effect = InvalidHostKey("line", ValueError("b64"))
            res = scaler.SSHExecutor("192.0.2.11", "tester", SECRET).run("true")
            client_cls.return_value.connect.assert_not_called()
            client_cls.return_value.set_missing_host_key_policy.assert_not_called()
        self.assertEqual(res.code, -1)
        self.assertIn("system known_hosts could not be loaded: InvalidHostKey", res.err)

    def test_build_daemon_rejects_missing_known_hosts(self):
        with self.assertRaises(scaler.KnownHostsError):
            scaler.build_daemon(live_cfg(ssh_known_hosts=self.bad_files()["missing"]),
                                recorder=scaler.MemoryRecorder())


class TlsTests(OfflineTestCase):
    def test_target_app_tls_verified_by_default(self):
        daemon = scaler.build_daemon(live_cfg(target_url="https://app.test.invalid/"),
                                     recorder=scaler.MemoryRecorder())
        self.assertIs(daemon.app_probe.verify, True)

    def test_ca_bundle_is_used_when_given(self):
        daemon = scaler.build_daemon(live_cfg(target_url="https://app.test.invalid/", http_ca_bundle="lab-ca.pem"),
                                     recorder=scaler.MemoryRecorder())
        self.assertEqual(daemon.app_probe.verify, "lab-ca.pem")

    def test_lab_flag_disables_verification_explicitly(self):
        daemon = scaler.build_daemon(live_cfg(target_url="https://app.test.invalid/", lab_insecure_tls=True),
                                     recorder=scaler.MemoryRecorder())
        self.assertIs(daemon.app_probe.verify, False)

    def test_application_probe_passes_verify_flag(self):
        session = FakeSession(FakeResponse(200))
        probe = scaler.ApplicationProbe("https://app.test.invalid/", session=session)
        self.assertEqual(probe.check(), (True, "HTTP 200"))
        self.assertIs(session.calls[0][1]["verify"], True)


class SecretHandlingTests(OfflineTestCase):
    def test_passwords_cannot_be_passed_on_the_command_line(self):
        for opt in ("--c1-password", "--esxi-password", "--atmos-api-key"):
            with self.subTest(opt=opt), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                scaler.parse_args([opt, SECRET], {})

    def test_secrets_come_from_environment_with_empty_fallback(self):
        env = {"CONNECTOR_SSH_USER": "tester", "CONNECTOR_SSH_PASSWORD": SECRET,
               "CONNECTOR_2_SSH_USER": "", "CONNECTOR_2_SSH_PASSWORD": "", "ESXI_PASSWORD": "esxi-pw"}
        config = scaler.build_config(scaler.parse_args([], env), env)
        self.assertEqual(config.c2_user, "tester")
        self.assertEqual(config.c2_password, SECRET)
        self.assertEqual(config.esxi_password, "esxi-pw")

    def test_secrets_not_in_config_repr(self):
        self.assertNotIn(SECRET, repr(live_cfg()))

    def test_secrets_are_redacted_from_events_and_errors(self):
        clock = scaler.SimClock()
        recorder = scaler.MemoryRecorder()
        config = live_cfg()
        daemon = scaler.ScalerDaemon(config, scaler.ScalerController(config), scaler.SimulatedESXi(clock),
                                     scaler.SimCpuSampler([None]), clock, recorder)
        with self.assertLogs("scaler", level="INFO") as logs:
            daemon._error("test", f"auth failed for password {SECRET}")
            daemon._event("TEST", f"token={SECRET}")
        self.assertNotIn(SECRET, json.dumps([recorder.errors, recorder.events]))
        self.assertNotIn(SECRET, "\n".join(logs.output))
        self.assertIn("***", recorder.errors[0]["message"])

    def test_bearer_token_only_in_authorization_header(self):
        session = FakeSession(FakeResponse(401))
        client = scaler.ConnectorStatusClient("https://api.test.invalid/api/v1.0", SECRET,
                                              "00000000-0000-0000-0000-000000000002", session=session)
        st = client.get_status()
        self.assertEqual((st.status, st.check_time), (None, None))
        self.assertEqual(st.error, "connector status HTTP 401")
        url, kwargs = session.calls[0]
        self.assertNotIn(SECRET, url)
        self.assertEqual(kwargs["headers"]["Authorization"], f"Bearer {SECRET}")
        self.assertNotIn("verify", kwargs)  # requests default: TLS verification on


class ImportSideEffectTests(OfflineTestCase):
    def test_import_does_not_load_dotenv_or_touch_environment(self):
        before = dict(os.environ)
        with mock.patch("dotenv.load_dotenv") as load_dotenv:
            load_module("02-scaler-poc/scaler_daemon.py", "scaler_daemon_import_check")
        load_dotenv.assert_not_called()
        self.assertEqual(dict(os.environ), before)

    def test_import_opens_no_ssh_client_host_keys_or_api_session(self):
        opened = []
        real_open = builtins.open

        def recording_open(file, *args, **kwargs):
            opened.append(str(file))
            return real_open(file, *args, **kwargs)

        # constructors/methods are hooked instead of replacing the classes, so the network guard stays intact
        with mock.patch.object(paramiko.SSHClient, "__init__", return_value=None) as ssh_client, \
                mock.patch.object(paramiko.HostKeys, "load") as host_keys_load, \
                mock.patch("requests.Session.request") as request, \
                mock.patch.object(builtins, "open", recording_open):
            load_module("02-scaler-poc/scaler_daemon.py", "scaler_daemon_import_tripwire")
        for m in (ssh_client, host_keys_load, request):
            m.assert_not_called()
        self.assertEqual([f for f in opened if "known_hosts" in f or f.endswith(".env")], [])

    def test_building_the_live_daemon_opens_no_ssh_connection(self):
        with mock.patch("paramiko.SSHClient") as ssh_client:
            scaler.build_daemon(live_cfg(c2_ip="192.0.2.12"), recorder=scaler.MemoryRecorder())
        ssh_client.assert_not_called()


class SwaggerContractTests(OfflineTestCase):
    def test_connector_status_endpoint_exists_in_swagger(self):
        with open(os.path.join(ROOT, "04-threat-intel", "atmos-swagger.json"), encoding="utf-8") as f:
            swagger = json.load(f)
        op = swagger["paths"]["/api/v1.0/Connectors/{id}/status"]["get"]
        self.assertEqual(op["operationId"], "Connectors_Status")
        props = swagger["definitions"]["ConnectorStatusResponseModelV1"]["properties"]
        self.assertIn("status", props)
        self.assertIn("systemStatusCheckTime", props)
        statuses = swagger["definitions"]["ConnectorStatus"]["enum"]
        self.assertTrue(set(scaler.ScalerConfig().connector_ready_statuses) <= set(statuses))

        client = scaler.ConnectorStatusClient("https://admin-api.axissecurity.com/api/v1.0", "k", "abc")
        self.assertEqual(client.url, "https://admin-api.axissecurity.com/api/v1.0/Connectors/abc/status")

    def test_status_response_parsing(self):
        body = {"id": "abc", "status": "Available", "systemStatusCheckTime": "2026-10-26T10:00:00.1234567Z"}
        client = scaler.ConnectorStatusClient("https://api.test.invalid/api/v1.0", "k", "abc",
                                              session=FakeSession(FakeResponse(200, body)))
        st = client.get_status()
        self.assertEqual((st.status, st.error, st.tz_assumed), ("Available", "", False))
        self.assertEqual(st.check_time.microsecond, 123456)
        self.assertEqual(st.raw_check_time, "2026-10-26T10:00:00.1234567Z")

        body["systemStatusCheckTime"] = "2026-10-26T10:00:00"
        st = client.get_status()
        self.assertTrue(st.tz_assumed)
        self.assertEqual(st.raw_check_time, "2026-10-26T10:00:00")


if __name__ == "__main__":
    unittest.main()
