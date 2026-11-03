"""C2 power backends: vCenter REST API (least-privilege user) and operator-assisted manual mode.

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

All HTTP traffic goes to an in-memory fake vCenter; no socket is opened.
"""

import contextlib
import io
import json
import os
import tempfile
import unittest

import requests

from _helpers import OfflineTestCase, load_module

scaler = load_module("02-scaler-poc/scaler_daemon.py", "scaler_daemon_backends")

PASSWORD = "vc-Secret-123"
VM = "vm-1042"


class FakeResponse:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("no body")
        return json.loads(json.dumps(self._body))


class FakeVCenter:
    """Minimal vCenter REST model: one VM visible to the user, power state, session tokens.
    flavor="api" serves /api (7.0+) only, flavor="rest" serves /rest (6.7) only."""

    def __init__(self, flavor="api", state="POWERED_OFF", names=("SR-CONN02",), user_ok=True,
                 power_status=None, boot_after_polls=0):
        self.flavor = flavor
        self.state = state
        self.names = list(names)
        self.user_ok = user_ok
        self.power_status = power_status  # forced HTTP status of power actions (e.g. 403)
        self.boot_after_polls = boot_after_polls
        self.calls = []
        self.tokens = set()
        self.expire_next = False
        self._pending_boot = None

    def _wrap(self, body):
        return {"value": body} if self.flavor == "rest" else body

    def post(self, url, auth=None, verify=None, timeout=None):
        self.calls.append(("POST", url, None, auth is not None))
        assert verify is not False, "TLS verification must never be disabled"
        path = url.split("://", 1)[1].split("/", 1)[1]
        want = "api/session" if self.flavor == "api" else "rest/com/vmware/cis/session"
        if path != want:
            return FakeResponse(404)
        if not self.user_ok or auth != ("sse-scaler@vsphere.local", PASSWORD):
            return FakeResponse(401)
        token = f"tok{len(self.tokens) + 1}"
        self.tokens.add(token)
        return FakeResponse(201 if self.flavor == "api" else 200, self._wrap(token))

    def request(self, method, url, params=None, headers=None, verify=None, timeout=None):
        self.calls.append((method, url, dict(params or {}), False))
        assert verify is not False
        token = (headers or {}).get("vmware-api-session-id")
        if self.expire_next:
            self.expire_next = False
            self.tokens.discard(token)
        if token not in self.tokens:
            return FakeResponse(401)
        path = "/" + url.split("://", 1)[1].split("/", 1)[1]
        prefix = "/api/vcenter/vm" if self.flavor == "api" else "/rest/vcenter/vm"
        if not path.startswith(prefix):
            return FakeResponse(404)
        rest = path[len(prefix):]
        if rest == "" and method == "GET":
            key = "names" if self.flavor == "api" else "filter.names"
            wanted = (params or {}).get(key)
            vms = [{"vm": f"vm-{1042 + i}", "name": n, "power_state": self.state}
                   for i, n in enumerate(self.names) if wanted is None or n == wanted]
            return FakeResponse(200, self._wrap(vms))
        if rest == f"/{VM}/power" and method == "GET":
            if self._pending_boot is not None:
                self._pending_boot -= 1
                if self._pending_boot <= 0:
                    self.state, self._pending_boot = "POWERED_ON", None
            return FakeResponse(200, self._wrap({"state": self.state}))
        action = None
        if self.flavor == "api" and rest == f"/{VM}/power" and method == "POST":
            action = (params or {}).get("action")
        if self.flavor == "rest" and rest in (f"/{VM}/power/start", f"/{VM}/power/stop") and method == "POST":
            action = rest.rsplit("/", 1)[1]
        if rest == f"/{VM}/guest/power" and method == "POST" and (params or {}).get("action") == "shutdown":
            action = "shutdown"
        if action is None:
            return FakeResponse(404)
        if self.power_status:
            return FakeResponse(self.power_status, {"error_type": "UNAUTHORIZED", "messages": [
                {"default_message": "Permission to perform this operation was denied."}]})
        if action == "start":
            if self.state == "POWERED_ON":
                return FakeResponse(400, {"error_type": "ALREADY_IN_DESIRED_STATE"})
            if self.boot_after_polls:
                self._pending_boot = self.boot_after_polls
            else:
                self.state = "POWERED_ON"
        elif action in ("stop", "shutdown"):
            self.state = "POWERED_OFF"
        return FakeResponse(204 if self.flavor == "api" else 200)


def vm(fake, **kwargs):
    return scaler.VCenterVM("vcenter.test.invalid", "sse-scaler@vsphere.local", PASSWORD, "SR-CONN02",
                            session=fake, **kwargs)


class VCenterVMTests(OfflineTestCase):
    def test_power_state_and_power_on_with_the_7x_api(self):
        fake = FakeVCenter("api")
        c = vm(fake)
        self.assertEqual(c.get_power_state(), (scaler.STOPPED, ""))
        res = c.power_on()
        self.assertEqual(res.code, 0)
        self.assertEqual(c.get_power_state(), (scaler.RUNNING, ""))
        self.assertEqual(c.api, "api")
        self.assertIn(("POST", f"https://vcenter.test.invalid/api/vcenter/vm/{VM}/power", {"action": "start"}, False),
                      fake.calls)
        self.assertEqual(sum(1 for call in fake.calls if call[3]), 1)  # one login only

    def test_auto_falls_back_to_the_67_rest_api(self):
        fake = FakeVCenter("rest")
        c = vm(fake)
        self.assertEqual(c.get_power_state(), (scaler.STOPPED, ""))
        self.assertEqual(c.api, "rest")
        self.assertEqual(c.power_on().code, 0)
        self.assertEqual(fake.state, "POWERED_ON")
        lookup = [call for call in fake.calls if call[1].endswith("/rest/vcenter/vm")]
        self.assertEqual(lookup[0][2], {"filter.names": "SR-CONN02"})

    def test_forced_flavor_does_not_probe_the_other(self):
        fake = FakeVCenter("rest")
        vm(fake, api="rest").get_power_state()
        self.assertFalse(any("/api/" in call[1] for call in fake.calls))

    def test_vm_id_is_looked_up_once(self):
        fake = FakeVCenter("api")
        c = vm(fake)
        for _ in range(3):
            c.get_power_state()
        self.assertEqual(sum(1 for call in fake.calls if call[1].endswith("/api/vcenter/vm")), 1)
        self.assertEqual(c.vm_id(), VM)

    def test_expired_session_is_renewed_once(self):
        fake = FakeVCenter("api")
        c = vm(fake)
        c.get_power_state()
        fake.expire_next = True
        self.assertEqual(c.get_power_state(), (scaler.STOPPED, ""))
        self.assertEqual(sum(1 for call in fake.calls if call[3]), 2)

    def test_wrong_password_is_reported_without_the_password(self):
        fake = FakeVCenter("api", user_ok=False)
        state, err = vm(fake).get_power_state()
        self.assertEqual(state, scaler.UNKNOWN)
        self.assertIn("HTTP 401", err)
        self.assertNotIn(PASSWORD, err)
        res = vm(fake).power_on()
        self.assertEqual(res.code, 401)
        self.assertNotIn(PASSWORD, res.err)

    def test_missing_privilege_returns_the_http_status(self):
        fake = FakeVCenter("api", power_status=403)
        res = vm(fake).power_on()
        self.assertEqual(res.code, 403)
        self.assertIn("lacks this privilege", res.err)
        self.assertIn("Permission to perform this operation was denied", res.err)
        self.assertEqual(fake.state, "POWERED_OFF")

    def test_the_vm_name_must_match_exactly_one_vm(self):
        for names in ((), ("SR-CONN02", "SR-CONN02")):
            with self.subTest(names=names):
                state, err = vm(FakeVCenter("api", names=names)).get_power_state()
                self.assertEqual(state, scaler.UNKNOWN)
                self.assertIn("exactly one is required", err)

    def test_transport_error_is_code_minus_one(self):
        class Broken(FakeVCenter):
            def post(self, *a, **k):
                raise requests.ConnectionError("refused")
        res = vm(Broken()).power_on()
        self.assertEqual(res.code, -1)
        self.assertIn("ConnectionError", res.err)

    def test_unknown_power_state_is_unknown(self):
        fake = FakeVCenter("api", state="WEIRD")
        state, err = vm(fake).get_power_state()
        self.assertEqual(state, scaler.UNKNOWN)
        self.assertIn("WEIRD", err)

    def test_shutdown_and_power_off(self):
        for flavor in ("api", "rest"):
            with self.subTest(flavor=flavor):
                fake = FakeVCenter(flavor, state="POWERED_ON")
                c = vm(fake)
                self.assertEqual(c.shutdown().code, 0)
                fake.state = "POWERED_ON"
                self.assertEqual(c.power_off().code, 0)
                self.assertEqual(fake.state, "POWERED_OFF")

    def test_tls_verification_uses_the_ca_bundle(self):
        seen = []

        class Recording(FakeVCenter):
            def request(self, *a, verify=None, **k):
                seen.append(verify)
                return super().request(*a, verify=verify, **k)
        vm(Recording("api"), verify="/etc/vcenter-ca.pem").get_power_state()
        self.assertEqual(set(seen), {"/etc/vcenter-ca.pem"})


class ManualPowerControlTests(OfflineTestCase):
    def test_state_is_a_tcp_proxy_and_power_on_only_notifies(self):
        up = {"value": False}
        notes = []

        def connect(host, port, timeout):
            self.assertEqual((host, port), ("192.0.2.12", 22))
            if not up["value"]:
                raise ConnectionRefusedError()
            return True
        m = scaler.ManualPowerControl("192.0.2.12", connect=connect, notify=notes.append)
        self.assertEqual(m.get_power_state(), (scaler.STOPPED, ""))
        self.assertEqual(m.power_on().code, 0)
        self.assertEqual(len(notes), 1)
        self.assertIn("MANUAL ACTION", notes[0])
        up["value"] = True
        self.assertEqual(m.get_power_state(), (scaler.RUNNING, ""))

    def test_timeout_counts_as_stopped(self):
        def connect(*_):
            raise TimeoutError()
        m = scaler.ManualPowerControl("192.0.2.12", connect=connect, notify=lambda _m: None)
        self.assertEqual(m.get_power_state()[0], scaler.STOPPED)

    def test_shutdown_is_refused(self):
        m = scaler.ManualPowerControl("192.0.2.12", connect=lambda *_: True, notify=lambda _m: None)
        self.assertNotEqual(m.shutdown().code, 0)
        self.assertNotEqual(m.power_off().code, 0)


def live(**overrides):
    base = dict(c1_ip="192.0.2.11", c2_ip="192.0.2.12")
    base.update(overrides)
    return scaler.ScalerConfig(**base)


class BackendConfigTests(OfflineTestCase):
    VC = dict(c2_power_backend="vcenter-api", vcenter_host="vcenter.test.invalid",
              vcenter_user="sse-scaler@vsphere.local", vcenter_password=PASSWORD)

    def test_vcenter_backend_needs_no_esxi_settings(self):
        scaler.validate_config(live(**self.VC))

    def test_vcenter_backend_requires_its_settings(self):
        for key in ("vcenter_host", "vcenter_user", "vcenter_password", "vcenter_vm_name"):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    scaler.validate_config(live(**dict(self.VC, **{key: ""})))

    def test_missing_ca_bundle_file_is_rejected(self):
        with self.assertRaises(ValueError):
            scaler.validate_config(live(**dict(self.VC, vcenter_ca_bundle="/nonexistent/ca.pem")))
        with tempfile.NamedTemporaryFile(suffix=".pem") as f:
            scaler.validate_config(live(**dict(self.VC, vcenter_ca_bundle=f.name)))

    def test_esxi_backend_keeps_its_requirements(self):
        with self.assertRaises(ValueError):
            scaler.validate_config(live())
        scaler.validate_config(live(esxi_host="esxi.test.invalid", c2_vmid=12))

    def test_manual_backend_rules(self):
        scaler.validate_config(live(c2_power_backend="manual"))
        with self.assertRaises(ValueError):
            scaler.validate_config(live(c2_power_backend="manual", c2_ip=""))
        with self.assertRaises(ValueError):
            scaler.validate_config(live(c2_power_backend="manual", enable_scale_in=True))

    def test_unknown_backend_is_rejected_even_in_dry_run(self):
        with self.assertRaises(ValueError):
            scaler.validate_config(scaler.ScalerConfig(dry_run=True, c2_power_backend="ipmi"))

    def test_env_wiring_and_secret_handling(self):
        env = {"C2_POWER_BACKEND": "vcenter-api", "VCENTER_HOST": "10.0.1.6",
               "VCENTER_USER": "sse-scaler@vsphere.local", "VCENTER_PASSWORD": PASSWORD,
               "VCENTER_API": "rest", "CONNECTOR_1_IP": "192.0.2.11"}
        config = scaler.build_config(scaler.parse_args([], env), env)
        self.assertEqual((config.c2_power_backend, config.vcenter_host, config.vcenter_vm_name, config.vcenter_api),
                         ("vcenter-api", "10.0.1.6", "SR-CONN02", "rest"))
        self.assertIn(PASSWORD, config.secrets())
        self.assertNotIn(PASSWORD, repr(config))
        control = scaler.build_power_control(config)
        self.assertIsInstance(control, scaler.VCenterVM)
        self.assertEqual(control.api, "rest")
        self.assertIs(control.verify, True)
        self.assertNotIn(PASSWORD, scaler.describe_power_control(config))

    def test_password_is_not_a_command_line_option(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            scaler.parse_args(["--vcenter-password", "x"], {})

    def test_default_backend_is_esxi_ssh(self):
        config = scaler.build_config(scaler.parse_args([], {}), {})
        self.assertEqual(config.c2_power_backend, "esxi-ssh")


class VCenterDaemonTests(OfflineTestCase):
    def test_activation_through_the_vcenter_backend(self):
        config = live(**self.vc_cfg())
        clock = scaler.SimClock()
        recorder = scaler.MemoryRecorder()
        fake = FakeVCenter("api", boot_after_polls=3)
        daemon = scaler.ScalerDaemon(config, scaler.ScalerController(config), vm(fake),
                                     scaler.SimCpuSampler([90.0]), clock, recorder)
        daemon.run(max_cycles=6)
        names = [e["event"] for e in recorder.events]
        self.assertIn("POWER_ON_SENT", names)
        self.assertIn("VM_POWERED_ON", names)
        sent = next(e for e in recorder.events if e["event"] == "POWER_ON_SENT")
        self.assertTrue(sent["detail"].startswith("exit_code=0; "))
        starts = [c for c in fake.calls if c[0] == "POST" and c[2] == {"action": "start"}]
        self.assertEqual(len(starts), 1)
        self.assertFalse(any(PASSWORD in json.dumps(e) for e in recorder.events + recorder.errors))

    def test_denied_power_on_is_logged_as_failed(self):
        config = live(**self.vc_cfg())
        clock = scaler.SimClock()
        recorder = scaler.MemoryRecorder()
        daemon = scaler.ScalerDaemon(config, scaler.ScalerController(config), vm(FakeVCenter("api", power_status=403)),
                                     scaler.SimCpuSampler([90.0]), clock, recorder)
        with self.assertLogs("scaler", level="ERROR"):
            daemon.run(max_cycles=5)
        names = [e["event"] for e in recorder.events]
        self.assertIn("POWER_ON_FAILED", names)
        self.assertNotIn("VM_POWERED_ON", names)
        self.assertTrue(any("403" in e["message"] for e in recorder.errors))

    @staticmethod
    def vc_cfg():
        return dict(BackendConfigTests.VC, scale_out_pct=80.0, window_sec=15.0, poll_sec=5.0, cooldown_sec=60.0,
                    min_c2_uptime_sec=0.0, power_on_timeout_sec=60.0, power_state_poll_sec=1.0)


if __name__ == "__main__":
    unittest.main()
