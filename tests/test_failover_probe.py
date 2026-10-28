"""failover_probe.py: probes with fake sockets, persistent no-reconnect rule, probe loop, files, markers, CLI.

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

The HTTP tests drive the real http.client classes over a fake socket, so http.client's own
keep-alive, auto_open and response-reading logic is exercised; no real connection is opened.
"""

import contextlib
import csv
import errno
import http.client
import io
import json
import os
import socket
import ssl
import tempfile
import unittest
from unittest import mock

from _helpers import OfflineTestCase, load_module

fp = load_module("03-failover/failover_probe.py", "failover_probe")

TOKEN = "probe-token-7c1e"


def response(status=200, body=TOKEN.encode(), headers=None, length=True):
    lines = [f"HTTP/1.1 {status} X"]
    hdrs = dict(headers or {})
    if length:
        hdrs.setdefault("Content-Length", str(len(body)))
    lines += [f"{k}: {v}" for k, v in hdrs.items()]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


class FakeSocket:
    """Each sendall() of a request makes the next scripted item the response. An item is bytes
    (b"" = EOF) or an exception raised on sendall."""
    def __init__(self, script):
        self.script = list(script)
        self.sent = []
        self.current = b""

    def sendall(self, data):
        self.sent.append(data)
        if b"\r\n\r\n" in data or data.endswith(b"\r\n"):
            item = self.script.pop(0) if self.script else b""
            if isinstance(item, BaseException):
                raise item
            self.current = item

    def makefile(self, mode, *args, **kwargs):
        return io.BytesIO(self.current)

    def close(self):
        pass


class Factory:
    """Builds real http.client connections whose connect() installs a FakeSocket."""
    def __init__(self, script, connect_error=None):
        self.script, self.connect_error = script, connect_error
        self.real_connects = 0
        self.connections = []

    def __call__(self, scheme, host, port, timeout, ca_bundle=""):
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        factory = self

        def connect():
            factory.real_connects += 1
            if factory.connect_error:
                raise factory.connect_error
            conn.sock = FakeSocket(factory.script)

        conn.connect = connect
        self.connections.append(conn)
        return conn


def check(**kw):
    return fp.ContentCheck(**{"expect_status": 200, "expect_body": TOKEN, "max_body_bytes": 64, **kw})


class ClassifyTests(OfflineTestCase):
    def test_error_classes(self):
        cases = [
            (socket.gaierror(-2, "Name or service not known"), "dns_error"),
            (ssl.SSLCertVerificationError("bad cert"), "tls_error"),
            (ssl.SSLEOFError(8, "EOF"), "eof"),
            (socket.timeout("timed out"), "timeout"),
            (TimeoutError(), "timeout"),
            (ConnectionRefusedError(), "refused"),
            (http.client.RemoteDisconnected("closed"), "eof"),
            (ConnectionResetError(), "reset"),
            (BrokenPipeError(), "reset"),
            (OSError(errno.EHOSTUNREACH, "no route"), "unreachable"),
            (OSError(10051, "WSAENETUNREACH"), "unreachable"),
            (http.client.BadStatusLine("x"), "http_protocol_error"),
            (ValueError("x"), "other"),
        ]
        for exc, expected in cases:
            with self.subTest(exc=type(exc).__name__):
                self.assertEqual(fp.classify_error(exc), expected)


class TcpProbeTests(OfflineTestCase):
    def test_success_closes_the_new_connection(self):
        sock = mock.Mock()
        calls = []
        probe = fp.TcpProbe("app.test.invalid", 443, 0.25,
                            connect=lambda addr, timeout: calls.append((addr, timeout)) or sock)
        self.assertEqual(probe.probe(), fp.ProbeResult(True))
        self.assertEqual(calls, [(("app.test.invalid", 443), 0.25)])
        sock.close.assert_called_once()

    def test_failures_are_classified(self):
        for exc, cls in ((ConnectionRefusedError(), "refused"), (socket.timeout(), "timeout"),
                         (socket.gaierror(-2, "x"), "dns_error")):
            def boom(addr, timeout, exc=exc):
                raise exc
            with self.subTest(cls=cls):
                res = fp.TcpProbe("h.test.invalid", 443, 0.25, connect=boom).probe()
                self.assertEqual((res.ok, res.error_class), (False, cls))


class HttpProbeTests(OfflineTestCase):
    def probe(self, *script, **check_kw):
        factory = Factory(list(script))
        p = fp.HttpProbe("https://app.test.invalid/failover-probe.txt", 1.0, check(**check_kw),
                         connection_factory=factory)
        return p, factory

    def test_success_needs_status_and_content_and_uses_a_new_connection(self):
        p, factory = self.probe(response(), response())
        self.assertTrue(p.probe().ok)
        self.assertTrue(p.probe().ok)
        self.assertEqual((factory.real_connects, len(factory.connections)), (2, 2))   # new connection per probe

    def test_request_headers(self):
        sock_holder = {}
        factory = Factory([response()])
        original = factory.__call__

        def capture(*a, **k):
            conn = original(*a, **k)
            inner = conn.connect

            def connect():
                inner()
                sock_holder["sock"] = conn.sock
            conn.connect = connect
            return conn

        p = fp.HttpProbe("https://app.test.invalid/failover-probe.txt", 1.0, check(), connection_factory=capture)
        self.assertTrue(p.probe().ok)
        sent = b"".join(sock_holder["sock"].sent)
        self.assertIn(b"GET /failover-probe.txt HTTP/1.1", sent)
        self.assertIn(b"Connection: close", sent)

    def test_status_content_and_size_failures(self):
        cases = [
            (response(503), {}, "status_mismatch"),
            (response(302, b"", {"Location": "/elsewhere"}), {}, "status_mismatch"),   # redirect not followed
            (response(200, b"maintenance page"), {}, "content_mismatch"),
            (response(200, TOKEN.encode() + b" v2"), {"expect_regex": r"v[0-9]+$"}, None),
            (response(200, TOKEN.encode()), {"expect_regex": r"^nomatch"}, "content_mismatch"),
            (response(200, b"x" * 65), {"expect_body": "x"}, "body_too_large"),
            (b"", {}, "eof"),
            (ConnectionResetError(), {}, "reset"),
        ]
        for item, kw, cls in cases:
            with self.subTest(cls=cls, kw=kw):
                res = self.probe(item, **kw)[0].probe()
                self.assertEqual(res.ok, cls is None, res)
                if cls:
                    self.assertEqual(res.error_class, cls)

    def test_content_check_is_mandatory(self):
        with self.assertRaises(ValueError):
            fp.ContentCheck(200, "", "")

    def test_default_factory_verifies_tls_without_connecting(self):
        conn = fp.default_connection_factory("https", "app.test.invalid", 443, 1.0)
        self.assertIsNone(conn.sock)
        self.assertEqual(conn._context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(conn._context.check_hostname)


class PersistentProbeTests(OfflineTestCase):
    def make(self, *script, **check_kw):
        factory = Factory(list(script))
        probe = fp.PersistentHttpProbe("http://app.test.invalid/failover-probe.txt", 1.0, check(**check_kw),
                                       connection_factory=factory)
        self.assertTrue(probe.open().ok)
        return probe, factory

    def test_keep_alive_exchanges_on_one_connection(self):
        probe, factory = self.make(response(), response(), response())
        self.assertEqual([probe.probe().ok for _ in range(3)], [True, True, True])
        self.assertEqual((factory.real_connects, probe.connect_calls, len(factory.connections)), (1, 1, 1))
        self.assertIn(b"Connection: keep-alive", b"".join(probe.conn.sock.sent))

    def test_no_second_connect_after_the_connection_ended(self):
        probe, factory = self.make(response(), b"")
        self.assertTrue(probe.probe().ok)
        ended = probe.probe()
        self.assertEqual((ended.ok, ended.error_class, ended.ended, probe.end_class), (False, "eof", True, "eof"))
        after = probe.probe()
        self.assertEqual((after.error_class, after.ended), ("not_connected", True))
        with self.assertRaises(fp.ReconnectRefused):
            probe.conn.connect()                                        # guarded: second connect refused
        with self.assertRaises(fp.ReconnectRefused):
            probe.open()
        self.assertEqual(factory.real_connects, 1)

    def test_http_client_auto_reconnect_is_disabled(self):
        probe, factory = self.make(response(headers={"Connection": "close"}))
        res = probe.probe()
        self.assertEqual((res.ok, res.ended, probe.end_class), (True, True, "server_connection_close"))
        self.assertEqual(probe.conn.auto_open, 0)
        with self.assertRaises(http.client.NotConnected):              # not a silent reconnect
            probe.conn.request("GET", "/")
        self.assertEqual(factory.real_connects, 1)

    def test_unsafe_bodies_end_the_probe(self):
        cases = [
            (response(body=b"", headers={"Transfer-Encoding": "chunked"}, length=False) + b"0\r\n\r\n",
             "body_length_unknown"),
            (response(length=False), "body_length_unknown"),
            (response(body=b"x" * 100), "body_too_large"),
            (response(headers={"Content-Length": "40"}), "eof"),            # announced more than sent
        ]
        for item, cls in cases:
            with self.subTest(cls=cls):
                probe, factory = self.make(item, response())
                res = probe.probe()
                self.assertEqual((res.ok, res.error_class, res.ended), (False, cls, True))
                self.assertEqual(probe.probe().error_class, "not_connected")
                self.assertEqual(factory.real_connects, 1)

    def test_content_mismatch_does_not_end_the_connection(self):
        probe, _ = self.make(response(200, b"other"), response())
        res = probe.probe()
        self.assertEqual((res.error_class, res.ended), ("content_mismatch", False))
        self.assertTrue(probe.probe().ok)

    def test_reset_and_connect_failure(self):
        probe, _ = self.make(ConnectionResetError())
        res = probe.probe()
        self.assertEqual((res.error_class, res.ended), ("reset", True))
        factory = Factory([], connect_error=ConnectionRefusedError())
        p = fp.PersistentHttpProbe("http://app.test.invalid/x", 1.0, check(), connection_factory=factory)
        res = p.open()
        self.assertEqual((res.ok, res.error_class, res.ended), (False, "refused", True))


class Cfg:
    def __init__(self, probe="tcp", interval=0.05, duration=1.0, run_id="R1", dry_run=False):
        self.probe, self.interval_sec, self.duration_sec = probe, interval, duration
        self.run_id, self.dry_run = run_id, dry_run

    def describe(self):
        return {"probe": self.probe, "interval_ms": self.interval_sec * 1000}


class StepProbe:
    def __init__(self, clock, durations, results=None):
        self.clock, self.durations, self.results = clock, list(durations), list(results or [])
        self.conn = None

    def probe(self):
        self.clock.sleep(self.durations.pop(0) if self.durations else 0.001)
        return self.results.pop(0) if self.results else fp.ProbeResult(True)

    def open(self):
        return fp.ProbeResult(True)


def text(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def read(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


class ProbeLoopTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name

    def test_grid_schedule_actual_times_and_skipped_slots(self):
        clock = fp.SimClock()
        probe = StepProbe(clock, [0.004, 0.12, 0.004, 0.004])
        manifest, path = fp.run_probe(Cfg(duration=0.3), probe, clock, self.dir)
        rows = read(path)
        self.assertEqual([float(r["scheduled_mono_s"]) for r in rows], [0.0, 0.05, 0.2, 0.25])
        self.assertEqual([int(r["skipped_slots_after"]) for r in rows], [0, 2, 0, 0])
        self.assertAlmostEqual(float(rows[1]["end_mono_s"]) - float(rows[1]["start_mono_s"]), 0.12, places=6)
        self.assertTrue(all(r["start_utc"] and r["end_utc"] for r in rows))
        self.assertEqual((manifest["mode"], manifest["ended_by"]), ("measurement", "duration"))
        self.assertIn("not a guaranteed resolution", " ".join(manifest["notes"]))

    def test_existing_files_are_never_overwritten(self):
        clock = fp.SimClock()
        m1, p1 = fp.run_probe(Cfg(duration=0.1), StepProbe(clock, []), clock, self.dir)
        before = text(p1)
        m2, p2 = fp.run_probe(Cfg(duration=0.1), StepProbe(clock, []), clock, self.dir)
        self.assertEqual((m1["attempt"], m2["attempt"]), (1, 2))
        self.assertTrue(p2.endswith("probes_tcp.attempt2.csv"))
        self.assertEqual(text(p1), before)
        self.assertTrue(os.path.exists(os.path.join(self.dir, "manifest_tcp.attempt2.json")))
        with self.assertRaises(FileExistsError):
            fp.run_probe(Cfg(duration=0.1), StepProbe(clock, []), clock, self.dir, attempt=1)

    def test_persistent_run_ends_without_replacement_connection(self):
        clock = fp.SimClock()
        results = [fp.ProbeResult(True), fp.ProbeResult(False, "eof", "EOF", None, True)]
        probe = StepProbe(clock, [], results)
        probe.end_class = "eof"
        manifest, path = fp.run_probe(Cfg("persistent", interval=0.2, duration=5.0), probe, clock, self.dir)
        rows = read(path)
        self.assertEqual([r["event"] for r in rows], ["connect", "exchange", "exchange", "end"])
        self.assertEqual(rows[-1]["error_class"], "eof")
        self.assertIn("cause unknown", rows[-1]["detail"])
        self.assertEqual(manifest["ended_by"], "connection ended: eof")

    def test_persistent_run_until_duration_records_probe_stop(self):
        clock = fp.SimClock()
        manifest, path = fp.run_probe(Cfg("persistent", interval=0.2, duration=1.0), StepProbe(clock, []),
                                      clock, self.dir)
        rows = read(path)
        self.assertEqual((rows[-1]["event"], rows[-1]["error_class"]), ("end", "probe_stopped"))
        self.assertEqual(sum(1 for r in rows if r["event"] == "exchange"), 5)

    def test_keyboard_interrupt_keeps_records_and_manifest(self):
        clock = fp.SimClock()

        class Interrupting(StepProbe):
            def probe(self):
                if clock.monotonic() > 0.12:
                    raise KeyboardInterrupt
                return super().probe()

        manifest, path = fp.run_probe(Cfg(duration=5.0), Interrupting(clock, []), clock, self.dir)
        self.assertEqual(manifest["ended_by"], "keyboard_interrupt")
        self.assertEqual(len(read(path)), 3)


class MarkerFileTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        self.clock = fp.SimClock()
        self.domain = {"host": "h", "system": "Linux", "boot_id": "b", "boot_epoch_estimate": 1.0, "simulated": False}

    def test_header_written_once_and_operator_signal(self):
        fp.write_marker(self.dir, "R1", "fault_injected", "C1 stopped by hand", self.clock, self.domain)
        self.clock.sleep(10)
        fp.write_marker(self.dir, "R1", "fault_cleared", "", self.clock, self.domain)
        path = os.path.join(self.dir, "R1", "markers.csv")
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
        self.assertEqual(sum(1 for line in lines if line.startswith("run_id,")), 1)
        markers = fp.read_markers(path)
        self.assertEqual([m["kind"] for m in markers], ["fault_injected", "fault_cleared"])
        self.assertEqual(markers[1]["monotonic_s"] - markers[0]["monotonic_s"], 10.0)
        self.assertEqual(markers[0]["clock_domain"]["boot_id"], "b")
        self.assertTrue(all(r["source"] == "operator_signal" for r in read(path)))

    def test_foreign_rows_or_header_are_refused(self):
        run_dir = os.path.join(self.dir, "R1")
        os.makedirs(run_dir)
        path = os.path.join(run_dir, "markers.csv")
        with open(path, "w", newline="", encoding="utf-8") as f:
            f.write("time,kind\n1,fault\n")
        with self.assertRaisesRegex(ValueError, "unexpected header"):
            fp.write_marker(self.dir, "R1", "note", "", self.clock, self.domain)
        os.remove(path)
        fp.write_marker(self.dir, "R1", "note", "", self.clock, self.domain)
        with open(path, "a", newline="", encoding="utf-8") as f:   # simulate a misplaced row of another run
            csv.writer(f).writerow(["R2", 9, "note"] + [""] * 9)
        with self.assertRaisesRegex(ValueError, "other runs"):
            fp.write_marker(self.dir, "R1", "note", "", self.clock, self.domain)

    def test_invalid_kind(self):
        with self.assertRaises(ValueError):
            fp.write_marker(self.dir, "R1", "power_off", "", self.clock, self.domain)

    def test_clock_domain(self):
        real = fp.RealClock()
        d = fp.clock_domain(real, read_boot_id=lambda: "boot-123")
        self.assertEqual((d["boot_id"], d["simulated"]), ("boot-123", False))
        self.assertIsInstance(d["boot_epoch_estimate"], float)
        self.assertTrue(fp.clock_domain(fp.SimClock())["simulated"])


class CliTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name

    def main(self, *argv):
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            code = fp.main(list(argv) + ["--output-dir", self.dir], environ={})
        return code, out.getvalue(), err.getvalue()

    def test_configuration_errors(self):
        self.assertEqual(self.main("run", "--probe", "tcp", "--tcp-host", "h.test.invalid")[0], 2)    # no RUN_ID
        self.assertEqual(self.main("run", "--probe", "tcp", "--run-id", "R1")[0], 2)                  # no host
        code, _, err = self.main("run", "--probe", "http", "--run-id", "R1",
                                 "--http-url", "https://app.test.invalid/p")
        self.assertEqual(code, 2)
        self.assertIn("content check is required", err)
        self.assertEqual(self.main("mark", "--kind", "note")[0], 2)                                   # no RUN_ID

    def test_dry_run_end_to_end_is_labelled_simulated(self):
        with mock.patch("socket.create_connection", side_effect=AssertionError("no socket in dry-run")):
            for probe in ("tcp", "http", "persistent"):
                self.assertEqual(self.main("run", "--probe", probe, "--run-id", "SIM", "--dry-run",
                                           "--duration-sec", "60")[0], 0)
        for probe in ("tcp", "persistent"):
            self.assertEqual(self.main("analyze", "--probe", probe, "--run-id", "SIM")[0], 0)
        run_dir = os.path.join(self.dir, "SIM")
        with open(os.path.join(run_dir, "analysis_tcp.json"), encoding="utf-8") as f:
            summary = json.load(f)
        self.assertIn("SIMULATED - NOT A REAL MEASUREMENT", summary["mode"])
        self.assertEqual(summary["run_validity"], "valid")
        self.assertEqual(summary["recovery"]["outcome"], "recovered_stable")
        self.assertEqual(len(fp.read_markers(os.path.join(run_dir, "markers.csv"))), 1)   # one simulated marker
        # analyzing again never overwrites the first result
        self.assertEqual(self.main("analyze", "--probe", "tcp", "--run-id", "SIM")[0], 0)
        self.assertTrue(os.path.exists(os.path.join(run_dir, "analysis_tcp.rev2.json")))
        self.assertTrue(os.path.exists(os.path.join(run_dir, "outages_tcp.rev2.csv")))

    def test_import_has_no_side_effects(self):
        with mock.patch("dotenv.load_dotenv") as load_dotenv:
            load_module("03-failover/failover_probe.py", "failover_probe_import_check")
        load_dotenv.assert_not_called()


if __name__ == "__main__":
    unittest.main()
