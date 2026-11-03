"""lab.py: run-plan arithmetic, remote command construction, time sync, spec building, E1 flow (offline).

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.
"""

import json
import os
import shlex
import tempfile
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest import mock

from _helpers import OfflineTestCase, load_module

lab = load_module("lab.py", "lab_menu")

E1_ENV = {"LOAD_CONCURRENCY_STEPS": "10,25,50,100,150,200,300,400,500,600,700,800,1000", "LOAD_SWEEPS": "3",
          "LOAD_STEP_DURATION": "30s", "LOAD_COOLDOWN_SEC": "5", "LOAD_RATE_LIMIT_QPS": "0"}

TIMESYNC_OUT = """sr-benchmark-cli
NTPSynchronized=yes
       Server: 192.0.2.1 (ntp.example.invalid)
Poll interval: 34min 8s (min: 32s; max 34min 8s)
         Leap: normal
       Offset: -10.611ms
"""


class PlanTests(OfflineTestCase):
    def test_e1_plan_and_telemetry_length_match_the_documented_run(self):
        plan = lab.hey_plan(E1_ENV)
        self.assertEqual(len(plan["levels"]), 13)
        self.assertEqual(plan["estimate_sec"], 13 * 3 * 35)
        self.assertEqual(lab.telemetry_seconds(plan["estimate_sec"], 60), 1800)

    def test_defaults_are_those_of_run_hey_stepped(self):
        plan = lab.hey_plan({})
        self.assertEqual(plan["steps"], E1_ENV["LOAD_CONCURRENCY_STEPS"])
        self.assertEqual((plan["sweeps"], plan["duration"], plan["cooldown"], plan["qps"]), ("3", "30s", "5", "0"))

    def test_bad_steps_are_rejected(self):
        for steps in ("10,5", "10,10", "0,10", "a,b"):
            with self.assertRaises(lab.LabError):
                lab.hey_plan({"LOAD_CONCURRENCY_STEPS": steps})

    def test_hey_command_is_explicit(self):
        cmd = lab.hey_command("py", "E1-X", lab.hey_plan(E1_ENV))
        self.assertEqual(cmd[1], lab.HEY_SCRIPT)
        self.assertEqual(cmd[2:], ["--run-id", "E1-X", "--steps", E1_ENV["LOAD_CONCURRENCY_STEPS"], "--sweeps", "3",
                                   "--duration", "30s", "--cooldown", "5", "--qps", "0"])
        self.assertEqual(lab.hey_command("py", "E1-X", lab.hey_plan(E1_ENV), dry_run=True)[-1], "--dry-run")

    def test_run_id_suggestion_skips_existing(self):
        day = datetime(2026, 11, 3, tzinfo=timezone.utc)
        self.assertEqual(lab.suggest_run_id("E1", {"E1-20261103-01"}, day), "E1-20261103-02")
        self.assertEqual(lab.suggest_run_id("E3", {"E3-20261103-01-r01"}, day), "E3-20261103-01-r02")
        self.assertEqual(lab.suggest_run_id("DRY-E1", set(), day), "DRY-E1-20261103-01")
        with self.assertRaises(lab.LabError):
            lab.check_run_id("E1 x; rm")


class RemoteCommandTests(OfflineTestCase):
    def test_telemetry_start_is_detached_and_refuses_reuse(self):
        cmd = lab.remote_telemetry_start("sse-lab", "E1-20261103-01", "c1", 1800, 5)
        self.assertIn("test ! -e sse-lab/E1-20261103-01 ||", cmd)
        self.assertIn("RUN_START_EPOCH=$(date -u +%s)", cmd)
        self.assertIn("setsid nohup bash sse-lab/collect_connector_telemetry.sh 1800 1 sse-lab/E1-20261103-01", cmd)
        self.assertIn("< /dev/null & echo $!", cmd)

    def test_sadf_export_uses_the_documented_options(self):
        cmd = lab.remote_sadf_export("sse-lab", "E1-1", "c1")
        self.assertIn('sadf -d "$f" -- -u ALL > "${b}_cpu_sadf.csv"', cmd)
        self.assertIn('sadf -d "$f" -- -r > "${b}_mem_sadf.csv"', cmd)

    def test_ssh_is_key_only_with_host_key_checking(self):
        shell = mock.Mock()
        lab.Remote(shell, "richard", "10.0.1.121", "/k").ssh("hostname")
        argv = shell.run.call_args[0][0]
        self.assertEqual(argv[0], "ssh")
        for opt in ("BatchMode=yes", "StrictHostKeyChecking=yes", "UserKnownHostsFile=/k"):
            self.assertIn(opt, argv)
        self.assertEqual(argv[-2:], ["richard@10.0.1.121", "hostname"])

    def test_missing_connector_settings(self):
        with self.assertRaises(lab.LabError):
            lab.Remote(mock.Mock(), "", "10.0.1.121")


class TimeSyncTests(OfflineTestCase):
    def test_parse_and_statement(self):
        r = lab.parse_timesync(TIMESYNC_OUT)
        self.assertEqual(r, {"host": "sr-benchmark-cli", "ntp_synchronized": "yes",
                             "server": "192.0.2.1 (ntp.example.invalid)", "offset": "-10.611ms"})
        c1 = dict(r, host="sr-conn01", offset="-17.1ms")
        ts = lab.time_sync_statement([r, c1], datetime(2026, 11, 3, 12, tzinfo=timezone.utc))
        self.assertIn("sr-benchmark-cli and sr-conn01", ts["statement"])
        self.assertIn("offset -17.1ms", ts["source"])
        self.assertTrue(ts["known_uncertainty"])

    def test_no_statement_without_sync(self):
        r = lab.parse_timesync("h\nNTPSynchronized=no\n")
        self.assertIsNone(lab.time_sync_statement([r], datetime.now(timezone.utc)))


def draft(*kinds):
    return {"processing_id": "", "reviewed_by_operator": False, "time_sync": None, "groups": {"m2": [], "m1_resources": []},
            "datasets": [{"id": f"{k}-{i}", "kind": k, "path": f"/x/{k}", "provenance": "unknown", "run_id": ""}
                         for i, k in enumerate(kinds, 1)], "notes": []}


class SpecTests(OfflineTestCase):
    TS = {"statement": "s", "source": "src", "known_uncertainty": "u"}

    def test_e1_spec_matches_the_manual_procedure(self):
        spec, _ = lab.build_reviewed_spec(draft("hey", "telemetry_meta", "sar_cpu", "sar_mem"), "E1-1-P1", "real",
                                          self.TS, ["E1-1"])
        self.assertTrue(spec["reviewed_by_operator"])
        self.assertEqual(spec["processing_id"], "E1-1-P1")
        self.assertEqual({d["provenance"] for d in spec["datasets"]}, {"real"})
        self.assertEqual(spec["groups"]["m1_resources"], [{"hey": "hey-1", "sar_cpu": "sar_cpu-3", "sar_mem": "sar_mem-4",
                                                           "warmup_sec": 0, "min_coverage": 0.9}])
        self.assertEqual(spec["time_sync"], self.TS)

    def test_no_resource_group_without_time_sync_or_with_ambiguity(self):
        spec, _ = lab.build_reviewed_spec(draft("hey", "sar_cpu"), "P", "real", None, ["E1-1"])
        self.assertEqual(spec["groups"]["m1_resources"], [])
        spec, _ = lab.build_reviewed_spec(draft("hey", "sar_cpu", "sar_cpu"), "P", "real", self.TS, ["E1-1"])
        self.assertEqual(spec["groups"]["m1_resources"], [])

    def test_scaler_gets_the_run_id_and_an_m2_group(self):
        spec, _ = lab.build_reviewed_spec(draft("hey", "sar_cpu", "scaler"), "E2-1-P1", "real", self.TS, ["E2-1"])
        self.assertEqual(spec["datasets"][2]["run_id"], "E2-1")
        self.assertEqual(spec["groups"]["m2"], [{"scaler": "scaler-3", "app": ["hey-1"], "sar": ["sar_cpu-2"]}])
        self.assertEqual(spec["groups"]["m1_resources"], [])

    def test_provenance_from_tool_metadata(self):
        d = draft("hey", "sar_cpu")
        d["datasets"][0]["provenance"] = "real"
        spec, _ = lab.build_reviewed_spec(d, "P", None, None, ["X"])
        self.assertEqual({x["provenance"] for x in spec["datasets"]}, {"real"})
        d["datasets"][1]["provenance"] = "simulated"
        with self.assertRaises(lab.LabError):
            lab.build_reviewed_spec(d, "P", None, None, ["X"])
        with self.assertRaises(lab.LabError):
            lab.build_reviewed_spec(draft("sar_cpu"), "P", None, None, ["X"])

    def test_draft_is_not_modified(self):
        d = draft("hey")
        lab.build_reviewed_spec(d, "P", "simulated", None, ["X"])
        self.assertFalse(d["reviewed_by_operator"])


class ProbeTailTests(OfflineTestCase):
    def test_counts_and_partial_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "probes_http.csv")
            t = lab.ProbeTail(path)
            t.poll()
            self.assertEqual(t.status(), "starting")
            with open(path, "w", newline="") as f:
                f.write("seq,event,ok\n1,probe,True\n2,probe,False\n3,pro")
            t.poll()
            self.assertEqual((t.ok, t.failed), (1, 1))
            with open(path, "a", newline="") as f:
                f.write("be,True\n4,meta,False\n")
            t.poll()
            self.assertEqual((t.ok, t.failed, t.last_ok), (2, 1, True))
            self.assertEqual(t.status(), "ok (ok 2, failed 1)")


class FakeShell:
    """Records every command; answers ssh/scp/sadf/timedatectl like a healthy testbed."""

    def __init__(self, run_dir):
        self.calls, self.popens, self.run_dir = [], [], run_dir

    def run(self, cmd, check=False, capture=True, timeout=None):
        self.calls.append(cmd)
        out = ""
        joined = " ".join(cmd)
        if cmd[0] == "git":
            out = "abc123\n" if "rev-parse" in cmd else ""
        elif cmd[0] == "ssh":
            remote = cmd[-1]
            if remote.startswith("sha256sum"):
                out = lab.sha256_file(lab.TELEMETRY_SCRIPT) + "  x\n"
            elif "setsid nohup" in remote:
                out = "4242\n"
            elif remote.startswith("cat "):
                out = "[*] c1@sr-conn01: sar ... every 1s x 1800\n"
            elif remote.startswith("ps -p"):
                out = ""
            elif "sadf -d" in remote:
                out = ("telemetry_E1-T_c1_sr-conn01.sa\ntelemetry_E1-T_c1_sr-conn01_meta.json\n"
                       '"coverage": "full_from_run_start"\n')
            elif "timedatectl" in remote:
                out = TIMESYNC_OUT.replace("sr-benchmark-cli", "sr-conn01")
            elif "command -v sar" in remote:
                out = "sr-conn01\n"
        elif cmd[0] == "scp" and ":" in cmd[-1]:
            pass
        elif cmd[0] == "scp":
            dest = cmd[-1]
            for src in cmd[2:-1]:
                if ":" in src:
                    open(os.path.join(dest, src.rsplit("/", 1)[1]), "w").close()
        elif cmd[0] == "sadf":
            out = "# hostname;interval;timestamp;CPU;%usr\n"
        elif cmd[0] == "bash" and "timedatectl" in joined:
            out = TIMESYNC_OUT
        elif cmd[0] == "hostname":
            out = "10.0.1.124\n"
        return SimpleNamespace(returncode=0, stdout=out, stderr="")

    def popen(self, cmd, **kwargs):
        self.popens.append(cmd)
        if cmd[0] == "sar":
            open(cmd[-1], "w").close()
            return mock.Mock(wait=mock.Mock(return_value=0), poll=mock.Mock(return_value=0))
        os.makedirs(os.path.join(self.run_dir, "raw"), exist_ok=True)
        with open(os.path.join(self.run_dir, "manifest.json"), "w") as f:
            json.dump({"status": "complete", "validity": {"status": "all_runs_valid", "levels_by_status": {"accepted": [10]}}}, f)
        return mock.Mock(wait=mock.Mock(return_value=0))


class E1FlowTests(OfflineTestCase):
    def test_full_e1_sequence_without_processing(self):
        with tempfile.TemporaryDirectory() as tmp:
            results = os.path.join(tmp, "results")
            run_dir = os.path.join(results, "E1-T")
            shell, lines = FakeShell(run_dir), []
            clock = iter(range(0, 100000, 10))
            env = dict(E1_ENV, CONNECTOR_1_IP="10.0.1.121", CONNECTOR_SSH_USER="richard", TARGET_APP_URL="https://t/",
                       LAB_LEAD_SEC="60")
            lb = lab.Lab(env, shell=shell, out=lines.append, ask=lambda _p: "y", sleep=lambda _s: None,
                         clock=lambda: next(clock), http_status=lambda _u: 200)
            with mock.patch.object(lab, "LOAD_RESULTS", results), mock.patch.object(lab.shutil, "which", return_value="/x"), \
                    mock.patch.object(lab.os.path, "exists", side_effect=lambda p: True if p.endswith(".env") else os.path.lexists(p)):
                self.assertEqual(lb.e1("E1-T", process=False), 0)
            remote_cmds = [c[-1] for c in shell.calls if c[0] == "ssh"]
            start = next(i for i, c in enumerate(remote_cmds) if "setsid nohup" in c)
            export = next(i for i, c in enumerate(remote_cmds) if "sadf -d" in c)
            self.assertLess(start, export)
            hey = [p for p in shell.popens if p[1] == lab.HEY_SCRIPT][0]
            self.assertIn("--steps", hey)
            self.assertEqual(shell.popens[0][0], "sar")          # client sar starts before the load
            with open(os.path.join(run_dir, "lab_run.json")) as f:
                rec = json.load(f)
            self.assertEqual(rec["telemetry"]["coverage"], "full_from_run_start")
            self.assertEqual(rec["telemetry"]["seconds"], 1800)
            self.assertIn("sr-conn01", rec["time_sync"]["statement"])
            self.assertEqual(rec["commands"], [shlex.join(hey)])
            self.assertTrue(os.path.exists(os.path.join(run_dir, "client_sar", "client_cpu.csv")))
            self.assertTrue(os.path.exists(os.path.join(run_dir, "telemetry", "telemetry_E1-T_c1_sr-conn01_meta.json")))

    def test_existing_run_is_refused_before_anything_starts(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "E1-T"))
            shell = FakeShell(tmp)
            lb = lab.Lab(dict(E1_ENV), shell=shell, out=lambda *_: None, ask=lambda _p: "y")
            with mock.patch.object(lab, "LOAD_RESULTS", tmp):
                with self.assertRaises(lab.LabError):
                    lb.e1("E1-T", dry_run=True, process=False)
            self.assertEqual(shell.popens, [])
            self.assertFalse(any(c[0] in ("ssh", "scp") for c in shell.calls))


class SettingsTests(OfflineTestCase):
    def test_validation(self):
        self.assertEqual(lab.validate_setting("LOAD_CONCURRENCY_STEPS", "10,20"), "10,20")
        for key, value in (("LOAD_CONCURRENCY_STEPS", "20,10"), ("LOAD_STEP_DURATION", "30"),
                           ("LAB_LEAD_SEC", "abc"), ("ENABLE_SCALE_IN", "yes"), ("ESXI_PASSWORD", "x"),
                           ("ATMOS_API_KEY", "x"), ("UNKNOWN_KEY", "1"), ("LAB_LEAD_SEC", "1\n2")):
            with self.assertRaises(lab.LabError, msg=key):
                lab.validate_setting(key, value)

    def test_power_backend_settings(self):
        for value in ("esxi-ssh", "vcenter-api", "manual"):
            self.assertEqual(lab.validate_setting("C2_POWER_BACKEND", value), value)
        for key, value in (("C2_POWER_BACKEND", "ipmi"), ("VCENTER_API", "v8"), ("VCENTER_PASSWORD", "x")):
            with self.assertRaises(lab.LabError, msg=key):
                lab.validate_setting(key, value)

    def test_set_env_line_replaces_appends_and_keeps_crlf(self):
        text = "A=1\r\nLAB_LEAD_SEC=60\r\n# c\r\n"
        self.assertEqual(lab.set_env_line(text, "LAB_LEAD_SEC", "30"), "A=1\r\nLAB_LEAD_SEC=30\r\n# c\r\n")
        self.assertEqual(lab.set_env_line("A=1", "B", "x y"), 'A=1\nB="x y"\n')

    def test_menu_edit_writes_0600_and_keeps_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, ".env")
            with open(path, "w") as f:
                f.write("ESXI_PASSWORD=s3cret\nLOAD_SWEEPS=3\n")
            answers = iter(["load_sweeps", "5", ""])
            lines = []
            lb = lab.Lab({}, shell=mock.Mock(), out=lines.append, ask=lambda _p: next(answers))
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("LOAD_SWEEPS", None)
                lb.settings(path)
            with open(path) as f:
                self.assertEqual(f.read(), "ESXI_PASSWORD=s3cret\nLOAD_SWEEPS=5\n")
            self.assertFalse(any("s3cret" in l for l in lines))
            if os.name == "posix":
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
                self.assertEqual(os.stat(path + ".bak").st_mode & 0o777, 0o600)


class E2BackendTests(OfflineTestCase):
    BASE = dict(E1_ENV, E2_CONCURRENCY_STEPS="100,1000", CONNECTOR_1_IP="10.0.1.121")

    def e2_error(self, env):
        lb = lab.Lab(env, shell=mock.Mock(), out=lambda *_: None, ask=lambda _p: "n")
        with mock.patch.object(lab.Lab, "check", side_effect=AssertionError("prerequisites must fail first")):
            with self.assertRaises(lab.LabError) as cm:
                lb.e2("E2-T", process=False)
        return str(cm.exception)

    def test_prerequisites_follow_the_backend(self):
        self.assertIn("ESXI_HOST", self.e2_error(dict(self.BASE)))
        self.assertIn("VCENTER_HOST", self.e2_error(dict(self.BASE, C2_POWER_BACKEND="vcenter-api")))
        self.assertIn("VCENTER_PASSWORD", self.e2_error(dict(self.BASE, C2_POWER_BACKEND="vcenter-api",
                                                             VCENTER_HOST="10.0.1.6", VCENTER_USER="u")))
        self.assertIn("CONNECTOR_2_IP", self.e2_error(dict(self.BASE, C2_POWER_BACKEND="manual")))
        self.assertIn("not possible", self.e2_error(dict(self.BASE, C2_POWER_BACKEND="manual",
                                                         CONNECTOR_2_IP="10.0.1.122", ENABLE_SCALE_IN="true")))
        self.assertIn("not one of", self.e2_error(dict(self.BASE, C2_POWER_BACKEND="ipmi")))

    def test_power_text_names_the_backend(self):
        lb = lab.Lab(dict(self.BASE, VCENTER_HOST="10.0.1.6", VCENTER_USER="sse-scaler@vsphere.local"),
                     shell=mock.Mock(), out=lambda *_: None, ask=lambda _p: "n")
        self.assertIn("vCenter API, VM 'SR-CONN02' via 10.0.1.6", lb.c2_power_text("vcenter-api"))
        self.assertIn("MANUAL", lb.c2_power_text("manual"))


class ManualActionWatcherTests(OfflineTestCase):
    def test_manual_action_lines_are_repeated_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "scaler_console.log")
            lines = []
            w = lab.ManualActionWatcher(path, lines.append)
            w.scan()  # file not there yet
            with open(path, "w", encoding="utf-8") as f:
                f.write("INFO cycle\nMANUAL ACTION: power on SR-CONN02 now \u00e9\nMANUAL ACT")
            w.scan()
            self.assertEqual(w.alerts, 1)
            with open(path, "a", encoding="utf-8") as f:
                f.write("ION: again\n")
            w.scan()
            w.scan()
            self.assertEqual(w.alerts, 2)
            self.assertIn("MANUAL ACTION: power on SR-CONN02 now", lines[0])
            self.assertIn("\a", lines[0])


class TargetCheckTests(OfflineTestCase):
    def test_a_broken_application_path_blocks_the_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            shell = FakeShell(tmp)
            lines = []
            lb = lab.Lab(dict(E1_ENV, CONNECTOR_1_IP="10.0.1.121", CONNECTOR_SSH_USER="richard",
                              TARGET_APP_URL="https://t/"), shell=shell, out=lines.append, ask=lambda _p: "y",
                         http_status=lambda _u: 502)
            with mock.patch.object(lab.shutil, "which", return_value="/x"), \
                    mock.patch.object(lab.os.path, "exists", side_effect=lambda p: p.endswith(".env") or os.path.lexists(p)):
                problems = lb.check()
            self.assertTrue(any("answered 502" in p for p in problems))
            self.assertFalse(any(c[0] == "ssh" for c in shell.calls))
            with mock.patch.object(lab, "LOAD_RESULTS", tmp), mock.patch.object(lab.shutil, "which", return_value="/x"), \
                    mock.patch.object(lab.os.path, "exists", side_effect=lambda p: p.endswith(".env") or os.path.lexists(p)):
                with self.assertRaises(lab.LabError):
                    lb.e1("E1-T", process=False)
            self.assertEqual(shell.popens, [])

    def test_unreachable_target_is_reported_as_text(self):
        import urllib.error
        import urllib.request
        with mock.patch.object(urllib.request, "urlopen", side_effect=urllib.error.URLError("refused")):
            self.assertIn("no response", str(lab.target_http_status("https://t/")))
        err = urllib.error.HTTPError("https://t/", 502, "Bad Gateway", {}, None)
        with mock.patch.object(urllib.request, "urlopen", side_effect=err):
            self.assertEqual(lab.target_http_status("https://t/"), 502)
