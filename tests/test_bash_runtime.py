"""Unit tests for the Bash runtime detection (mocked subprocess; no shell is started).

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

These tests only check the selection and command-building logic. Whether the telemetry script
really runs in a runtime is tested separately in test_load_telemetry_bash.py.
"""

import os
import unittest

import _bash_runtime as br
from _helpers import OfflineTestCase

GIT_ROOT = os.path.join("C:\\", "Program Files", "Git")
GIT_BASH_EXE = os.path.join(GIT_ROOT, "bin", "bash.exe")


class FakeRun:
    """Records argv lists and answers from a list of (exit_code, stdout, stderr)."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = []

    def __call__(self, cmd, timeout):
        self.calls.append(list(cmd))
        return self.answers.pop(0)


class ClassifyTests(OfflineTestCase):
    def test_uname_mapping(self):
        cases = [
            ("MINGW64_NT-10.0-26200", "3.5.7-463ebcdc.x86_64", br.GIT_BASH),
            ("MSYS_NT-10.0-26200", "3.5.7", br.GIT_BASH),
            ("Linux", "6.6.87.2-microsoft-standard-WSL2", br.WSL),
            ("Linux", "4.4.0-19041-Microsoft", br.WSL),
            ("Linux", "6.8.0-45-generic", br.NATIVE_POSIX),
            ("Darwin", "23.6.0", br.NATIVE_POSIX),
            ("CYGWIN_NT-10.0", "3.4.9", None),
            ("", "", None),
        ]
        for uname_s, uname_r, expected in cases:
            with self.subTest(uname_s=uname_s, uname_r=uname_r):
                self.assertEqual(br.classify_uname(uname_s, uname_r), expected)


class CandidateTests(OfflineTestCase):
    def test_native_only_on_posix(self):
        which = {"bash": "/usr/bin/bash"}.get
        self.assertEqual(br.candidates(br.NATIVE_POSIX, os_name="posix", which=which),
                         [br.Candidate(br.NATIVE_POSIX, ("/usr/bin/bash",), None)])
        self.assertEqual(br.candidates(br.NATIVE_POSIX, os_name="nt", which=which), [])

    def test_windows_kinds_not_offered_on_posix(self):
        which = {"git": "/usr/bin/git", "wsl": "/usr/bin/wsl"}.get
        self.assertEqual(br.candidates(br.GIT_BASH, os_name="posix", which=which), [])
        self.assertEqual(br.candidates(br.WSL, os_name="posix", which=which), [])

    def test_git_bash_uses_bin_launcher_derived_from_git(self):
        git = os.path.join(GIT_ROOT, "cmd", "git.exe")
        found = br.candidates(br.GIT_BASH, os_name="nt", which={"git": git}.get,
                              environ={"ProgramFiles": os.path.join("C:\\", "Program Files")},
                              exists=lambda p: p == GIT_BASH_EXE)
        self.assertEqual(found, [br.Candidate(br.GIT_BASH, (GIT_BASH_EXE,), "cygpath")])  # de-duplicated
        self.assertNotIn(os.path.join("usr", "bin"), found[0].prefix[0])

    def test_git_bash_missing(self):
        self.assertEqual(br.candidates(br.GIT_BASH, os_name="nt", which=lambda n: None, environ={},
                                       exists=lambda p: False), [])

    def test_wsl_goes_through_wsl_exe_not_the_bash_alias(self):
        wsl = os.path.join("C:\\", "WINDOWS", "system32", "wsl.exe")
        found = br.candidates(br.WSL, os_name="nt", which={"wsl": wsl}.get)
        self.assertEqual(found, [br.Candidate(br.WSL, (wsl, "--exec", "bash"), "wslpath")])

    def test_unknown_kind(self):
        with self.assertRaises(ValueError):
            br.candidates("cygwin", os_name="nt")


class ProbeTests(OfflineTestCase):
    def kwargs(self):
        return {"os_name": "nt", "which": {"git": os.path.join(GIT_ROOT, "cmd", "git.exe")}.get,
                "environ": {}, "exists": lambda p: p == GIT_BASH_EXE}

    def test_accepts_matching_runtime(self):
        run = FakeRun((0, "MINGW64_NT-10.0-26200\n3.5.7-463ebcdc.x86_64\n", ""))
        result = br.probe(br.GIT_BASH, run=run, **self.kwargs())
        self.assertEqual(result.reason, "")
        self.assertEqual(result.runtime.kind, br.GIT_BASH)
        self.assertEqual(run.calls, [[GIT_BASH_EXE, "-c", br.PROBE_SCRIPT]])

    def test_rejects_launcher_that_is_really_wsl(self):
        # the failure seen on this machine: a "bash.exe" that turns out to start WSL
        run = FakeRun((0, "Linux\n6.6.87.2-microsoft-standard-WSL2\n", ""))
        result = br.probe(br.GIT_BASH, run=run, **self.kwargs())
        self.assertIsNone(result.runtime)
        self.assertIn("identifies as 'wsl', not git_bash", result.reason)

    def test_failed_probe_reports_exit_code_and_stderr(self):
        run = FakeRun((127, "", "/usr/bin/bash: line 1: uname: command not found"))
        result = br.probe(br.GIT_BASH, run=run, **self.kwargs())
        self.assertIsNone(result.runtime)
        self.assertIn("exit 127", result.reason)
        self.assertIn("uname: command not found", result.reason)

    def test_no_launcher(self):
        result = br.probe(br.WSL, run=FakeRun(), os_name="nt", which=lambda n: None)
        self.assertIsNone(result.runtime)
        self.assertIn("no launcher found", result.reason)

    def test_runtime_not_applicable_to_this_os(self):
        run = FakeRun()
        self.assertIn("not applicable", br.probe(br.NATIVE_POSIX, run=run, os_name="nt").reason)
        self.assertIn("not applicable", br.probe(br.WSL, run=run, os_name="posix").reason)
        self.assertEqual(run.calls, [])

    def test_launcher_not_found_or_timeout(self):
        run = FakeRun((None, "", "no answer within 120s"))
        result = br.probe(br.GIT_BASH, run=run, **self.kwargs())
        self.assertIn("no answer within 120s", result.reason)

    def test_subprocess_run_decodes_wsl_utf16_errors(self):
        self.assertEqual(br._decode("Hiba".encode("utf-16-le")), "Hiba")
        self.assertEqual(br._decode("café naïve".encode("utf-8")), "café naïve")


class RuntimeCommandTests(OfflineTestCase):
    def runtime(self, kind, prefix, tool, *answers):
        run = FakeRun(*answers)
        return br.BashRuntime(br.Candidate(kind, prefix, tool), run, "test"), run

    def test_native_paths_are_unchanged_without_subprocess(self):
        rt, run = self.runtime(br.NATIVE_POSIX, ("/bin/bash",), None)
        self.assertEqual(rt.to_runtime_path("/tmp/x y"), "/tmp/x y")
        self.assertEqual(run.calls, [])

    def test_git_bash_path_via_cygpath_as_separate_argument(self):
        rt, run = self.runtime(br.GIT_BASH, (GIT_BASH_EXE,), "cygpath", (0, "/c/Users/R/x y\n", ""))
        self.assertEqual(rt.to_runtime_path(r"C:\Users\R\x y"), "/c/Users/R/x y")
        self.assertEqual(run.calls, [[GIT_BASH_EXE, "-c", 'cygpath -u "$1"', "path", r"C:\Users\R\x y"]])

    def test_wsl_path_via_wslpath(self):
        rt, run = self.runtime(br.WSL, ("wsl.exe", "--exec", "bash"), "wslpath", (0, "/mnt/c/Users/R\n", ""))
        self.assertEqual(rt.to_runtime_path(r"C:\Users\R"), "/mnt/c/Users/R")
        self.assertEqual(run.calls[0][:4], ["wsl.exe", "--exec", "bash", "-c"])

    def test_failed_conversion_raises(self):
        rt, _ = self.runtime(br.WSL, ("wsl.exe", "--exec", "bash"), "wslpath", (1, "", "wslpath: bad path"))
        with self.assertRaisesRegex(RuntimeError, "bad path"):
            rt.to_runtime_path(r"\\server\share")

    def test_command_passes_env_through_env_and_prepends_path(self):
        rt, _ = self.runtime(br.WSL, ("wsl.exe", "--exec", "bash"), "wslpath")
        cmd = rt.command("/mnt/c/repo/t.sh", ["1", 2], env={"ROLE": "c2", "NOTE": "a b"}, prepend_path="/mnt/c/stub")
        self.assertEqual(cmd, ["wsl.exe", "--exec", "bash", "-c", br.LAUNCH_SCRIPT, "bash-test", "/mnt/c/stub",
                               "NOTE=a b", "ROLE=c2", "bash", "/mnt/c/repo/t.sh", "1", "2"])

    def test_invalid_env_name_rejected(self):
        rt, _ = self.runtime(br.NATIVE_POSIX, ("/bin/bash",), None)
        with self.assertRaises(ValueError):
            rt.command("/x.sh", env={"A=B": "1"})


if __name__ == "__main__":
    unittest.main()
