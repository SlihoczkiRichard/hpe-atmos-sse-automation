"""Bash runtime detection for the shell-script integration tests.

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

The telemetry collector is a Bash script meant for the Linux connector VMs. The tests execute it
for real, so they need a Bash that can see the repository files. Three runtimes are handled
separately, because each one needs its own path form and its own launcher:

  native_posix  Python runs on Linux/macOS (incl. Python inside WSL); bash from PATH, paths as-is
  git_bash      Python on Windows, Git for Windows' <git>/bin/bash.exe launcher; paths via cygpath
                (<git>/usr/bin/bash.exe is NOT used: started from a Windows process it has no
                /usr/bin on PATH, so coreutils such as uname are "command not found", exit 127)
  wsl           Python on Windows, "wsl.exe --exec bash" into the default distribution; paths via
                wslpath. The WindowsApps/System32 bash.exe aliases also start WSL, which is why a
                plain shutil.which("bash") on Windows can silently pick WSL and pass it a C:/ path
                that does not exist there (exit 127, "No such file or directory").

Each candidate is probed with "uname -s; uname -r" and accepted only if the probe identifies the
expected runtime. Environment variables for the script are passed on the bash command line through
"env", so they reach WSL without WSLENV. Everything here only starts local processes; nothing in
this module opens a network connection.
"""

import os
import shutil
import subprocess
from collections import namedtuple

NATIVE_POSIX = "native_posix"
GIT_BASH = "git_bash"
WSL = "wsl"
KINDS = (NATIVE_POSIX, GIT_BASH, WSL)

PROBE_SCRIPT = "uname -s; uname -r"
# $1 = directory prepended to PATH, then NAME=VALUE pairs, then "bash", the script and its arguments
LAUNCH_SCRIPT = 'PATH="$1:$PATH"; shift; exec env "$@"'

Candidate = namedtuple("Candidate", "kind prefix path_tool")
ProbeResult = namedtuple("ProbeResult", "runtime reason")


def _decode(data):
    if isinstance(data, str):
        return data
    # wsl.exe writes its own error messages in UTF-16LE
    return data.decode("utf-16-le" if b"\x00" in data else "utf-8", errors="replace")


def classify_uname(uname_s, uname_r):
    """Maps 'uname -s' / 'uname -r' output to a runtime kind; None if it is none of them."""
    s, r = uname_s.strip(), uname_r.strip().lower()
    if s.startswith(("MINGW", "MSYS")):
        return GIT_BASH
    if s == "Linux" and ("microsoft" in r or "wsl" in r):
        return WSL
    if s in ("Linux", "Darwin"):
        return NATIVE_POSIX
    return None


def candidates(kind, os_name=os.name, which=shutil.which, environ=os.environ, exists=os.path.exists):
    """Launcher candidates for one runtime kind on this OS (not yet probed)."""
    if kind == NATIVE_POSIX:
        bash = which("bash") if os_name == "posix" else None
        return [Candidate(NATIVE_POSIX, (bash,), None)] if bash else []
    if os_name != "nt":
        return []
    if kind == GIT_BASH:
        found = []
        git = which("git")
        if git:
            # <git>/cmd/git.exe or <git>/bin/git.exe -> <git>/bin/bash.exe
            found.append(os.path.join(os.path.dirname(os.path.dirname(git)), "bin", "bash.exe"))
        for var in ("ProgramFiles", "ProgramW6432", "LOCALAPPDATA"):
            base = environ.get(var)
            if base:
                sub = ("Programs", "Git") if var == "LOCALAPPDATA" else ("Git",)
                found.append(os.path.join(base, *sub, "bin", "bash.exe"))
        unique = []
        for path in found:
            if exists(path) and os.path.normcase(path) not in [os.path.normcase(u) for u in unique]:
                unique.append(path)
        return [Candidate(GIT_BASH, (p,), "cygpath") for p in unique]
    if kind == WSL:
        wsl = which("wsl")
        return [Candidate(WSL, (wsl, "--exec", "bash"), "wslpath")] if wsl else []
    raise ValueError(f"unknown runtime kind: {kind}")


class BashRuntime:
    def __init__(self, candidate, run, uname):
        self.kind = candidate.kind
        self.prefix = tuple(candidate.prefix)
        self.path_tool = candidate.path_tool
        self.uname = uname
        self._run = run

    def describe(self):
        return f"{self.kind} via {' '.join(self.prefix)} ({self.uname})"

    def to_runtime_path(self, path):
        """Converts a host path to the form this runtime understands (asks cygpath/wslpath)."""
        if self.path_tool is None:
            return path
        code, out, err = self._run([*self.prefix, "-c", f'{self.path_tool} -u "$1"', "path", path], 60)
        converted = out.strip()
        if code != 0 or not converted.startswith("/"):
            raise RuntimeError(f"{self.path_tool} could not convert {path!r}: {(err or out).strip()[:200]}")
        return converted

    def command(self, script, args=(), env=None, prepend_path=None):
        """argv that runs 'bash <script> <args>' inside this runtime with the given variables set.

        script and prepend_path must already be runtime paths (see to_runtime_path)."""
        if any("=" in k or not k for k in (env or {})):
            raise ValueError("invalid environment variable name")
        pairs = [f"{k}={v}" for k, v in sorted((env or {}).items())]
        return [*self.prefix, "-c", LAUNCH_SCRIPT, "bash-test", prepend_path or "/nonexistent-stub-dir",
                *pairs, "bash", script, *[str(a) for a in args]]


def subprocess_run(cmd, timeout):
    try:
        res = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        return None, "", f"launcher not found: {exc}"
    except subprocess.TimeoutExpired:
        return None, "", f"no answer within {timeout}s"
    return res.returncode, _decode(res.stdout), _decode(res.stderr)


def probe(kind, run=subprocess_run, **candidate_kwargs):
    """Finds a working runtime of the given kind. Returns ProbeResult(runtime or None, reason)."""
    os_name = candidate_kwargs.get("os_name", os.name)
    if (kind == NATIVE_POSIX) != (os_name == "posix"):
        where = "a POSIX OS" if kind == NATIVE_POSIX else "Windows"
        return ProbeResult(None, f"{kind}: not applicable, Python is not running on {where} (os.name={os_name!r})")
    found = candidates(kind, **candidate_kwargs)
    if not found:
        return ProbeResult(None, f"{kind}: no launcher found on this system")
    reasons = []
    for cand in found:
        code, out, err = run([*cand.prefix, "-c", PROBE_SCRIPT], 120)
        lines = out.splitlines()
        if code != 0 or len(lines) < 2:
            reasons.append(f"{' '.join(cand.prefix)}: probe failed (exit {code}): {(err or out).strip()[:200]}")
            continue
        seen = classify_uname(lines[0], lines[1])
        if seen != kind:
            reasons.append(f"{' '.join(cand.prefix)}: identifies as {seen or lines[0]!r}, not {kind}")
            continue
        return ProbeResult(BashRuntime(cand, run, f"{lines[0].strip()} {lines[1].strip()}"), "")
    return ProbeResult(None, f"{kind}: " + "; ".join(reasons))


_CACHE = {}


def get_runtime(kind):
    """Cached probe for the integration tests; returns ProbeResult."""
    if kind not in _CACHE:
        _CACHE[kind] = probe(kind)
    return _CACHE[kind]
