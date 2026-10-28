#!/usr/bin/env python3
"""
Pillar 4: run directories and files that are never overwritten.

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

Every invocation writes into its own directory results/<RUN_ID>/<mode>[.attemptN]/, created
exclusively (os.mkdir fails if it exists), and every file inside is opened with mode 'x'.
"""

import os
import json
import re

RUN_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")


def check_run_id(run_id):
    if not run_id or not RUN_ID_RE.match(run_id):
        raise ValueError("RUN_ID is required (letters, digits, '.', '_', '-')")
    return run_id


def make_run_dir(base_dir, run_id, mode, max_attempts=99):
    """Creates base_dir/run_id/mode[.attemptN] and returns (path, attempt)."""
    parent = os.path.join(base_dir, check_run_id(run_id))
    os.makedirs(parent, exist_ok=True)
    for attempt in range(1, max_attempts + 1):
        path = os.path.join(parent, mode if attempt == 1 else f"{mode}.attempt{attempt}")
        try:
            os.mkdir(path)
            return path, attempt
        except FileExistsError:
            continue
    raise FileExistsError(f"no free attempt directory for {mode} in {parent}")


def write_json(path, data):
    with open(path, "x", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=False, default=str)


def write_json_durable(path, data):
    """Like write_json, but the content is serialised first (a serialisation error creates no file)
    and the file is flushed, fsync'ed and closed before returning. Any failure raises; the caller
    must then not perform the operation the file is meant to protect.
    Limit: fsync covers the file's data; whether the directory entry survives a power loss or an OS
    crash right afterwards depends on the file system and is not guaranteed here."""
    text = json.dumps(data, indent=2, sort_keys=False, default=str)
    with open(path, "x", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())


def write_text(path, text):
    with open(path, "x", encoding="utf-8", newline="") as f:
        f.write(text)


class JsonLines:
    """Append-only JSON lines file created exclusively."""
    def __init__(self, path):
        self.path = path
        self._f = open(path, "x", encoding="utf-8")

    def write(self, record):
        self._f.write(json.dumps(record, default=str) + "\n")
        self._f.flush()

    def close(self):
        self._f.close()
