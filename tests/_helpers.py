"""Shared test helpers: module loading and a network guard.

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

The network guard is installed when this module is imported, i.e. before any test module can
load a script under test, and stays active for the whole test process: real socket connections,
name resolution and paramiko SSH connections raise NetworkBlocked. load_module() refuses to import
a script if the guard is not active. OfflineTestCase additionally re-applies the patches per test.
Subprocess-based tests (Bash, node) run in separate processes and are not affected.
"""

import importlib.util
import os
import socket
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class NetworkBlocked(AssertionError):
    pass


def _blocked(*_args, **_kwargs):
    raise NetworkBlocked("real network access is disabled in tests")


def _guard_patches():
    patches = [
        mock.patch.object(socket.socket, "connect", _blocked),
        mock.patch.object(socket.socket, "connect_ex", _blocked),
        mock.patch.object(socket, "create_connection", _blocked),
        mock.patch.object(socket, "getaddrinfo", _blocked),
    ]
    try:
        import paramiko
    except ImportError:
        pass
    else:
        patches.append(mock.patch.object(paramiko.SSHClient, "connect", _blocked))
    return patches


_PROCESS_GUARD = _guard_patches()
for _patch in _PROCESS_GUARD:
    _patch.start()  # never stopped: the guard lasts for the whole test process


def network_guard_active():
    try:
        import paramiko
    except ImportError:
        paramiko = None
    active = socket.create_connection is _blocked and socket.getaddrinfo is _blocked \
        and socket.socket.connect is _blocked
    return active and (paramiko is None or paramiko.SSHClient.connect is _blocked)


def load_module(rel_path, name):
    """Imports a script from a directory whose name is not a valid package name (e.g. 02-scaler-poc).
    Refuses to do so unless the network guard is active."""
    if not network_guard_active():
        raise RuntimeError("network guard not active; refusing to import a script under test")
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, rel_path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class OfflineTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        for p in _guard_patches():
            p.start()
            self.addCleanup(p.stop)
