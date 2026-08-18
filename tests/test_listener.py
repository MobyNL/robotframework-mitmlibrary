"""Tests for the listener that releases the proxy when a suite ends.

The library is suite scoped, so a suite that never calls `Stop Mitm Proxy` used to leave
its port bound for the rest of the run. Robot Framework calls `close()` on a library
listener when the library goes out of scope, and these tests cover what that has to do.
"""

import asyncio
import socket
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from robot.api import logger

from MitmLibrary import MitmLibrary
from MitmLibrary.listener import LibraryListener


def free_port() -> int:
    """Returns a port that is free right now, to keep parallel runs from colliding."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _addons_by_name(proxyserver):
    """Fakes mitmproxy's addon lookup, which answers per name.

    The library asks for "proxyserver" and for "errorcheck", and handing the proxyserver
    stand-in to both would give it something that is not an errorcheck addon.
    """

    def get(name):
        return proxyserver if name == "proxyserver" else None

    return get


async def _noop_update(_modes):
    return True


async def _runs_until_stopped(stop):
    """Stands in for `Master.run()`: alive until shutdown is requested."""
    while not stop.is_set():
        await asyncio.sleep(0.01)


class TestLibraryListener(unittest.TestCase):
    def setUp(self):
        self.library = MitmLibrary()

    def tearDown(self):
        self.library.controller.shutdown()

    def test_the_library_registers_the_listener(self):
        """Without this attribute Robot Framework never calls close() at all."""
        self.assertIsInstance(self.library.ROBOT_LIBRARY_LISTENER, LibraryListener)
        self.assertEqual(LibraryListener.ROBOT_LISTENER_API_VERSION, 3)

    def test_close_stops_a_running_proxy_and_reports_it(self):
        with patch("MitmLibrary.dump.DumpMaster") as mock_master:
            stop = threading.Event()
            mock_master.return_value.addons.get.side_effect = _addons_by_name(
                SimpleNamespace(
                    listen_addrs=lambda: [("127.0.0.1", 8099)],
                    servers=SimpleNamespace(update=_noop_update),
                )
            )
            mock_master.return_value.shutdown.side_effect = stop.set
            mock_master.return_value.run = lambda: _runs_until_stopped(stop)
            self.library.start_mitm_proxy(listen_port=8099)
            with patch.object(logger, "info") as mock_info:
                self.library.ROBOT_LIBRARY_LISTENER.close()
        mock_master.return_value.shutdown.assert_called_once()
        logged = " ".join(call.args[0] for call in mock_info.call_args_list)
        self.assertIn("still running", logged)

    def test_close_without_a_proxy_is_quiet(self):
        """Most suites stop their own proxy; that case must not log a warning."""
        with patch.object(logger, "info") as mock_info:
            self.library.ROBOT_LIBRARY_LISTENER.close()
        logged = " ".join(call.args[0] for call in mock_info.call_args_list)
        self.assertNotIn("still running", logged)
        self.assertFalse(self.library.loop_handler.is_alive())

    def test_close_is_idempotent(self):
        """A suite that stops its proxy still gets close() afterwards."""
        self.library.ROBOT_LIBRARY_LISTENER.close()
        self.library.ROBOT_LIBRARY_LISTENER.close()  # must not raise

    def test_close_releases_the_port_of_a_real_proxy(self):
        """The point of the listener, against a real socket rather than a mock.

        A mocked master cannot prove a port was handed back, because there was never a
        socket to hand back.
        """
        port = free_port()
        self.library.start_mitm_proxy(listen_port=port)
        self.library.ROBOT_LIBRARY_LISTENER.close()

        # Rebinding immediately can still lose a race with the operating system's own
        # socket teardown, which is slower on Windows, so allow a moment for it.
        deadline = time.monotonic() + 5
        while True:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.bind(("127.0.0.1", port))
                    break
            except OSError:
                if time.monotonic() > deadline:
                    self.fail(f"Port {port} was never released after close().")
                time.sleep(0.1)


if __name__ == "__main__":
    unittest.main()
