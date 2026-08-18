"""Integration tests that start a real mitmproxy instance.

The unit tests patch out `DumpMaster`, which means they cannot catch a regression in the
way the library talks to mitmproxy itself. These tests exercise that boundary for real:
both of the failure modes below were live bugs that a mocked DumpMaster hid.
"""

import pathlib
import shutil
import socket
import tempfile
import time
import unittest

from MitmLibrary import MitmLibrary


def free_port() -> int:
    """Returns a port that is free right now, to keep parallel runs from colliding."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class TestProxyIntegration(unittest.TestCase):
    def setUp(self):
        self.library = MitmLibrary()
        self.port = free_port()

    def tearDown(self):
        self.library.stop_mitm_proxy()
        loop = self.library.loop_handler.loop
        loop.call_soon_threadsafe(loop.stop)
        self.library.loop_handler.join(timeout=5)

    def test_starts_without_a_certificates_directory(self):
        """`Options` rejects confdir=None, so the default call must omit the key."""
        self.library.start_mitm_proxy(listen_port=self.port)
        self.assertEqual(
            self.library._listening_addresses(), [("127.0.0.1", self.port)]
        )

    def test_certificates_directory_is_used(self):
        """A given directory must reach mitmproxy and receive its generated CA."""
        certs_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, certs_dir, True)
        self.library.start_mitm_proxy(
            listen_port=self.port, certificates_directory=certs_dir
        )
        self.assertEqual(
            self.library.proxy_master.options.confdir, certs_dir
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            written = list(pathlib.Path(certs_dir).glob("mitmproxy-ca*"))
            if written:
                break
            time.sleep(0.1)
        self.assertTrue(
            written,
            "mitmproxy did not write its certificate authority to the given directory",
        )

    def test_busy_port_fails_the_keyword(self):
        """mitmproxy only logs bind failures, so this must not silently run green."""
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        blocker.bind(("127.0.0.1", self.port))
        blocker.listen(1)
        self.addCleanup(blocker.close)

        with self.assertRaises(RuntimeError) as context:
            self.library.start_mitm_proxy(listen_port=self.port)
        # The wording of the bind error differs per platform, so match on what the
        # library itself contributes rather than on the operating system's message.
        self.assertIn("Could not start the proxy", str(context.exception))
        self.assertIn(str(self.port), str(context.exception))
        self.assertIsNone(self.library.proxy_master)

    def test_proxy_can_be_restarted_on_the_same_port(self):
        """Stopping must release the port, so a suite can restart the proxy."""
        self.library.start_mitm_proxy(listen_port=self.port)
        self.library.stop_mitm_proxy()
        self.library.start_mitm_proxy(listen_port=self.port)
        self.assertEqual(
            self.library._listening_addresses(), [("127.0.0.1", self.port)]
        )


if __name__ == "__main__":
    unittest.main()
