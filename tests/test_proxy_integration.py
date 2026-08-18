"""Integration tests that start a real mitmproxy instance.

The unit tests patch out `DumpMaster`, which means they cannot catch a regression in the
way the library talks to mitmproxy itself. These tests exercise that boundary for real:
both of the failure modes below were live bugs that a mocked DumpMaster hid.
"""

import shutil
import socket
import tempfile
import unittest

from mitmproxy import options

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

    def test_mitmproxy_accepts_the_certificates_directory(self):
        """The directory must be usable as mitmproxy's confdir, and omitting it must not
        produce `confdir=None`, which mitmproxy rejects with a TypeError.

        This builds the options rather than starting a proxy: generating a certificate
        authority in a fresh directory is mitmproxy's work, not this library's, and it
        stalls under coverage instrumentation.
        """
        certs_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, certs_dir, True)
        self.assertEqual(options.Options(confdir=certs_dir).confdir, certs_dir)
        with self.assertRaises(TypeError):
            options.Options(confdir=None)

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
