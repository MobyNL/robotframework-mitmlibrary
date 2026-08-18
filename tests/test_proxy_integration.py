"""Integration tests that start a real mitmproxy instance.

The unit tests patch out `DumpMaster`, which means they cannot catch a regression in the
way the library talks to mitmproxy itself. These tests exercise that boundary for real:
both of the failure modes below were live bugs that a mocked DumpMaster hid.
"""

import logging
import shutil
import socket
import tempfile
import threading
import time
import unittest
import urllib.request

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
        self.library.controller.shutdown()

    def test_starts_without_a_certificates_directory(self):
        """`Options` rejects confdir=None, so the default call must omit the key."""
        self.library.start_mitm_proxy(listen_port=self.port)
        self.assertEqual(
            self.library.controller.listen_addresses(), [("127.0.0.1", self.port)]
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
            self.library.controller.listen_addresses(), [("127.0.0.1", self.port)]
        )

    def test_port_zero_reports_the_port_the_system_picked(self):
        """Port 0 is only usable if the caller can find out what it was resolved to.

        This is the whole justification for `Get Proxy Address`, and it cannot be proven
        against a mocked master: only a real proxy resolves port 0 to a real port.
        """
        self.library.start_mitm_proxy(listen_port=0)
        address = self.library.get_proxy_address()
        self.assertEqual(address.host, "127.0.0.1")
        self.assertNotEqual(address.port, 0)
        self.assertEqual(address.url, f"http://127.0.0.1:{address.port}")

        # The reported port must be the one that is actually bound, which binding it
        # ourselves proves. Opening a connection would prove it too, but a client that
        # connects and never sends a request makes the proxy log an error, and that
        # error then belongs to no test in particular.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            with self.assertRaises(OSError):
                sock.bind(("127.0.0.1", address.port))

    def test_an_unrelated_error_during_startup_does_not_fail_the_keyword(self):
        """A proxy stopped moments ago still logs from its own teardown, and the rest of
        the test run logs too. Those must not be read as this proxy failing to bind: the
        collector listens on the root logger, so it hears all of them.
        """
        noisy = threading.Thread(target=self._log_errors_briefly)
        noisy.start()
        self.addCleanup(noisy.join, 5)
        self.library.start_mitm_proxy(listen_port=self.port)
        self.assertEqual(
            self.library.controller.listen_addresses(), [("127.0.0.1", self.port)]
        )

    @staticmethod
    def _log_errors_briefly():
        """Logs the kind of noise a stopping proxy leaves behind."""
        deadline = time.monotonic() + 1
        mitm_logger = logging.getLogger("mitmproxy.addons.something")
        while time.monotonic() < deadline:
            mitm_logger.error("Addon error: Event loop is closed")
            logging.getLogger("asyncio").error("Task was destroyed but it is pending!")
            time.sleep(0.02)

    def test_a_real_bind_failure_is_still_reported(self):
        """The noise filter must not swallow the failure it exists to report."""
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        blocker.bind(("127.0.0.1", self.port))
        blocker.listen(1)
        self.addCleanup(blocker.close)
        with self.assertRaises(RuntimeError) as context:
            self.library.start_mitm_proxy(listen_port=self.port)
        self.assertIn("failed to listen", str(context.exception))

    def test_an_unrelated_logged_error_does_not_kill_the_proxy(self):
        """mitmproxy's errorcheck addon exits the process when anything logged an error
        while a master starts. It watches the root logger, so the error can come from a
        proxy started earlier or from any other part of the test run, and the library
        removes the addon rather than let an unrelated message take a proxy down.
        """
        logging.getLogger("some.other.component").error("unrelated failure")
        self.library.start_mitm_proxy(listen_port=self.port)
        self.assertEqual(
            self.library.controller.listen_addresses(), [("127.0.0.1", self.port)]
        )

    def test_the_errorcheck_addon_is_removed(self):
        """Pins the reason for the test above, so a revert is reported as itself."""
        self.library.start_mitm_proxy(listen_port=self.port)
        self.assertIsNone(self.library.proxy_master.addons.get("errorcheck"))

    def test_traffic_is_recorded_across_the_proxy_thread(self):
        """Recording crosses a thread boundary, which a mocked proxy cannot exercise.

        The proxy records on its own event loop thread while the keywords read from this
        one, so only a real request through a real proxy proves the two agree.
        """
        self.library.start_mitm_proxy(listen_port=self.port, record=True)
        address = self.library.get_proxy_address()

        # A request the proxy cannot forward: the point is that it was *seen*, and a
        # failed request has to be recorded too, or a blocked call could never be
        # asserted on.
        self._request_through_proxy(address.port, "http://127.0.0.1:1/recorded")

        found = self.library.wait_until_request_is_made("/recorded", timeout="10s")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].method, "GET")
        self.assertIn("/recorded", found[0].url)
        self.library.request_should_have_been_made("/recorded")
        self.library.request_should_not_have_been_made("/never-asked-for")

    def test_waiting_returns_when_the_request_arrives(self):
        """The wait is woken by the proxy thread, not by a poll on this one."""
        self.library.start_mitm_proxy(listen_port=self.port, record=True)
        address = self.library.get_proxy_address()

        timer = threading.Timer(
            0.3,
            self._request_through_proxy,
            (address.port, "http://127.0.0.1:1/later"),
        )
        timer.start()
        self.addCleanup(timer.cancel)

        started = time.monotonic()
        found = self.library.wait_until_request_is_made("/later", timeout="15s")
        self.assertEqual(len(found), 1)
        self.assertLess(time.monotonic() - started, 10)

    @staticmethod
    def _request_through_proxy(proxy_port, url):
        """Sends one request through the proxy, ignoring how it turns out."""
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler(
                {"http": f"http://127.0.0.1:{proxy_port}"}
            )
        )
        try:
            opener.open(url, timeout=5).close()
        except Exception:  # noqa: BLE001 - the answer does not matter, only the record
            pass
    def test_stopping_removes_the_mitmproxy_log_handler(self):
        """mitmproxy leaves a root logger handler behind that outlives its own loop.

        Every record logged afterwards is forwarded to a closed event loop, which raises
        inside logging, and a run that starts several proxies accumulates one handler
        per proxy. Nothing in the library logs enough to notice; a long suite does.
        """
        from mitmproxy import log as mitmproxy_log

        def installed():
            return [
                handler
                for handler in logging.getLogger().handlers
                if isinstance(handler, mitmproxy_log.MitmLogHandler)
            ]

        before = len(installed())
        self.library.start_mitm_proxy(listen_port=self.port)
        self.assertGreater(len(installed()), before)
        self.library.stop_mitm_proxy()
        self.assertEqual(len(installed()), before)

        # Logging after the proxy is gone must not raise into the logging machinery.
        logging.getLogger("some.other.component").warning("after the proxy stopped")

    def test_starting_several_proxies_does_not_pile_up_log_handlers(self):
        from mitmproxy import log as mitmproxy_log

        def installed():
            return [
                handler
                for handler in logging.getLogger().handlers
                if isinstance(handler, mitmproxy_log.MitmLogHandler)
            ]

        before = len(installed())
        for _ in range(3):
            self.library.start_mitm_proxy(listen_port=free_port())
            self.library.stop_mitm_proxy()
        self.assertEqual(len(installed()), before)


if __name__ == "__main__":
    unittest.main()
