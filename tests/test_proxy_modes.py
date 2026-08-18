"""Tests for the proxy modes and for proxy authentication.

The options themselves are checked against a mocked master, because what matters there is
that the right values reach mitmproxy. Reverse and upstream mode are then exercised for
real, against a live proxy: both are modes people actually use, and both can be proven
without any network beyond localhost.
"""

import http.server
import socket
import threading
import unittest
import urllib.error
import urllib.request
from types import SimpleNamespace
from unittest.mock import patch

from MitmLibrary import MitmLibrary


def free_port() -> int:
    """Returns a port that is free right now, to keep parallel runs from colliding."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _addons_by_name(proxyserver):
    """Fakes mitmproxy's addon lookup, which answers per name."""

    def get(name):
        return proxyserver if name == "proxyserver" else None

    return get


async def _noop_update(_modes):
    return True


async def _runs_until_stopped(stop):
    import asyncio

    while not stop.is_set():
        await asyncio.sleep(0.01)


class _Handler(http.server.BaseHTTPRequestHandler):
    """Answers everything with a fixed body, so a test can tell it apart."""

    def do_GET(self):  # noqa: N802 - the name is fixed by http.server
        body = b"hello from the origin"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        """Silences the default logging to stderr, which is noise in a test run."""


class TestModeOptions(unittest.TestCase):
    """What reaches mitmproxy's options, against a mocked master."""

    def setUp(self):
        self.library = MitmLibrary()
        self.stop = threading.Event()
        patcher = patch("MitmLibrary.dump.DumpMaster")
        mock_master = patcher.start()
        self.addCleanup(patcher.stop)
        mock_master.return_value.addons.get.side_effect = _addons_by_name(
            SimpleNamespace(
                listen_addrs=lambda: [("127.0.0.1", 8099)],
                servers=SimpleNamespace(update=_noop_update),
            )
        )
        mock_master.return_value.shutdown.side_effect = self.stop.set
        mock_master.return_value.run = lambda: _runs_until_stopped(self.stop)
        options_patcher = patch("MitmLibrary.proxy_controller.options.Options")
        self.mock_options = options_patcher.start()
        self.addCleanup(options_patcher.stop)

    def tearDown(self):
        self.library.controller.shutdown()

    def kwargs(self):
        return self.mock_options.call_args.kwargs

    def test_no_mode_is_passed_when_none_is_given(self):
        """mitmproxy has its own default, and an unasked-for value would override it."""
        self.library.start_mitm_proxy()
        self.assertNotIn("mode", self.kwargs())
        self.assertNotIn("proxyauth", self.kwargs())

    def test_a_single_mode_is_passed_as_a_list(self):
        """The option is a sequence, but a suite naturally passes one string."""
        self.library.start_mitm_proxy(mode="reverse:http://127.0.0.1:5000")
        self.assertEqual(self.kwargs()["mode"], ["reverse:http://127.0.0.1:5000"])

    def test_several_modes_are_passed_through(self):
        self.library.start_mitm_proxy(mode=["regular", "socks5@127.0.0.1:9050"])
        self.assertEqual(self.kwargs()["mode"], ["regular", "socks5@127.0.0.1:9050"])

    def test_proxy_authentication_is_set_on_the_master(self):
        """proxyauth belongs to an addon, so it is not a core option and cannot be
        passed when the options are built; it is set once the master has loaded them.
        """
        self.library.start_mitm_proxy(proxy_auth="tester:secret")
        self.assertNotIn("proxyauth", self.kwargs())
        self.library.proxy_master.options.update.assert_called_once_with(
            proxyauth="tester:secret"
        )

    def test_transparent_and_socks_are_accepted_even_though_untested(self):
        """Passed through to mitmproxy; the library does not second-guess them."""
        self.library.start_mitm_proxy(mode="transparent")
        self.assertEqual(self.kwargs()["mode"], ["transparent"])


class TestModeValidation(unittest.TestCase):
    def setUp(self):
        self.library = MitmLibrary()

    def tearDown(self):
        self.library.controller.shutdown()

    def test_an_unknown_mode_fails_the_keyword(self):
        """Left to the proxy this would be a startup timeout with no reason attached."""
        with self.assertRaises(ValueError) as context:
            self.library.start_mitm_proxy(mode="nonsense:foo")
        message = str(context.exception)
        self.assertIn("nonsense:foo", message)
        self.assertIn("not a usable proxy mode", message)

    def test_the_failure_explains_what_a_mode_looks_like(self):
        with self.assertRaises(ValueError) as context:
            self.library.start_mitm_proxy(mode="reverse:")
        self.assertIn("reverse:http://host:port", str(context.exception))

    def test_one_bad_mode_in_a_list_fails(self):
        with self.assertRaises(ValueError):
            self.library.start_mitm_proxy(mode=["regular", "nonsense:foo"])

    def test_nothing_is_left_running_after_a_bad_mode(self):
        with self.assertRaises(ValueError):
            self.library.start_mitm_proxy(mode="nonsense:foo")
        self.assertIsNone(self.library.proxy_master)


class TestReverseMode(unittest.TestCase):
    """Reverse mode against a real server, which needs no network beyond localhost."""

    def setUp(self):
        self.library = MitmLibrary()
        self.origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.origin_port = self.origin.server_address[1]
        self.thread = threading.Thread(target=self.origin.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.library.controller.shutdown()
        self.origin.shutdown()
        self.origin.server_close()
        self.thread.join(timeout=5)

    def test_a_client_reaches_the_origin_without_proxy_settings(self):
        """The point of reverse mode: the client talks to the proxy as if it were the
        server, so nothing has to be configured to use a proxy at all.
        """
        port = free_port()
        self.library.start_mitm_proxy(
            listen_port=port, mode=f"reverse:http://127.0.0.1:{self.origin_port}"
        )
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=10) as answer:
            self.assertEqual(answer.read(), b"hello from the origin")

    def test_rules_apply_in_reverse_mode(self):
        """A mode that could not be manipulated would not be worth having."""
        port = free_port()
        self.library.start_mitm_proxy(
            listen_port=port, mode=f"reverse:http://127.0.0.1:{self.origin_port}"
        )
        self.library.set_response_body("stub", "/", "replaced by the proxy")
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=10) as answer:
            self.assertEqual(answer.read(), b"replaced by the proxy")

    def test_a_blocked_request_is_blocked_in_reverse_mode(self):
        """Request-phase rules have to run too, not only response-phase ones."""
        port = free_port()
        self.library.start_mitm_proxy(
            listen_port=port, mode=f"reverse:http://127.0.0.1:{self.origin_port}"
        )
        self.library.block_requests("blocked", "/", status_code=503)
        with self.assertRaises(urllib.error.HTTPError) as context:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=10)
        self.assertEqual(context.exception.code, 503)


class TestUpstreamMode(unittest.TestCase):
    """Two proxies chained, which is what a corporate network needs.

    These assert that traffic is *routed* through the upstream proxy, by contrasting a
    live upstream with a dead one. They deliberately do not assert that the upstream
    proxy can read or change the traffic: with a live upstream mitmproxy the request
    arrives at its port but produces no HTTP flow there, so rules on the upstream proxy
    do not fire. Routing is what this library configures and what a suite depends on;
    what an arbitrary upstream proxy then does with the traffic is its own business.
    """

    def setUp(self):
        self.origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.origin_port = self.origin.server_address[1]
        self.thread = threading.Thread(target=self.origin.serve_forever, daemon=True)
        self.thread.start()
        self.upstream = MitmLibrary()
        self.downstream = MitmLibrary()

    def tearDown(self):
        self.downstream.controller.shutdown()
        self.upstream.controller.shutdown()
        self.origin.shutdown()
        self.origin.server_close()
        self.thread.join(timeout=5)

    def _open_through(self, proxy_port):
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
        )
        return opener.open(f"http://127.0.0.1:{self.origin_port}/", timeout=10)

    def test_a_request_reaches_the_origin_through_the_chain(self):
        upstream_port = free_port()
        downstream_port = free_port()
        self.upstream.start_mitm_proxy(listen_port=upstream_port)
        self.downstream.start_mitm_proxy(
            listen_port=downstream_port,
            mode=f"upstream:http://127.0.0.1:{upstream_port}",
        )
        with self._open_through(downstream_port) as answer:
            self.assertEqual(answer.read(), b"hello from the origin")

    def test_the_request_really_goes_through_the_upstream_proxy(self):
        """The other half of the test above, and the half that proves anything.

        Reaching the origin does not on its own show the upstream proxy was involved,
        because the origin is reachable either way. Pointing the chain at an upstream
        that is not there has to break it.
        """
        downstream_port = free_port()
        nothing_listening = free_port()
        self.downstream.start_mitm_proxy(
            listen_port=downstream_port,
            mode=f"upstream:http://127.0.0.1:{nothing_listening}",
        )
        with self.assertRaises(urllib.error.HTTPError) as context:
            self._open_through(downstream_port)
        self.assertEqual(context.exception.code, 502)

    def test_the_downstream_proxy_still_applies_its_own_rules(self):
        upstream_port = free_port()
        downstream_port = free_port()
        self.upstream.start_mitm_proxy(listen_port=upstream_port)
        self.downstream.start_mitm_proxy(
            listen_port=downstream_port,
            mode=f"upstream:http://127.0.0.1:{upstream_port}",
        )
        self.downstream.set_response_body("stub", "/", "answered downstream")
        with self._open_through(downstream_port) as answer:
            self.assertEqual(answer.read(), b"answered downstream")


class TestProxyAuthentication(unittest.TestCase):
    def setUp(self):
        self.library = MitmLibrary()
        self.origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.origin_port = self.origin.server_address[1]
        self.thread = threading.Thread(target=self.origin.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.library.controller.shutdown()
        self.origin.shutdown()
        self.origin.server_close()
        self.thread.join(timeout=5)

    def test_a_client_without_credentials_is_refused(self):
        port = free_port()
        self.library.start_mitm_proxy(listen_port=port, proxy_auth="tester:secret")
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}"})
        )
        with self.assertRaises(urllib.error.HTTPError) as context:
            opener.open(f"http://127.0.0.1:{self.origin_port}/", timeout=10)
        self.assertEqual(context.exception.code, 407)


if __name__ == "__main__":
    unittest.main()
