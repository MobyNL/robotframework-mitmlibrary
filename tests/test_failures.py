"""Tests for the rules that break traffic on purpose.

These are the most version-sensitive rules in the library, because each depends on a
mitmproxy behaviour that is documented but not promised. The assertions are written to
notice if one of those behaviours changes, rather than only that the keyword ran.
"""

import asyncio
import unittest
from unittest.mock import patch

from mitmproxy import exceptions, http
from mitmproxy.test import tflow, tutils
from robot.api import logger

from MitmLibrary.failures import TimeoutAction, TruncateAction
from MitmLibrary.interceptor import Interceptor
from MitmLibrary.matching import MatchMode, UrlMatcher
from MitmLibrary.rules import Rule, RuleRegistry


def make_flow(url="http://example.com/api/users", body=b"a full response body"):
    """A real flow whose content-length agrees with its body, as a server's would."""
    flow = tflow.tflow(req=tutils.treq(), resp=tutils.tresp(content=body))
    flow.request.url = url
    flow.response.headers["content-length"] = str(len(body))
    return flow


class FailureTestCase(unittest.TestCase):
    def setUp(self):
        self.registry = RuleRegistry()
        self.interceptor = Interceptor(self.registry, log_to_console=False)

    def add(self, alias, action, url="/api", method="ANY", times=0):
        self.registry.add(
            Rule(alias, UrlMatcher(url, MatchMode.SUBSTRING, method), action, times)
        )

    def send(self, flow):
        asyncio.run(self.interceptor.request(flow))

    def respond(self, flow):
        asyncio.run(self.interceptor.response(flow))


class TestTimeout(unittest.TestCase):
    """The wait is asserted with a patched sleep; waiting for real proves nothing extra."""

    def setUp(self):
        self.registry = RuleRegistry()
        self.interceptor = Interceptor(self.registry, log_to_console=False)
        self.registry.add(
            Rule("hang", UrlMatcher("/api"), TimeoutAction(30.0, "30s"))
        )

    def test_the_request_is_held_for_the_configured_time(self):
        flow = make_flow()
        waited = []

        async def record(seconds):
            waited.append(seconds)

        with patch("MitmLibrary.failures.asyncio.sleep", record):
            asyncio.run(self.interceptor.request(flow))
        self.assertEqual(waited, [30.0])

    def test_the_request_is_dropped_afterwards(self):
        """Without this the client waits forever when its own timeout is longer."""
        flow = make_flow()
        flow.kill = lambda: setattr(flow, "killed", True)

        async def record(_seconds):
            self.assertFalse(getattr(flow, "killed", False))  # held, not yet dropped

        with patch("MitmLibrary.failures.asyncio.sleep", record):
            asyncio.run(self.interceptor.request(flow))
        self.assertTrue(flow.killed)

    def test_the_request_never_reaches_the_server(self):
        """A timeout is not a slow answer: the request is not sent at all."""
        flow = make_flow()

        async def record(_seconds):
            return None

        with patch("MitmLibrary.failures.asyncio.sleep", record):
            asyncio.run(self.interceptor.request(flow))
        self.assertIsNotNone(flow.error)

    def test_a_timeout_ends_the_flow(self):
        """Nothing after it should run, since there is no longer a request to change."""
        later = Rule("later", UrlMatcher("/api"), TimeoutAction(1.0, "1s"))
        self.registry.add(later)

        async def record(_seconds):
            return None

        with patch("MitmLibrary.failures.asyncio.sleep", record):
            asyncio.run(self.interceptor.request(make_flow()))
        self.assertEqual(later.used, 0)

    def test_holding_one_request_does_not_hold_up_another(self):
        """The whole point of holding rather than blocking: other traffic keeps flowing."""
        self.registry.clear()
        self.registry.add(Rule("hang", UrlMatcher("/slow"), TimeoutAction(0.4, "0.4s")))
        slow = make_flow(url="http://example.com/slow")
        fast = make_flow()

        async def scenario():
            held = asyncio.create_task(self.interceptor.request(slow))
            await asyncio.sleep(0)
            start = asyncio.get_running_loop().time()
            await self.interceptor.request(fast)
            elapsed = asyncio.get_running_loop().time() - start
            await held
            return elapsed

        self.assertLess(asyncio.run(scenario()), 0.2)

    def test_a_flow_that_cannot_be_killed_does_not_raise(self):
        flow = make_flow()
        flow.kill = lambda: (_ for _ in ()).throw(
            exceptions.ControlException("Flow is not killable.")
        )
        flow.live = False

        async def record(_seconds):
            return None

        with patch("MitmLibrary.failures.asyncio.sleep", record):
            asyncio.run(self.interceptor.request(flow))  # must not raise

    def test_the_rule_reports_what_it_was_asked_for(self):
        described = self.registry.describe()[0]
        self.assertEqual(described.type, "timeout")
        self.assertEqual(described.hold, "30s")
        self.assertEqual(described.hold_seconds, 30.0)
        self.assertEqual(described.phase, "request")


class TestTruncate(FailureTestCase):
    def test_the_body_is_cut_short(self):
        self.add("cut", TruncateAction(keep_bytes=6))
        flow = make_flow(body=b"a full response body")
        self.respond(flow)
        self.assertEqual(flow.response.raw_content, b"a full")

    def test_the_declared_length_is_left_alone(self):
        """The mismatch is the fault being injected.

        set_content would correct content-length and leave a perfectly valid, merely
        shorter response, which is not a failure at all. This assertion is what would
        notice a mitmproxy version that started normalising the header on write.
        """
        self.add("cut", TruncateAction(keep_bytes=6))
        flow = make_flow(body=b"a full response body")
        self.respond(flow)
        self.assertEqual(flow.response.headers["content-length"], "20")
        self.assertEqual(len(flow.response.raw_content), 6)

    def test_half_the_body_is_kept_by_default(self):
        self.add("cut", TruncateAction())
        flow = make_flow(body=b"0123456789")
        self.respond(flow)
        self.assertEqual(flow.response.raw_content, b"01234")

    def test_a_fraction_can_be_given(self):
        self.add("cut", TruncateAction(keep_fraction=0.25))
        flow = make_flow(body=b"0123456789")
        self.respond(flow)
        self.assertEqual(flow.response.raw_content, b"01")

    def test_a_byte_count_wins_over_a_fraction(self):
        self.add("cut", TruncateAction(keep_bytes=3, keep_fraction=0.9))
        flow = make_flow(body=b"0123456789")
        self.respond(flow)
        self.assertEqual(flow.response.raw_content, b"012")

    def test_nothing_at_all_can_be_kept(self):
        self.add("cut", TruncateAction(keep_bytes=0))
        flow = make_flow(body=b"0123456789")
        self.respond(flow)
        self.assertEqual(flow.response.raw_content, b"")
        self.assertEqual(flow.response.headers["content-length"], "10")

    def test_a_negative_count_keeps_nothing_rather_than_failing(self):
        self.add("cut", TruncateAction(keep_bytes=-5))
        flow = make_flow(body=b"0123456789")
        self.respond(flow)
        self.assertEqual(flow.response.raw_content, b"")

    def test_a_body_that_is_already_short_enough_is_left_alone(self):
        self.add("cut", TruncateAction(keep_bytes=100))
        flow = make_flow(body=b"short")
        with patch.object(logger, "info") as mock_info:
            self.respond(flow)
        self.assertEqual(flow.response.raw_content, b"short")
        logged = " ".join(str(call.args[0]) for call in mock_info.call_args_list)
        self.assertIn("unchanged", logged)

    def test_a_response_without_a_body_says_so(self):
        """A 204 or a streamed response has nothing here to cut."""
        self.add("cut", TruncateAction(keep_bytes=1))
        flow = make_flow()
        flow.response = http.Response.make(204)
        flow.response.raw_content = None
        with patch.object(logger, "info") as mock_info:
            self.respond(flow)
        logged = " ".join(str(call.args[0]) for call in mock_info.call_args_list)
        self.assertIn("no body to truncate", logged)

    def test_a_flow_without_a_response_is_a_no_op(self):
        self.add("cut", TruncateAction(keep_bytes=1))
        flow = make_flow()
        flow.response = None
        self.respond(flow)  # must not raise

    def test_a_compressed_body_is_cut_in_its_compressed_form(self):
        """What arrives is not a valid shorter document but a broken one.

        That is the more realistic failure and the more interesting one to test an
        application with. mitmproxy does not raise on a body it cannot decompress - it
        hands back nothing - so the assertion is that the original text is gone, not that
        decoding fails.
        """
        self.add("cut", TruncateAction(keep_fraction=0.5))
        flow = make_flow(body=b"a full response body repeated over and over and over")
        flow.response.encode("gzip")
        compressed = flow.response.raw_content
        self.respond(flow)
        self.assertEqual(len(flow.response.raw_content), len(compressed) // 2)
        self.assertNotIn(b"a full response body", flow.response.get_content())

    def test_the_rule_reports_what_it_was_asked_for(self):
        self.add("cut", TruncateAction(keep_bytes=6))
        described = self.registry.describe()[0]
        self.assertEqual(described.type, "truncate")
        self.assertEqual(described.keep_bytes, 6)
        self.assertEqual(described.phase, "response")


if __name__ == "__main__":
    unittest.main()
