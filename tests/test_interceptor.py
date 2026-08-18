"""Tests for the addon that applies the rules to real flows.

Replaces the old test_request_logger.py. The flow factory is the same idea as before: a
mock flow carrying a real mitmproxy Response, because the response is the thing being
changed and a mock would accept changes that mitmproxy would not.
"""

import asyncio
import unittest
from unittest.mock import Mock, patch

from mitmproxy import exceptions, http
from robot.api import logger

from MitmLibrary.interceptor import Interceptor
from MitmLibrary.matching import MatchMode, UrlMatcher
from MitmLibrary.rules import (
    BlockAction,
    BlockMode,
    DelayAction,
    ResponseAction,
    Rule,
    RuleRegistry,
    StatusAction,
)

URL = "http://example.com/api/users"


def make_flow(url=URL, body=b"original", status_code=200, headers=None, method="GET"):
    """Builds a mock HTTPFlow with a real Response, as mitmproxy would hand us."""
    flow = Mock()
    flow.request.pretty_url = url
    flow.request.pretty_host = url
    flow.request.method = method
    flow.killable = True
    flow.response = http.Response.make(
        status_code, body, headers or {"Content-Type": "text/plain"}
    )
    return flow


class InterceptorTestCase(unittest.TestCase):
    def setUp(self):
        self.registry = RuleRegistry()
        self.interceptor = Interceptor(self.registry, log_to_console=False)

    def add(self, alias, action, url="/api", method="ANY", times=0, mode=None):
        rule = Rule(
            alias,
            UrlMatcher(url, mode or MatchMode.SUBSTRING, method),
            action,
            times,
        )
        self.registry.add(rule)
        return rule

    def respond(self, flow):
        """Runs the async response hook, as mitmproxy would."""
        asyncio.run(self.interceptor.response(flow))

    def send(self, flow):
        """Runs the async request hook, as mitmproxy would."""
        asyncio.run(self.interceptor.request(flow))


class TestBlocking(InterceptorTestCase):
    def test_respond_mode_answers_without_reaching_the_server(self):
        self.add("block", BlockAction(BlockMode.RESPOND, 403))
        flow = make_flow()
        self.send(flow)
        self.assertEqual(flow.response.status_code, 403)
        flow.kill.assert_not_called()

    def test_respond_mode_can_carry_a_body(self):
        self.add("block", BlockAction(BlockMode.RESPOND, 503, "maintenance"))
        flow = make_flow()
        self.send(flow)
        self.assertEqual(flow.response.content, b"maintenance")
        self.assertEqual(flow.response.status_code, 503)

    def test_reset_mode_drops_the_connection(self):
        self.add("block", BlockAction(BlockMode.RESET))
        flow = make_flow()
        self.send(flow)
        flow.kill.assert_called_once()

    def test_reset_mode_does_not_raise_on_a_flow_that_cannot_be_killed(self):
        """mitmproxy raises when a flow is no longer killable; that must not fail a test."""
        self.add("block", BlockAction(BlockMode.RESET))
        flow = make_flow()
        flow.killable = False
        flow.kill.side_effect = exceptions.ControlException("Flow is not killable.")
        self.send(flow)  # must not raise
        flow.kill.assert_not_called()

    def test_a_request_that_does_not_match_is_left_alone(self):
        self.add("block", BlockAction(), url="/orders")
        flow = make_flow()
        self.send(flow)
        self.assertEqual(flow.response.status_code, 200)

    def test_blocking_ends_the_flow(self):
        """Nothing after a block should run, including another blocking rule."""
        self.add("first", BlockAction(BlockMode.RESPOND, 403))
        second = self.add("second", BlockAction(BlockMode.RESPOND, 503))
        flow = make_flow()
        self.send(flow)
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(second.used, 0)


class TestResponseRules(InterceptorTestCase):
    def test_the_body_can_be_replaced(self):
        self.add("response", ResponseAction(200, None, "replaced"))
        flow = make_flow()
        self.respond(flow)
        self.assertEqual(flow.response.content, b"replaced")

    def test_the_original_body_is_kept_when_none_is_given(self):
        self.add("response", ResponseAction(201))
        flow = make_flow()
        self.respond(flow)
        self.assertEqual(flow.response.content, b"original")
        self.assertEqual(flow.response.status_code, 201)

    def test_headers_replace_the_original_ones(self):
        self.add("response", ResponseAction(200, {"Content-Type": "application/json"}))
        flow = make_flow()
        self.respond(flow)
        self.assertEqual(flow.response.headers["Content-Type"], "application/json")

    def test_the_original_headers_are_kept_when_none_are_given(self):
        self.add("response", ResponseAction(200, None, "replaced"))
        flow = make_flow(headers={"X-Kept": "yes"})
        self.respond(flow)
        self.assertEqual(flow.response.headers["X-Kept"], "yes")

    def test_a_flow_without_a_response_still_gets_one(self):
        self.add("response", ResponseAction(204))
        flow = make_flow()
        flow.response = None
        self.respond(flow)
        self.assertEqual(flow.response.status_code, 204)

    def test_a_status_rule_leaves_the_rest_alone(self):
        self.add("status", StatusAction(418))
        flow = make_flow()
        self.respond(flow)
        self.assertEqual(flow.response.status_code, 418)
        self.assertEqual(flow.response.content, b"original")

    def test_a_status_rule_on_a_flow_without_a_response_is_a_no_op(self):
        self.add("status", StatusAction(418))
        flow = make_flow()
        flow.response = None
        self.respond(flow)  # must not raise
        self.assertIsNone(flow.response)

    def test_an_unusable_response_is_reported_rather_than_raised(self):
        """A response mitmproxy rejects must fail loudly in the log, not kill the proxy.

        A non-string status code is what Robot Framework produces when a suite passes an
        argument it did not convert, so this is a reachable mistake rather than a
        contrived one.
        """
        self.add("response", ResponseAction("not a status"))
        flow = make_flow()
        with patch.object(logger, "error") as mock_error:
            self.respond(flow)
        self.assertIn("Replacing the response failed", mock_error.call_args[0][0])


class TestOrdering(InterceptorTestCase):
    def test_a_replacement_and_a_status_change_combine(self):
        """The old model let a later custom response throw away an earlier status."""
        self.add("status", StatusAction(418))
        self.add("response", ResponseAction(200, None, "replaced"))
        flow = make_flow()
        self.respond(flow)
        self.assertEqual(flow.response.content, b"replaced")
        self.assertEqual(flow.response.status_code, 418)

    def test_the_last_rule_of_equal_rank_wins(self):
        self.add("first", StatusAction(404))
        self.add("second", StatusAction(500))
        flow = make_flow()
        self.respond(flow)
        self.assertEqual(flow.response.status_code, 500)

    def test_delays_add_up(self):
        """Waiting for real would make this test slow for no extra confidence."""
        self.add("one", DelayAction(0.5, "0.5s"))
        self.add("two", DelayAction(0.25, "0.25s"))
        flow = make_flow()
        waited = _record_sleeps()
        with patch("MitmLibrary.rules.asyncio.sleep", waited.sleep):
            self.respond(flow)
        self.assertEqual(waited.seconds, [0.5, 0.25])

    def test_a_delay_runs_after_the_response_was_changed(self):
        """A delay is applied last, so the wait covers the finished response."""
        self.add("delay", DelayAction(0.1, "0.1s"))
        self.add("status", StatusAction(500))
        flow = make_flow()
        seen = []
        waited = _record_sleeps(lambda: seen.append(flow.response.status_code))
        with patch("MitmLibrary.rules.asyncio.sleep", waited.sleep):
            self.respond(flow)
        self.assertEqual(seen, [500])


class TestMatchingThroughTheInterceptor(InterceptorTestCase):
    def test_a_method_restricts_which_requests_are_touched(self):
        self.add("status", StatusAction(418), method="POST")
        self.respond(make_flow(method="POST"))
        flow = make_flow(method="GET")
        self.respond(flow)
        self.assertEqual(flow.response.status_code, 200)

    def test_a_regex_rule_matches_through_the_hook(self):
        self.add("status", StatusAction(418), url=r"/api/\w+", mode=MatchMode.REGEX)
        flow = make_flow()
        self.respond(flow)
        self.assertEqual(flow.response.status_code, 418)

    def test_a_flow_without_a_method_still_matches_an_any_rule(self):
        """Not every flow mitmproxy hands us reports a method."""
        self.add("status", StatusAction(418))
        flow = make_flow()
        flow.request.method = None
        self.respond(flow)
        self.assertEqual(flow.response.status_code, 418)


class TestTimes(InterceptorTestCase):
    def test_a_rule_can_be_limited_to_one_request(self):
        self.add("status", StatusAction(418), times=1)
        first = make_flow()
        second = make_flow()
        self.respond(first)
        self.respond(second)
        self.assertEqual(first.response.status_code, 418)
        self.assertEqual(second.response.status_code, 200)

    def test_an_exhausted_rule_is_skipped_in_the_response_hook(self):
        """The rule still matches; the registry is what refuses to let it run again."""
        rule = self.add("status", StatusAction(418), times=1)
        self.respond(make_flow())
        flow = make_flow()
        self.respond(flow)
        self.assertEqual(flow.response.status_code, 200)
        self.assertEqual(rule.used, 1)

    def test_an_exhausted_rule_is_skipped_in_the_request_hook(self):
        rule = self.add("block", BlockAction(BlockMode.RESPOND, 403), times=1)
        self.send(make_flow())
        flow = make_flow()
        self.send(flow)
        self.assertEqual(flow.response.status_code, 200)
        self.assertEqual(rule.used, 1)

    def test_only_matching_requests_use_up_a_rule(self):
        """A rule limited to one request must not be spent by a request it ignores."""
        rule = self.add("status", StatusAction(418), url="/api", times=1)
        self.respond(make_flow(url="http://example.com/orders"))
        self.assertEqual(rule.remaining, 1)
        flow = make_flow()
        self.respond(flow)
        self.assertEqual(flow.response.status_code, 418)


class TestConsoleLogging(InterceptorTestCase):
    def test_each_manipulation_is_reported(self):
        self.add("status", StatusAction(418))
        with patch.object(logger, "info") as mock_info:
            self.respond(make_flow())
        logged = " ".join(str(call.args[0]) for call in mock_info.call_args_list)
        self.assertIn("status", logged)
        self.assertIn(URL, logged)

    def test_console_logging_can_be_turned_off_and_on(self):
        self.add("status", StatusAction(418))
        self.interceptor.set_console_logging(True)
        with patch.object(logger, "info") as mock_info:
            self.respond(make_flow())
        self.assertTrue(mock_info.call_args.kwargs["also_console"])
        self.interceptor.set_console_logging(False)
        with patch.object(logger, "info") as mock_info:
            self.respond(make_flow())
        self.assertFalse(mock_info.call_args.kwargs["also_console"])


class TestConcurrency(InterceptorTestCase):
    def test_a_delayed_response_does_not_hold_up_another_one(self):
        """The registry must not be locked while a rule waits."""
        self.add("delay", DelayAction(0.3, "0.3s"), url="/slow")
        slow = make_flow(url="http://example.com/slow")
        fast = make_flow()

        async def scenario():
            slow_task = asyncio.create_task(self.interceptor.response(slow))
            await asyncio.sleep(0)
            start = asyncio.get_running_loop().time()
            await self.interceptor.response(fast)
            elapsed = asyncio.get_running_loop().time() - start
            await slow_task
            return elapsed

        self.assertLess(asyncio.run(scenario()), 0.2)


class _record_sleeps:
    """Stands in for asyncio.sleep, recording what it was asked to wait for."""

    def __init__(self, on_sleep=None):
        self.seconds = []
        self.on_sleep = on_sleep

    async def sleep(self, seconds):
        self.seconds.append(seconds)
        if self.on_sleep is not None:
            self.on_sleep()


if __name__ == "__main__":
    unittest.main()
