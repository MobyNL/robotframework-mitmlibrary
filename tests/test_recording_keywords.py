"""Tests for the keywords that record traffic and assert on it.

The assertion keywords are the point of recording, and their failure messages are most of
their value: when one fails, the useful question is what the application asked for
instead. That is what these mostly check.
"""

import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from mitmproxy.test import tflow, tutils
from robot.api import logger

from MitmLibrary import MitmLibrary
from MitmLibrary.matching import MatchMode


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


def make_flow(url="http://example.com/api/users", method="GET", status_code=200):
    flow = tflow.tflow(
        req=tutils.treq(method=method), resp=tutils.tresp(status_code=status_code)
    )
    flow.request.url = url
    return flow


class RecordingKeywordTestCase(unittest.TestCase):
    def setUp(self):
        self.library = MitmLibrary()
        self.stop = threading.Event()
        self.patcher = patch("MitmLibrary.dump.DumpMaster")
        mock_master = self.patcher.start()
        self.addCleanup(self.patcher.stop)
        mock_master.return_value.addons.get.side_effect = _addons_by_name(
            SimpleNamespace(
                listen_addrs=lambda: [("127.0.0.1", 8099)],
                servers=SimpleNamespace(update=_noop_update),
            )
        )
        mock_master.return_value.shutdown.side_effect = self.stop.set
        mock_master.return_value.run = lambda: _runs_until_stopped(self.stop)
        self.mock_master = mock_master

    def tearDown(self):
        self.library.controller.shutdown()

    def record(self, **kwargs):
        self.library.recorder.response(make_flow(**kwargs))


class TestRecordingIsOptional(RecordingKeywordTestCase):
    def test_recording_keywords_need_a_proxy(self):
        with self.assertRaises(RuntimeError) as context:
            self.library.get_recorded_requests()
        self.assertIn("Start Mitm Proxy", str(context.exception))

    def test_recording_keywords_explain_that_recording_is_off(self):
        """Off by default, so the error has to say how to turn it on."""
        self.library.start_mitm_proxy()
        with self.assertRaises(RuntimeError) as context:
            self.library.get_recorded_requests()
        self.assertIn("Start Recording", str(context.exception))
        self.assertIn("record=True", str(context.exception))

    def test_recording_can_be_started_with_the_proxy(self):
        self.library.start_mitm_proxy(record=True)
        self.assertIsNotNone(self.library.recorder)
        self.assertEqual(self.library.get_recorded_requests(), [])

    def test_the_limits_can_be_set_when_starting_the_proxy(self):
        self.library.start_mitm_proxy(record=True, record_limit=5, record_body_limit=10)
        self.assertEqual(self.library.recorder.limit, 5)
        self.assertEqual(self.library.recorder.body_limit, 10)

    def test_recording_can_be_started_afterwards(self):
        self.library.start_mitm_proxy()
        self.library.start_recording(limit=5)
        self.assertEqual(self.library.recorder.limit, 5)
        self.mock_master.return_value.addons.add.assert_called()

    def test_recording_can_be_stopped(self):
        self.library.start_mitm_proxy(record=True)
        self.library.stop_recording()
        self.assertIsNone(self.library.recorder)
        self.mock_master.return_value.addons.remove.assert_called()

    def test_stopping_when_nothing_was_recording_is_a_no_op(self):
        self.library.start_mitm_proxy()
        self.library.stop_recording()  # must not raise

    def test_stopping_the_proxy_forgets_the_recorder(self):
        self.library.start_mitm_proxy(record=True)
        self.library.stop_mitm_proxy()
        self.assertIsNone(self.library.recorder)


class TestAddonManagement(RecordingKeywordTestCase):
    def test_adding_an_addon_without_a_proxy_is_refused(self):
        with self.assertRaises(RuntimeError) as context:
            self.library.controller.add_addon(object())
        self.assertIn("No proxy is running", str(context.exception))

    def test_removing_an_addon_without_a_proxy_is_a_no_op(self):
        self.library.controller.remove_addon(object())  # must not raise

    def test_removing_an_addon_the_proxy_no_longer_has_is_reported_not_raised(self):
        """Stopping the proxy takes its addons with it, which is not a failure."""
        self.library.start_mitm_proxy(record=True)
        self.mock_master.return_value.addons.remove.side_effect = KeyError("gone")
        with patch.object(logger, "info") as mock_info:
            self.library.stop_recording()
        logged = " ".join(str(call.args[0]) for call in mock_info.call_args_list)
        self.assertIn("already gone", logged)


class TestQuerying(RecordingKeywordTestCase):
    def setUp(self):
        super().setUp()
        self.library.start_mitm_proxy(record=True)
        self.record(url="http://example.com/api/users", method="GET")
        self.record(url="http://example.com/api/users", method="POST")
        self.record(url="http://example.com/orders", method="GET")

    def test_everything_is_returned_when_nothing_is_asked_for(self):
        self.assertEqual(len(self.library.get_recorded_requests()), 3)

    def test_requests_can_be_filtered(self):
        found = self.library.get_recorded_requests("/api/users", method="POST")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].method, "POST")

    def test_counting(self):
        self.assertEqual(self.library.get_request_count(), 3)
        self.assertEqual(self.library.get_request_count("/api/users"), 2)
        self.assertEqual(self.library.get_request_count(method="POST"), 1)

    def test_counting_with_a_regex(self):
        self.assertEqual(
            self.library.get_request_count(r"/api/\w+", match=MatchMode.REGEX), 2
        )

    def test_clearing_keeps_recording(self):
        self.library.clear_recorded_requests()
        self.assertEqual(self.library.get_request_count(), 0)
        self.record()
        self.assertEqual(self.library.get_request_count(), 1)


class TestAssertions(RecordingKeywordTestCase):
    def setUp(self):
        super().setUp()
        self.library.start_mitm_proxy(record=True)

    def test_a_request_that_was_made_passes(self):
        self.record()
        self.library.request_should_have_been_made("/api/users")

    def test_a_request_that_was_not_made_fails(self):
        self.record(url="http://example.com/orders")
        with self.assertRaises(AssertionError) as context:
            self.library.request_should_have_been_made("/api/users")
        message = str(context.exception)
        self.assertIn("/api/users", message)
        # The whole value of the message is saying what happened instead.
        self.assertIn("/orders", message)

    def test_the_method_is_part_of_the_assertion(self):
        self.record(method="GET")
        with self.assertRaises(AssertionError):
            self.library.request_should_have_been_made("/api/users", method="POST")

    def test_an_exact_count_can_be_required(self):
        self.record()
        self.record()
        self.library.request_should_have_been_made("/api/users", times=2)
        with self.assertRaises(AssertionError) as context:
            self.library.request_should_have_been_made("/api/users", times=3)
        self.assertIn("exactly 3", str(context.exception))

    def test_a_custom_message_replaces_the_default(self):
        with self.assertRaises(AssertionError) as context:
            self.library.request_should_have_been_made("/api", msg="No call was made.")
        self.assertEqual(str(context.exception), "No call was made.")

    def test_asserting_a_request_was_not_made_passes_when_it_was_not(self):
        self.library.request_should_not_have_been_made("/api/telemetry")

    def test_asserting_a_request_was_not_made_fails_when_it_was(self):
        self.record()
        with self.assertRaises(AssertionError) as context:
            self.library.request_should_not_have_been_made("/api/users")
        self.assertIn("/api/users", str(context.exception))

    def test_a_custom_message_replaces_the_default_negative(self):
        self.record()
        with self.assertRaises(AssertionError) as context:
            self.library.request_should_not_have_been_made("/api", msg="Called anyway.")
        self.assertEqual(str(context.exception), "Called anyway.")

    def test_the_failure_message_mentions_dropped_requests(self):
        """An assertion against a shortened recording must not look complete."""
        self.library.start_recording(limit=2)
        for _ in range(5):
            self.record(url="http://example.com/orders")
        with self.assertRaises(AssertionError) as context:
            self.library.request_should_have_been_made("/api/users")
        self.assertIn("dropped", str(context.exception))


class TestWaitingKeyword(RecordingKeywordTestCase):
    def setUp(self):
        super().setUp()
        self.library.start_mitm_proxy(record=True)

    def test_waiting_returns_the_matching_requests(self):
        self.record()
        found = self.library.wait_until_request_is_made("/api/users", timeout="5s")
        self.assertEqual(len(found), 1)

    def test_waiting_accepts_robot_time_strings(self):
        with self.assertRaises(AssertionError):
            self.library.wait_until_request_is_made("/nothing", timeout="200 ms")

    def test_waiting_for_a_request_that_arrives_later(self):
        timer = threading.Timer(0.2, self.record)
        timer.start()
        self.addCleanup(timer.cancel)
        found = self.library.wait_until_request_is_made("/api/users", timeout="10s")
        self.assertEqual(len(found), 1)


if __name__ == "__main__":
    unittest.main()
