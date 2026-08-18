"""Tests for the recorder that remembers the traffic passing through the proxy."""

import threading
import time
import unittest

from mitmproxy.test import tflow, tutils

from MitmLibrary.matching import MatchMode, UrlMatcher
from MitmLibrary.recorder import FlowRecorder


def make_flow(
    url="http://example.com/api/users",
    method="GET",
    status_code=200,
    request_body=b"",
    response_body=b"answer",
    with_response=True,
):
    """A real HTTPFlow, addressed at the given url."""
    flow = tflow.tflow(
        req=tutils.treq(method=method, content=request_body),
        resp=(
            tutils.tresp(status_code=status_code, content=response_body)
            if with_response
            else False
        ),
    )
    flow.request.url = url
    return flow


class TestRecording(unittest.TestCase):
    def setUp(self):
        self.recorder = FlowRecorder()

    def test_a_request_is_recorded_with_what_a_test_might_assert_on(self):
        flow = make_flow(
            url="http://example.com/api/users?page=2",
            method="POST",
            status_code=201,
            request_body=b"sent",
            response_body=b"received",
        )
        self.recorder.response(flow)
        entry = self.recorder.entries()[0]
        self.assertEqual(entry.method, "POST")
        self.assertEqual(entry.url, "http://example.com/api/users?page=2")
        self.assertEqual(entry.host, "example.com")
        self.assertEqual(entry.path, "/api/users?page=2")
        self.assertEqual(entry.query, {"page": "2"})
        self.assertEqual(entry.request_body, "sent")
        self.assertEqual(entry.status_code, 201)
        self.assertEqual(entry.response_body, "received")

    def test_requests_are_returned_oldest_first(self):
        self.recorder.response(make_flow(url="http://example.com/first"))
        self.recorder.response(make_flow(url="http://example.com/second"))
        self.assertEqual(
            [entry.path for entry in self.recorder.entries()], ["/first", "/second"]
        )

    def test_a_failed_request_is_recorded_too(self):
        """A blocked request never gets a response, and is exactly what a test asks about."""
        flow = make_flow(with_response=False)
        flow.error = tflow.terr("killed")
        self.recorder.error(flow)
        entry = self.recorder.entries()[0]
        self.assertIsNone(entry.status_code)
        self.assertIn("killed", entry.error)

    def test_the_recorded_request_does_not_change_with_the_flow(self):
        """The flow keeps being used; a recorded request has to stay as it was."""
        flow = make_flow(response_body=b"original")
        self.recorder.response(flow)
        flow.response.content = b"changed afterwards"
        self.assertEqual(self.recorder.entries()[0].response_body, "original")

    def test_clearing_forgets_everything(self):
        self.recorder.response(make_flow())
        self.recorder.clear()
        self.assertEqual(self.recorder.entries(), [])


class TestLimits(unittest.TestCase):
    def test_the_oldest_request_is_dropped_when_full(self):
        recorder = FlowRecorder(limit=2)
        for path in ("first", "second", "third"):
            recorder.response(make_flow(url=f"http://example.com/{path}"))
        self.assertEqual(
            [entry.path for entry in recorder.entries()], ["/second", "/third"]
        )

    def test_dropped_requests_are_counted(self):
        """A suite that recorded more than it kept must be told, not quietly shortchanged."""
        recorder = FlowRecorder(limit=2)
        for _ in range(5):
            recorder.response(make_flow())
        self.assertEqual(recorder.dropped, 3)
        self.assertIn("3 were dropped", recorder.summary())

    def test_the_dropped_count_is_reset_by_clearing(self):
        recorder = FlowRecorder(limit=1)
        recorder.response(make_flow())
        recorder.response(make_flow())
        recorder.clear()
        self.assertEqual(recorder.dropped, 0)

    def test_a_long_body_is_shortened_and_says_so(self):
        recorder = FlowRecorder(body_limit=4)
        recorder.response(
            make_flow(request_body=b"much longer", response_body=b"also longer")
        )
        entry = recorder.entries()[0]
        self.assertEqual(entry.request_body, "much")
        self.assertTrue(entry.request_body_truncated)
        self.assertEqual(entry.response_body, "also")
        self.assertTrue(entry.response_body_truncated)

    def test_a_short_body_is_kept_whole(self):
        recorder = FlowRecorder(body_limit=100)
        recorder.response(make_flow(response_body=b"short"))
        entry = recorder.entries()[0]
        self.assertEqual(entry.response_body, "short")
        self.assertFalse(entry.response_body_truncated)

    def test_a_body_that_is_not_text_does_not_break_recording(self):
        recorder = FlowRecorder()
        recorder.response(make_flow(response_body=b"\xff\xfe binary"))
        self.assertIn("binary", recorder.entries()[0].response_body)

    def test_stats_report_what_was_kept(self):
        recorder = FlowRecorder(limit=2)
        for _ in range(3):
            recorder.response(make_flow())
        self.assertEqual(recorder.stats(), {"recorded": 2, "dropped": 1, "limit": 2})


class TestFiltering(unittest.TestCase):
    def setUp(self):
        self.recorder = FlowRecorder()
        self.recorder.response(make_flow(url="http://example.com/api/users", method="GET"))
        self.recorder.response(make_flow(url="http://example.com/api/users", method="POST"))
        self.recorder.response(make_flow(url="http://example.com/orders", method="GET"))

    def test_filtering_by_url(self):
        matcher = UrlMatcher("/api/users")
        self.assertEqual(self.recorder.count(matcher), 2)

    def test_filtering_by_method(self):
        matcher = UrlMatcher("", method="POST")
        self.assertEqual(self.recorder.count(matcher), 1)

    def test_filtering_by_url_and_method(self):
        matcher = UrlMatcher("/api/users", method="GET")
        self.assertEqual(self.recorder.count(matcher), 1)

    def test_filtering_with_a_regex(self):
        matcher = UrlMatcher(r"/api/\w+", MatchMode.REGEX)
        self.assertEqual(self.recorder.count(matcher), 2)

    def test_an_empty_pattern_matches_everything(self):
        """Leaving the url out of a recording keyword means all of them."""
        self.assertEqual(self.recorder.count(UrlMatcher("")), 3)

    def test_no_matcher_returns_everything(self):
        self.assertEqual(self.recorder.count(), 3)


class TestWaiting(unittest.TestCase):
    def setUp(self):
        self.recorder = FlowRecorder()

    def test_a_request_already_recorded_returns_at_once(self):
        self.recorder.response(make_flow())
        started = time.monotonic()
        found = self.recorder.wait_for(UrlMatcher("/api/users"), timeout=5)
        self.assertEqual(len(found), 1)
        self.assertLess(time.monotonic() - started, 0.5)

    def test_waiting_returns_as_soon_as_the_request_arrives(self):
        """A condition variable, not a poll: the wait must not outlast the request."""
        timer = threading.Timer(0.2, lambda: self.recorder.response(make_flow()))
        timer.start()
        self.addCleanup(timer.cancel)
        started = time.monotonic()
        found = self.recorder.wait_for(UrlMatcher("/api/users"), timeout=10)
        elapsed = time.monotonic() - started
        self.assertEqual(len(found), 1)
        self.assertLess(elapsed, 5)
        self.assertGreater(elapsed, 0.1)

    def test_waiting_for_several_requests(self):
        def record_two():
            self.recorder.response(make_flow())
            self.recorder.response(make_flow())

        timer = threading.Timer(0.1, record_two)
        timer.start()
        self.addCleanup(timer.cancel)
        found = self.recorder.wait_for(UrlMatcher("/api/users"), timeout=10, count=2)
        self.assertEqual(len(found), 2)

    def test_waiting_too_long_fails_with_what_was_recorded(self):
        self.recorder.response(make_flow(url="http://example.com/orders"))
        with self.assertRaises(AssertionError) as context:
            self.recorder.wait_for(UrlMatcher("/api/users"), timeout=0.2)
        message = str(context.exception)
        self.assertIn("/api/users", message)
        self.assertIn("/orders", message)

    def test_the_failure_is_an_assertion_error(self):
        """Robot Framework reports an AssertionError as a failure, not as an error."""
        with self.assertRaises(AssertionError):
            self.recorder.wait_for(UrlMatcher("/nothing"), timeout=0.1)

    def test_waiting_with_nothing_recorded_says_so(self):
        with self.assertRaises(AssertionError) as context:
            self.recorder.wait_for(UrlMatcher("/api"), timeout=0.1)
        self.assertIn("Nothing was recorded", str(context.exception))


class TestThreadSafety(unittest.TestCase):
    def test_recording_from_several_threads_keeps_every_request(self):
        """The proxy records from its own thread while keywords read from another."""
        recorder = FlowRecorder(limit=1000)
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            for _ in range(50):
                recorder.response(make_flow())

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(recorder.count(), 400)

    def test_reading_while_recording_does_not_fail(self):
        recorder = FlowRecorder(limit=100)
        stop = threading.Event()

        def record():
            while not stop.is_set():
                recorder.response(make_flow())

        writer = threading.Thread(target=record)
        writer.start()
        self.addCleanup(writer.join, 5)
        try:
            for _ in range(200):
                recorder.entries(UrlMatcher("/api"))
        finally:
            stop.set()


if __name__ == "__main__":
    unittest.main()
