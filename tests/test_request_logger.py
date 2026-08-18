import asyncio
import time
import unittest
from unittest.mock import Mock, patch

from mitmproxy import http
from robot.api import logger

from MitmLibrary.request_logger import (
    RequestLogger,  # Adjust the import based on the actual module structure
)


def make_flow(url, body=b"original", status_code=200, headers=None):
    """Builds a mock HTTPFlow with a real Response, as mitmproxy would hand us."""
    flow = Mock()
    flow.request.pretty_url = url
    flow.request.pretty_host = url
    flow.response = http.Response.make(
        status_code, body, headers or {"Content-Type": "text/plain"}
    )
    return flow


class TestRequestLogger(unittest.TestCase):
    def setUp(self):
        self.mock_master = Mock()
        self.req_logger = RequestLogger(self.mock_master)

    def test_add_to_blocklist(self):
        url = "http://example.com"
        self.req_logger.add_to_blocklist(url)
        self.assertIn(url, self.req_logger.block_list)

    def test_remove_from_blocklist(self):
        url = "http://example.com"
        self.req_logger.add_to_blocklist(url)
        self.req_logger.remove_from_blocklist(url)
        self.assertNotIn(url, self.req_logger.block_list)

    def test_add_custom_response_item(self):
        url = "http://example.com"
        response = {"status": 200, "body": "OK"}
        self.req_logger.add_custom_response_item(
            "alias", url, None, response["body"], response["status"]
        )
        self.assertEqual(self.req_logger.custom_response_list[0].url, url)

    def test_remove_custom_response_item(self):
        url = "http://example.com"
        self.req_logger.add_custom_response_item("alias", url, None, "OK", 200)
        self.req_logger.remove_custom_response_item("alias")
        self.assertNotIn(
            url,
            [item.url for item in self.req_logger.custom_response_list],
        )

    def test_remove_unknown_custom_response_item_warns(self):
        """An unknown alias must warn, not raise."""
        with patch.object(logger, "warn") as mock_warn:
            self.req_logger.remove_custom_response_item("does-not-exist")
        mock_warn.assert_called_once()

    def test_remove_unknown_custom_status_warns(self):
        """An unknown alias must warn, not raise."""
        with patch.object(logger, "warn") as mock_warn:
            self.req_logger.remove_custom_status("does-not-exist")
        mock_warn.assert_called_once()

    def test_remove_custom_status(self):
        self.req_logger.add_custom_response_status("alias", "http://example.com", 404)
        self.req_logger.remove_custom_status("alias")
        self.assertEqual(self.req_logger.custom_response_status, [])

    def test_add_response_delay_item(self):
        url = "http://example.com"
        delay = "2s"
        self.req_logger.add_response_delay_item("alias", url, delay)
        self.assertEqual(self.req_logger.response_delays_list[0].url, url)

    def test_clear_all_proxy_items(self):
        self.req_logger.add_to_blocklist("http://example.com")
        self.req_logger.add_custom_response_item(
            "alias", "http://example.com", None, "OK", 200
        )
        self.req_logger.add_custom_response_status("alias", "http://example.com", 404)
        self.req_logger.add_response_delay_item("alias", "http://example.com", "2s")
        self.req_logger.clear_all_proxy_items()
        self.assertEqual(len(self.req_logger.block_list), 0)
        self.assertEqual(len(self.req_logger.custom_response_list), 0)
        self.assertEqual(len(self.req_logger.custom_response_status), 0)
        self.assertEqual(len(self.req_logger.response_delays_list), 0)

    def test_cleared_items_no_longer_apply(self):
        """Clearing must leave no state behind that still matches a response."""
        url = "http://example.com/api"
        self.req_logger.add_custom_response_item("alias", url, None, "OK", 200)
        self.req_logger.add_custom_response_status("alias", url, 404)
        flow = make_flow(url)
        asyncio.run(self.req_logger.response(flow))
        self.req_logger.clear_all_proxy_items()

        untouched = make_flow(url)
        asyncio.run(self.req_logger.response(untouched))
        self.assertEqual(untouched.response.content, b"original")
        self.assertEqual(untouched.response.status_code, 200)

    def test_request_blocked(self):
        url = "http://example.com"
        self.req_logger.add_to_blocklist(url)
        flow = Mock()
        flow.request.pretty_url = url
        flow.request.pretty_host = url
        with (
            patch.object(flow, "kill") as mock_kill,
            patch.object(logger, "info") as mock_info,
        ):
            self.req_logger.request(flow)
            mock_kill.assert_called_once()
            mock_info.assert_called_once_with(
                f"Blocked request for {flow.request.pretty_url}",
                also_console=self.req_logger.log_to_console,
            )

    def test_request_blocked_on_path(self):
        """A blocklist entry matching only the path must still block."""
        flow = Mock()
        flow.request.pretty_url = "https://example.com/admin/panel"
        flow.request.pretty_host = "example.com"
        self.req_logger.add_to_blocklist("/admin")
        self.req_logger.request(flow)
        flow.kill.assert_called_once()

    def test_request_not_blocked_when_no_match(self):
        flow = Mock()
        flow.request.pretty_url = "https://example.com/public"
        flow.request.pretty_host = "example.com"
        self.req_logger.add_to_blocklist("other.com")
        self.req_logger.request(flow)
        flow.kill.assert_not_called()

    def test_request_killed_once_for_multiple_matches(self):
        flow = Mock()
        flow.request.pretty_url = "https://example.com/admin"
        flow.request.pretty_host = "example.com"
        self.req_logger.add_to_blocklist("example.com")
        self.req_logger.add_to_blocklist("/admin")
        self.req_logger.request(flow)
        flow.kill.assert_called_once()

    def test_response_customized(self):
        """A configured custom response is applied to a matching flow."""
        url = "http://example.com/api"
        self.req_logger.add_custom_response_item(
            alias="alias",
            url=url,
            overwrite_body="OK",
            status_code=201,
        )
        flow = make_flow(url)
        asyncio.run(self.req_logger.response(flow))
        self.assertEqual(flow.response.content, b"OK")
        self.assertEqual(flow.response.status_code, 201)

    def test_response_applies_custom_body(self):
        url = "http://example.com/api"
        self.req_logger.add_custom_response_item("alias", "/api", None, "replaced", 200)
        flow = make_flow(url)
        asyncio.run(self.req_logger.response(flow))
        self.assertEqual(flow.response.content, b"replaced")

    def test_response_without_body_keeps_original_body(self):
        """Headers-only custom responses must not overwrite the body."""
        url = "http://example.com/api"
        self.req_logger.add_custom_response_item(
            "alias", "/api", {"Content-Type": "application/json"}, None, 200
        )
        flow = make_flow(url)
        asyncio.run(self.req_logger.response(flow))
        self.assertEqual(flow.response.content, b"original")
        self.assertEqual(flow.response.headers["Content-Type"], "application/json")

    def test_response_without_headers_keeps_original_headers(self):
        url = "http://example.com/api"
        self.req_logger.add_custom_response_item("alias", "/api", None, "replaced", 201)
        flow = make_flow(url, headers={"X-Origin": "upstream"})
        asyncio.run(self.req_logger.response(flow))
        self.assertEqual(flow.response.headers["X-Origin"], "upstream")
        self.assertEqual(flow.response.status_code, 201)

    def test_response_applies_custom_status_code(self):
        url = "http://example.com/api"
        self.req_logger.add_custom_response_status("alias", "/api", 418)
        flow = make_flow(url)
        asyncio.run(self.req_logger.response(flow))
        self.assertEqual(flow.response.status_code, 418)

    def test_response_leaves_non_matching_url_untouched(self):
        self.req_logger.add_custom_response_item("alias", "/api", None, "replaced", 500)
        self.req_logger.add_custom_response_status("alias", "/api", 418)
        self.req_logger.add_response_delay_item("alias", "/api", "10s")
        flow = make_flow("http://example.com/other")
        asyncio.run(self.req_logger.response(flow))
        self.assertEqual(flow.response.content, b"original")
        self.assertEqual(flow.response.status_code, 200)

    def test_response_delay_is_applied(self):
        self.req_logger.add_response_delay_item("alias", "/api", "300ms")
        flow = make_flow("http://example.com/api")
        start = time.monotonic()
        asyncio.run(self.req_logger.response(flow))
        self.assertGreaterEqual(time.monotonic() - start, 0.3)

    def test_response_delay_does_not_block_the_event_loop(self):
        """The delay must yield to the loop so other flows keep being served."""
        self.req_logger.add_response_delay_item("alias", "/slow", "500ms")
        slow = make_flow("http://example.com/slow")
        fast = make_flow("http://example.com/fast")

        async def scenario():
            slow_task = asyncio.create_task(self.req_logger.response(slow))
            await asyncio.sleep(0)
            start = time.monotonic()
            await self.req_logger.response(fast)
            elapsed = time.monotonic() - start
            await slow_task
            return elapsed

        self.assertLess(asyncio.run(scenario()), 0.2)

    def test_response_does_not_accumulate_state(self):
        """Repeated responses must not grow any internal list (memory leak guard)."""
        self.req_logger.add_custom_response_item("alias", "/api", None, "replaced", 200)
        self.req_logger.add_custom_response_status("alias", "/api", 418)
        self.req_logger.add_response_delay_item("alias", "/nope", "1s")

        def list_sizes():
            return {
                name: len(value)
                for name, value in vars(self.req_logger).items()
                if isinstance(value, list)
            }

        before = list_sizes()
        for _ in range(100):
            asyncio.run(self.req_logger.response(make_flow("http://example.com/api")))
        self.assertEqual(list_sizes(), before)

    def test_remove_unknown_url_from_blocklist_warns(self):
        with patch.object(logger, "warn") as mock_warn:
            self.req_logger.remove_from_blocklist("never-added.com")
        mock_warn.assert_called_once()

    def test_failure_to_build_response_is_logged_not_raised(self):
        """logger.error takes no 'also_console' argument; passing one raises TypeError."""
        self.req_logger.add_custom_response_item("alias", "/api", None, "body", 200)
        flow = make_flow("http://example.com/api")
        with (
            patch.object(http.Response, "make", side_effect=ValueError("boom")),
            patch.object(logger, "error") as mock_error,
        ):
            asyncio.run(self.req_logger.response(flow))
        mock_error.assert_called_once()
        self.assertEqual(mock_error.call_args.kwargs, {})
        self.assertIn("boom", mock_error.call_args.args[0])

    def test_custom_response_without_original_response(self):
        """A flow that has no response yet must not blow up on the header/body fallbacks."""
        self.req_logger.add_custom_response_item("alias", "/api", None, None, 204)
        flow = Mock()
        flow.request.pretty_url = "http://example.com/api"
        flow.response = None
        asyncio.run(self.req_logger.response(flow))
        self.assertEqual(flow.response.status_code, 204)
        self.assertEqual(flow.response.content, b"")

    def test_invalid_delay_fails_when_added(self):
        """An unusable delay must fail the keyword, not a later request."""
        with self.assertRaises(ValueError):
            self.req_logger.add_response_delay_item("alias", "/api", "not-a-delay")
        self.assertEqual(self.req_logger.response_delays_list, [])

    def test_delay_is_converted_once_when_added(self):
        self.req_logger.add_response_delay_item("alias", "/api", "1.5s")
        self.assertEqual(self.req_logger.response_delays_list[0].delay_in_seconds, 1.5)

    def test_reusing_a_custom_response_alias_replaces_the_entry(self):
        self.req_logger.add_custom_response_item("same", "/first", None, "one", 200)
        self.req_logger.add_custom_response_item("same", "/second", None, "two", 201)
        self.assertEqual(len(self.req_logger.custom_response_list), 1)
        self.assertEqual(self.req_logger.custom_response_list[0].url, "/second")
        self.req_logger.remove_custom_response_item("same")
        self.assertEqual(self.req_logger.custom_response_list, [])

    def test_reusing_a_status_alias_replaces_the_entry(self):
        self.req_logger.add_custom_response_status("same", "/first", 404)
        self.req_logger.add_custom_response_status("same", "/second", 418)
        self.assertEqual(len(self.req_logger.custom_response_status), 1)
        self.assertEqual(self.req_logger.custom_response_status[0].status_code, 418)

    def test_reusing_a_delay_alias_replaces_the_entry(self):
        self.req_logger.add_response_delay_item("same", "/first", "1s")
        self.req_logger.add_response_delay_item("same", "/second", "2s")
        self.assertEqual(len(self.req_logger.response_delays_list), 1)
        self.assertEqual(self.req_logger.response_delays_list[0].url, "/second")

    def test_log_warning(self):
        self.req_logger.set_console_logging(True)
        self.assertTrue(self.req_logger.log_to_console)
        self.req_logger.set_console_logging(False)
        self.assertFalse(self.req_logger.log_to_console)
