import unittest
from unittest.mock import Mock, patch

from robot.api import logger

from MitmLibrary.request_logger import (
    RequestLogger,  # Adjust the import based on the actual module structure
)


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
        self.req_logger.add_response_delay_item("alias", "http://example.com", "2s")
        self.req_logger.clear_all_proxy_items()
        self.assertEqual(len(self.req_logger.block_list), 0)
        self.assertEqual(len(self.req_logger.custom_response_list), 0)
        self.assertEqual(len(self.req_logger.response_delays_list), 0)

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

    def test_response_customized(self):
        url = "http://example.com"
        response = {
            "alias": "alias",
            "url": url,
            "headers": None,
            "status_code": 200,
            "body": "OK",
        }
        self.req_logger.add_custom_response_item(
            alias=response["alias"],
            url=response["url"],
            overwrite_body=response["body"],
            status_code=response["status_code"],
        )
        flow = Mock()
        flow.request.pretty_url = url
        self.assertEqual(self.req_logger.custom_response_list[0], response)

    def test_log_warning(self):
        self.req_logger.set_console_logging(True)
        self.assertTrue(self.req_logger.log_to_console)
        self.req_logger.set_console_logging(False)
        self.assertFalse(self.req_logger.log_to_console)
