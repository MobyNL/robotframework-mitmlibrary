import unittest
from unittest.mock import Mock

from request_logger import (
    RequestLogger,  # Adjust the import based on the actual module structure
)
from robot.api import logger


class TestRequestLogger(unittest.TestCase):
    def setUp(self):
        self.mock_master = Mock()
        self.logger = RequestLogger(self.mock_master)

    def test_add_to_blocklist(self):
        url = "http://example.com"
        self.logger.add_to_blocklist(url)
        self.assertIn(url, self.logger.block_list)

    def test_remove_from_blocklist(self):
        url = "http://example.com"
        self.logger.add_to_blocklist(url)
        self.logger.remove_from_blocklist(url)
        self.assertNotIn(url, self.logger.block_list)

    def test_add_custom_response_item(self):
        url = "http://example.com"
        response = {"status": 200, "body": "OK"}
        self.logger.add_custom_response_item(
            "alias", url, None, response["body"], response["status"]
        )
        self.assertEqual(self.logger.custom_response_list[0].url, url)

    def test_remove_custom_response_item(self):
        url = "http://example.com"
        self.logger.add_custom_response_item("alias", url, None, "OK", 200)
        self.logger.remove_custom_response_item("alias")
        self.assertNotIn(url, [item.url for item in self.logger.custom_response_list])

    def test_add_response_delay_item(self):
        url = "http://example.com"
        delay = "2s"
        self.logger.add_response_delay_item("alias", url, delay)
        self.assertEqual(self.logger.response_delays_list[0].url, url)

    def test_clear_all_proxy_items(self):
        self.logger.add_to_blocklist("http://example.com")
        self.logger.add_custom_response_item(
            "alias", "http://example.com", None, "OK", 200
        )
        self.logger.add_response_delay_item("alias", "http://example.com", "2s")
        self.logger.clear_all_proxy_items()
        self.assertEqual(len(self.logger.block_list), 0)
        self.assertEqual(len(self.logger.custom_response_list), 0)
        self.assertEqual(len(self.logger.response_delays_list), 0)

    def test_request_blocked(self):
        url = "http://example.com"
        self.logger.add_to_blocklist(url)
        flow = Mock()
        flow.request.pretty_url = url
        flow.request.pretty_host = url
        self.logger.request(flow)
        flow.kill.assert_called_once()

    def test_response_customized(self):
        url = "http://example.com"
        response = {"status": 200, "body": "OK"}
        self.logger.add_custom_response_item(
            "alias", url, None, response["body"], response["status"]
        )
        flow = Mock()
        flow.request.pretty_url = url
        self.assertEqual(flow.response.status_code, response["status"])

    def test_log_warning(self):
        with self.assertLogs("robot.api", level="WARNING") as cm:
            self.logger.set_console_logging(True)
            logger.warn("This is a warning")
            self.assertTrue(
                any("This is a warning" in message for message in cm.output)
            )


if __name__ == "__main__":
    unittest.main()
