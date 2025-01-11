"""
This file defines the RequestLogger class, which is a core component of MitmLibrary.

The RequestLogger class is responsible for intercepting and modifying HTTP requests and responses using the mitmproxy library. It provides various functionalities to manipulate network traffic during Robot Framework test execution.

Here's a breakdown of the key functionalities offered by RequestLogger:

* **Blocking Requests:** URLs can be added to a blocklist, causing the RequestLogger to block those requests with a 403 Forbidden response.
* **Modifying Responses:** Custom responses can be configured to modify the response body, headers, or status code for specific URLs.
* **Delaying Responses:** Responses can be delayed for a specified duration to simulate network latency or test application behavior under slow network conditions.

By leveraging these functionalities, MitmLibrary empowers you to control network traffic and create realistic testing scenarios within your Robot Framework tests.
"""

from time import sleep as time_sleep
from typing import List

from mitmproxy import http
from mitmproxy.tools import dump
from robot.api import logger
from robot.utils import DotDict, safe_str, timestr_to_secs


class RequestLogger:
    """
    This class handles the interception and modification of HTTP requests and responses
    using the mitmproxy library.

    Attributes:
        master: The mitmproxy DumpMaster instance.
        log_to_console: A boolean flag indicating whether to log messages to the console.
        block_list: A list of URLs to block.
        custom_response_list: A list of custom response configurations.
        custom_response_status: A list of custom response status code configurations.
        response_delays_list: A list of response delay configurations.
    """

    def __init__(self, master: dump.DumpMaster, log_to_console: bool = True) -> None:
        """
        Initializes the RequestLogger instance.

        Args:
            master: The mitmproxy DumpMaster instance.
            log_to_console: A boolean flag indicating whether to log messages to the console.
                          Defaults to True.
        """
        self.master = master
        self.log_to_console = log_to_console
        self.block_list: List[str] = []
        self.custom_response_list: List[DotDict] = []
        self.custom_response_status: List[DotDict] = []
        self.response_delays_list: List[DotDict] = []
        self.custom_status_urls: List[str] = []
        self.custom_response_urls: List[str] = []
        self.delay_response_urls: List[str] = []

    def request(self, flow: http.HTTPFlow) -> None:
        """
        Handles the request event.

        This method checks if the requested URL is in the blocklist.
        If it is, the request is blocked with a 403 Forbidden response.

        Args:
            flow: The HTTPFlow object representing the request.
        """
        if any(url in flow.request.pretty_url for url in self.block_list):
            for url in self.block_list:
                if url in flow.request.pretty_host:
                    flow.kill()
                    logger.info(
                        f"Blocked request for {flow.request.pretty_url}",
                        also_console=self.log_to_console,
                    )

    def response(self, flow: http.HTTPFlow) -> None:
        """
        Handles the response event.

        This method checks if the requested URL matches any of the
        configured custom responses or custom status codes.
        If a match is found, the response is modified accordingly.

        Args:
            flow: The HTTPFlow object representing the request and response.
        """
        self.custom_status_urls.extend(
            status.url for status in self.custom_response_status
        )
        self.custom_response_urls.extend(
            response.url for response in self.custom_response_list
        )
        self.delay_response_urls.extend(
            response.url for response in self.response_delays_list
        )

        if any(url in flow.request.pretty_url for url in self.custom_response_urls):
            for custom_response in self.custom_response_list:
                if custom_response.url in flow.request.pretty_url:
                    self.update_request_with_custom_response(flow, custom_response)

        if any(url in flow.request.pretty_url for url in self.custom_status_urls):
            for custom_status in self.custom_response_status:
                logger.info(
                    f"Updating status code for {custom_status.url} to {custom_status.status_code}",
                    also_console=self.log_to_console,
                )
                if custom_status.url in flow.request.pretty_url:
                    flow.response.status_code = custom_status.status_code

        if any(url in flow.request.pretty_url for url in self.delay_response_urls):
            for response_delay in self.response_delays_list:
                if response_delay.url in flow.request.pretty_url:
                    logger.info(
                        f"Delaying response for {response_delay.url} for "
                        f"{response_delay.delay} seconds",
                        also_console=self.log_to_console,
                    )
                    time_sleep(timestr_to_secs(response_delay.delay))

    def add_to_blocklist(self, url: str) -> None:
        """
        Adds the given URL to the blocklist.

        Args:
            url: The URL to block.
        """
        self.block_list.append(url)

    def add_response_delay_item(self, alias: str, url: str, delay: str) -> None:
        """
        Adds a response delay item to the response_delays_list.

        Args:
            alias: A unique alias for this response delay.
            url: The URL to match for applying the response delay.
            delay: The delay in seconds (can be a string like "1.5s").
        """
        self.response_delays_list.append(
            DotDict({"alias": alias, "url": url, "delay": delay})
        )

    def clear_all_proxy_items(self) -> None:
        """
        Clears all proxy items, including blocklist, custom responses (both status and list), and response delays.
        """
        self.block_list.clear()
        self.custom_response_list.clear()
        self.custom_response_status.clear()
        self.response_delays_list.clear()

    def remove_from_blocklist(self, url: str) -> None:
        """
        Removes the given URL from the blocklist.

        Args:
            url: The URL to remove from the blocklist.
        """
        try:
            self.block_list.remove(url)
        except ValueError:
            logger.warn(f"{url} was not found in blocklist")

    def add_custom_response_item(
        self,
        alias: str,
        url: str,
        overwrite_headers=None,
        overwrite_body=None,
        status_code: int = 200,
    ) -> None:
        """
        Adds a custom response item to the custom_response_list.

        Args:
            alias: A unique alias for this custom response.
            url: The URL to match for applying the custom response.
            overwrite_headers: A dictionary of headers to overwrite in the response.
            overwrite_body: The custom response body to use.
            status_code: The HTTP status code to return in the response. Defaults to 200.
        """
        self.custom_response_list.append(
            DotDict(
                {
                    "alias": alias,
                    "url": url,
                    "headers": overwrite_headers,
                    "body": overwrite_body,
                    "status_code": status_code,
                }
            )
        )

    def remove_custom_response_item(self, alias: str) -> None:
        """
        Removes a custom response item based on its alias.

        Args:
            alias: The alias of the custom response to remove.
        """
        try:
            alias_index = next(
                (
                    index
                    for (index, d) in enumerate(self.custom_response_list)
                    if d["alias"] == alias
                ),
                None,
            )
            url_to_remove = self.custom_response_list[alias_index].url
            self.custom_response_list.pop(alias_index)
            self.custom_response_urls.remove(url_to_remove)
        except (ValueError, IndexError):
            logger.warn(f"Custom response with alias '{alias}' not found.")

    def update_request_with_custom_response(
        self, flow: http.HTTPFlow, custom_response: DotDict
    ) -> None:
        """
        Updates the flow's response with the given custom response details.

        Args:
            flow: The HTTPFlow object representing the request and response.
            custom_response: A DotDict containing the custom response details.
        """
        logger.info(
            f"Trying to update response for {custom_response.url}",
            also_console=self.log_to_console,
        )
        if custom_response.headers:
            header_list = []
            for key, value in custom_response.headers.items():
                logger.info(key, also_console=self.log_to_console)
                header_list.append((bytes(key, "utf-8"), bytes(value, "utf-8")))
            headers = http.Headers(header_list)
        elif hasattr(flow, "headers"):
            headers = flow["headers"]
        else:
            headers = http.Headers()
        try:
            flow.response = http.Response.make(
                custom_response.status_code, safe_str(custom_response.body), headers
            )
            logger.info(
                f"Succesfully updated response for {custom_response.url}",
                also_console=self.log_to_console,
            )
        except Exception as e:  # Catch specific exceptions for better error handling
            logger.error(
                f"Updating response for {custom_response.url} failed: {e}",
                also_console=self.log_to_console,
            )

    def add_custom_response_status(
        self, alias: str, url: str, status_code: int
    ) -> None:
        """
        Adds a custom response status code for requests matching the given URL.

        Args:
            alias: A unique alias for this custom response.
            url: The URL to match for applying the custom response.
            status_code: The HTTP status code to return in the response.
        """
        self.custom_response_status.append(
            DotDict({"alias": alias, "url": url, "status_code": status_code})
        )

    def remove_custom_status(self, alias: str) -> None:
        """
        Removes the custom response status code with the given alias.

        Args:
            alias: The alias of the custom response to remove.
        """
        try:
            alias_index = next(
                (
                    index
                    for (index, d) in enumerate(self.custom_response_status)
                    if d["alias"] == alias
                ),
                None,
            )
            self.custom_response_status.pop(alias_index)
        except ValueError:
            logger.error(f"Custom response status with alias '{alias}' not found.")

    def set_console_logging(self, value: bool) -> None:
        """
        Enables or disables console logging.

        Args:
            value: True to enable console logging, False to disable.
        """
        self.log_to_console = value
