"""
This file defines the RequestLogger class, which is a core component of MitmLibrary.

The RequestLogger class is responsible for intercepting and modifying HTTP requests and
responses using the mitmproxy library. It provides various functionalities to manipulate
network traffic during Robot Framework test execution.

Here's a breakdown of the key functionalities offered by RequestLogger:

* **Blocking Requests:** URLs can be added to a blocklist, causing the RequestLogger to block those requests with a 403 Forbidden response.
* **Modifying Responses:** Custom responses can be configured to modify the response body, headers, or status code for specific URLs.
* **Delaying Responses:** Responses can be delayed for a specified duration to simulate
  network latency or test application behavior under slow network conditions.

By leveraging these functionalities, MitmLibrary empowers you to control network traffic
and create realistic testing scenarios within your Robot Framework tests.
"""

import asyncio
from typing import Dict, List, Optional, Union

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

    def request(self, flow: http.HTTPFlow) -> None:
        """
        Handles the request event.

        This method checks if the requested URL is in the blocklist.
        If it is, the request is blocked with a 403 Forbidden response.

        Args:
            flow: The HTTPFlow object representing the request.
        """
        for url in self.block_list:
            if url in flow.request.pretty_url:
                flow.kill()
                logger.info(
                    f"Blocked request for {flow.request.pretty_url}",
                    also_console=self.log_to_console,
                )
                break

    async def response(self, flow: http.HTTPFlow) -> None:
        """
        Handles the response event.

        This method checks if the requested URL matches any of the
        configured custom responses or custom status codes.
        If a match is found, the response is modified accordingly.

        Args:
            flow: The HTTPFlow object representing the request and response.
        """
        pretty_url = flow.request.pretty_url

        for custom_response in self.custom_response_list:
            if custom_response.url in pretty_url:
                self.update_request_with_custom_response(flow, custom_response)

        for custom_status in self.custom_response_status:
            if custom_status.url in pretty_url and flow.response is not None:
                logger.info(
                    f"Updating status code for {custom_status.url} to {custom_status.status_code}",
                    also_console=self.log_to_console,
                )
                flow.response.status_code = custom_status.status_code

        for response_delay in self.response_delays_list:
            if response_delay.url in pretty_url:
                logger.info(
                    f"Delaying response for {response_delay.url} for "
                    f"{response_delay.delay} seconds",
                    also_console=self.log_to_console,
                )
                await asyncio.sleep(response_delay.delay_in_seconds)

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

        The delay is converted here rather than while handling a response, so that an
        invalid value fails this call instead of failing later inside the proxy, far
        away from the keyword that caused it.

        Args:
            alias: A unique alias for this response delay.
            url: The URL to match for applying the response delay.
            delay: The delay, in Robot Framework time format (e.g. ``2``, ``1.5s``,
                ``500 ms``, ``1 min``).

        Raises:
            ValueError: If the delay is not a valid Robot Framework time string.
        """
        self._add_item(
            self.response_delays_list,
            DotDict(
                {
                    "alias": alias,
                    "url": url,
                    "delay": delay,
                    "delay_in_seconds": timestr_to_secs(delay),
                }
            ),
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
        overwrite_headers: Optional[Dict[str, str]] = None,
        overwrite_body: Optional[str] = None,
        status_code: int = 200,
    ) -> None:
        """
        Adds a custom response item to the custom_response_list.

        Args:
            alias: A unique alias for this custom response. Adding a second item with
                the same alias replaces the first one.
            url: The URL to match for applying the custom response.
            overwrite_headers: A dictionary of headers to overwrite in the response.
            overwrite_body: The custom response body to use. When None, the original
                response body is kept.
            status_code: The HTTP status code to return in the response. Defaults to 200.
        """
        self._add_item(
            self.custom_response_list,
            DotDict(
                {
                    "alias": alias,
                    "url": url,
                    "headers": overwrite_headers,
                    "body": overwrite_body,
                    "status_code": status_code,
                }
            ),
        )

    def remove_custom_response_item(self, alias: str) -> None:
        """
        Removes a custom response item based on its alias.

        Args:
            alias: The alias of the custom response to remove.
        """
        alias_index = self._find_alias_index(self.custom_response_list, alias)
        if alias_index is None:
            logger.warn(f"Custom response with alias '{alias}' not found.")
            return
        self.custom_response_list.pop(alias_index)

    def update_request_with_custom_response(
        self, flow: http.HTTPFlow, custom_response: DotDict
    ) -> None:
        """
        Updates the flow's response with the given custom response details.

        Headers and body are only replaced when the custom response actually defines
        them; otherwise the values of the original response are kept.

        Args:
            flow: The HTTPFlow object representing the request and response.
            custom_response: A DotDict containing the custom response details.
        """
        logger.info(
            f"Trying to update response for {custom_response.url}",
            also_console=self.log_to_console,
        )
        headers = self._resolve_headers(flow, custom_response)
        content = self._resolve_content(flow, custom_response)
        try:
            flow.response = http.Response.make(
                custom_response.status_code, content, headers
            )
            logger.info(
                f"Succesfully updated response for {custom_response.url}",
                also_console=self.log_to_console,
            )
        except (TypeError, ValueError) as error:
            # logger.error has no 'also_console' argument; it already logs to console.
            logger.error(
                f"Updating response for {custom_response.url} failed: {error}"
            )

    def _resolve_headers(
        self, flow: http.HTTPFlow, custom_response: DotDict
    ) -> http.Headers:
        """Returns the headers to use, preferring the custom ones when given."""
        if custom_response.headers:
            header_list = []
            for key, value in custom_response.headers.items():
                logger.info(key, also_console=self.log_to_console)
                header_list.append((bytes(key, "utf-8"), bytes(value, "utf-8")))
            return http.Headers(header_list)
        if flow.response is not None:
            return flow.response.headers
        return http.Headers()

    @staticmethod
    def _resolve_content(flow: http.HTTPFlow, custom_response: DotDict) -> Union[str, bytes]:
        """Returns the body to use, keeping the original one when none is given."""
        if custom_response.body is not None:
            return safe_str(custom_response.body)
        if flow.response is not None and flow.response.content is not None:
            return flow.response.content
        return b""

    def _add_item(self, items: List[DotDict], item: DotDict) -> None:
        """Adds an item, replacing any existing item that uses the same alias.

        An alias is the handle used to remove an item again, so allowing two items to
        share one would make removal ambiguous.
        """
        existing_index = self._find_alias_index(items, item.alias)
        if existing_index is None:
            items.append(item)
            return
        logger.info(
            f"Replacing the existing item with alias '{item.alias}'.",
            also_console=self.log_to_console,
        )
        items[existing_index] = item

    @staticmethod
    def _find_alias_index(items: List[DotDict], alias: str) -> Optional[int]:
        """Returns the index of the first item with the given alias, or None."""
        return next(
            (index for index, item in enumerate(items) if item["alias"] == alias),
            None,
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
        self._add_item(
            self.custom_response_status,
            DotDict({"alias": alias, "url": url, "status_code": status_code}),
        )

    def remove_custom_status(self, alias: str) -> None:
        """
        Removes the custom response status code with the given alias.

        Args:
            alias: The alias of the custom response to remove.
        """
        alias_index = self._find_alias_index(self.custom_response_status, alias)
        if alias_index is None:
            logger.warn(f"Custom response status with alias '{alias}' not found.")
            return
        self.custom_response_status.pop(alias_index)

    def set_console_logging(self, value: bool) -> None:
        """
        Enables or disables console logging.

        Args:
            value: True to enable console logging, False to disable.
        """
        self.log_to_console = value
