"""
This file defines the MitmLibrary class, the main entry point for interacting with the MitmProxy library within Robot Framework.

The MitmLibrary class provides a suite-scoped interface for:

* Starting and stopping the MitmProxy server.
* Configuring proxy behavior (e.g., blocking requests, modifying responses).
* Controlling console logging.

This library allows you to intercept and manipulate network traffic during your Robot Framework tests, enabling you to simulate various network conditions and test your applications in a more realistic and controlled environment.
"""

import asyncio
from typing import Dict, Optional

from mitmproxy import options
from mitmproxy.tools import dump
from robot.api import logger
from robot.api.deco import keyword, library, not_keyword

from MitmLibrary.async_loop_thread import AsyncLoopThread
from MitmLibrary.request_logger import RequestLogger
from MitmLibrary.version import VERSION


@library(scope="SUITE", version=VERSION, auto_keywords=True)
class MitmLibrary(object):
    """
    MitmLibrary is a Robot Framework library that integrates the mitmproxy package,
    enabling you to listen, intercept, and manipulate network traffic. With MitmLibrary,
    you can manipulate network traffic on a per-request level without the need for
    building stubs or mocks.

    = Why Use MitmLibrary? =
    MitmLibrary offers the following advantages:
    - Allows you to manipulate network traffic on a single browser instance using a proxy.
    - Eliminates the need to set up stubs or mocks that might affect the entire application.
    - Facilitates testing without the risk of using stubbed/mocked behavior during manual testing.

    == Examples of When to Use MitmLibrary ==
    MitmLibrary is particularly useful in the following scenarios:
    - Running tests in parallel when you want to avoid influencing other instances.
    - Manipulating responses of requests to assess how the frontend handles integrated services that are always up.
    - When stubs or mocks are not available yet or their behavior is insufficient.

    = Mitm Certificates =
    To test with SSL verification or use a browser without ignoring certificates, you need to set up
    certificates related to mitm. Follow the guide on the [https://docs.mitmproxy.org/stable/concepts-certificates/|Mitm website] for detailed instructions.

    == Example ==
    | Library    MitmLibrary

    | Example Test
    |     Start Mitm Proxy    0.0.0.0    8080    /path/to/certificates    False
    |     Add Response Delay    MyAlias    https://example.com/some/path    2s
    |     # Perform tests with manipulated network traffic
    |     Stop Mitm Proxy

    Use MitmLibrary to manipulate network traffic and assess how your system responds to different scenarios.

    == Keywords ==
    | MitmLibrary provides several keywords for controlling network traffic, including:
    | - Start Mitm Proxy
    | - Stop Mitm Proxy
    | - Add Response Delay
    | - ...

    Enjoy using MitmLibrary to enhance your network traffic testing capabilities in Robot Framework.
    """

    @not_keyword
    def __init__(self) -> None:
        """
        Initializes the MitmLibrary instance.

        This constructor initializes the proxy_master and request_logger instances used for managing the proxy server.
        """
        self.proxy_master: dump.DumpMaster = ""
        self.request_logger: RequestLogger = ""
        self.loop_handler: AsyncLoopThread = AsyncLoopThread()
        self.loop_handler.start()

    @keyword
    async def start_mitm_proxy(
        self,
        listen_host: str = "0.0.0.0",
        listen_port: int = 8080,
        certificates_directory: str = None,
        ssl_insecure: bool = False,
        log_to_console: bool = True,
    ) -> None:
        """
        Starts a proxy at the given host and port.

        - listen_host: Host to listen on. Default is '0.0.0.0'.
        - listen_port: Port to listen on. Default is 8080.
        - certificates_directory: Directory containing MITM certificates. See the 'Mitm Certificates' section for more information.
        - ssl_insecure: If True, SSL verification is disabled.

        Example:
        | Start Mitm Proxy    192.168.1.100    8888    /path/to/certificates    True

        See the 'Mitm Certificates' section in the documentation for more information.
        """
        self.log_to_console = log_to_console
        opts = options.Options(
            listen_host=listen_host,
            listen_port=listen_port,
            confdir=certificates_directory,
            ssl_insecure=ssl_insecure,
        )
        self.proxy_master = dump.DumpMaster(
            opts,
            with_termlog=False,
            with_dumper=False,
        )
        self.request_logger = RequestLogger(self.proxy_master, log_to_console)
        self.proxy_master.addons.add(self.request_logger)
        asyncio.run_coroutine_threadsafe(
            self.proxy_master.run(), self.loop_handler.loop
        )

    @keyword
    async def stop_mitm_proxy(self) -> None:
        """Stops the proxy."""
        self.proxy_master.shutdown()

    @keyword
    def add_to_blocklist(self, url: str) -> None:
        """
        Adds a (partial) url to the list of blocked urls. If the url is found in any part
        of the pretty_url of the host, it will be blocked.

        - `url` (str): The (partial) URL to add to the blocklist.
        """
        self.request_logger.add_to_blocklist(url)

    @keyword
    def add_custom_response(
        self,
        alias: str,
        url: str,
        overwrite_headers: Optional[Dict[str, str]] = None,
        overwrite_body: Optional[str] = None,
        status_code: int = 200,
    ) -> None:
        """
        Adds a custom response based on a (partial) url to the list of blocked urls.
        If the (partial) url is found in any part of the pretty_url of the host, its response will be changed.

        - `alias` (str): The alias for the custom response.
        - `url` (str): The (partial) URL that triggers the custom response.
        - `overwrite_headers` (Optional[Dict[str, str]]): Headers to overwrite in the response (default is None).
        - `overwrite_body` (Optional[str]): Body content to overwrite in the response (default is None).
        - `status_code` (int): The HTTP status code to return for matching URLs (default is 200).
        """
        self.request_logger.add_custom_response_item(
            alias, url, overwrite_headers, overwrite_body, status_code
        )

    @keyword
    def add_response_delay(self, alias: str, url: str, delay: str) -> None:
        """Add a response delay entry using Robot Framework syntax.

        - alias: The alias for the response delay entry.
        - url: The URL for which the response delay should be applied.
        - delay: The delay in seconds to be added for the specified URL.

        Example:
        | Add Response Delay   MyAlias   https://example.com/some/path   2s

        This keyword adds an entry to the list of response delay items using the provided alias, URL, and delay.
        """
        self.request_logger.add_response_delay_item(alias, url, delay)

    @keyword
    def add_custom_response_status_code(
        self, alias: str, url: str, status_code: int = 200
    ) -> None:
        """
        Adds a custom response status code to each request where the URL contains the (partial) URL of the custom status code.

        - alias: The alias for the custom response status code.
        - url: The (partial) URL that, when found in a request's URL, triggers the custom status code.
        - status_code: The HTTP status code to return for matching URLs.

        Often used status codes:
        - 200: Success
        - 401: Unauthorized
        - 403: Forbidden
        - 404: Not found
        - 418: I'm a Teapot
        - 500: Internal Server error

        For more information on HTTP status codes, visit: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status
        """
        self.request_logger.add_custom_response_status(alias, url, status_code)

    @keyword
    def clear_all_proxy_items(self) -> None:
        """Removes all custom responses, blocked urls, etc. Basically, this acts as
        restarting the proxy, without actually restarting the proxy."""
        self.request_logger.clear_all_proxy_items()

    @keyword
    def log_blocked_urls(self) -> None:
        """Logs the current list of items that will result in a block, if the url is
        found in the pretty_url of a host."""
        block_items = ", ".join(self.request_logger.block_list)
        logger.info(
            f"URLs containing any of the following in their url will "
            f"be blocked: {block_items}."
        )

    @keyword
    def log_delayed_responses(self) -> None:
        """
        Logs the URLs for which custom response delays are configured.

        This keyword logs the URLs that will result in a response delay when the URL is found
        in the request's URL. Response delays can be set using the 'Add Response Delay' keyword.

        Example:
        | Log Delayed Responses

        This will log all URLs for which custom response delays have been configured in the current test case.

        See 'Add Response Delay' for more information on how to configure response delays.
        """
        delayed_items = ", ".join(
            [response.url for response in self.request_logger.response_delays_list]
        )
        logger.info(
            f"URLs containing any of the following in their url will "
            f"be delayed: {delayed_items}."
        )

    @keyword
    def log_custom_response_items(self) -> None:
        """Logs the current list of urls that will result in a custom response, if the
        url is found in the pretty_url of a host.

        Will also log the custom response items themselves."""
        custom_responses = ", ".join(
            [response.url for response in self.request_logger.custom_response_list]
        )
        logger.info(
            f"The following custom responses are currently loaded: {custom_responses}."
        )
        for response in self.request_logger.custom_response_list:
            logger.info(f"{response}")

    @keyword
    def log_custom_status_items(self) -> None:
        """Logs the current list of urls that will result in a custom response, if the
        url is found in the pretty_url of a host.

        Will also log the custom response items themselves."""
        logger.info("The following custom responses are currently loaded: ")
        for custom_response in self.request_logger.custom_response_status:
            logger.info(
                f"Alias {custom_response.alias}: Url {custom_response.url} - Status code: {custom_response.status_code}."
            )

    @keyword
    def remove_url_from_blocklist(self, url: str) -> None:
        """Removes a custom (partial) url from the list."""
        self.request_logger.remove_from_blocklist(url)

    @keyword
    def remove_custom_response(self, alias: str) -> None:
        """Removes a custom response from the list, based on it's alias."""
        self.request_logger.remove_custom_response_item(alias)

    @keyword
    def remove_custom_status_code(self, alias: str) -> None:
        """Removes a custom status_code from the list."""
        self.request_logger.remove_custom_status(alias)

    @keyword
    def turn_mitm_console_logging_off(self) -> None:
        """Turns the console logging off whenever a request/response is manipulated by MITM"""
        self.request_logger.set_console_logging(False)

    @keyword
    def turn_mitm_console_logging_on(self) -> None:
        """Turns the console logging on whenever a request/response is manipulated by MITM."""
        self.request_logger.set_console_logging(True)
