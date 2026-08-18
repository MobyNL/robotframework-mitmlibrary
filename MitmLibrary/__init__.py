"""
This file defines the MitmLibrary class, the main entry point for interacting with the MitmProxy library within Robot Framework.

The MitmLibrary class provides a suite-scoped interface for:

* Starting and stopping the MitmProxy server.
* Configuring proxy behavior (e.g., blocking requests, modifying responses).
* Controlling console logging.

This library allows you to intercept and manipulate network traffic during your Robot
Framework tests, enabling you to simulate various network conditions and test your
applications in a more realistic and controlled environment.
"""

import asyncio
import logging
import time
from concurrent.futures import Future, TimeoutError as FutureTimeoutError
from typing import Any, Dict, List, Optional

from mitmproxy import options
from mitmproxy.tools import dump
from robot.api import logger
from robot.api.deco import keyword, library, not_keyword

from MitmLibrary.async_loop_thread import AsyncLoopThread
from MitmLibrary.request_logger import RequestLogger
from MitmLibrary.version import VERSION

STARTUP_TIMEOUT = 10
SHUTDOWN_TIMEOUT = 10
STARTUP_POLL_INTERVAL = 0.05


class StartupErrorCollector(logging.Handler):
    """Collects the error messages mitmproxy logs while the proxy is starting.

    mitmproxy reports bind failures through the logging module rather than by raising,
    so this is the only way to tell the user *why* the proxy did not start.
    """

    def __init__(self) -> None:
        super().__init__(level=logging.ERROR)
        self.messages: List[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


@library(scope="SUITE", version=VERSION, auto_keywords=True)
class MitmLibrary:
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
    certificates related to mitm. Follow the guide on the
    [https://docs.mitmproxy.org/stable/concepts-certificates/|Mitm website] for detailed instructions.

    == Example ==
    | Library    MitmLibrary

    | Example Test
    |     Start Mitm Proxy    127.0.0.1    8080    /path/to/certificates    False
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
        self.proxy_master: Optional[dump.DumpMaster] = None
        self.request_logger: Optional[RequestLogger] = None
        self.proxy_future: Optional[Future] = None
        self.log_to_console: bool = True
        self.loop_handler: AsyncLoopThread = AsyncLoopThread()
        self.loop_handler.start()

    @not_keyword
    def _require_proxy(self) -> RequestLogger:
        """Returns the active request logger, or raises a readable error."""
        if self.request_logger is None:
            raise RuntimeError(
                "No proxy is running. Call 'Start Mitm Proxy' before this keyword."
            )
        return self.request_logger

    @keyword
    def start_mitm_proxy(
        self,
        listen_host: str = "127.0.0.1",
        listen_port: int = 8080,
        certificates_directory: Optional[str] = None,
        ssl_insecure: bool = False,
        log_to_console: bool = True,
    ) -> None:
        """
        Starts a proxy at the given host and port.

        - listen_host: Host to listen on. Default is '127.0.0.1'. Use '0.0.0.0' only when
          the proxy must be reachable from other machines or containers - it exposes an
          intercepting proxy on every network interface.
        - listen_port: Port to listen on. Default is 8080.
        - certificates_directory: Directory containing MITM certificates. When omitted,
          mitmproxy's own default (`~/.mitmproxy`) is used.
          See the 'Mitm Certificates' section for more information.
        - ssl_insecure: If True, SSL verification is disabled.
        - log_to_console: If True, manipulated requests/responses are also logged to the console.

        Fails if the proxy cannot be started, for example when the port is already in use.

        Example:
        | Start Mitm Proxy    192.168.1.100    8888    /path/to/certificates    True

        See the 'Mitm Certificates' section in the documentation for more information.
        """
        self.log_to_console = log_to_console
        option_kwargs: Dict[str, Any] = {
            "listen_host": listen_host,
            "listen_port": listen_port,
            "ssl_insecure": ssl_insecure,
        }
        if certificates_directory is not None:
            option_kwargs["confdir"] = certificates_directory
        opts = options.Options(**option_kwargs)
        # Bind the master to the loop it will actually run on. Without this it binds
        # to whatever loop happens to be running on the calling thread, which is not
        # the loop that `run()` is scheduled on below.
        self.proxy_master = dump.DumpMaster(
            opts,
            loop=self.loop_handler.loop,
            with_termlog=False,
            with_dumper=False,
        )
        self.request_logger = RequestLogger(self.proxy_master, log_to_console)
        self.proxy_master.addons.add(self.request_logger)
        collector = StartupErrorCollector()
        logging.getLogger().addHandler(collector)
        try:
            self.proxy_future = asyncio.run_coroutine_threadsafe(
                self.proxy_master.run(), self.loop_handler.loop
            )
            self._fail_on_startup_error(
                listen_host, listen_port, collector, self.proxy_future, self.proxy_master
            )
        finally:
            logging.getLogger().removeHandler(collector)

    @not_keyword
    def _fail_on_startup_error(
        self,
        listen_host: str,
        listen_port: int,
        collector: "StartupErrorCollector",
        proxy_future: Future,
        proxy_master: dump.DumpMaster,
    ) -> None:
        """Raises if the proxy did not manage to bind its listening address.

        mitmproxy does not propagate bind failures out of `run()`: it logs the error and
        keeps the master alive with no listening address, and `run_coroutine_threadsafe`
        hides the failure as well. Without this check a suite would run green against a
        proxy that never came up.
        """
        deadline = time.monotonic() + STARTUP_TIMEOUT
        while time.monotonic() < deadline:
            if proxy_future.done():
                error = proxy_future.exception()
                self._discard_proxy(wait=False)
                raise RuntimeError(
                    f"The proxy on {listen_host}:{listen_port} stopped immediately "
                    f"after starting: {error or 'no error reported'}"
                )
            if self._listening_addresses(proxy_master):
                return
            if collector.messages:
                break
            time.sleep(STARTUP_POLL_INTERVAL)

        reported = "; ".join(collector.messages) or "no error reported"
        self._discard_proxy(wait=False)
        raise RuntimeError(
            f"Could not start the proxy on {listen_host}:{listen_port}: {reported}"
        )

    @not_keyword
    def _listening_addresses(self, proxy_master: Optional[dump.DumpMaster] = None) -> list:
        """Returns the addresses the proxy server addon is currently bound to."""
        master = proxy_master or self.proxy_master
        if master is None:
            return []
        proxyserver = master.addons.get("proxyserver")
        return proxyserver.listen_addrs() if proxyserver else []

    @not_keyword
    def _discard_proxy(self, wait: bool = True) -> None:
        """Shuts the proxy down and waits until it has actually finished.

        `Master.shutdown()` only signals the event loop; the listening socket is closed
        later, when `Master.run()` reaches its cleanup. Returning before that happens
        would leave the port occupied, so restarting the proxy on the same port fails.

        Pass `wait=False` for a proxy that never came up: there is no socket of ours to
        release, and a master stuck in a failed startup never completes its future.
        """
        if self.proxy_master is not None:
            if wait:
                self._close_servers()
            self.proxy_master.shutdown()
        if self.proxy_future is not None and wait:
            try:
                self.proxy_future.result(timeout=SHUTDOWN_TIMEOUT)
            except FutureTimeoutError:
                logger.warn(
                    f"The proxy did not shut down within {SHUTDOWN_TIMEOUT} seconds; "
                    f"its port may still be in use."
                )
            except Exception as error:  # pylint: disable=broad-exception-caught
                logger.info(f"The proxy stopped with an error: {error}")
        self.proxy_master = None
        self.request_logger = None
        self.proxy_future = None

    @not_keyword
    def _close_servers(self) -> None:
        """Closes the listening sockets held by the proxyserver addon.

        The addon has no teardown hook of its own, and shutting the master down does not
        close its servers, so without this the port stays bound after the proxy stops.
        """
        if self.proxy_master is None:
            return
        proxyserver = self.proxy_master.addons.get("proxyserver")
        if proxyserver is None:
            return
        try:
            asyncio.run_coroutine_threadsafe(
                proxyserver.servers.update([]), self.loop_handler.loop
            ).result(timeout=SHUTDOWN_TIMEOUT)
        except Exception as error:  # pylint: disable=broad-exception-caught
            logger.warn(f"Could not close the proxy servers cleanly: {error}")

    @keyword
    def stop_mitm_proxy(self) -> None:
        """Stops the proxy and waits for it to release its port.

        Does nothing when no proxy is running."""
        if self.proxy_master is None:
            logger.info("No proxy is running, nothing to stop.")
            return
        self._discard_proxy()

    @keyword
    def add_to_blocklist(self, url: str) -> None:
        """
        Adds a (partial) url to the list of blocked urls. If the url is found in any part
        of the pretty_url of the host, it will be blocked.

        - `url` (str): The (partial) URL to add to the blocklist.
        """
        self._require_proxy().add_to_blocklist(url)

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

        - `alias` (str): The alias for the custom response. Reusing an alias replaces
          the entry that already uses it.
        - `url` (str): The (partial) URL that triggers the custom response.
        - `overwrite_headers` (Optional[Dict[str, str]]): Headers to overwrite in the response (default is None).
        - `overwrite_body` (Optional[str]): Body content to overwrite in the response (default is None).
        - `status_code` (int): The HTTP status code to return for matching URLs (default is 200).
        """
        self._require_proxy().add_custom_response_item(
            alias, url, overwrite_headers, overwrite_body, status_code
        )

    @keyword
    def add_response_delay(self, alias: str, url: str, delay: str) -> None:
        """Add a response delay entry using Robot Framework syntax.

        - alias: The alias for the response delay entry.
        - url: The URL for which the response delay should be applied.
        - delay: The delay to be added for the specified URL, in Robot Framework time
          format (e.g. ``2``, ``1.5s``, ``500 ms``, ``1 min``).

        Fails immediately if the delay is not a valid time string.

        Adding a second entry with an alias that is already in use replaces the first one.

        Example:
        | Add Response Delay   MyAlias   https://example.com/some/path   2s

        This keyword adds an entry to the list of response delay items using the provided alias, URL, and delay.
        """
        self._require_proxy().add_response_delay_item(alias, url, delay)

    @keyword
    def add_custom_response_status_code(
        self, alias: str, url: str, status_code: int = 200
    ) -> None:
        """
        Adds a custom response status code to each request where the URL contains the (partial) URL of the custom status code.

        - alias: The alias for the custom response status code. Reusing an alias
          replaces the entry that already uses it.
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
        self._require_proxy().add_custom_response_status(alias, url, status_code)

    @keyword
    def clear_all_proxy_items(self) -> None:
        """Removes all custom responses, blocked urls, etc. Basically, this acts as
        restarting the proxy, without actually restarting the proxy."""
        self._require_proxy().clear_all_proxy_items()

    @keyword
    def log_blocked_urls(self) -> None:
        """Logs the current list of items that will result in a block, if the url is
        found in the pretty_url of a host."""
        block_items = ", ".join(self._require_proxy().block_list)
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
            [response.url for response in self._require_proxy().response_delays_list]
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
        request_logger = self._require_proxy()
        custom_responses = ", ".join(
            [response.url for response in request_logger.custom_response_list]
        )
        logger.info(
            f"The following custom responses are currently loaded: {custom_responses}."
        )
        for response in request_logger.custom_response_list:
            logger.info(f"{response}")

    @keyword
    def log_custom_status_items(self) -> None:
        """Logs the current list of urls that will result in a custom response, if the
        url is found in the pretty_url of a host.

        Will also log the custom response items themselves."""
        logger.info("The following custom responses are currently loaded: ")
        for custom_response in self._require_proxy().custom_response_status:
            logger.info(
                f"Alias {custom_response.alias}: Url {custom_response.url} - Status code: {custom_response.status_code}."
            )

    @keyword
    def remove_url_from_blocklist(self, url: str) -> None:
        """Removes a custom (partial) url from the list."""
        self._require_proxy().remove_from_blocklist(url)

    @keyword
    def remove_custom_response(self, alias: str) -> None:
        """Removes a custom response from the list, based on it's alias."""
        self._require_proxy().remove_custom_response_item(alias)

    @keyword
    def remove_custom_status_code(self, alias: str) -> None:
        """Removes a custom status_code from the list."""
        self._require_proxy().remove_custom_status(alias)

    @keyword
    def turn_mitm_console_logging_off(self) -> None:
        """Turns the console logging off whenever a request/response is manipulated by MITM"""
        self._set_console_logging(False)

    @keyword
    def turn_mitm_console_logging_on(self) -> None:
        """Turns the console logging on whenever a request/response is manipulated by MITM."""
        self._set_console_logging(True)

    @not_keyword
    def _set_console_logging(self, value: bool) -> None:
        """Stores the console logging preference and applies it to a running proxy."""
        self.log_to_console = value
        if self.request_logger is not None:
            self.request_logger.set_console_logging(value)
