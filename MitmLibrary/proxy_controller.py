"""
This file defines the ProxyController class, which owns the lifetime of the mitmproxy
instance the library drives.

Everything that knows how to start, inspect and stop a mitmproxy `DumpMaster` lives here,
including the parts that reach into mitmproxy's internals because its public surface does
not expose them: the addresses the proxy is bound to, and closing the listening sockets on
shutdown. Keeping those in one module means a change in mitmproxy has a single place to
break, rather than being spread through the keyword definitions.
"""

import asyncio
import logging
import time
from concurrent.futures import Future, TimeoutError as FutureTimeoutError
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

from mitmproxy import options
from mitmproxy.proxy import mode_specs
from mitmproxy.tools import dump
from robot.api import logger

from MitmLibrary.async_loop_thread import AsyncLoopThread

STARTUP_TIMEOUT = 10
SHUTDOWN_TIMEOUT = 10
STARTUP_POLL_INTERVAL = 0.05

AddonFactory = Callable[[dump.DumpMaster], Sequence[Any]]


class StartupErrorCollector(logging.Handler):
    """Collects the error messages mitmproxy logs while the proxy is starting.

    mitmproxy reports bind failures through the logging module rather than by raising,
    so this is the only way to tell the user *why* the proxy did not start.

    It listens on the root logger, which means it also hears errors that have nothing to
    do with this proxy - a proxy stopped moments ago still logs from its own teardown,
    and so does the rest of the test run. Only records from mitmproxy are kept, and only
    those that report a failure to listen are treated as a reason to give up. Everything
    else is remembered for the failure message but does not, by itself, fail a startup
    that would otherwise have succeeded.
    """

    #: What mitmproxy says when it cannot bind, which is the failure worth acting on.
    BIND_FAILURE = "failed to listen"

    def __init__(self) -> None:
        super().__init__(level=logging.ERROR)
        self.messages: List[str] = []
        self.bind_failures: List[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        if not record.name.startswith("mitmproxy"):
            return
        message = record.getMessage()
        self.messages.append(message)
        if self.BIND_FAILURE in message:
            self.bind_failures.append(message)


class ProxyController:
    """Starts, inspects and stops the mitmproxy instance.

    The proxy runs on its own event loop in a background thread, so that starting it does
    not block the Robot Framework thread that called the keyword.
    """

    def __init__(self) -> None:
        self.master: Optional[dump.DumpMaster] = None
        self.future: Optional[Future] = None
        self.loop_handler: AsyncLoopThread = AsyncLoopThread()
        self.loop_handler.start()

    @property
    def is_running(self) -> bool:
        """Whether a proxy is currently started."""
        return self.master is not None

    def start(
        self,
        listen_host: str,
        listen_port: int,
        certificates_directory: Optional[str],
        ssl_insecure: bool,
        addon_factory: AddonFactory,
        mode: Optional[Union[str, Sequence[str]]] = None,
        proxy_auth: Optional[str] = None,
    ) -> None:
        """Starts the proxy and waits until it is actually listening.

        `addon_factory` is called with the master once it exists, and returns the addons to
        register before the proxy runs. Addons added afterwards would miss the first flows.

        Raises RuntimeError if the proxy cannot be started, for example when the port is
        already in use.
        """
        option_kwargs: Dict[str, Any] = {
            "listen_host": listen_host,
            "listen_port": listen_port,
            "ssl_insecure": ssl_insecure,
        }
        if certificates_directory is not None:
            option_kwargs["confdir"] = certificates_directory
        if mode is not None:
            option_kwargs["mode"] = self._parse_modes(mode)
        opts = options.Options(**option_kwargs)
        # Bind the master to the loop it will actually run on. Without this it binds
        # to whatever loop happens to be running on the calling thread, which is not
        # the loop that `run()` is scheduled on below.
        master = dump.DumpMaster(
            opts,
            loop=self.loop_handler.loop,
            with_termlog=False,
            with_dumper=False,
        )
        self.master = master
        if proxy_auth is not None:
            # proxyauth belongs to the addon of the same name, which registers it when
            # the master loads its addons, so it does not exist yet when the options are
            # built above.
            master.options.update(proxyauth=proxy_auth)
        self._disable_errorcheck(master)
        for addon in addon_factory(master):
            master.addons.add(addon)
        collector = StartupErrorCollector()
        logging.getLogger().addHandler(collector)
        try:
            self.future = asyncio.run_coroutine_threadsafe(
                master.run(), self.loop_handler.loop
            )
            self._fail_on_startup_error(
                listen_host, listen_port, collector, self.future, master
            )
        finally:
            logging.getLogger().removeHandler(collector)

    @staticmethod
    def _parse_modes(mode: Union[str, Sequence[str]]) -> List[str]:
        """Checks the mode specifications and returns them as mitmproxy wants them.

        Parsing here means an unusable specification fails the keyword that gave it,
        with mitmproxy's own explanation of what is wrong. Left to the proxy it would
        surface as a startup timeout with nothing useful attached, because mitmproxy
        logs the problem rather than raising it.
        """
        modes = [mode] if isinstance(mode, str) else list(mode)
        for spec in modes:
            try:
                mode_specs.ProxyMode.parse(spec)
            except ValueError as error:
                raise ValueError(
                    f"'{spec}' is not a usable proxy mode: {error}. Modes look like "
                    f"'regular', 'reverse:http://host:port', 'upstream:http://host:port', "
                    f"'transparent' or 'socks5', optionally followed by '@host:port'."
                ) from error
        return modes

    @staticmethod
    def _disable_errorcheck(master: dump.DumpMaster) -> None:
        """Removes mitmproxy's errorcheck addon, which is wrong for a library.

        The addon calls `sys.exit(1)` when anything logged an error while a master starts,
        which is right for the mitmproxy command line tools and wrong here. It watches the
        root logger, so the error can come from a proxy this library started earlier, or
        from anywhere else in the test run, and killing an unrelated proxy for it is not
        something a suite can act on - least of all as a SystemExit raised on the
        background loop thread. Startup failures are detected by `_fail_on_startup_error`
        instead, which reports what actually went wrong with this proxy.
        """
        errorcheck = master.addons.get("errorcheck")
        if errorcheck is None:  # pragma: no cover - always present in DumpMaster
            return
        master.addons.remove(errorcheck)
        # The addon installs a handler on the root logger in its constructor and only
        # uninstalls it on the startup path it no longer reaches.
        errorcheck.finish()

    def _fail_on_startup_error(
        self,
        listen_host: str,
        listen_port: int,
        collector: StartupErrorCollector,
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
                self.discard(wait=False)
                raise RuntimeError(
                    f"The proxy on {listen_host}:{listen_port} stopped immediately "
                    f"after starting: {error or 'no error reported'}"
                )
            if self.listen_addresses(proxy_master):
                return
            if collector.bind_failures:
                break
            time.sleep(STARTUP_POLL_INTERVAL)

        reported = "; ".join(
            collector.bind_failures or collector.messages
        ) or "no error reported"
        self.discard(wait=False)
        raise RuntimeError(
            f"Could not start the proxy on {listen_host}:{listen_port}: {reported}"
        )

    def add_addon(self, addon: Any) -> None:
        """Registers an addon with the running proxy.

        Used for addons a suite turns on after the proxy started, such as the recorder.
        Anything the proxy must never miss belongs in the factory passed to `start`.
        """
        if self.master is None:
            raise RuntimeError("No proxy is running.")
        self.master.addons.add(addon)

    def remove_addon(self, addon: Any) -> None:
        """Removes an addon from the running proxy, if it is still registered.

        The proxy may already have stopped, taking its addons with it, which is not a
        problem worth failing a keyword over.
        """
        if self.master is None:
            return
        try:
            self.master.addons.remove(addon)
        except Exception as error:  # pylint: disable=broad-exception-caught
            logger.info(f"The addon was already gone: {error}")

    def listen_addresses(
        self, proxy_master: Optional[dump.DumpMaster] = None
    ) -> List[Tuple[Any, ...]]:
        """Returns the addresses the proxy server addon is currently bound to.

        Reads them from mitmproxy rather than echoing back the requested host and port,
        because the two can differ: port 0 is resolved to a real port, and a mode spec
        can carry its own listening address.
        """
        master = proxy_master or self.master
        if master is None:
            return []
        proxyserver = master.addons.get("proxyserver")
        return list(proxyserver.listen_addrs()) if proxyserver else []

    def discard(self, wait: bool = True) -> None:
        """Shuts the proxy down and waits until it has actually finished.

        `Master.shutdown()` only signals the event loop; the listening socket is closed
        later, when `Master.run()` reaches its cleanup. Returning before that happens
        would leave the port occupied, so restarting the proxy on the same port fails.

        Pass `wait=False` for a proxy that never came up: there is no socket of ours to
        release, and a master stuck in a failed startup never completes its future.
        """
        if self.master is not None:
            if wait:
                self._close_servers()
            self.master.shutdown()
        if self.future is not None and wait:
            try:
                self.future.result(timeout=SHUTDOWN_TIMEOUT)
            except FutureTimeoutError:
                logger.warn(
                    f"The proxy did not shut down within {SHUTDOWN_TIMEOUT} seconds; "
                    f"its port may still be in use."
                )
            except Exception as error:  # pylint: disable=broad-exception-caught
                logger.info(f"The proxy stopped with an error: {error}")
        self._uninstall_log_handler()
        self.master = None
        self.future = None

    def _uninstall_log_handler(self) -> None:
        """Removes the root logger handler mitmproxy installed for this master.

        mitmproxy attaches a handler to the root logger that forwards every log record
        to the master's event loop. It never removes it, so once the proxy has stopped
        and its loop is closed, any later log record - from anywhere in the test run -
        raises "Event loop is closed" inside logging. Starting several proxies in one run
        leaves one such handler behind each time.
        """
        if self.master is None:
            return
        handler = getattr(self.master, "_legacy_log_events", None)
        if handler is None:  # pragma: no cover - present in every version we support
            return
        try:
            handler.uninstall()
        except Exception as error:  # pylint: disable=broad-exception-caught
            logger.info(f"Could not remove the mitmproxy log handler: {error}")

    def _close_servers(self) -> None:
        """Closes the listening sockets held by the proxyserver addon.

        The addon has no teardown hook of its own, and shutting the master down does not
        close its servers, so without this the port stays bound after the proxy stops.
        """
        if self.master is None:
            return
        proxyserver = self.master.addons.get("proxyserver")
        if proxyserver is None:
            return
        try:
            asyncio.run_coroutine_threadsafe(
                proxyserver.servers.update([]), self.loop_handler.loop
            ).result(timeout=SHUTDOWN_TIMEOUT)
        except Exception as error:  # pylint: disable=broad-exception-caught
            logger.warn(f"Could not close the proxy servers cleanly: {error}")

    def shutdown(self) -> None:
        """Stops the proxy, if any, and then the loop thread it ran on.

        Used when the library itself is going away, so the thread does not outlive it.
        """
        if self.master is not None:
            self.discard()
        self.loop_handler.stop()
