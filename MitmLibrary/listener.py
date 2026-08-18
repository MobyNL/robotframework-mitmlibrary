"""
This file defines the LibraryListener class, which releases the proxy when the suite that
started it ends.

The library is suite scoped, so a suite that starts a proxy and never calls
`Stop Mitm Proxy` - because a test failed, or because the teardown was simply forgotten -
would leave the port bound for the rest of the run, and the next suite that wants that port
fails for a reason that has nothing to do with it. Robot Framework calls `close()` on a
library listener when the library goes out of scope, which is exactly the moment to hand
the port back.
"""

from typing import TYPE_CHECKING

from robot.api import logger

if TYPE_CHECKING:  # pragma: no cover - imported for typing only, avoids a circular import
    from MitmLibrary.proxy_controller import ProxyController


class LibraryListener:
    """Stops the proxy and its loop thread when the library goes out of scope."""

    ROBOT_LISTENER_API_VERSION = 3

    def __init__(self, controller: "ProxyController") -> None:
        self.controller = controller

    def close(self) -> None:
        """Releases whatever the library still holds.

        Reports a proxy that was still running, because a suite relying on this rather
        than on `Stop Mitm Proxy` is usually a mistake worth seeing in the log. Stopping
        the loop thread is silent: it always needs doing, forgotten or not.
        """
        if self.controller.is_running:
            logger.info(
                "The suite ended while the proxy was still running; stopping it so its "
                "port is released. Call 'Stop Mitm Proxy' to do this explicitly."
            )
        self.controller.shutdown()
