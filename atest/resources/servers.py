"""Helpers for the acceptance suite.

The suite used to hardcode ports 5000 and 8080 and to reach the public internet for its
only HTTPS coverage. Both made the suite fragile: fixed ports collide when suites run in
parallel, and a network dependency fails on an offline or sandboxed runner.
"""

import socket
import time
from urllib.error import URLError
from urllib.request import urlopen
import ssl


def get_free_port() -> int:
    """Returns a port that is free right now."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_until_server_is_up(url: str, timeout: int = 30) -> None:
    """Blocks until the given URL answers, so tests never race the server starting.

    Args:
        url: The URL to poll.
        timeout: How long to keep trying, in seconds.

    Raises:
        AssertionError: If the server did not come up in time.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            with urlopen(url, timeout=2, context=context):
                return
        except URLError as error:
            last_error = error
            time.sleep(0.2)
        except OSError as error:
            last_error = error
            time.sleep(0.2)
    raise AssertionError(f"{url} did not come up within {timeout}s: {last_error}")
