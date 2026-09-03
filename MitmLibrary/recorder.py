"""
This file defines the recorder, which remembers the traffic that passed through the proxy.

Until now the library could change traffic but never report on it: every flow was thrown
away once the rules had been applied, so a suite could fake a response but could not assert
what the application actually sent. The recorder keeps what went past, so a test can ask.

Recording is off unless a suite turns it on, and what it keeps is capped in two directions:
a maximum number of requests, and a maximum body size per request. A test run can be long
and a body can be large, and neither should quietly turn into unbounded memory.

The proxy appends from its own thread while keywords read from the thread running the
tests, so everything here is guarded. Waiting for a request uses a condition variable
rather than polling, so `Wait Until Request Is Made` returns the moment the request
arrives instead of at the end of its next poll.
"""

import threading
import time
from collections import deque
from typing import Any

from mitmproxy import http
from robot.utils import DotDict

from MitmLibrary.matching import UrlMatcher

DEFAULT_LIMIT = 1000
DEFAULT_BODY_LIMIT = 65536


def _decode(content: bytes | None, limit: int) -> Any:
    """Returns the body as text, shortened to the limit, and whether it was shortened."""
    if content is None:
        return None, False
    truncated = len(content) > limit
    kept = content[:limit] if truncated else content
    return kept.decode("utf-8", errors="replace"), truncated


class FlowRecorder:
    """A mitmproxy addon that remembers the requests that passed through.

    Holds at most `limit` requests; once full, the oldest is dropped to make room. The
    number dropped is counted, so a suite that recorded more than it kept can be told
    rather than quietly given an incomplete answer.
    """

    def __init__(
        self, limit: int = DEFAULT_LIMIT, body_limit: int = DEFAULT_BODY_LIMIT
    ) -> None:
        self.limit = limit
        self.body_limit = body_limit
        self._lock = threading.Lock()
        self._new_entry = threading.Condition(self._lock)
        self._entries: deque[DotDict] = deque(maxlen=limit)
        self._dropped = 0

    @property
    def dropped(self) -> int:
        """How many recorded requests were dropped because the limit was reached."""
        with self._lock:
            return self._dropped

    def response(self, flow: http.HTTPFlow) -> None:
        """Records a request that got an answer."""
        self._record(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        """Records a request that failed, so a blocked request is visible too."""
        self._record(flow)

    def _record(self, flow: http.HTTPFlow) -> None:
        """Stores what a flow tells us, and wakes anything waiting for it."""
        entry = self._describe(flow)
        with self._new_entry:
            if len(self._entries) == self._entries.maxlen:
                self._dropped += 1
            self._entries.append(entry)
            self._new_entry.notify_all()

    def _describe(self, flow: http.HTTPFlow) -> DotDict:
        """Copies out of the flow everything a test might assert on.

        Copied rather than referenced: the flow keeps being used after this returns, and
        a recorded request has to stay the way it was when it passed.
        """
        request = flow.request
        request_body, request_truncated = _decode(request.content, self.body_limit)
        response_body, response_truncated = _decode(
            flow.response.content if flow.response is not None else None,
            self.body_limit,
        )
        started = getattr(request, "timestamp_start", None) or time.time()
        ended = (
            getattr(flow.response, "timestamp_end", None)
            if flow.response is not None
            else None
        )
        return DotDict(
            {
                "method": request.method,
                "url": request.pretty_url,
                "host": request.pretty_host,
                "path": request.path,
                "query": dict(request.query),
                "request_headers": dict(request.headers),
                "request_body": request_body,
                "request_body_truncated": request_truncated,
                "status_code": (
                    flow.response.status_code if flow.response is not None else None
                ),
                "response_headers": (
                    dict(flow.response.headers) if flow.response is not None else {}
                ),
                "response_body": response_body,
                "response_body_truncated": response_truncated,
                "started": started,
                "ended": ended,
                "duration": (ended - started) if ended and started else None,
                "error": str(flow.error) if flow.error is not None else None,
            }
        )

    def entries(self, matcher: UrlMatcher | None = None) -> list[DotDict]:
        """The recorded requests, oldest first, optionally only the matching ones."""
        with self._lock:
            recorded = list(self._entries)
        if matcher is None:
            return recorded
        return [entry for entry in recorded if matcher.matches(entry.url, entry.method)]

    def count(self, matcher: UrlMatcher | None = None) -> int:
        """How many recorded requests match."""
        return len(self.entries(matcher))

    def clear(self) -> None:
        """Forgets everything recorded so far, including the dropped count."""
        with self._lock:
            self._entries.clear()
            self._dropped = 0

    def wait_for(
        self, matcher: UrlMatcher, timeout: float, count: int = 1
    ) -> list[DotDict]:
        """Waits until at least `count` recorded requests match, and returns them.

        Raises AssertionError when the timeout passes first, so Robot Framework reports it
        as a failed test rather than as an error in the library.
        """
        deadline = time.monotonic() + timeout
        with self._new_entry:
            while True:
                matching = [
                    entry
                    for entry in self._entries
                    if matcher.matches(entry.url, entry.method)
                ]
                if len(matching) >= count:
                    return matching
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AssertionError(
                        f"Waited {timeout} seconds for {count} request(s) matching "
                        f"{matcher.describe()}, but {len(matching)} were made. "
                        f"{self._summary_locked()}"
                    )
                self._new_entry.wait(remaining)

    def summary(self) -> str:
        """A short description of what was recorded, for a failure message."""
        with self._lock:
            return self._summary_locked()

    def _summary_locked(self) -> str:
        """The same, for callers that already hold the lock."""
        if not self._entries:
            return "Nothing was recorded."
        listed = ", ".join(
            f"{entry.method} {entry.url}" for entry in list(self._entries)[-10:]
        )
        described = f"Recorded {len(self._entries)} request(s); the most recent are: {listed}."
        if self._dropped:
            described += (
                f" A further {self._dropped} were dropped, because more than "
                f"{self.limit} were recorded."
            )
        return described

    def stats(self) -> dict[str, int]:
        """How much was recorded and how much was dropped."""
        with self._lock:
            return {
                "recorded": len(self._entries),
                "dropped": self._dropped,
                "limit": self.limit,
            }
