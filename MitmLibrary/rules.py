"""
This file defines the rules the proxy applies, and the registry that holds them.

Before this, each kind of manipulation had its own list, its own remove keyword and its own
log keyword, and the blocklist had no alias at all. They now share one model: a rule is an
alias, something that decides whether it applies, and an action that does the work. That
gives every kind of rule the same matching options, one way to remove it, and one way to
list what is loaded.

The registry is read by the proxy on its own thread while keywords change it from the
thread running the tests, so it is guarded by a lock. Actions are frozen: only the
registry mutates a rule, and only its own bookkeeping.
"""

import asyncio
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any

from mitmproxy import http
from robot.api import logger
from robot.utils import DotDict, safe_str

from MitmLibrary.matching import UrlMatcher

UNLIMITED = 0


class Phase(Enum):
    """Which mitmproxy hook a rule runs in.

    The order matters when rules of both kinds are listed together: everything in the
    request hook happens before anything in the response hook, because the request has
    to be sent before there is an answer to change.
    """

    REQUEST = "request"
    RESPONSE = "response"

    @property
    def order(self) -> int:
        return 0 if self is Phase.REQUEST else 1


class Priority(IntEnum):
    """The order in which matching rules are applied within a phase.

    Lower runs first. The order is what makes combinations predictable: a rule that
    replaces a whole response has to run before one that changes a single header on it,
    or the header would be thrown away again.
    """

    TERMINAL = 0
    REPLACE = 1
    MUTATE = 2
    TIMING = 3


class BlockMode(Enum):
    """What a blocked request gets back.

    - `RESPOND`: answer with a status code, without contacting the server. The default,
      because every client reports it the same way.
    - `RESET`: drop the connection. Closer to a network failure, but each HTTP client
      surfaces it as a different exception, so a suite asserting on one is fragile.
    """

    RESPOND = "respond"
    RESET = "reset"


class Action:
    """What a rule does when it matches.

    Subclasses declare the phase they belong to and their priority within it, and
    implement `apply`. Returning True from a request-phase action means the flow is
    finished and no further rule should look at it.
    """

    phase: Phase = Phase.RESPONSE
    priority: Priority = Priority.MUTATE

    def apply(self, flow: http.HTTPFlow) -> bool:
        """Applies the action. Returns True when nothing else should touch the flow."""
        raise NotImplementedError

    async def apply_async(self, flow: http.HTTPFlow) -> bool:
        """Applies the action from an async hook. Overridden only by actions that wait."""
        return self.apply(flow)

    def describe(self) -> dict[str, Any]:
        """The action's settings, for `Get Proxy Rules` and the log."""
        raise NotImplementedError


@dataclass(frozen=True)
class BlockAction(Action):
    """Stops a request from reaching its destination."""

    mode: BlockMode = BlockMode.RESPOND
    status_code: int = 403
    body: str | None = None

    phase = Phase.REQUEST
    priority = Priority.TERMINAL

    def apply(self, flow: http.HTTPFlow) -> bool:
        if self.mode is BlockMode.RESET:
            kill_flow(flow)
            return True
        flow.response = http.Response.make(
            self.status_code, safe_str(self.body) if self.body is not None else b""
        )
        return True

    def describe(self) -> dict[str, Any]:
        described: dict[str, Any] = {"type": "block", "mode": self.mode.value}
        if self.mode is BlockMode.RESPOND:
            described["status_code"] = self.status_code
            described["body"] = self.body
        return described


@dataclass(frozen=True)
class ResponseAction(Action):
    """Replaces the whole response."""

    status_code: int = 200
    headers: dict[str, str] | None = None
    body: str | None = None

    phase = Phase.RESPONSE
    priority = Priority.REPLACE

    def apply(self, flow: http.HTTPFlow) -> bool:
        headers = self._headers(flow)
        content = self._content(flow)
        try:
            flow.response = http.Response.make(self.status_code, content, headers)
        except (TypeError, ValueError) as error:
            # logger.error has no 'also_console' argument; it already logs to console.
            logger.error(f"Replacing the response failed: {error}")
        return False

    def _headers(self, flow: http.HTTPFlow) -> http.Headers:
        """The headers to use, keeping the original ones when none were given."""
        if self.headers:
            return http.Headers(
                [
                    (key.encode("utf-8"), value.encode("utf-8"))
                    for key, value in self.headers.items()
                ]
            )
        if flow.response is not None:
            return flow.response.headers
        return http.Headers()

    def _content(self, flow: http.HTTPFlow) -> str | bytes:
        """The body to use, keeping the original one when none was given."""
        if self.body is not None:
            return safe_str(self.body)
        if flow.response is not None and flow.response.content is not None:
            return flow.response.content
        return b""

    def describe(self) -> dict[str, Any]:
        return {
            "type": "response",
            "status_code": self.status_code,
            "headers": self.headers,
            "body": self.body,
        }


@dataclass(frozen=True)
class StatusAction(Action):
    """Changes the status code of a response, leaving the rest of it alone."""

    status_code: int = 200

    phase = Phase.RESPONSE
    priority = Priority.MUTATE

    def apply(self, flow: http.HTTPFlow) -> bool:
        if flow.response is not None:
            flow.response.status_code = self.status_code
        return False

    def describe(self) -> dict[str, Any]:
        return {"type": "status", "status_code": self.status_code}


@dataclass(frozen=True)
class DelayAction(Action):
    """Holds a response back, to imitate a slow service."""

    seconds: float = 0.0
    delay: str = ""

    phase = Phase.RESPONSE
    priority = Priority.TIMING

    def apply(self, flow: http.HTTPFlow) -> bool:  # pragma: no cover - async path is used
        raise NotImplementedError("A delay can only be applied from the async hook.")

    async def apply_async(self, flow: http.HTTPFlow) -> bool:
        await asyncio.sleep(self.seconds)
        return False

    def describe(self) -> dict[str, Any]:
        return {"type": "delay", "delay": self.delay, "seconds": self.seconds}


@dataclass(frozen=True)
class HeadersAction(Action):
    """Sets and removes named headers, leaving the rest of them alone.

    Merging rather than replacing is what makes this useful next to `ResponseAction`:
    adding one header should not mean restating every other header the response had.
    """

    set_headers: dict[str, str] | None = None
    remove_headers: Sequence[str] | None = None

    phase = Phase.RESPONSE
    priority = Priority.MUTATE

    def _target(self, flow: http.HTTPFlow) -> http.Message | None:
        """The message this action edits."""
        return flow.response if self.phase is Phase.RESPONSE else flow.request

    def apply(self, flow: http.HTTPFlow) -> bool:
        message = self._target(flow)
        if message is None:
            return False
        for name in self.remove_headers or ():
            # Headers can repeat, and pop removes every one of them, which is what a
            # suite asking for a header to be gone means.
            message.headers.pop(name, None)
        for name, value in (self.set_headers or {}).items():
            message.headers[name] = value
        return False

    def describe(self) -> dict[str, Any]:
        return {
            "type": f"{self.phase.value}_headers",
            "headers": self.set_headers,
            "remove": list(self.remove_headers) if self.remove_headers else None,
        }


@dataclass(frozen=True)
class RequestHeadersAction(HeadersAction):
    """Sets and removes headers on the request before it is sent."""

    phase = Phase.REQUEST
    priority = Priority.MUTATE


@dataclass(frozen=True)
class BodyAction(Action):
    """Replaces the body, leaving the status and headers alone."""

    body: str = ""

    phase = Phase.RESPONSE
    priority = Priority.MUTATE

    def _target(self, flow: http.HTTPFlow) -> http.Message | None:
        return flow.response if self.phase is Phase.RESPONSE else flow.request

    def apply(self, flow: http.HTTPFlow) -> bool:
        message = self._target(flow)
        if message is None:
            return False
        # set_content recomputes content-length, which a body replacement needs: a
        # declared length that no longer matches makes the message unreadable.
        message.set_content(safe_str(self.body).encode("utf-8"))
        return False

    def describe(self) -> dict[str, Any]:
        return {"type": f"{self.phase.value}_body", "body": self.body}


@dataclass(frozen=True)
class RequestBodyAction(BodyAction):
    """Replaces the body of the request before it is sent."""

    phase = Phase.REQUEST
    priority = Priority.MUTATE


@dataclass(frozen=True)
class RewriteAction(Action):
    """Sends the request somewhere else entirely."""

    target: str = ""

    phase = Phase.REQUEST
    priority = Priority.MUTATE

    def apply(self, flow: http.HTTPFlow) -> bool:
        # mitmproxy's url setter updates the scheme, host, port and path together, and
        # rewrites the Host header with them, so the request stays consistent.
        flow.request.url = self.target
        return False

    def describe(self) -> dict[str, Any]:
        return {"type": "rewrite", "target": self.target}


@dataclass(frozen=True)
class RedirectAction(Action):
    """Sends the request to a different host, keeping its path and query."""

    host: str = ""
    port: int | None = None
    scheme: str | None = None

    phase = Phase.REQUEST
    priority = Priority.MUTATE

    def apply(self, flow: http.HTTPFlow) -> bool:
        request = flow.request
        if self.scheme is not None:
            request.scheme = self.scheme
        request.host = self.host
        if self.port is not None:
            request.port = self.port
        # The host header carries the original name, which the new host would not
        # recognise, and which mitmproxy only rewrites when the whole url is set.
        if request.host_header is not None:
            port = self.port if self.port is not None else request.port
            request.host_header = (
                self.host if _is_default_port(request.scheme, port) else f"{self.host}:{port}"
            )
        return False

    def describe(self) -> dict[str, Any]:
        return {
            "type": "redirect",
            "host": self.host,
            "port": self.port,
            "scheme": self.scheme,
        }


def _is_default_port(scheme: str, port: int) -> bool:
    """Whether the port is the one the scheme implies, and so left out of a host header."""
    return (scheme == "http" and port == 80) or (scheme == "https" and port == 443)


def kill_flow(flow: http.HTTPFlow) -> None:
    """Drops the connection, if mitmproxy still lets us.

    `kill()` raises when the flow is no longer killable, which happens when something else
    already killed it or it is no longer live. That is not a problem worth failing a test
    over: the request is not reaching its destination either way.
    """
    if not flow.killable:
        logger.info("The flow was already finished, so it could not be killed.")
        return
    flow.kill()


@dataclass
class Rule:
    """One piece of configured behaviour, addressed by its alias."""

    alias: str
    matcher: UrlMatcher
    action: Action
    times: int = UNLIMITED
    remaining: int = field(default=0, init=False)
    used: int = field(default=0, init=False)
    seq: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self.remaining = self.times

    @property
    def exhausted(self) -> bool:
        """Whether the rule has already been applied as often as it was allowed to."""
        return self.times != UNLIMITED and self.remaining <= 0

    def describe(self) -> DotDict:
        """A readable summary, returned by `Get Proxy Rules`."""
        described = DotDict(
            {
                "alias": self.alias,
                "url": self.matcher.pattern,
                "match": self.matcher.mode.value,
                "method": self.matcher.method,
                "times": self.times,
                "remaining": self.remaining,
                "used": self.used,
                "phase": self.action.phase.value,
            }
        )
        described.update(self.action.describe())
        return described


class RuleRegistry:
    """Holds the rules, keyed by alias, in the order they were added.

    Keywords change this from the thread running the tests while the proxy reads it from
    its own thread, so every access is guarded. Hooks take a snapshot and then work
    without the lock, so a rule that waits never holds it.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._rules: dict[str, Rule] = {}
        self._counter = 0

    def add(self, rule: Rule) -> bool:
        """Adds a rule, replacing any rule that already uses its alias.

        Returns True when an existing rule was replaced. An alias is the handle used to
        remove a rule again, so two rules sharing one would make removal ambiguous.
        """
        with self._lock:
            replaced = rule.alias in self._rules
            if replaced:
                # Keep the position of the rule being replaced, so that replacing a rule
                # does not quietly change the order in which rules are applied.
                rule.seq = self._rules[rule.alias].seq
            else:
                self._counter += 1
                rule.seq = self._counter
            self._rules[rule.alias] = rule
        return replaced

    def remove(self, alias: str) -> bool:
        """Removes a rule. Returns False when there was nothing to remove."""
        with self._lock:
            return self._rules.pop(alias, None) is not None

    def clear(self) -> None:
        """Removes every rule."""
        with self._lock:
            self._rules.clear()

    def get(self, alias: str) -> Rule | None:
        with self._lock:
            return self._rules.get(alias)

    def snapshot(self, phase: Phase | None = None) -> list[Rule]:
        """The rules for a phase, in the order they should be applied.

        A copy, so the proxy can work through it while a keyword adds or removes rules.
        """
        with self._lock:
            rules = [
                rule
                for rule in self._rules.values()
                if phase is None or rule.action.phase is phase
            ]
        return sorted(
            rules,
            key=lambda rule: (rule.action.phase.order, rule.action.priority, rule.seq),
        )

    def consume(self, rule: Rule) -> bool:
        """Claims one application of a rule. Returns False when it must not be applied.

        Called after a rule matched and before its action runs. Re-checking under the lock
        is what makes `times` exact: two requests arriving together cannot both claim the
        last application, and a rule that was removed or replaced since the snapshot does
        not fire at all.
        """
        with self._lock:
            if self._rules.get(rule.alias) is not rule:
                return False
            if rule.exhausted:
                return False
            if rule.times != UNLIMITED:
                rule.remaining -= 1
            rule.used += 1
            return True

    def describe(self) -> list[DotDict]:
        """Every rule, in application order, for `Get Proxy Rules`."""
        return [rule.describe() for rule in self.snapshot()]
