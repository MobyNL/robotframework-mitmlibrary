"""
This file defines the rules that break traffic on purpose.

Blocking a request answers it, cleanly and immediately. These do the opposite: they make a
request fail the way a real network fails, so a suite can see what the application under
test does when a service hangs or an answer arrives half-finished. Those paths are usually
the least exercised and the most likely to be wrong.

They live apart from the other rules because they are the most version-sensitive part of
the library: each one depends on a mitmproxy behaviour that is documented but not promised,
and if one has to be reverted it should be possible to do that without touching the model
everything else is built on.
"""

import asyncio
from dataclasses import dataclass
from typing import Any

from mitmproxy import http
from robot.api import logger

from MitmLibrary.rules import Action, kill_flow, Phase, Priority


@dataclass(frozen=True)
class TimeoutAction(Action):
    """Holds a request and then drops it, so the client runs into its own timeout.

    The request is never sent, so the service is not involved at all: this is what a
    client sees when a service accepts a connection and then says nothing. Holding rather
    than answering is the point - an application that handles a 504 correctly may still
    hang forever when nothing arrives.
    """

    hold_seconds: float = 60.0
    hold: str = ""

    phase = Phase.REQUEST
    priority = Priority.TERMINAL

    def apply(self, flow: http.HTTPFlow) -> bool:  # pragma: no cover - async path is used
        raise NotImplementedError("A timeout can only be applied from the async hook.")

    async def apply_async(self, flow: http.HTTPFlow) -> bool:
        await asyncio.sleep(self.hold_seconds)
        kill_flow(flow)
        return True

    def describe(self) -> dict[str, Any]:
        return {"type": "timeout", "hold": self.hold, "hold_seconds": self.hold_seconds}


@dataclass(frozen=True)
class TruncateAction(Action):
    """Cuts a response short while it still claims to be the full length.

    The `content-length` header keeps saying how long the body was meant to be, so a
    client reads it, waits for the rest, and eventually gives up. That mismatch is the
    fault being injected, which is why the body is replaced through `raw_content`:
    `set_content` would helpfully correct the header and there would be nothing wrong
    with the response at all.
    """

    keep_bytes: int | None = None
    keep_fraction: float = 0.5

    phase = Phase.RESPONSE
    priority = Priority.MUTATE

    def apply(self, flow: http.HTTPFlow) -> bool:
        if flow.response is None:
            return False
        body = flow.response.raw_content
        if body is None:
            # A streamed response has no body to cut here, and a 204 or 304 has none at
            # all. Saying so beats a rule that silently did nothing.
            logger.info("There was no body to truncate, so the response is unchanged.")
            return False
        keep = self._keep(len(body))
        if keep >= len(body):
            logger.info(
                f"The body is {len(body)} bytes, which is not longer than the "
                f"{keep} bytes to keep, so the response is unchanged."
            )
            return False
        flow.response.raw_content = body[:keep]
        return False

    def _keep(self, length: int) -> int:
        """How many bytes to keep, from either a count or a fraction of the body."""
        if self.keep_bytes is not None:
            return max(0, self.keep_bytes)
        return max(0, int(length * self.keep_fraction))

    def describe(self) -> dict[str, Any]:
        return {
            "type": "truncate",
            "keep_bytes": self.keep_bytes,
            "keep_fraction": self.keep_fraction,
        }
