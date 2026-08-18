"""
This file defines the Interceptor, the mitmproxy addon that applies the configured rules.

mitmproxy calls `request` before a request leaves for its destination and `response` once
an answer came back. Both do the same thing: take the rules for that phase, apply the ones
that match, and stop early if one of them ended the flow.

The rules themselves live in a RuleRegistry and know how to apply themselves, so this class
only decides *when* they run, not *what* they do.
"""

from typing import Optional

from mitmproxy import http
from robot.api import logger

from MitmLibrary.rules import Phase, Rule, RuleRegistry


class Interceptor:
    """Applies the registered rules to the traffic passing through the proxy."""

    def __init__(self, registry: RuleRegistry, log_to_console: bool = True) -> None:
        self.registry = registry
        self.log_to_console = log_to_console

    def set_console_logging(self, value: bool) -> None:
        """Enables or disables reporting each manipulation on the console."""
        self.log_to_console = value

    async def request(self, flow: http.HTTPFlow) -> None:
        """Applies the rules that act before the request is sent.

        Asynchronous because a rule may wait here: a simulated timeout holds the request
        rather than answering it. mitmproxy awaits an addon hook that returns a
        coroutine, and waiting in one flow does not hold up the others.
        """
        for rule in self.registry.snapshot(Phase.REQUEST):
            if not self._applies(rule, flow):
                continue
            if not self.registry.consume(rule):
                continue
            self._log(rule, flow)
            if await rule.action.apply_async(flow):
                return

    async def response(self, flow: http.HTTPFlow) -> None:
        """Applies the rules that act on the answer that came back."""
        for rule in self.registry.snapshot(Phase.RESPONSE):
            if not self._applies(rule, flow):
                continue
            if not self.registry.consume(rule):
                continue
            self._log(rule, flow)
            if await rule.action.apply_async(flow):
                return

    @staticmethod
    def _applies(rule: Rule, flow: http.HTTPFlow) -> bool:
        """Whether the rule matches this flow."""
        return rule.matcher.matches(flow.request.pretty_url, _method(flow))

    def _log(self, rule: Rule, flow: http.HTTPFlow) -> None:
        """Reports what is being done, and to which request."""
        logger.info(
            f"Applying rule '{rule.alias}' ({rule.action.describe()['type']}) "
            f"to {flow.request.pretty_url}",
            also_console=self.log_to_console,
        )


def _method(flow: http.HTTPFlow) -> Optional[str]:
    """The request method, or None when the flow does not report one."""
    method = getattr(flow.request, "method", None)
    return method if isinstance(method, str) else None
