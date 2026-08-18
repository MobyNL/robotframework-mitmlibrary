"""
This file defines how a rule decides whether it applies to a request.

Every rule in the library is addressed the same way: a url pattern, how that pattern is
interpreted, and optionally an HTTP method. Keeping that in one place means the matching
behaviour is identical for a blocked request, a custom response and a response delay, and
that it can be described once in the documentation rather than per keyword.
"""

import fnmatch
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Pattern

ANY_METHOD = "ANY"


class MatchMode(Enum):
    """How the url of a rule is compared against the url of a request.

    - `SUBSTRING`: the pattern appears anywhere in the url. The default, and what the
      library did before there was a choice.
    - `REGEX`: the pattern is a regular expression, searched anywhere in the url.
    - `GLOB`: the pattern is a shell-style glob (`*`, `?`, `[abc]`) matched against the
      whole url, so `*/api/*` matches but `api` on its own does not.
    """

    SUBSTRING = "substring"
    REGEX = "regex"
    GLOB = "glob"


class InvalidPatternError(ValueError):
    """Raised when a pattern cannot be compiled for the match mode it was given."""


@dataclass(frozen=True)
class UrlMatcher:
    """Decides whether a rule applies to a request.

    The pattern is compiled once, when the keyword that created the rule runs, so an
    unusable regular expression fails that keyword rather than failing later inside the
    proxy, where the error would be reported far from its cause.
    """

    pattern: str
    mode: MatchMode = MatchMode.SUBSTRING
    method: str = ANY_METHOD
    _regex: Optional[Pattern[str]] = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        # The dataclass is frozen so that a rule cannot change what it matches while the
        # proxy is reading it; setting the derived fields needs the same escape hatch
        # that frozen dataclasses use in their own __init__.
        object.__setattr__(self, "method", (self.method or ANY_METHOD).strip().upper())
        object.__setattr__(self, "_regex", self._compile())

    def _compile(self) -> Optional[Pattern[str]]:
        """Builds the expression for the mode, or None when the mode needs no expression."""
        if self.mode is MatchMode.SUBSTRING:
            return None
        if self.mode is MatchMode.GLOB:
            return re.compile(fnmatch.translate(self.pattern))
        try:
            return re.compile(self.pattern)
        except re.error as error:
            raise InvalidPatternError(
                f"'{self.pattern}' is not a valid regular expression: {error}"
            ) from error

    def matches_url(self, url: str) -> bool:
        """Whether the url matches, ignoring the method."""
        if self._regex is None:
            return self.pattern in url
        if self.mode is MatchMode.GLOB:
            return self._regex.match(url) is not None
        return self._regex.search(url) is not None

    def matches_method(self, method: Optional[str]) -> bool:
        """Whether the method matches. `ANY` matches everything, including no method."""
        if self.method == ANY_METHOD:
            return True
        return (method or "").upper() == self.method

    def matches(self, url: str, method: Optional[str] = None) -> bool:
        """Whether both the url and the method match."""
        return self.matches_method(method) and self.matches_url(url)

    def describe(self) -> str:
        """A short readable form, for logs and for `Get Proxy Rules`."""
        method = "" if self.method == ANY_METHOD else f"{self.method} "
        return f"{method}{self.mode.value}:{self.pattern}"
