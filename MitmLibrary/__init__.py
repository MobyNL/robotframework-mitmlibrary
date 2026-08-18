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

from typing import Any, Dict, List, Optional, Sequence, Union

from mitmproxy.tools import dump
from robot.api import logger
from robot.api.deco import keyword, library, not_keyword
from robot.utils import DotDict, timestr_to_secs

from MitmLibrary.interceptor import Interceptor
from MitmLibrary.listener import LibraryListener
from MitmLibrary.matching import ANY_METHOD, MatchMode, UrlMatcher
from MitmLibrary.proxy_controller import ProxyController
from MitmLibrary.recorder import DEFAULT_BODY_LIMIT, DEFAULT_LIMIT, FlowRecorder
from MitmLibrary.rules import (
    Action,
    BlockAction,
    BlockMode,
    BodyAction,
    DelayAction,
    HeadersAction,
    RedirectAction,
    RequestBodyAction,
    RequestHeadersAction,
    ResponseAction,
    RewriteAction,
    Rule,
    RuleRegistry,
    StatusAction,
)
from MitmLibrary.version import VERSION


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

    = Rules =
    Everything the proxy does is a rule, and every rule is addressed the same way: an
    alias, a url pattern, and optionally an HTTP method. `Remove Rule` removes any of
    them, `Clear All Rules` removes all of them, and `Get Proxy Rules` reports what is
    loaded.

    An alias is the handle used to remove a rule, so adding a second rule with an alias
    that is already in use replaces the first one, keeping its position.

    == Matching ==
    The `match` argument decides how a url pattern is compared against the url of a
    request:
    - `SUBSTRING` (the default): the pattern appears anywhere in the url.
    - `REGEX`: the pattern is a regular expression, searched anywhere in the url.
    - `GLOB`: shell-style wildcards (`*`, `?`, `[abc]`) matched against the whole url, so
      `*/api/*` matches but `api` on its own does not.

    An unusable regular expression fails the keyword that configured it, rather than
    failing later inside the proxy.

    `method` restricts a rule to one HTTP method; `ANY`, the default, matches all of them.

    `times` limits how often a rule may be applied. `0`, the default, means unlimited. An
    exhausted rule stays in the list showing `remaining=0`, so it is visible in the log
    rather than silently disappearing.

    == Order ==
    All matching rules are applied, in a defined order:
    - A rule that blocks a request ends it. Nothing after it runs.
    - Otherwise `Set Response` runs before rules that change part of a response, which
      run before delays. So `Set Response` and `Set Response Status` combine as you would
      expect, rather than one throwing away the other.
    - Rules of equal rank run in the order they were added, and the last one to write a
      value wins.
    - Delays add up: two matching delay rules hold the response for the sum of both.

    A keyword takes effect from the next request onwards; a request already being handled
    finishes under the rules that were loaded when it started.

    = Recording =
    The proxy can remember the traffic that passes through it, so a suite can assert on
    what the application under test actually sent rather than only on what came back.
    Start it with `Start Recording`, or with `record=True` on `Start Mitm Proxy`, and ask
    with `Get Recorded Requests`, `Get Request Count`, `Request Should Have Been Made`,
    `Request Should Not Have Been Made` and `Wait Until Request Is Made`.

    Recording is off by default. A long run holds a lot of traffic, so what is kept is
    capped in two directions: how many requests are remembered, and how many bytes of
    each body. When the first cap is reached the oldest request is dropped, and the
    number dropped is reported in the failure message of an assertion rather than being
    hidden. A body longer than the second cap is shortened, and the recorded request says
    so.
    = Proxy modes =
    By default the proxy is a normal forward proxy: a client is configured to send its
    traffic through it. `mode` on `Start Mitm Proxy` changes that, and takes either one
    mode or a list of them.

    - `regular`: a forward proxy. The default.
    - `reverse:http://host:port`: the proxy stands in front of one server. Clients talk
      to the proxy directly, as if it were that server, so nothing needs to be configured
      to use a proxy at all.
    - `upstream:http://host:port`: a forward proxy that passes everything on to another
      proxy. This is what a corporate network needs, where the machine running the tests
      may not reach the internet on its own. Rules and recording still apply here, on
      this proxy; what the proxy further up the chain makes of the traffic is its own
      business, and it does not necessarily see it as separate requests.
    - `transparent`: traffic is routed to the proxy by the network itself. Needs the
      operating system to be set up for it.
    - `socks5`: a SOCKS5 proxy rather than an HTTP one.

    A mode may be followed by `@host:port` to give it its own listening address, which
    overrides `listen_host` and `listen_port`. `Get Proxy Address` reports where the
    proxy actually ended up listening, which is why it reads that from the proxy rather
    than repeating the arguments back.

    A specification that cannot be understood fails `Start Mitm Proxy` with mitmproxy's
    own explanation, rather than leaving the proxy to fail to start for an unstated
    reason.

    `transparent` and `socks5` are passed through to mitmproxy but are not exercised by
    this library's own tests, because they need the operating system or a client
    configured for them.

    == Example ==
    | # Stand in front of a service, so a client needs no proxy settings at all
    | Start Mitm Proxy    mode=reverse:http://127.0.0.1:5000

    | # Send everything on through the network's own proxy
    | Start Mitm Proxy    mode=upstream:http://corporate-proxy:3128

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

    Enjoy using MitmLibrary to enhance your network traffic testing capabilities in Robot Framework.
    """

    @not_keyword
    def __init__(self) -> None:
        """
        Initializes the MitmLibrary instance.

        This constructor initializes the proxy controller and request_logger instances used
        for managing the proxy server.
        """
        self.controller: ProxyController = ProxyController()
        self.registry: RuleRegistry = RuleRegistry()
        self.interceptor: Optional[Interceptor] = None
        self.recorder: Optional[FlowRecorder] = None
        self.log_to_console: bool = True
        # Robot Framework calls close() on this when the suite that imported the library
        # ends, which releases the port even if the suite never stopped the proxy itself.
        self.ROBOT_LIBRARY_LISTENER: LibraryListener = LibraryListener(self.controller)

    @property
    def proxy_master(self) -> Optional[dump.DumpMaster]:
        """The running mitmproxy master, or None when no proxy is running."""
        return self.controller.master

    @property
    def loop_handler(self) -> Any:
        """The thread the proxy's event loop runs on."""
        return self.controller.loop_handler

    @not_keyword
    def _require_proxy(self) -> Interceptor:
        """Returns the running interceptor, or raises a readable error."""
        if self.interceptor is None:
            raise RuntimeError(
                "No proxy is running. Call 'Start Mitm Proxy' before this keyword."
            )
        return self.interceptor

    @not_keyword
    def _require_registry(self) -> RuleRegistry:
        """Returns the rule registry, once a proxy is running to apply it."""
        self._require_proxy()
        return self.registry

    @keyword
    def start_mitm_proxy(
        self,
        listen_host: str = "127.0.0.1",
        listen_port: int = 8080,
        certificates_directory: Optional[str] = None,
        ssl_insecure: bool = False,
        log_to_console: bool = True,
        record: bool = False,
        record_limit: int = DEFAULT_LIMIT,
        record_body_limit: int = DEFAULT_BODY_LIMIT,
        mode: Optional[Union[str, List[str]]] = None,
        proxy_auth: Optional[str] = None,
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
        - record: If True, traffic is recorded from the start, as if `Start Recording`
          had been called. Off by default; see the `Recording` section.
        - record_limit: How many requests to keep when recording.
        - record_body_limit: How many bytes of each body to keep when recording.
        - mode: How the proxy handles the traffic it receives. A single mode or a list of
          them. Defaults to a normal forward proxy. See the `Proxy modes` section.
        - proxy_auth: Require clients to authenticate before the proxy serves them.
          `username:password` for one account, `any` to accept any combination, or
          `@path/to/htpasswd` for an Apache htpasswd file.

        Fails if the proxy cannot be started, for example when the port is already in use,
        or if a mode cannot be understood.

        Example:
        | Start Mitm Proxy    192.168.1.100    8888    /path/to/certificates    True
        | Start Mitm Proxy    mode=reverse:http://127.0.0.1:5000
        | Start Mitm Proxy    proxy_auth=tester:secret

        See the 'Mitm Certificates' section in the documentation for more information.
        """
        self.log_to_console = log_to_console
        if record:
            self.recorder = FlowRecorder(record_limit, record_body_limit)
        try:
            self.controller.start(
                listen_host,
                listen_port,
                certificates_directory,
                ssl_insecure,
                self._build_addons,
                mode,
                proxy_auth,
            )
        except Exception:
            # The controller has already discarded the master it could not start. The
            # addon it was built with has to go with it, or the next keyword would talk
            # to an interceptor belonging to a proxy that is not running.
            self.interceptor = None
            self.recorder = None
            raise

    @not_keyword
    def _build_addons(self, master: dump.DumpMaster) -> Sequence[Any]:
        """Builds the addons the proxy runs with, once its master exists.

        The registry outlives the proxy, so rules configured before a restart are still
        there afterwards. Only the addon reading them is rebuilt.
        """
        self.interceptor = Interceptor(self.registry, self.log_to_console)
        addons: List[Any] = [self.interceptor]
        if self.recorder is not None:
            addons.append(self.recorder)
        return addons

    @keyword
    def stop_mitm_proxy(self) -> None:
        """Stops the proxy and waits for it to release its port.

        Does nothing when no proxy is running."""
        if not self.controller.is_running:
            logger.info("No proxy is running, nothing to stop.")
            return
        self.controller.discard()
        self.interceptor = None
        self.recorder = None

    @keyword
    def get_proxy_address(self) -> DotDict:
        """Returns the address the proxy is actually listening on.

        The result is a dictionary with `host`, `port` and `url`. The address is read from
        the running proxy rather than echoed back from ``Start Mitm Proxy``, so it is the
        real one: passing port ``0`` lets the operating system pick a free port, and this
        keyword is how you find out which. That is what makes it safe to run several
        suites in parallel without them competing for port 8080.

        Fails if no proxy is running.

        Example:
        | Start Mitm Proxy    127.0.0.1    0
        | ${address}    Get Proxy Address
        | Log    The proxy is on ${address.url}
        """
        if not self.controller.is_running:
            raise RuntimeError(
                "No proxy is running. Call 'Start Mitm Proxy' before this keyword."
            )
        addresses = self.controller.listen_addresses()
        if not addresses:
            raise RuntimeError("The proxy is running but is not listening on any address.")
        if len(addresses) > 1:
            logger.info(f"The proxy is listening on {addresses}; returning the first.")
        host, port = addresses[0][0], addresses[0][1]
        return DotDict({"host": host, "port": port, "url": f"http://{host}:{port}"})

    @keyword
    def block_requests(
        self,
        alias: str,
        url: str,
        mode: BlockMode = BlockMode.RESPOND,
        status_code: int = 403,
        body: Optional[str] = None,
        method: str = ANY_METHOD,
        match: MatchMode = MatchMode.SUBSTRING,
        times: int = 0,
    ) -> None:
        """Stops matching requests from reaching their destination.

        - `alias`: The handle for this rule. Reusing an alias replaces the rule that
          already uses it, keeping its position in the order.
        - `url`: The pattern the request url is compared against. See `match`.
        - `mode`: `RESPOND` answers with `status_code` without contacting the server, and
          is the default because every client reports it the same way. `RESET` drops the
          connection instead, which is closer to a network failure but surfaces as a
          different exception in each HTTP client.
        - `status_code`: The status to answer with in `RESPOND` mode.
        - `body`: The body to answer with in `RESPOND` mode. Empty when not given.
        - `method`: Only match this HTTP method. `ANY` matches every method.
        - `match`: How `url` is interpreted. See the `Matching` section.
        - `times`: How often the rule may be applied. `0` means unlimited.

        Example:
        | Block Requests    ads    doubleclick.net
        | Block Requests    api    /api/users    status_code=503    method=POST
        """
        self._require_proxy()
        self._add_rule(
            alias, url, method, match, times, BlockAction(mode, status_code, body)
        )

    @keyword
    def set_response(
        self,
        alias: str,
        url: str,
        status_code: int = 200,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        method: str = ANY_METHOD,
        match: MatchMode = MatchMode.SUBSTRING,
        times: int = 0,
    ) -> None:
        """Replaces the response of matching requests.

        The request still reaches its destination; the answer is replaced afterwards. What
        is not given is kept from the original response, so a rule that only sets a status
        code leaves the body and headers alone.

        - `alias`: The handle for this rule. Reusing an alias replaces the rule that
          already uses it.
        - `url`: The pattern the request url is compared against. See `match`.
        - `status_code`: The status code to answer with.
        - `headers`: Headers to answer with. When given, they replace the original
          headers entirely rather than being merged into them.
        - `body`: The body to answer with. The original body is kept when not given.
        - `method`: Only match this HTTP method. `ANY` matches every method.
        - `match`: How `url` is interpreted. See the `Matching` section.
        - `times`: How often the rule may be applied. `0` means unlimited.

        Example:
        | Set Response    user    /api/user    body={"name": "test"}
        | VAR    &{headers}    Content-Type=application/json
        | Set Response    user    /api/user    headers=${headers}    status_code=201
        """
        self._require_proxy()
        self._add_rule(
            alias,
            url,
            method,
            match,
            times,
            ResponseAction(status_code, headers, body),
        )

    @keyword
    def set_response_status(
        self,
        alias: str,
        url: str,
        status_code: int = 200,
        method: str = ANY_METHOD,
        match: MatchMode = MatchMode.SUBSTRING,
        times: int = 0,
    ) -> None:
        """Changes the status code of matching responses, leaving the rest alone.

        - `alias`: The handle for this rule. Reusing an alias replaces the rule that
          already uses it.
        - `url`: The pattern the request url is compared against. See `match`.
        - `status_code`: The status code to report instead of the original one.
        - `method`: Only match this HTTP method. `ANY` matches every method.
        - `match`: How `url` is interpreted. See the `Matching` section.
        - `times`: How often the rule may be applied. `0` means unlimited.

        Often used status codes:
        - 200: Success
        - 401: Unauthorized
        - 403: Forbidden
        - 404: Not found
        - 418: I'm a Teapot
        - 500: Internal Server error

        For more information on HTTP status codes, visit:
        https://developer.mozilla.org/en-US/docs/Web/HTTP/Status

        Example:
        | Set Response Status    outage    /api/orders    500
        """
        self._require_proxy()
        self._add_rule(alias, url, method, match, times, StatusAction(status_code))

    @keyword
    def add_response_delay(
        self,
        alias: str,
        url: str,
        delay: str,
        method: str = ANY_METHOD,
        match: MatchMode = MatchMode.SUBSTRING,
        times: int = 0,
    ) -> None:
        """Holds matching responses back, to imitate a slow service.

        - `alias`: The handle for this rule. Reusing an alias replaces the rule that
          already uses it.
        - `url`: The pattern the request url is compared against. See `match`.
        - `delay`: How long to wait, in Robot Framework time format (e.g. ``2``,
          ``1.5s``, ``500 ms``, ``1 min``). An invalid value fails this keyword rather
          than failing later inside the proxy.
        - `method`: Only match this HTTP method. `ANY` matches every method.
        - `match`: How `url` is interpreted. See the `Matching` section.
        - `times`: How often the rule may be applied. `0` means unlimited.

        Delays add up: when two matching rules each wait a second, the response is held
        for two.

        Example:
        | Add Response Delay    slow    https://example.com/some/path    2s
        """
        self._require_proxy()
        self._add_rule(
            alias, url, method, match, times, DelayAction(timestr_to_secs(delay), delay)
        )

    @keyword
    def set_response_headers(
        self,
        alias: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        remove: Optional[List[str]] = None,
        method: str = ANY_METHOD,
        match: MatchMode = MatchMode.SUBSTRING,
        times: int = 0,
    ) -> None:
        """Sets and removes named headers on matching responses.

        Unlike `Set Response`, this merges: headers that are not named are left as they
        were, so adding one header does not mean restating all the others.

        - `alias`: The handle for this rule. Reusing an alias replaces the rule that
          already uses it.
        - `url`: The pattern the request url is compared against. See `match`.
        - `headers`: Headers to set. An existing header of the same name is replaced.
        - `remove`: Names of headers to remove. Removal happens before setting, so a
          header can be named in both to replace every copy of it with a single value.
        - `method`: Only match this HTTP method. `ANY` matches every method.
        - `match`: How `url` is interpreted. See the `Matching` section.
        - `times`: How often the rule may be applied. `0` means unlimited.

        Example:
        | VAR    &{headers}    Cache-Control=no-store
        | Set Response Headers    caching    /api    headers=${headers}
        | Set Response Headers    cookies    /api    remove=['Set-Cookie']
        """
        self._require_proxy()
        self._add_rule(
            alias, url, method, match, times, HeadersAction(headers, remove)
        )

    @keyword
    def set_response_body(
        self,
        alias: str,
        url: str,
        body: str,
        method: str = ANY_METHOD,
        match: MatchMode = MatchMode.SUBSTRING,
        times: int = 0,
    ) -> None:
        """Replaces the body of matching responses, keeping their status and headers.

        The `content-length` header is updated to match the new body.

        - `alias`: The handle for this rule. Reusing an alias replaces the rule that
          already uses it.
        - `url`: The pattern the request url is compared against. See `match`.
        - `body`: The body to answer with.
        - `method`: Only match this HTTP method. `ANY` matches every method.
        - `match`: How `url` is interpreted. See the `Matching` section.
        - `times`: How often the rule may be applied. `0` means unlimited.

        Example:
        | Set Response Body    empty    /api/users    []
        """
        self._require_proxy()
        self._add_rule(alias, url, method, match, times, BodyAction(body))

    @keyword
    def set_request_headers(
        self,
        alias: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        remove: Optional[List[str]] = None,
        method: str = ANY_METHOD,
        match: MatchMode = MatchMode.SUBSTRING,
        times: int = 0,
    ) -> None:
        """Sets and removes named headers on matching requests, before they are sent.

        The request still reaches its destination; it arrives with the headers changed.
        Useful for injecting an authorization header a test cannot obtain otherwise, or
        for taking one away to see how the application under test copes.

        - `alias`: The handle for this rule. Reusing an alias replaces the rule that
          already uses it.
        - `url`: The pattern the request url is compared against. See `match`.
        - `headers`: Headers to set. An existing header of the same name is replaced.
        - `remove`: Names of headers to remove.
        - `method`: Only match this HTTP method. `ANY` matches every method.
        - `match`: How `url` is interpreted. See the `Matching` section.
        - `times`: How often the rule may be applied. `0` means unlimited.

        Example:
        | VAR    &{headers}    Authorization=Bearer test-token
        | Set Request Headers    auth    /api    headers=${headers}
        """
        self._require_proxy()
        self._add_rule(
            alias, url, method, match, times, RequestHeadersAction(headers, remove)
        )

    @keyword
    def set_request_body(
        self,
        alias: str,
        url: str,
        body: str,
        method: str = ANY_METHOD,
        match: MatchMode = MatchMode.SUBSTRING,
        times: int = 0,
    ) -> None:
        """Replaces the body of matching requests, before they are sent.

        The `content-length` header is updated to match the new body.

        - `alias`: The handle for this rule. Reusing an alias replaces the rule that
          already uses it.
        - `url`: The pattern the request url is compared against. See `match`.
        - `body`: The body to send instead of the original one.
        - `method`: Only match this HTTP method. `ANY` matches every method.
        - `match`: How `url` is interpreted. See the `Matching` section.
        - `times`: How often the rule may be applied. `0` means unlimited.

        Example:
        | Set Request Body    payload    /api/orders    {"id": 1}    method=POST
        """
        self._require_proxy()
        self._add_rule(alias, url, method, match, times, RequestBodyAction(body))

    @keyword
    def rewrite_request_url(
        self,
        alias: str,
        url: str,
        target: str,
        method: str = ANY_METHOD,
        match: MatchMode = MatchMode.SUBSTRING,
        times: int = 0,
    ) -> None:
        """Sends matching requests to a different url entirely.

        The whole url is replaced, so the path and query of the original request are not
        kept. Use `Redirect Requests To Host` to send a request elsewhere while keeping
        the rest of it.

        The scheme, host, port and path are set together and the `Host` header is updated
        with them, so the request that arrives is consistent.

        - `alias`: The handle for this rule. Reusing an alias replaces the rule that
          already uses it.
        - `url`: The pattern the request url is compared against. See `match`.
        - `target`: The absolute url to send the request to instead.
        - `method`: Only match this HTTP method. `ANY` matches every method.
        - `match`: How `url` is interpreted. See the `Matching` section.
        - `times`: How often the rule may be applied. `0` means unlimited.

        Example:
        | Rewrite Request Url    v2    /api/v1/users    https://example.com/api/v2/users
        """
        self._require_proxy()
        self._add_rule(alias, url, method, match, times, RewriteAction(target))

    @keyword
    def redirect_requests_to_host(
        self,
        alias: str,
        url: str,
        host: str,
        port: Optional[int] = None,
        scheme: Optional[str] = None,
        method: str = ANY_METHOD,
        match: MatchMode = MatchMode.SUBSTRING,
        times: int = 0,
    ) -> None:
        """Sends matching requests to a different host, keeping their path and query.

        This is how a suite points an application at a local stub without changing the
        application's configuration. The `Host` header is updated too, so the receiving
        server is addressed by the name it actually answers to.

        - `alias`: The handle for this rule. Reusing an alias replaces the rule that
          already uses it.
        - `url`: The pattern the request url is compared against. See `match`.
        - `host`: The host to send the request to instead.
        - `port`: The port to use. The original port is kept when not given.
        - `scheme`: `http` or `https`. The original scheme is kept when not given.
        - `method`: Only match this HTTP method. `ANY` matches every method.
        - `match`: How `url` is interpreted. See the `Matching` section.
        - `times`: How often the rule may be applied. `0` means unlimited.

        Example:
        | Redirect Requests To Host    stub    api.example.com    127.0.0.1    port=8000
        """
        self._require_proxy()
        self._add_rule(
            alias, url, method, match, times, RedirectAction(host, port, scheme)
        )

    @keyword
    def remove_rule(self, alias: str) -> None:
        """Removes the rule with the given alias.

        Warns when there is no such rule, rather than failing: a teardown that removes a
        rule a failing test never added should not turn into a second failure.

        Example:
        | Remove Rule    ads
        """
        if not self._require_registry().remove(alias):
            logger.warn(f"There is no rule with alias '{alias}'.")

    @keyword
    def clear_all_rules(self) -> None:
        """Removes every rule.

        The proxy keeps running; this only empties what it was told to do, which is the
        cheap way to get a clean slate between tests.
        """
        self._require_registry().clear()

    @keyword
    def get_proxy_rules(self) -> List[DotDict]:
        """Returns the loaded rules, in the order they are applied.

        Each rule is a dictionary with at least `alias`, `url`, `match`, `method`,
        `times`, `remaining`, `used`, `phase` and `type`, plus whatever else that kind of
        rule was configured with.

        Example:
        | ${rules}    Get Proxy Rules
        | Length Should Be    ${rules}    2
        | Should Be Equal    ${rules}[0][alias]    ads
        """
        return self._require_registry().describe()

    @keyword
    def log_proxy_rules(self) -> None:
        """Logs the loaded rules, in the order they are applied."""
        rules = self._require_registry().describe()
        if not rules:
            logger.info("No rules are loaded.")
            return
        logger.info(f"{len(rules)} rule(s) are loaded, in the order they are applied:")
        for rule in rules:
            logger.info(f"{rule}")

    @keyword
    def start_recording(
        self, limit: int = DEFAULT_LIMIT, body_limit: int = DEFAULT_BODY_LIMIT
    ) -> None:
        """Starts remembering the traffic that passes through the proxy.

        Recording is off by default, because a long run holds a lot of traffic and
        nothing should quietly turn into unbounded memory. What is kept is capped in two
        directions, and both caps can be raised when a suite needs more.

        - `limit`: How many requests to keep. Once full, the oldest is dropped, and the
          number dropped is reported by the assertion keywords rather than being hidden.
        - `body_limit`: How many bytes of each body to keep. A body longer than this is
          shortened, and the recorded request says so.

        Calling this again replaces what was recorded so far.

        Example:
        | Start Recording
        | Start Recording    limit=50    body_limit=1024
        """
        self._require_proxy()
        self.recorder = FlowRecorder(limit, body_limit)
        self.controller.add_addon(self.recorder)

    @keyword
    def stop_recording(self) -> None:
        """Stops recording traffic and forgets what was recorded.

        Does nothing when nothing was being recorded.
        """
        if self.recorder is None:
            logger.info("Nothing was being recorded.")
            return
        self.controller.remove_addon(self.recorder)
        self.recorder = None

    @keyword
    def clear_recorded_requests(self) -> None:
        """Forgets the requests recorded so far, and keeps recording.

        Useful between tests, so one test does not assert on another test's traffic.
        """
        self._require_recorder().clear()

    @keyword
    def get_recorded_requests(
        self,
        url: Optional[str] = None,
        method: str = ANY_METHOD,
        match: MatchMode = MatchMode.SUBSTRING,
    ) -> List[DotDict]:
        """Returns the recorded requests, oldest first.

        Each request is a dictionary with `method`, `url`, `host`, `path`, `query`,
        `request_headers`, `request_body`, `status_code`, `response_headers`,
        `response_body`, `started`, `ended`, `duration` and `error`, plus
        `request_body_truncated` and `response_body_truncated` telling you whether a body
        was longer than the recorded limit.

        - `url`: Only return requests whose url matches. All of them when not given.
        - `method`: Only return requests with this method. `ANY` matches every method.
        - `match`: How `url` is interpreted. See the `Matching` section.

        Example:
        | ${requests}    Get Recorded Requests    /api/users    method=POST
        | Should Be Equal    ${requests}[0][status_code]    ${201}
        """
        return self._require_recorder().entries(self._recording_matcher(url, method, match))

    @keyword
    def get_request_count(
        self,
        url: Optional[str] = None,
        method: str = ANY_METHOD,
        match: MatchMode = MatchMode.SUBSTRING,
    ) -> int:
        """Returns how many recorded requests match.

        - `url`: Only count requests whose url matches. All of them when not given.
        - `method`: Only count requests with this method. `ANY` matches every method.
        - `match`: How `url` is interpreted. See the `Matching` section.

        Example:
        | ${count}    Get Request Count    /api/users
        | Should Be Equal As Integers    ${count}    3
        """
        return self._require_recorder().count(
            self._recording_matcher(url, method, match)
        )

    @keyword
    def request_should_have_been_made(
        self,
        url: str,
        method: str = ANY_METHOD,
        match: MatchMode = MatchMode.SUBSTRING,
        times: Optional[int] = None,
        msg: Optional[str] = None,
    ) -> None:
        """Fails unless a matching request was recorded.

        - `url`: The pattern the recorded url is compared against. See `match`.
        - `method`: Only match this HTTP method. `ANY` matches every method.
        - `match`: How `url` is interpreted. See the `Matching` section.
        - `times`: Require exactly this many matching requests. Any number above zero
          when not given.
        - `msg`: Used instead of the default failure message.

        The default failure message lists what *was* recorded, because the useful
        question when this fails is what the application asked for instead.

        Example:
        | Request Should Have Been Made    /api/users    method=POST
        | Request Should Have Been Made    /api/users    times=2
        """
        recorder = self._require_recorder()
        matcher = self._recording_matcher(url, method, match)
        found = recorder.count(matcher)
        if times is None:
            if found > 0:
                return
            expected = "at least one request"
        else:
            if found == times:
                return
            expected = f"exactly {times} request(s)"
        raise AssertionError(
            msg
            or (
                f"Expected {expected} matching {matcher.describe()}, but {found} "
                f"were made. {recorder.summary()}"
            )
        )

    @keyword
    def request_should_not_have_been_made(
        self,
        url: str,
        method: str = ANY_METHOD,
        match: MatchMode = MatchMode.SUBSTRING,
        msg: Optional[str] = None,
    ) -> None:
        """Fails when a matching request was recorded.

        - `url`: The pattern the recorded url is compared against. See `match`.
        - `method`: Only match this HTTP method. `ANY` matches every method.
        - `match`: How `url` is interpreted. See the `Matching` section.
        - `msg`: Used instead of the default failure message.

        Example:
        | Request Should Not Have Been Made    /api/telemetry
        """
        recorder = self._require_recorder()
        matcher = self._recording_matcher(url, method, match)
        found = recorder.count(matcher)
        if found == 0:
            return
        made = ", ".join(
            f"{entry.method} {entry.url}" for entry in recorder.entries(matcher)[:10]
        )
        raise AssertionError(
            msg
            or (
                f"Expected no request matching {matcher.describe()}, but {found} "
                f"were made: {made}."
            )
        )

    @keyword
    def wait_until_request_is_made(
        self,
        url: str,
        method: str = ANY_METHOD,
        match: MatchMode = MatchMode.SUBSTRING,
        timeout: str = "10s",
        count: int = 1,
    ) -> List[DotDict]:
        """Waits until matching requests have been recorded, and returns them.

        For traffic a test does not trigger directly, such as a request a page makes
        after it has loaded. Returns as soon as the request arrives rather than at the
        end of a polling interval, and fails when the timeout passes first.

        - `url`: The pattern the recorded url is compared against. See `match`.
        - `method`: Only match this HTTP method. `ANY` matches every method.
        - `match`: How `url` is interpreted. See the `Matching` section.
        - `timeout`: How long to wait, in Robot Framework time format.
        - `count`: How many matching requests to wait for.

        Example:
        | ${requests}    Wait Until Request Is Made    /api/events    timeout=5s
        """
        recorder = self._require_recorder()
        matcher = self._recording_matcher(url, method, match)
        return recorder.wait_for(matcher, timestr_to_secs(timeout), count)

    @not_keyword
    def _require_recorder(self) -> FlowRecorder:
        """Returns the recorder, or explains how to get one."""
        self._require_proxy()
        if self.recorder is None:
            raise RuntimeError(
                "Traffic is not being recorded. Call 'Start Recording', or start the "
                "proxy with record=True, before this keyword."
            )
        return self.recorder

    @not_keyword
    def _recording_matcher(
        self, url: Optional[str], method: str, match: MatchMode
    ) -> UrlMatcher:
        """Builds the matcher the recording keywords filter with.

        An empty pattern matches every url, which is what leaving `url` out means.
        """
        return UrlMatcher(url if url is not None else "", match, method)

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
        if self.interceptor is not None:
            self.interceptor.set_console_logging(value)

    @not_keyword
    def _add_rule(
        self,
        alias: str,
        url: str,
        method: str,
        match: MatchMode,
        times: int,
        action: Action,
    ) -> None:
        """Registers a rule and reports it when it replaced one."""
        matcher = UrlMatcher(url, match, method)
        if self.registry.add(Rule(alias, matcher, action, times)):
            logger.info(
                f"Replaced the existing rule with alias '{alias}'.",
                also_console=self.log_to_console,
            )
