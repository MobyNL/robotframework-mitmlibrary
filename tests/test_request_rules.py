"""Tests for the rules that change a request before it is sent, and parts of a response.

These build real flows with `mitmproxy.test.tflow`, not mocks. Rewriting a url and
replacing a body have to keep the message consistent - the host header, the content
length - and a mock request would accept changes that mitmproxy would reject or ignore.
"""

import asyncio
import unittest

from mitmproxy.test import tflow, tutils

from MitmLibrary.interceptor import Interceptor
from MitmLibrary.matching import MatchMode, UrlMatcher
from MitmLibrary.rules import (
    BodyAction,
    HeadersAction,
    RedirectAction,
    RequestBodyAction,
    RequestHeadersAction,
    ResponseAction,
    RewriteAction,
    Rule,
    RuleRegistry,
)


def make_flow(url="http://example.com/api/users", method="GET", headers=None, body=b""):
    """A real HTTPFlow, addressed at the given url."""
    flow = tflow.tflow(
        req=tutils.treq(method=method, content=body),
        resp=tutils.tresp(content=b"original"),
    )
    flow.request.url = url
    for name, value in (headers or {}).items():
        flow.request.headers[name] = value
    return flow


class RequestRuleTestCase(unittest.TestCase):
    def setUp(self):
        self.registry = RuleRegistry()
        self.interceptor = Interceptor(self.registry, log_to_console=False)

    def add(self, alias, action, url="/api", method="ANY", times=0):
        self.registry.add(
            Rule(alias, UrlMatcher(url, MatchMode.SUBSTRING, method), action, times)
        )

    def respond(self, flow):
        asyncio.run(self.interceptor.response(flow))


class TestRequestHeaders(RequestRuleTestCase):
    def test_a_header_can_be_added(self):
        self.add("auth", RequestHeadersAction({"Authorization": "Bearer token"}))
        flow = make_flow()
        self.interceptor.request(flow)
        self.assertEqual(flow.request.headers["Authorization"], "Bearer token")

    def test_an_existing_header_is_replaced(self):
        self.add("auth", RequestHeadersAction({"Authorization": "Bearer new"}))
        flow = make_flow(headers={"Authorization": "Bearer old"})
        self.interceptor.request(flow)
        self.assertEqual(flow.request.headers["Authorization"], "Bearer new")

    def test_other_headers_are_left_alone(self):
        """Merging is the point: setting one header must not drop the rest."""
        self.add("auth", RequestHeadersAction({"Authorization": "Bearer token"}))
        flow = make_flow(headers={"X-Kept": "yes"})
        self.interceptor.request(flow)
        self.assertEqual(flow.request.headers["X-Kept"], "yes")

    def test_a_header_can_be_removed(self):
        self.add("cookies", RequestHeadersAction(None, ["Cookie"]))
        flow = make_flow(headers={"Cookie": "session=1"})
        self.interceptor.request(flow)
        self.assertNotIn("Cookie", flow.request.headers)

    def test_removing_a_header_that_is_not_there_is_a_no_op(self):
        self.add("cookies", RequestHeadersAction(None, ["Cookie"]))
        self.interceptor.request(make_flow())  # must not raise

    def test_removing_and_setting_the_same_header_leaves_one_value(self):
        """Headers can repeat; naming one in both is how a suite collapses them."""
        self.add("auth", RequestHeadersAction({"Accept": "application/json"}, ["Accept"]))
        flow = make_flow()
        flow.request.headers.add("Accept", "text/plain")
        flow.request.headers.add("Accept", "text/html")
        self.interceptor.request(flow)
        self.assertEqual(
            flow.request.headers.get_all("Accept"), ["application/json"]
        )


class TestRequestBody(RequestRuleTestCase):
    def test_the_body_is_replaced(self):
        self.add("payload", RequestBodyAction('{"id": 1}'))
        flow = make_flow(method="POST", body=b"original request")
        self.interceptor.request(flow)
        self.assertEqual(flow.request.content, b'{"id": 1}')

    def test_the_content_length_is_updated(self):
        """A declared length that no longer matches makes the request unreadable."""
        self.add("payload", RequestBodyAction("short"))
        flow = make_flow(method="POST", body=b"a much longer original body")
        self.interceptor.request(flow)
        self.assertEqual(flow.request.headers["content-length"], "5")


class TestRewrite(RequestRuleTestCase):
    def test_the_whole_url_is_replaced(self):
        self.add("v2", RewriteAction("https://other.example.com:8443/api/v2/users?x=1"))
        flow = make_flow()
        self.interceptor.request(flow)
        self.assertEqual(
            flow.request.pretty_url, "https://other.example.com:8443/api/v2/users?x=1"
        )

    def test_the_parts_of_the_request_stay_consistent(self):
        self.add("v2", RewriteAction("https://other.example.com:8443/api/v2/users"))
        flow = make_flow()
        self.interceptor.request(flow)
        self.assertEqual(flow.request.scheme, "https")
        self.assertEqual(flow.request.host, "other.example.com")
        self.assertEqual(flow.request.port, 8443)
        self.assertEqual(flow.request.path, "/api/v2/users")

    def test_the_host_header_follows_the_url(self):
        """A stale host header is the classic rewrite bug: the request would arrive at
        the new server still asking for the old one. mitmproxy's url setter updates it,
        and this pins that so an upgrade that stopped doing so would be reported here.
        """
        self.add("v2", RewriteAction("https://other.example.com:8443/api/v2/users"))
        flow = make_flow(headers={"Host": "example.com"})
        self.interceptor.request(flow)
        self.assertEqual(flow.request.host_header, "other.example.com:8443")


class TestRedirect(RequestRuleTestCase):
    def test_the_host_is_replaced_and_the_path_is_kept(self):
        self.add("stub", RedirectAction("127.0.0.1", 8000))
        flow = make_flow(url="http://api.example.com/api/users?page=2")
        self.interceptor.request(flow)
        self.assertEqual(flow.request.host, "127.0.0.1")
        self.assertEqual(flow.request.port, 8000)
        self.assertEqual(flow.request.path, "/api/users?page=2")

    def test_the_original_port_is_kept_when_none_is_given(self):
        self.add("stub", RedirectAction("127.0.0.1"))
        flow = make_flow(url="http://api.example.com:9000/api/users")
        self.interceptor.request(flow)
        self.assertEqual(flow.request.port, 9000)

    def test_the_scheme_can_be_changed(self):
        self.add("stub", RedirectAction("127.0.0.1", 8000, "https"))
        flow = make_flow(url="http://api.example.com/api/users")
        self.interceptor.request(flow)
        self.assertEqual(flow.request.scheme, "https")

    def test_the_host_header_is_updated(self):
        """The receiving server would not recognise the original name."""
        self.add("stub", RedirectAction("127.0.0.1", 8000))
        flow = make_flow(url="http://api.example.com/api/users",
                         headers={"Host": "api.example.com"})
        self.interceptor.request(flow)
        self.assertEqual(flow.request.host_header, "127.0.0.1:8000")

    def test_a_default_port_is_left_out_of_the_host_header(self):
        """`example.com:80` is legal but not what a server expects to see."""
        self.add("stub", RedirectAction("other.example.com", 80))
        flow = make_flow(url="http://api.example.com/api/users",
                         headers={"Host": "api.example.com"})
        self.interceptor.request(flow)
        self.assertEqual(flow.request.host_header, "other.example.com")

    def test_a_default_https_port_is_left_out_too(self):
        self.add("stub", RedirectAction("other.example.com", 443, "https"))
        flow = make_flow(url="http://api.example.com/api/users",
                         headers={"Host": "api.example.com"})
        self.interceptor.request(flow)
        self.assertEqual(flow.request.host_header, "other.example.com")

    def test_a_request_without_a_host_header_does_not_gain_one(self):
        """HTTP/2 carries the authority in the request line, not in a header."""
        self.add("stub", RedirectAction("127.0.0.1", 8000))
        flow = make_flow()
        self.assertIsNone(flow.request.host_header)  # tflow builds one without it
        self.interceptor.request(flow)
        self.assertIsNone(flow.request.host_header)


class TestResponseHeadersAndBody(RequestRuleTestCase):
    def test_a_response_header_can_be_set(self):
        self.add("caching", HeadersAction({"Cache-Control": "no-store"}))
        flow = make_flow()
        self.respond(flow)
        self.assertEqual(flow.response.headers["Cache-Control"], "no-store")

    def test_a_response_header_can_be_removed(self):
        self.add("cookies", HeadersAction(None, ["Set-Cookie"]))
        flow = make_flow()
        flow.response.headers["Set-Cookie"] = "session=1"
        self.respond(flow)
        self.assertNotIn("Set-Cookie", flow.response.headers)

    def test_response_headers_merge_rather_than_replace(self):
        self.add("caching", HeadersAction({"Cache-Control": "no-store"}))
        flow = make_flow()
        flow.response.headers["X-Kept"] = "yes"
        self.respond(flow)
        self.assertEqual(flow.response.headers["X-Kept"], "yes")

    def test_the_response_body_is_replaced_and_the_length_updated(self):
        self.add("body", BodyAction("[]"))
        flow = make_flow()
        self.respond(flow)
        self.assertEqual(flow.response.content, b"[]")
        self.assertEqual(flow.response.headers["content-length"], "2")

    def test_response_rules_on_a_flow_without_a_response_are_a_no_op(self):
        self.add("body", BodyAction("[]"))
        self.add("headers", HeadersAction({"X": "1"}))
        flow = make_flow()
        flow.response = None
        self.respond(flow)  # must not raise
        self.assertIsNone(flow.response)

    def test_a_replacement_runs_before_a_header_is_added_to_it(self):
        """Set Response rebuilds the response, so it has to run first."""
        self.add("headers", HeadersAction({"X-Added": "yes"}))
        self.add("response", ResponseAction(200, {"Content-Type": "text/plain"}, "new"))
        flow = make_flow()
        self.respond(flow)
        self.assertEqual(flow.response.content, b"new")
        self.assertEqual(flow.response.headers["X-Added"], "yes")


class TestDescriptions(RequestRuleTestCase):
    def test_each_action_reports_its_type(self):
        self.add("request_headers", RequestHeadersAction({"A": "1"}, ["B"]))
        self.add("request_body", RequestBodyAction("x"))
        self.add("rewrite", RewriteAction("http://example.com"))
        self.add("redirect", RedirectAction("127.0.0.1", 8000, "http"))
        self.add("response_headers", HeadersAction({"A": "1"}))
        self.add("response_body", BodyAction("x"))
        described = {rule.alias: rule for rule in self.registry.describe()}
        self.assertEqual(described["request_headers"].type, "request_headers")
        self.assertEqual(described["request_headers"].remove, ["B"])
        self.assertEqual(described["request_body"].type, "request_body")
        self.assertEqual(described["rewrite"].target, "http://example.com")
        self.assertEqual(described["redirect"].host, "127.0.0.1")
        self.assertEqual(described["redirect"].port, 8000)
        self.assertEqual(described["response_headers"].type, "response_headers")
        self.assertEqual(described["response_body"].type, "response_body")

    def test_request_rules_run_in_the_request_phase(self):
        self.add("rewrite", RewriteAction("http://example.com"))
        self.add("body", BodyAction("x"))
        described = {rule.alias: rule.phase for rule in self.registry.describe()}
        self.assertEqual(described["rewrite"], "request")
        self.assertEqual(described["body"], "response")


if __name__ == "__main__":
    unittest.main()
