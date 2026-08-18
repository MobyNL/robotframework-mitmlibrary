"""Tests for how a rule decides whether it applies to a request."""

import unittest

from MitmLibrary.matching import ANY_METHOD, InvalidPatternError, MatchMode, UrlMatcher

URL = "https://example.com/api/users?page=2"


class TestSubstringMatching(unittest.TestCase):
    def test_a_fragment_anywhere_in_the_url_matches(self):
        self.assertTrue(UrlMatcher("/api/").matches_url(URL))
        self.assertTrue(UrlMatcher("example.com").matches_url(URL))
        self.assertTrue(UrlMatcher("page=2").matches_url(URL))

    def test_a_fragment_that_is_not_there_does_not_match(self):
        self.assertFalse(UrlMatcher("/orders").matches_url(URL))

    def test_matching_is_case_sensitive(self):
        """Urls are case sensitive past the host, so matching must not paper over that."""
        self.assertFalse(UrlMatcher("/API/").matches_url(URL))

    def test_substring_is_the_default_mode(self):
        self.assertIs(UrlMatcher("/api/").mode, MatchMode.SUBSTRING)


class TestRegexMatching(unittest.TestCase):
    def test_an_expression_is_searched_anywhere_in_the_url(self):
        matcher = UrlMatcher(r"/api/\w+", MatchMode.REGEX)
        self.assertTrue(matcher.matches_url(URL))

    def test_an_expression_that_does_not_match(self):
        matcher = UrlMatcher(r"/api/\d+", MatchMode.REGEX)
        self.assertFalse(matcher.matches_url(URL))

    def test_anchors_work_as_they_would_in_python(self):
        self.assertTrue(UrlMatcher(r"^https://", MatchMode.REGEX).matches_url(URL))
        self.assertFalse(UrlMatcher(r"^/api", MatchMode.REGEX).matches_url(URL))

    def test_the_query_string_is_part_of_what_is_matched(self):
        self.assertTrue(UrlMatcher(r"page=\d", MatchMode.REGEX).matches_url(URL))

    def test_an_invalid_expression_fails_immediately(self):
        """Compiling here means a bad pattern fails the keyword, not the proxy later."""
        with self.assertRaises(InvalidPatternError) as context:
            UrlMatcher("[unclosed", MatchMode.REGEX)
        self.assertIn("[unclosed", str(context.exception))

    def test_an_invalid_expression_is_a_value_error(self):
        """Robot Framework reports a ValueError from a keyword as a failure."""
        self.assertTrue(issubclass(InvalidPatternError, ValueError))


class TestGlobMatching(unittest.TestCase):
    def test_a_glob_is_matched_against_the_whole_url(self):
        self.assertTrue(UrlMatcher("*/api/*", MatchMode.GLOB).matches_url(URL))
        self.assertFalse(UrlMatcher("/api/", MatchMode.GLOB).matches_url(URL))

    def test_single_character_wildcards_and_classes(self):
        self.assertTrue(UrlMatcher("*/user?*", MatchMode.GLOB).matches_url(URL))
        self.assertTrue(UrlMatcher("*page=[0-9]", MatchMode.GLOB).matches_url(URL))

    def test_a_glob_that_does_not_match(self):
        self.assertFalse(UrlMatcher("*/orders/*", MatchMode.GLOB).matches_url(URL))


class TestMethodMatching(unittest.TestCase):
    def test_any_matches_every_method(self):
        matcher = UrlMatcher("/api/")
        self.assertEqual(matcher.method, ANY_METHOD)
        self.assertTrue(matcher.matches_method("GET"))
        self.assertTrue(matcher.matches_method("POST"))
        self.assertTrue(matcher.matches_method(None))

    def test_a_method_restricts_the_rule(self):
        matcher = UrlMatcher("/api/", method="POST")
        self.assertTrue(matcher.matches_method("POST"))
        self.assertFalse(matcher.matches_method("GET"))

    def test_the_method_is_normalised(self):
        """Robot Framework arguments are strings; ' post ' must behave like 'POST'."""
        self.assertTrue(UrlMatcher("/api/", method=" post ").matches_method("post"))

    def test_a_flow_without_a_method_does_not_match_a_specific_one(self):
        self.assertFalse(UrlMatcher("/api/", method="GET").matches_method(None))

    def test_matches_requires_both_url_and_method(self):
        matcher = UrlMatcher("/api/", method="POST")
        self.assertTrue(matcher.matches(URL, "POST"))
        self.assertFalse(matcher.matches(URL, "GET"))
        self.assertFalse(matcher.matches("https://example.com/orders", "POST"))


class TestDescription(unittest.TestCase):
    def test_a_matcher_without_a_method_omits_it(self):
        self.assertEqual(UrlMatcher("/api/").describe(), "substring:/api/")

    def test_a_matcher_with_a_method_reports_it(self):
        matcher = UrlMatcher("/api/", MatchMode.REGEX, "post")
        self.assertEqual(matcher.describe(), "POST regex:/api/")


if __name__ == "__main__":
    unittest.main()
