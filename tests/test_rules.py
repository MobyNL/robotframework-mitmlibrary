"""Tests for the rule registry.

The registry is the one piece of shared mutable state in the library: keywords change it
from the thread running the tests while the proxy reads it from its own thread. Most of
what is tested here is that bookkeeping, in particular that `times` is exact.
"""

import threading
import unittest

from MitmLibrary.matching import MatchMode, UrlMatcher
from MitmLibrary.rules import (
    BlockAction,
    DelayAction,
    Phase,
    Priority,
    ResponseAction,
    Rule,
    RuleRegistry,
    StatusAction,
)


def make_rule(alias, url="/api", action=None, times=0, method="ANY", mode=None):
    """Builds a rule the way the library's keywords do."""
    matcher = UrlMatcher(url, mode or MatchMode.SUBSTRING, method)
    return Rule(alias, matcher, action or StatusAction(404), times)


class TestRegistryContents(unittest.TestCase):
    def setUp(self):
        self.registry = RuleRegistry()

    def test_a_rule_can_be_added_and_found(self):
        self.assertFalse(self.registry.add(make_rule("one")))
        self.assertEqual(self.registry.get("one").alias, "one")

    def test_an_alias_is_replaced_rather_than_duplicated(self):
        self.registry.add(make_rule("one", action=StatusAction(404)))
        self.assertTrue(self.registry.add(make_rule("one", action=StatusAction(500))))
        self.assertEqual(len(self.registry.snapshot()), 1)
        self.assertEqual(self.registry.get("one").action.status_code, 500)

    def test_replacing_a_rule_keeps_its_position(self):
        """Replacing a rule must not quietly change the order rules are applied in."""
        self.registry.add(make_rule("first"))
        self.registry.add(make_rule("second"))
        self.registry.add(make_rule("first", action=StatusAction(500)))
        self.assertEqual(
            [rule.alias for rule in self.registry.snapshot()], ["first", "second"]
        )

    def test_removing_a_rule(self):
        self.registry.add(make_rule("one"))
        self.assertTrue(self.registry.remove("one"))
        self.assertIsNone(self.registry.get("one"))

    def test_removing_an_unknown_rule_reports_that_it_was_not_there(self):
        self.assertFalse(self.registry.remove("nothing"))

    def test_clear_removes_everything(self):
        self.registry.add(make_rule("one"))
        self.registry.add(make_rule("two"))
        self.registry.clear()
        self.assertEqual(self.registry.snapshot(), [])


class TestRegistryOrdering(unittest.TestCase):
    def setUp(self):
        self.registry = RuleRegistry()

    def test_rules_are_ordered_by_priority_then_insertion(self):
        """A whole-response replacement has to run before something that edits it."""
        self.registry.add(make_rule("delay", action=DelayAction(1, "1s")))
        self.registry.add(make_rule("status", action=StatusAction(500)))
        self.registry.add(make_rule("response", action=ResponseAction(200)))
        self.assertEqual(
            [rule.alias for rule in self.registry.snapshot()],
            ["response", "status", "delay"],
        )

    def test_rules_of_equal_rank_keep_the_order_they_were_added(self):
        self.registry.add(make_rule("first", action=StatusAction(500)))
        self.registry.add(make_rule("second", action=StatusAction(404)))
        self.assertEqual(
            [rule.alias for rule in self.registry.snapshot()], ["first", "second"]
        )

    def test_a_snapshot_can_be_limited_to_one_phase(self):
        self.registry.add(make_rule("block", action=BlockAction()))
        self.registry.add(make_rule("status", action=StatusAction(500)))
        self.assertEqual(
            [rule.alias for rule in self.registry.snapshot(Phase.REQUEST)], ["block"]
        )
        self.assertEqual(
            [rule.alias for rule in self.registry.snapshot(Phase.RESPONSE)], ["status"]
        )

    def test_a_snapshot_is_a_copy(self):
        """The proxy works through its snapshot while keywords keep changing rules."""
        self.registry.add(make_rule("one"))
        snapshot = self.registry.snapshot()
        self.registry.clear()
        self.assertEqual(len(snapshot), 1)

    def test_priorities_are_ordered_as_documented(self):
        self.assertLess(Priority.TERMINAL, Priority.REPLACE)
        self.assertLess(Priority.REPLACE, Priority.MUTATE)
        self.assertLess(Priority.MUTATE, Priority.TIMING)


class TestConsume(unittest.TestCase):
    def setUp(self):
        self.registry = RuleRegistry()

    def test_an_unlimited_rule_never_runs_out(self):
        rule = make_rule("one", times=0)
        self.registry.add(rule)
        for _ in range(100):
            self.assertTrue(self.registry.consume(rule))
        self.assertEqual(rule.used, 100)
        self.assertFalse(rule.exhausted)

    def test_a_limited_rule_stops_after_its_count(self):
        rule = make_rule("one", times=2)
        self.registry.add(rule)
        self.assertTrue(self.registry.consume(rule))
        self.assertTrue(self.registry.consume(rule))
        self.assertFalse(self.registry.consume(rule))
        self.assertEqual(rule.used, 2)
        self.assertEqual(rule.remaining, 0)

    def test_an_exhausted_rule_stays_visible(self):
        """A rule that silently disappeared would be unexplainable in a Robot log."""
        rule = make_rule("one", times=1)
        self.registry.add(rule)
        self.registry.consume(rule)
        self.registry.consume(rule)
        self.assertIsNotNone(self.registry.get("one"))
        self.assertTrue(rule.exhausted)

    def test_a_removed_rule_is_not_consumed(self):
        """A rule removed between the snapshot and its turn must not fire."""
        rule = make_rule("one")
        self.registry.add(rule)
        self.registry.remove("one")
        self.assertFalse(self.registry.consume(rule))

    def test_a_replaced_rule_is_not_consumed(self):
        """The snapshot holds the old object; only the rule now registered may run."""
        original = make_rule("one")
        self.registry.add(original)
        self.registry.add(make_rule("one", action=StatusAction(500)))
        self.assertFalse(self.registry.consume(original))

    def test_times_is_exact_under_concurrent_use(self):
        """Two requests arriving together must not both claim the last application.

        This is the reason consume() re-checks under the lock rather than the caller
        testing `remaining` first.
        """
        rule = make_rule("one", times=5)
        self.registry.add(rule)
        granted = []
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            for _ in range(100):
                if self.registry.consume(rule):
                    granted.append(1)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(len(granted), 5)
        self.assertEqual(rule.used, 5)


class TestDescription(unittest.TestCase):
    def setUp(self):
        self.registry = RuleRegistry()

    def test_a_rule_reports_its_matching_and_its_action(self):
        rule = make_rule("one", url="/api", action=StatusAction(418), times=3)
        self.registry.add(rule)
        self.registry.consume(rule)
        described = self.registry.describe()[0]
        self.assertEqual(described.alias, "one")
        self.assertEqual(described.url, "/api")
        self.assertEqual(described.match, "substring")
        self.assertEqual(described.method, "ANY")
        self.assertEqual(described.times, 3)
        self.assertEqual(described.remaining, 2)
        self.assertEqual(described.used, 1)
        self.assertEqual(described.phase, "response")
        self.assertEqual(described.type, "status")
        self.assertEqual(described.status_code, 418)

    def test_a_blocking_rule_reports_its_mode(self):
        self.registry.add(make_rule("one", action=BlockAction()))
        described = self.registry.describe()[0]
        self.assertEqual(described.type, "block")
        self.assertEqual(described.mode, "respond")
        self.assertEqual(described.status_code, 403)
        self.assertEqual(described.phase, "request")

    def test_a_resetting_rule_omits_the_status_it_does_not_send(self):
        from MitmLibrary.rules import BlockMode

        self.registry.add(make_rule("one", action=BlockAction(BlockMode.RESET)))
        described = self.registry.describe()[0]
        self.assertEqual(described.mode, "reset")
        self.assertNotIn("status_code", described)

    def test_descriptions_are_in_application_order(self):
        self.registry.add(make_rule("delay", action=DelayAction(1, "1s")))
        self.registry.add(make_rule("response", action=ResponseAction(200)))
        self.assertEqual(
            [described.alias for described in self.registry.describe()],
            ["response", "delay"],
        )


if __name__ == "__main__":
    unittest.main()
