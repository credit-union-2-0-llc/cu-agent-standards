#!/usr/bin/env python3
"""Self-test for the override-staleness detector.

Run before the detector is trusted to judge anyone else's repository — the
reusable workflow does exactly that, mirroring the theater gate.

unittest rather than bare asserts so `Ran N tests` is emitted, which is how
ci.yml's discovery and tools/lint/test_measured_claims.py count this suite.
Zero dependencies, so it runs on a bare ubuntu-latest with no install step.

The cases are the real ones from the 2026-09-07 estate sweep, not invented
shapes. Where a case exists to stop a FALSE POSITIVE it says so, because a
security gate that cries wolf gets switched off and then protects nothing.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from semver_lite import (  # noqa: E402
    satisfies, min_patched, parse_version, is_exact_version,
)
from check_override_staleness import (  # noqa: E402
    split_override_key,
    parse_yaml_overrides,
    pin_is_dead,
    evaluate,
)


class TestSemverLite(unittest.TestCase):
    def test_parse_version(self):
        self.assertEqual(parse_version("3.1.6"), (3, 1, 6))
        self.assertEqual(parse_version("v1.2"), (1, 2, 0))
        self.assertEqual(parse_version("1.2.3-rc.1"), (1, 2, 3))

    def test_a_range_is_not_a_concrete_version(self):
        # This is what distinguishes an EXACT pin from a RANGE pin downstream.
        self.assertIsNone(parse_version("^1.2.3"))
        self.assertIsNone(parse_version(">=3.1.5 <4"))
        self.assertIsNone(parse_version(None))

    def test_advisory_strings_as_pnpm_audit_emits_them(self):
        # Comma-and-space form and bare-space form must both work.
        self.assertTrue(satisfies("3.1.5", ">= 3.0.0, < 3.1.6"))
        self.assertFalse(satisfies("3.1.6", ">= 3.0.0, < 3.1.6"))
        self.assertTrue(satisfies("3.1.5", ">=3.0.0 <3.1.6"))
        self.assertTrue(satisfies("6.15.2", ">= 6.14.2, <= 6.15.3"))
        self.assertFalse(satisfies("6.16.0", ">= 6.14.2, <= 6.15.3"))
        self.assertTrue(satisfies("7.1.5", "<8.0.0"))

    def test_caret_tilde_wildcard_and_or(self):
        self.assertTrue(satisfies("3.1.6", "^3.1.5"))
        self.assertFalse(satisfies("4.0.0", "^3.1.5"))
        self.assertTrue(satisfies("3.1.9", "~3.1.5"))
        self.assertFalse(satisfies("3.2.0", "~3.1.5"))
        self.assertTrue(satisfies("9.9.9", "*"))
        self.assertTrue(satisfies("2.1.0", "^1.0.0 || ^2.0.0"))

    def test_unparseable_input_is_false_never_true(self):
        # Failing closed matters more than being clever: a range we cannot read
        # must not silently satisfy anything.
        self.assertFalse(satisfies("1.0.0", "not-a-range"))
        self.assertFalse(satisfies("garbage", ">=1.0.0"))

    def test_min_patched(self):
        self.assertEqual(min_patched(">=3.1.6"), "3.1.6")
        self.assertEqual(min_patched(">= 6.16.0"), "6.16.0")
        self.assertIsNone(min_patched(""))

    def test_min_patched_takes_the_lowest_floor_across_or_branches(self):
        # Returning the FIRST floor would report 3.0.0 here and then condemn a
        # '^2.0.0' pin that legitimately reaches 2.1.0.
        self.assertEqual(min_patched(">=3.0.0 || >=2.1.0"), "2.1.0")

    def test_partial_versions_are_x_ranges_not_exact_pins(self):
        # npm/pnpm read '3.1' as '>=3.1.0 <3.2.0', so it REACHES 3.1.6.
        # Treating it as the exact version 3.1.0 would condemn a healthy pin.
        self.assertFalse(is_exact_version("3.1"))
        self.assertFalse(is_exact_version("3"))
        self.assertTrue(is_exact_version("3.1.6"))
        self.assertTrue(satisfies("3.1.6", "3.1"))
        self.assertFalse(satisfies("3.2.0", "3.1"))
        self.assertTrue(satisfies("3.9.9", "3"))
        self.assertTrue(satisfies("3.1.6", "3.1.x"))


class TestOverrideKeySplitting(unittest.TestCase):
    def test_plain_and_selector_keys(self):
        self.assertEqual(split_override_key("fast-uri"), ("fast-uri", None))
        self.assertEqual(
            split_override_key("fast-uri@>=3.0.0 <3.1.5"),
            ("fast-uri", ">=3.0.0 <3.1.5"),
        )

    def test_pnpm_parent_selector_targets_the_CHILD(self):
        # 'qar@1>zoo' overrides `zoo` where it is a dependency of qar@1. The
        # overridden package is what follows the last '>', never the parent.
        # Reading the parent means a `zoo` advisory never matches, is filed as
        # upstream, and the gate returns 0 while the caller still forces a
        # vulnerable zoo. Real keys of this shape are in the estate today:
        # 'minimatch@3>brace-expansion'.
        self.assertEqual(split_override_key("qar@1>zoo"), ("zoo", None))
        self.assertEqual(
            split_override_key("minimatch@3>brace-expansion"),
            ("brace-expansion", None),
        )
        self.assertEqual(
            split_override_key("foo@^1.0.0>@scope/bar@<2.0.0"),
            ("@scope/bar", "<2.0.0"),
        )

    def test_parent_selector_advisory_actually_matches(self):
        # End-to-end version of the above: the advisory is for the CHILD.
        adv = {"module_name": "brace-expansion", "severity": "high",
               "vulnerable_versions": "<1.1.18", "patched_versions": ">=1.1.18"}
        held, upstream = evaluate(
            [adv], {"minimatch@3>brace-expansion": [("1.1.17", "package.json overrides")]})
        self.assertEqual([h["module_name"] for h in held], ["brace-expansion"])
        self.assertEqual(upstream, [])

    def test_scoped_package_keeps_its_leading_at(self):
        # A scoped package BEGINS with '@'. Splitting on the FIRST '@' would
        # yield ('', 'xmldom/xmldom') and the gate would silently stop covering
        # every scoped package — the same silent-coverage-loss class it exists
        # to catch.
        self.assertEqual(
            split_override_key("@xmldom/xmldom"), ("@xmldom/xmldom", None))
        self.assertEqual(
            split_override_key("@xmldom/xmldom@<0.8.13"),
            ("@xmldom/xmldom", "<0.8.13"),
        )


YAML = """packages:
  - 'apps/*'

overrides:
  postcss: 8.5.23
  'fast-uri@<3.1.5': '3.1.5'
  # a comment inside the block
  "@hono/node-server": 1.19.17
  '@xmldom/xmldom': 0.8.13

minimumReleaseAge: 10080
"""


class TestYamlOverrideParsing(unittest.TestCase):
    def setUp(self):
        self.pins = parse_yaml_overrides(YAML)

    def test_reads_plain_quoted_and_scoped_keys(self):
        self.assertEqual(self.pins.get("postcss"), ["8.5.23"])
        self.assertEqual(self.pins.get("fast-uri@<3.1.5"), ["3.1.5"])
        self.assertEqual(self.pins.get("@hono/node-server"), ["1.19.17"])
        self.assertEqual(self.pins.get("@xmldom/xmldom"), ["0.8.13"])

    def test_block_boundaries(self):
        self.assertNotIn("minimumReleaseAge", self.pins)  # stops at next top key
        self.assertNotIn("packages", self.pins)           # ignores keys above
        self.assertEqual(parse_yaml_overrides("packages:\n  - a\n"), {})


class TestPinIsDead(unittest.TestCase):
    def test_the_real_regression(self):
        # 2026-09-07: fast-uri pinned 3.1.5, advisory had widened to < 3.1.6.
        self.assertTrue(pin_is_dead("3.1.5", ">= 3.0.0, < 3.1.6", ">=3.1.6"))
        self.assertFalse(pin_is_dead("3.1.6", ">= 3.0.0, < 3.1.6", ">=3.1.6"))

    def test_range_pins_that_reach_the_fix_are_alive(self):
        # FALSE-POSITIVE GUARD. A first pass on the estate sweep coerced range
        # pins to their floor and wrongly condemned two repositories whose pins
        # ('>=3.1.5 <4.0.0', '^6.15.2') both reach the patched version.
        self.assertFalse(
            pin_is_dead("^6.15.2", ">= 6.14.2, <= 6.15.3", ">=6.16.0"))
        self.assertFalse(
            pin_is_dead(">=3.1.5 <4.0.0", ">= 3.0.0, < 3.1.6", ">=3.1.6"))

    def test_a_range_that_cannot_reach_the_fix_is_dead(self):
        self.assertTrue(
            pin_is_dead("~6.15.2", ">= 6.14.2, <= 6.15.3", ">=6.16.0"))

    def test_no_expressible_patched_floor_is_not_condemned(self):
        self.assertFalse(pin_is_dead("^1.0.0", "<2.0.0", None))

    def test_partial_pin_is_treated_as_a_range(self):
        # A '3.1' pin reaches 3.1.6, so it is NOT dead — another false-positive
        # guard. '3.0' cannot reach 3.1.6, so that one is.
        self.assertFalse(pin_is_dead("3.1", ">= 3.0.0, < 3.1.6", ">=3.1.6"))
        self.assertTrue(pin_is_dead("3.0", ">= 3.0.0, < 3.1.6", ">=3.1.6"))


ADV_FAST_URI = {
    "module_name": "fast-uri", "severity": "high",
    "vulnerable_versions": ">= 3.0.0, < 3.1.6", "patched_versions": ">=3.1.6",
}
# deepmerge-ts arrives via @prisma/config — nothing any calling repo pins, so
# failing on it would turn the gate red for something nobody there can fix.
ADV_UPSTREAM = {
    "module_name": "deepmerge-ts", "severity": "high",
    "vulnerable_versions": "<8.0.0", "patched_versions": ">=8.0.0",
}


class TestEvaluate(unittest.TestCase):
    def test_routes_held_versus_upstream(self):
        held, upstream = evaluate(
            [ADV_FAST_URI, ADV_UPSTREAM],
            {"fast-uri@<3.1.5": [("3.1.5", "pnpm-workspace.yaml")]},
        )
        self.assertEqual([h["module_name"] for h in held], ["fast-uri"])
        self.assertEqual(held[0]["pins"][0]["pinned"], "3.1.5")
        self.assertEqual(held[0]["pins"][0]["home"], "pnpm-workspace.yaml")
        self.assertEqual([u["module_name"] for u in upstream], ["deepmerge-ts"])

    def test_a_fixed_pin_is_not_held_but_is_still_reported(self):
        held, upstream = evaluate(
            [ADV_FAST_URI], {"fast-uri@<3.1.6": [("3.1.6", "pnpm-workspace.yaml")]})
        self.assertEqual(held, [])
        # It must not vanish: still an open advisory, just not ours to force.
        self.assertEqual([u["module_name"] for u in upstream], ["fast-uri"])

    def test_no_advisories_holds_nothing(self):
        self.assertEqual(evaluate([], {"qs": [("6.16.0", "x")]}), ([], []))


if __name__ == "__main__":
    unittest.main(verbosity=2)
