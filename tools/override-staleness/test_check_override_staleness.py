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

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from semver_lite import (  # noqa: E402
    satisfies, min_patched, parse_version, is_exact_version,
)
from check_override_staleness import (  # noqa: E402
    split_override_key,
    parse_yaml_overrides,
    pin_is_dead,
    evaluate,
    pinned_pnpm_version,
    pnpm_cmd,
    run_audit,
    main,
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


def _which(*present):
    """A `shutil.which` that finds only the named tools."""
    return lambda name: "/usr/bin/" + name if name in present else None


# What `pnpm audit --json` really emits, measured 2026-10-06 with corepack
# pnpm@9.15.9 / 10.18.3 / 11.1.3. A report ALWAYS has an `advisories` dict
# (empty when clean) and a `metadata` dict; 9 and 10 add `actions` and `muted`.
# A failed audit is a JSON object with only `error`, and pnpm exits 1 for both,
# so the exit code cannot tell them apart; only the shape can.
_METADATA = {"vulnerabilities": {"info": 0, "low": 0, "moderate": 0, "high": 0, "critical": 0},
             "dependencies": 1, "devDependencies": 0, "optionalDependencies": 0,
             "totalDependencies": 1}
CLEAN_REPORT = {"actions": [], "advisories": {}, "muted": [], "metadata": _METADATA}
PNPM10_ERROR = {"error": {"code": "ECONNREFUSED",
                          "message": "request to http://127.0.0.1:9/-/npm/v1/security/audits "
                                     "failed, reason: connect ECONNREFUSED 127.0.0.1:9"}}
PNPM11_ERROR = {"error": {"code": "pnpm", "message": "fetch failed"}}


class _Proc:
    def __init__(self, stdout, stderr="", returncode=1):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


class TestPnpmCommand(unittest.TestCase):
    """How `pnpm audit` is reached on a host that may have no `pnpm` on PATH.

    2026-10-06: the Spark nightly wolf runner has corepack but no `pnpm`, and a
    bare `["pnpm", "audit", "--json"]` failed with ENOENT on 5 repositories
    (`override_pins incomplete`). The command now mirrors the wolf's own
    `_pnpm_cmd` (cu2-standards tools/wolf/wolves/override_pins.py): the repo's
    `packageManager` pin through corepack, else bare `pnpm`. No real pnpm or
    corepack is ever run here; `shutil.which` and `subprocess.run` are mocked.
    """

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)

    def write_pkg(self, content):
        with open(os.path.join(self.root, "package.json"), "w", encoding="utf-8") as fh:
            fh.write(content if isinstance(content, str) else json.dumps(content))

    def test_the_command_is_built_from_package_manager(self):
        self.write_pkg({"packageManager": "pnpm@11.1.3"})
        self.assertEqual(pinned_pnpm_version(self.root), "11.1.3")
        self.assertEqual(pnpm_cmd(self.root, which=_which("corepack")),
                         ["corepack", "pnpm@11.1.3"])

    def test_corepack_integrity_suffix_is_dropped(self):
        self.write_pkg({"packageManager": "pnpm@9.15.9+sha512.abc123"})
        self.assertEqual(pnpm_cmd(self.root, which=_which("corepack", "pnpm")),
                         ["corepack", "pnpm@9.15.9"])

    def test_a_full_sha512_integrity_suffix_is_still_pinned(self):
        # The form `corepack use pnpm@x` writes into package.json.
        self.write_pkg({"packageManager": "pnpm@10.18.3+sha512." + "0f" * 64})
        self.assertEqual(pinned_pnpm_version(self.root), "10.18.3")

    def test_a_prerelease_pin_is_unpinned_never_truncated(self):
        # Reading `pnpm@11.1.3-rc.1` as 11.1.3 would audit with a version the
        # repo does not run. Unpinned means bare pnpm, never a wrong corepack.
        for pm in ("pnpm@11.1.3-rc.1", "pnpm@11.1.3-alpha", "pnpm@11.1.3junk",
                   "pnpm@11.1.3+", "pnpm@11.1.3+sha512.", "pnpm@11.1.3+sha512.xyz",
                   "pnpm@11.1.3+md5.abc", "pnpm@11.1.3 ", " pnpm@11.1.3"):
            with self.subTest(packageManager=pm):
                self.write_pkg({"packageManager": pm})
                self.assertIsNone(pinned_pnpm_version(self.root))
                self.assertEqual(pnpm_cmd(self.root, which=_which("corepack", "pnpm")),
                                 ["pnpm"])

    def test_corepack_is_preferred_over_a_pnpm_on_path(self):
        # The pinned version is the one the repo's own CI runs; a stray global
        # pnpm of another major must not win just because it is on PATH.
        self.write_pkg({"packageManager": "pnpm@11.1.3"})
        self.assertEqual(pnpm_cmd(self.root, which=_which("corepack", "pnpm")),
                         ["corepack", "pnpm@11.1.3"])

    def test_falls_back_to_bare_pnpm_when_corepack_is_absent(self):
        self.write_pkg({"packageManager": "pnpm@11.1.3"})
        self.assertEqual(pnpm_cmd(self.root, which=_which("pnpm")), ["pnpm"])

    def test_without_a_pin_corepack_is_never_used(self):
        # An unpinned corepack installs the LATEST pnpm (pnpm 12 broke Docker
        # builds that way), so no pin means bare pnpm or nothing.
        self.write_pkg({"name": "x"})
        self.assertEqual(pnpm_cmd(self.root, which=_which("corepack", "pnpm")), ["pnpm"])
        self.assertIsNone(pnpm_cmd(self.root, which=_which("corepack")))

    def test_nothing_runnable_is_none(self):
        self.write_pkg({"packageManager": "pnpm@11.1.3"})
        self.assertIsNone(pnpm_cmd(self.root, which=_which()))

    def test_malformed_package_manager_is_treated_as_unpinned(self):
        for bad in ("pnpm@latest", "pnpm@11", "pnpm", "yarn@4.1.0", "npm@10.0.0",
                    "", 11, None, ["pnpm@11.1.3"]):
            with self.subTest(packageManager=bad):
                self.write_pkg({"packageManager": bad})
                self.assertIsNone(pinned_pnpm_version(self.root))
                self.assertEqual(pnpm_cmd(self.root, which=_which("corepack", "pnpm")),
                                 ["pnpm"])

    def test_unreadable_or_absent_package_json_is_unpinned(self):
        self.assertIsNone(pinned_pnpm_version(self.root))  # no package.json at all
        for bad in ("{not json", "[]", '"pnpm@11.1.3"'):
            with self.subTest(package_json=bad):
                self.write_pkg(bad)
                self.assertIsNone(pinned_pnpm_version(self.root))

    def test_run_audit_runs_the_chosen_command_with_json(self):
        self.write_pkg({"packageManager": "pnpm@11.1.3"})
        out = json.dumps(CLEAN_REPORT)
        with mock.patch("check_override_staleness.shutil.which", _which("corepack")), \
                mock.patch("check_override_staleness.subprocess.run",
                           return_value=_Proc(out, returncode=0)) as run:
            self.assertEqual(run_audit(self.root), CLEAN_REPORT)
        argv = run.call_args.args[0]
        self.assertEqual(argv, ["corepack", "pnpm@11.1.3", "audit", "--json"])
        self.assertEqual(run.call_args.kwargs["cwd"], self.root)
        env = run.call_args.kwargs["env"]
        # A corepack download prompt in a cron job is a hang.
        self.assertEqual(env["COREPACK_ENABLE_DOWNLOAD_PROMPT"], "0")
        self.assertEqual(env["CI"], "true")

    def test_audit_env_carries_the_corepack_guards_and_the_callers_environment(self):
        # Each guard is pinned on its own: deleting either from run_audit's env
        # must turn this red. AUTO_PIN off = corepack never rewrites the
        # caller's package.json; DOWNLOAD_PROMPT off = no hang waiting on a
        # prompt nobody answers. The caller's environment must still reach
        # pnpm (PATH, registry auth, proxies), so a sentinel rides along.
        self.write_pkg({"packageManager": "pnpm@11.1.3"})
        out = json.dumps(CLEAN_REPORT)
        with mock.patch.dict(os.environ, {"OVERRIDE_STALENESS_SENTINEL": "kept"}), \
                mock.patch("check_override_staleness.shutil.which", _which("corepack")), \
                mock.patch("check_override_staleness.subprocess.run",
                           return_value=_Proc(out)) as run:
            # A host that already exports these (a dev Mac did) would let a
            # deleted guard pass unnoticed, so the inherited env must lack them.
            for inherited in ("COREPACK_ENABLE_AUTO_PIN", "COREPACK_ENABLE_DOWNLOAD_PROMPT", "CI"):
                os.environ.pop(inherited, None)
            run_audit(self.root)
        env = run.call_args.kwargs["env"]
        self.assertEqual(env.get("COREPACK_ENABLE_AUTO_PIN"), "0")
        self.assertEqual(env.get("COREPACK_ENABLE_DOWNLOAD_PROMPT"), "0")
        self.assertEqual(env.get("CI"), "true")
        self.assertEqual(env.get("OVERRIDE_STALENESS_SENTINEL"), "kept")

    def test_nothing_runnable_is_a_clear_error_and_nothing_is_executed(self):
        self.write_pkg({"packageManager": "pnpm@11.1.3"})
        with mock.patch("check_override_staleness.shutil.which", _which()), \
                mock.patch("check_override_staleness.subprocess.run") as run:
            with self.assertRaises(RuntimeError) as ctx:
                run_audit(self.root)
        run.assert_not_called()
        msg = str(ctx.exception)
        self.assertIn("could not execute `pnpm audit`", msg)
        self.assertIn("corepack", msg)
        self.assertIn("pnpm@11.1.3", msg)

    def test_an_exec_failure_keeps_the_existing_message(self):
        self.write_pkg({"name": "x"})
        boom = FileNotFoundError(2, "No such file or directory", "pnpm")
        with mock.patch("check_override_staleness.shutil.which", _which("pnpm")), \
                mock.patch("check_override_staleness.subprocess.run", side_effect=boom):
            with self.assertRaises(RuntimeError) as ctx:
                run_audit(self.root)
        self.assertTrue(str(ctx.exception).startswith("could not execute `pnpm audit`: "))

    def test_empty_and_invalid_output_still_fail(self):
        self.write_pkg({"name": "x"})
        for stdout, expected in (("", "produced no output"), ("not json", "not valid JSON")):
            with self.subTest(stdout=stdout), \
                    mock.patch("check_override_staleness.shutil.which", _which("pnpm")), \
                    mock.patch("check_override_staleness.subprocess.run",
                               return_value=_Proc(stdout, "boom")):
                with self.assertRaises(RuntimeError) as ctx:
                    run_audit(self.root)
                self.assertIn(expected, str(ctx.exception))

    def audit_with_stdout(self, stdout, returncode=1):
        self.write_pkg({"name": "x"})
        with mock.patch("check_override_staleness.shutil.which", _which("pnpm")), \
                mock.patch("check_override_staleness.subprocess.run",
                           return_value=_Proc(stdout, returncode=returncode)):
            return run_audit(self.root)

    def test_a_pnpm_error_result_is_a_failure_not_a_clean_audit(self):
        # Fail-open guard: pnpm prints valid JSON when the audit endpoint fails.
        # Read as a report, it has no advisories and the gate would say OK.
        for err in (PNPM10_ERROR, PNPM11_ERROR):
            with self.subTest(code=err["error"]["code"]):
                with self.assertRaises(RuntimeError) as ctx:
                    self.audit_with_stdout(json.dumps(err))
                self.assertIn(err["error"]["code"], str(ctx.exception))
                self.assertIn(err["error"]["message"][:20], str(ctx.exception))

    def test_a_report_without_advisories_or_metadata_is_rejected(self):
        for bad in ({"metadata": _METADATA},                       # no advisories
                    {"advisories": {}},                            # no metadata
                    {"advisories": [], "metadata": _METADATA},     # wrong type
                    {"advisories": {}, "metadata": None},
                    {}, [], [CLEAN_REPORT], "ok", 0, None):
            with self.subTest(report=bad):
                with self.assertRaises(RuntimeError) as ctx:
                    self.audit_with_stdout(json.dumps(bad))
                self.assertIn("not a pnpm audit report", str(ctx.exception))

    def test_a_nonzero_exit_with_a_valid_report_is_accepted(self):
        # pnpm exits 1 whenever it FINDS vulnerabilities: that is a real result.
        report = dict(CLEAN_REPORT, advisories={"1": {"module_name": "fast-uri"}})
        self.assertEqual(self.audit_with_stdout(json.dumps(report), returncode=1), report)
        self.assertEqual(self.audit_with_stdout(json.dumps(CLEAN_REPORT), returncode=0),
                         CLEAN_REPORT)

    def test_main_exits_2_on_a_pnpm_error_result(self):
        self.write_pkg({"name": "x"})
        with open(os.path.join(self.root, "pnpm-lock.yaml"), "w", encoding="utf-8") as fh:
            fh.write("lockfileVersion: '9.0'\n")
        with mock.patch("check_override_staleness.shutil.which", _which("pnpm")), \
                mock.patch("check_override_staleness.subprocess.run",
                           return_value=_Proc(json.dumps(PNPM11_ERROR))), \
                mock.patch("sys.stdout"):
            self.assertEqual(main(["check_override_staleness.py", self.root]), 2)

    def test_subprocess_error_is_wrapped(self):
        self.write_pkg({"name": "x"})
        with mock.patch("check_override_staleness.shutil.which", _which("pnpm")), \
                mock.patch("check_override_staleness.subprocess.run",
                           side_effect=subprocess.SubprocessError("killed")):
            with self.assertRaises(RuntimeError):
                run_audit(self.root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
