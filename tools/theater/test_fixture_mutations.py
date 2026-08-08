#!/usr/bin/env python3
r"""
Fixture-mutation smoke test for theater_scan.

WHY THIS FILE EXISTS, AND WHY test_theater_scan.py WAS NOT ENOUGH

test_theater_scan.py already proves every detector fires on a hand-written
positive sample, and it proves the inverse too (`TestFalsePositives`) --
every detector in this repository already ships with both halves of that
test, which is exactly the discipline `tools/sanitize/test_fixture_mutations.py`
added for the sanitizer. What neither suite does is what The Agent Foundry's
`gates/scripts/fixture_smoke.py` does for its own fixtures, and what this
repository's sanitizer harness now does too: start from a document that is
KNOWN GOOD, apply one deliberate, targeted mutation, and assert that mutation
alone is what flips the verdict -- through the real `scan_file()` dispatch
(path gating, detector wiring, declaration handling), not the detector
function called directly in isolation.

That distinction is not academic here. Ledger bug 20 (see tools/theater/README.md)
was exactly a "detector called directly in isolation" blind spot: `detect_t11`'s
unit tests passed throughout, because a unit test calls `detect_t11` directly.
The wiring bug -- the call landing inside `if "T8" in active:` -- was only
reachable by going through `scan_file()`, the same way `--detector T11` is
reached from the CLI. `test_t11_is_reachable_through_the_scan_entry_point` now
pins that one bug by hand. This file generalizes the pattern across every
detector: every mutation below is run through `scan_file()`, never through a
`detect_tN()` call directly, so a future wiring regression in the dispatch
table fails here the same way bug 20 would have.

WHY NINE SEPARATE BASELINE FIXTURES, NOT ONE SHARED DOCUMENT

The sanitizer's fixture-mutation harness mutates one shared prose document,
because every sanitize rule can fire against the same kind of file. Theater's
detectors cannot: T1/T2/T6/T8/T11 only look at `.github/workflows/*.yml`, T4
only looks at a fixed set of config basenames, T12 only looks at JS/TS, and T3
and T5 both read ordinary code but need different shapes of it. A single
shared fixture would either dilute most detectors to inert prose around it, or
force every detector's trigger into one file whose extension only some of them
recognise. So each detector gets its own minimal, independently-verified-clean
fixture file, in its own temporary tree -- and `TestFullPipelineSmoke` below
still exercises all nine at once, laid out at nine distinct paths in a single
tree and run through the real CLI, the same end-to-end shape the sanitizer's
combined-fixture test uses.

THE MUTATION CATALOG (`FIXTURES`) IS CHECKED BIDIRECTIONALLY against the live
`theater_scan.DETECTORS` tuple: a detector added without a fixture fails CI,
and a fixture keyed to a detector id that was renamed or removed also fails
CI. The catalog cannot silently stop covering what it claims to.

A SECOND CLASS OF MUTATION, PAST "DOES IT FIRE": declaring a finding must
annotate it, never delete it. This toolchain has hit that exact failure shape
four separate times, all in the ledger this repository keeps of its own
lies: bug 18 (a `theater-ok` reason that quoted its own idempotent command
exempted the line from `--inventory` entirely), and three same-line-comment
regressions documented directly in test_theater_scan.py's own docstrings for
T3, T11 and T12 (a trailing comment breaking an exact-match regex, or a
`theater-ok` REASON's prose accidentally satisfying the escape-hatch pattern
it was explaining). `TestDeclarationDoesNotSilentlyDeleteAFinding` below
generalizes that regression class into a standing check: for every detector,
declaring its mutation must leave the finding present and marked `declared`,
never make it vanish.

A THIRD CLASS, PAST "IS IT FOUND AT ALL": which profile can see it. T5, T11
and T12 are deliberately excluded from the `gate` profile (see theater_scan.py's
own comments on why), and bug 20 above is proof that a detector's presence in
`DETECTORS` does not guarantee it is reachable from every entry point that is
supposed to reach it. `test_each_mutation_respects_its_gate_profile_membership`
pins the inverse too: a detector NOT in `gate` must not fire when only `gate`
detectors are active, or the backlog-shielding the whole ratchet strategy
depends on would be silently defeated.

NOTE ON SAMPLES: every trigger line below is written the same way
test_theater_scan.py already writes its own T5 samples ("x" + "it(...")-- a
risky keyword is split across a string-concatenation boundary at the source
level, so the literal substring this file's own gate would need to see never
sits contiguous in these bytes. T1/T2/T4/T6/T8/T11/T12's trigger text needs no
such treatment: every one of those detectors gates on the PATH being scanned
(`.github/workflows/*.yml`, a fixed config basename, or a JS/TS extension)
before it ever reads a line, and this file's own path (a `.py` file outside
`.github/workflows/`) satisfies none of those gates. Only T3 and T5 read
ordinary `.py` content the way this file itself is read, and T3's own
detectors are all anchored to the *start* of a line (`^\s*except...`,
`^\s*return...`) -- a pattern this file only ever embeds mid-line inside a
quoted literal, never at a physical line's own start, so no anchor can match
it. T5's SKIP_PATTERNS are unanchored `search()`s, which is the one case that
genuinely needs the split.

Run:
    python3 tools/theater/test_fixture_mutations.py
    python3 -m unittest discover -s tools/theater -v
"""

import io
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import theater_scan as ts  # noqa: E402


# ---------------------------------------------------------------------------
# Harness plumbing
# ---------------------------------------------------------------------------

def write_tree(files):
    tmp = tempfile.mkdtemp(prefix="theater-mutation-")
    for rel, content in files.items():
        full = os.path.join(tmp, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as fh:
            fh.write(content)
    return tmp


def run_cli(argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = ts.main(argv)
    return code, buf.getvalue()


def scan_tree(detector, mutated=False, declared=False, active=None):
    """Build the fixture tree for `detector`, then run the real scan_file()
    pipeline against it -- path gating, detector dispatch, and declaration
    handling exactly as CI exercises them, never `detect_tN()` called
    directly."""
    spec = FIXTURES[detector]
    files = dict(spec.get("extra_files", {}))
    content = spec["baseline"]
    if mutated:
        content += spec["declared_trigger"] if declared else spec["trigger"]
    files[spec["path"]] = content

    tmp = write_tree(files)
    try:
        acts = set(ts.DETECTORS) if active is None else set(active)
        known_scripts = ts.collect_package_scripts(tmp) if "T6" in acts else set()
        target = os.path.join(tmp, spec["path"])
        return ts.scan_file(target, acts, tmp, known_scripts)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# One fixture per detector: a baseline verified clean, plus an undeclared and
# a declared trigger. Every trigger is the minimal shape that flips the
# baseline from silent to firing -- see the module docstring for why nine
# separate fixtures exist instead of one shared document.
# ---------------------------------------------------------------------------

_CLEAN_WF = "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"

_SKIP_MARK = "@pytest.mark" + ".skip(reason='flaky in CI')"

FIXTURES = {

    "T1": {
        "path": ".github/workflows/t1.yml",
        "baseline": _CLEAN_WF,
        "trigger": "      - run: pnpm audit --audit-level=high || true\n",
        "declared_trigger": (
            "      - run: pnpm audit --audit-level=high || true  "
            "# theater-ok: advisory only, tracked separately in the security backlog board\n"
        ),
    },

    "T2": {
        "path": ".github/workflows/t2.yml",
        "baseline": _CLEAN_WF,
        "trigger": "      - name: Post scan\n        continue-on-error: true\n",
        "declared_trigger": (
            "      - name: Post scan\n        continue-on-error: true  "
            "# theater-ok: telemetry only, this step must never gate the deploy pipeline\n"
        ),
    },

    "T3": {
        "path": "app_t3.py",
        "baseline": (
            "def load():\n"
            "    try:\n"
            "        return fetch()\n"
            "    except Exception:\n"
            "        return fallback_list()\n"
        ),
        "trigger": (
            "\n\n"
            "def load_v2():\n"
            "    try:\n"
            "        return fetch()\n"
            "    except Exception:\n"
            "        return []\n"
        ),
        "declared_trigger": (
            "\n\n"
            "def load_v2():\n"
            "    try:\n"
            "        return fetch()\n"
            "    except Exception:\n"
            "        return []  # theater-ok: already logged upstream by the shared retry wrapper\n"
        ),
    },

    "T4": {
        "path": "pyproject.toml",
        "baseline": "[tool.ruff]\nignore = [\"E501\", \"F401\"]\n",
        "trigger": "\n[tool.mypy]\nignore_errors = true\n",
        "declared_trigger": (
            "\n[tool.mypy]\nignore_errors = true  "
            "# theater-ok: legacy vendored bindings module ships no type stubs upstream\n"
        ),
    },

    "T5": {
        "path": "checks_t5.py",
        "baseline": "def test_ok():\n    assert True\n",
        "trigger": (
            "\n\n" + _SKIP_MARK + "\n"
            "def test_flaky():\n    assert True\n"
        ),
        "declared_trigger": (
            "\n\n" + _SKIP_MARK
            + "  # theater-ok: quarantined pending a fix for the shared fixture race\n"
            "def test_flaky():\n    assert True\n"
        ),
    },

    "T6": {
        "path": ".github/workflows/t6.yml",
        "extra_files": {
            "package.json": (
                '{"scripts": {"build": "tsc -p ."}, '
                '"devDependencies": {"typescript": "^5"}}\n'
            ),
        },
        "baseline": (
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: pnpm install --frozen-lockfile\n"
            "      - run: pnpm build\n"
        ),
        "trigger": "      - run: pnpm typecheck\n",
        "declared_trigger": (
            "      - run: pnpm typecheck  "
            "# theater-ok: wired up in a follow-on repo split, tracked in PLAT-441\n"
        ),
    },

    "T8": {
        "path": ".github/workflows/t8.yml",
        "baseline": _CLEAN_WF,
        "trigger": "          exit-code: '0'\n",
        "declared_trigger": (
            "          exit-code: '0'  "
            "# theater-ok: a later step reads the SARIF upload and gates on it directly\n"
        ),
    },

    "T11": {
        "path": ".github/workflows/t11.yml",
        "baseline": _CLEAN_WF,
        "trigger": (
            '      - run: ./scripts/verify-domain.sh || echo '
            '"verification may need a retry once DNS fully propagates"\n'
        ),
        "declared_trigger": (
            '      - run: ./scripts/verify-domain.sh || echo '
            '"verification may need a retry once DNS fully propagates" '
            '# theater-ok: paged separately by the domain-health monitor, not silent\n'
        ),
    },

    "T12": {
        "path": "api_t12.ts",
        "baseline": (
            "export async function loadItems() {\n"
            "  const res = await fetch('/api/items');\n"
            "  return res.json();\n"
            "}\n"
        ),
        "trigger": (
            "\n\n"
            "export async function loadStats() {\n"
            "  const r = await fetch('/api/stats');\n"
            "  if (!r.ok) return [];\n"
            "  return r.json();\n"
            "}\n"
        ),
        "declared_trigger": (
            "\n\n"
            "export async function loadStats() {\n"
            "  const r = await fetch('/api/stats');\n"
            "  if (!r.ok) return []; // theater-ok: 404 is the documented empty-state "
            "response and callers check a loaded flag separately\n"
            "  return r.json();\n"
            "}\n"
        ),
    },
}


# ---------------------------------------------------------------------------
# Coverage + mutation-rejection
# ---------------------------------------------------------------------------

class TestFixtureMutationsCoverTheFullDetectorSet(unittest.TestCase):

    def test_every_active_detector_has_a_mutation(self):
        """A detector added to theater_scan.DETECTORS without a matching
        fixture here is a detector this harness cannot vouch for."""
        for d in ts.DETECTORS:
            with self.subTest(detector=d):
                self.assertIn(d, FIXTURES, f"detector {d!r} has no fixture mutation")

    def test_every_mutation_targets_a_real_detector(self):
        """The inverse: a fixture keyed to a detector id that no longer
        exists (renamed or removed) must also fail, or this catalog could
        silently stop covering anything."""
        detector_ids = set(ts.DETECTORS)
        for d in FIXTURES:
            with self.subTest(detector=d):
                self.assertIn(d, detector_ids,
                               f"fixture {d!r} does not match any current detector id")

    def test_baseline_fixtures_are_themselves_clean(self):
        """The known-good half of 'known-good fixture, mutate, assert
        reject'. If any of these fail, the mutation test for that detector
        is meaningless: it only proves something when the unmutated fixture
        was clean to begin with."""
        for d in FIXTURES:
            with self.subTest(detector=d):
                findings = scan_tree(d, mutated=False)
                self.assertEqual(
                    findings, [],
                    f"the baseline fixture for {d} must be clean before mutation: "
                    f"{findings}",
                )

    def test_each_mutation_is_rejected_by_its_own_detector(self):
        """The core assertion: mutating the known-good fixture for detector X
        must produce a finding attributed to X, through the real scan_file()
        dispatch. If X's regex silently stops matching -- a bad refactor, an
        over-eager exclusion, a path guard tightened one character too far --
        this fails."""
        for d in FIXTURES:
            with self.subTest(detector=d):
                findings = scan_tree(d, mutated=True)
                found = {f.detector for f in findings}
                self.assertIn(
                    d, found,
                    f"mutating the fixture for {d} did not trigger a matching "
                    f"finding (got: {sorted(found)}); the detector may have "
                    "silently stopped working",
                )

    def test_each_mutation_respects_its_gate_profile_membership(self):
        """Catches a detector reachable through a profile that is supposed to
        exclude it (bug 20's exact shape: `detect_t11`'s call landed inside
        `if "T8" in active:`, so it fired regardless of whether T11 itself
        was active) as well as the opposite -- a `gate`-profile detector that
        silently stopped firing when the backlog-shielding detectors are
        switched off."""
        gate = ts.PROFILES["gate"]
        for d in FIXTURES:
            with self.subTest(detector=d):
                found = {f.detector for f in scan_tree(d, mutated=True, active=gate)}
                if d in gate:
                    self.assertIn(
                        d, found,
                        f"{d} is in the gate profile but did not fire when only "
                        "gate detectors were active",
                    )
                else:
                    self.assertNotIn(
                        d, found,
                        f"{d} is deliberately excluded from the gate profile "
                        "(its backlog is not yet triaged) but fired anyway when "
                        "only gate detectors were active -- it is reachable "
                        "through a profile that is supposed to exclude it",
                    )


# ---------------------------------------------------------------------------
# Declaration must annotate a finding, never delete it -- generalizes bug 18
# and the three same-line-comment regressions documented in
# test_theater_scan.py (T3, T11, T12).
# ---------------------------------------------------------------------------

class TestDeclarationDoesNotSilentlyDeleteAFinding(unittest.TestCase):
    """
    This toolchain has made this exact mistake four times, all recorded in
    tools/theater/README.md's ledger or pinned directly in
    test_theater_scan.py's docstrings: a `theater-ok` declaration landing on
    the same line as, or quoting, the very thing it annotates has repeatedly
    broken the regex that was supposed to still recognise the finding --
    which makes the finding vanish UNDECLARED-AND-UNSEEN rather than
    declared-and-inventoried. That is the worst outcome the convention can
    produce: the count drops and nothing records why.

    These tests pin that every detector's declared mutation is still FOUND,
    and marked `declared`, not silently erased.
    """

    def test_declared_mutation_is_still_found_and_marked_declared(self):
        for d in FIXTURES:
            with self.subTest(detector=d):
                findings = scan_tree(d, mutated=True, declared=True)
                matches = [f for f in findings if f.detector == d]
                self.assertTrue(
                    matches,
                    f"the declared mutation for {d} produced no finding attributed "
                    f"to it at all -- a declaration must annotate a finding, never "
                    f"delete it (got: {[(f.detector) for f in findings]})",
                )
                self.assertTrue(
                    any(f.declared for f in matches),
                    f"{d}'s declared mutation was found but none of its findings "
                    f"were marked declared: {matches}",
                )


# ---------------------------------------------------------------------------
# Full-pipeline smoke: every detector tripped at once, through the real CLI
# ---------------------------------------------------------------------------

class TestFullPipelineSmoke(unittest.TestCase):
    """Foundry's fixture_smoke.py validates a whole fixture tree in one pass,
    not detector-by-detector in isolation. This is the equivalent here: one
    tree carrying all nine fixtures at nine distinct paths, run through
    theater_scan.main() the same way CI invokes it, asserting the aggregate
    behaviour end to end."""

    @staticmethod
    def _combined_tree(mutated):
        files = {}
        for spec in FIXTURES.values():
            files.update(spec.get("extra_files", {}))
        for spec in FIXTURES.values():
            content = spec["baseline"]
            if mutated:
                content += spec["trigger"]
            files[spec["path"]] = content
        return files

    def test_every_mutation_together_fails_the_full_cli_gate(self):
        tmp = write_tree(self._combined_tree(mutated=True))
        try:
            code, out = run_cli([tmp, "--profile", "all"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

        self.assertEqual(
            code, 1,
            f"a fixture tripping every detector at once must fail the gate:\n{out}",
        )
        for d in ts.DETECTORS:
            with self.subTest(detector=d):
                self.assertIn(
                    f"[{d}/", out,
                    f"no finding attributed to {d} surfaced when every detector "
                    f"was tripped at once:\n{out}",
                )
        self.assertIn("by detector:", out)

    def test_clean_baseline_alone_passes_the_full_cli_gate(self):
        """The control: the same pipeline, same profile, no mutation."""
        tmp = write_tree(self._combined_tree(mutated=False))
        try:
            code, out = run_cli([tmp, "--profile", "all"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        self.assertEqual(code, 0, f"the unmutated combined baseline must pass:\n{out}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
