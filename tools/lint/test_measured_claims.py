"""Prose claims about this repository's own size must match measurement.

Ledger row 21 and 22, in the sense that matters. Two numbers in this repository
drifted from the thing they described, in a repository whose thesis is that
signals lie:

  * The bug-ledger count was stale in three files — "seventeen" in two and
    "eleven" in the workflow every adopting repo calls, against a 20-row table.
    Pinned by ``tools/theater/test_ledger_count.py``.
  * ``.github/workflows/ci.yml`` narrated "224 tests" and stayed at 224 while the
    suite grew to 277. The comment went stale within a day of being written, in
    the same commit series that fixed the ledger count. Pinned here.

The distinction this file draws, and the reason it is not simply a second
ledger-count test:

  MEASURABLE claims describe this repository and can be recounted from a clean
  checkout — test count, suite count. Those are asserted.

  ESTATE claims describe 92 private repositories at a point in time — "774
  candidates", "92 repositories", "6 T7 findings". Those cannot be reproduced
  from here at all, so asserting them is impossible and pretending otherwise
  would be its own theater. They are instead required to be DATED, so a reader
  can tell a historical measurement from a live one. An undated estate number is
  the failure mode; a dated one is evidence.

Nothing here checks whether an estate figure is *correct*. It checks that the
repository does not present an unreproducible number as if it were current.
"""

import functools
import pathlib
import re
import subprocess
import sys
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]

# Prose that states a count of THIS repository's own suite.
#
# Deliberately narrow. A general `\d+ tests?` pattern was tried first and
# rejected: this repository's docs are full of test counts belonging to OTHER
# repositories, because that is what the scanner reports on — "15 test files had
# never run", "78 test files running on every push", "153 tests" in a skill
# example. Six of that pattern's eight matches were those, and a check whose
# output is mostly false positives gets muted, which is worse than no check.
# So: only phrasings that can ONLY mean this repo's own total.
TEST_CLAIM_RE = re.compile(
    r"\b(\d{2,4})\s+tests?\s+(?:in tools/|across \d+ discovered|across \d+ suites?)"
    r"|\bsuite has\s+(\d{2,4})\s+tests?"
    r"|\b(\d{2,4})\s+tests?\s+of its own",
    re.IGNORECASE,
)
SUITE_CLAIM_RE = re.compile(
    r"\b(\d{1,3})\s+(?:discovered\s+)?suites?\s+(?:under tools/|discovered|in tools/)"
    r"|\bdiscovered\s+(\d{1,3})\s+suites?",
    re.IGNORECASE,
)

# An estate claim: a count of repositories, or of findings across them.
ESTATE_CLAIM_RE = re.compile(
    r"\b\d{2,4}\s+(?:repos|repositories|candidates|findings)\b", re.IGNORECASE
)
# What makes an estate claim legitimate: a date, or an explicit marker that the
# figure is historical / not reproducible from here.
DATED_RE = re.compile(
    r"(20\d{2}-\d{2}-\d{2}"
    r"|\bat (?:that|the) time\b"
    r"|\bhistorical\b"
    r"|\bat the time\b"
    r"|\bcannot be reproduced\b"
    r"|\bpoint in time\b"
    r"|\buntil 20\d{2}\b)",
    re.IGNORECASE,
)

SEARCH_SUFFIXES = (".md", ".yml", ".yaml")
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv"}

# This file quotes stale numbers on purpose, to explain them.
SELF = pathlib.Path(__file__).name

# Skill examples carry illustrative output skeletons ("Audit: 12 findings -> 0",
# "Full scan: 63 findings"). Those are worked examples of what a record looks
# like, not claims about the estate, and dating them would be nonsense.
EXEMPT_FRAGMENTS = ("skills/examples/",)


def sections(path):
    """Yield (label, text) blocks in which a date can legitimately scope claims.

    Markdown is split on headings: a section that opens "Full estate, 92 repos,
    2026-07-28" legitimately dates every figure beneath it, and requiring the date
    on each bullet would be noise a maintainer would strip.

    YAML is treated as one block, because its counts live in a single leading
    comment header that carries its own scope marker.
    """
    raw = path.read_text(encoding="utf-8", errors="ignore")
    if path.suffix in (".yml", ".yaml"):
        yield "(file)", " ".join(raw.split())
        return
    label, buf = "(preamble)", []
    for line in raw.splitlines():
        if re.match(r"^#{1,6}\s+\S", line):
            if buf:
                yield label, " ".join(" ".join(buf).split())
            label, buf = line.strip("# ").strip(), []
        else:
            buf.append(line)
    if buf:
        yield label, " ".join(" ".join(buf).split())


def docs():
    for path in sorted(REPO.rglob("*")):
        if not path.is_file() or path.suffix not in SEARCH_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in path.parts) or path.name == SELF:
            continue
        yield path


@functools.lru_cache(maxsize=1)
def measure():
    """Recount tests and suites the way CI does: by discovery, not a list.

    Cached: this spawns every suite in the repository, including a ~20s one, and
    three test methods below need the answer. Without the cache this file alone
    would triple the suite's runtime — a self-referential test that makes the
    thing it measures slower is a bad trade.

    Skips its own file to avoid recursing into itself.
    """
    suites = [p for p in sorted(REPO.glob("tools/**/test_*.py")) if p.name != SELF]
    total = 0
    for suite in suites:
        proc = subprocess.run(
            [sys.executable, str(suite)],
            capture_output=True, text=True, cwd=REPO,
        )
        m = re.search(r"Ran (\d+) test", proc.stdout + proc.stderr)
        if not m:
            raise AssertionError(f"could not read a test count out of {suite}")
        total += int(m.group(1))
    # This file's own tests count toward the total a reader would see reported.
    own = len(
        [
            name
            for cls in (
                TestMeasurementIsPossible,
                TestNarratedCountsMatchReality,
                TestEstateClaimsAreDated,
            )
            for name in dir(cls)
            if name.startswith("test_")
        ]
    )
    return total + own, len(suites) + 1


class TestMeasurementIsPossible(unittest.TestCase):
    def test_suites_are_discoverable_and_countable(self):
        total, suites = measure()
        self.assertGreaterEqual(
            suites, 6, "fewer suites discovered than the CI floor expects"
        )
        self.assertGreater(total, 0, "discovered suites but counted no tests")


class TestNarratedCountsMatchReality(unittest.TestCase):
    """A prose test/suite count must equal the measured one."""

    def test_no_document_misstates_the_test_count(self):
        total, _ = measure()
        wrong = []
        for path in docs():
            text = " ".join(path.read_text(encoding="utf-8", errors="ignore").split())
            for m in TEST_CLAIM_RE.finditer(text):
                claimed = int(m.group(1))
                if claimed == total:
                    continue
                window = text[max(0, m.start() - 220): m.end() + 220]
                # A historical count is fine if it says so.
                if DATED_RE.search(window):
                    continue
                wrong.append((str(path.relative_to(REPO)), claimed, m.group(0)))
        self.assertEqual(
            wrong, [],
            f"the suite has {total} tests, but these undated claims disagree: {wrong}. "
            "Either correct the number, or mark it historical with a date — an "
            "undated stale count is the defect this repository is named after.",
        )

    def test_no_document_misstates_the_suite_count(self):
        _, suites = measure()
        wrong = []
        for path in docs():
            text = " ".join(path.read_text(encoding="utf-8", errors="ignore").split())
            for m in SUITE_CLAIM_RE.finditer(text):
                if int(m.group(1)) == suites:
                    continue
                window = text[max(0, m.start() - 220): m.end() + 220]
                if DATED_RE.search(window):
                    continue
                wrong.append((str(path.relative_to(REPO)), m.group(0)))
        self.assertEqual(
            wrong, [],
            f"{suites} suites are discovered, but these undated claims disagree: {wrong}",
        )


class TestEstateClaimsAreDated(unittest.TestCase):
    """Estate figures cannot be verified from here, so they must be dated."""

    def test_every_estate_claim_sits_in_a_dated_section(self):
        undated = []
        for path in docs():
            rel = str(path.relative_to(REPO)).replace("\\", "/")
            if any(frag in rel for frag in EXEMPT_FRAGMENTS):
                continue
            for label, text in sections(path):
                # The label counts: a section headed "Measured baseline —
                # 2026-07-31" dates its own contents.
                if DATED_RE.search(label) or DATED_RE.search(text):
                    continue
                for m in ESTATE_CLAIM_RE.finditer(text):
                    undated.append((rel, label, m.group(0)))
        self.assertEqual(
            undated, [],
            "these estate figures describe 92 private repositories and cannot be "
            f"reproduced from this checkout, and the section holding them carries "
            f"no date or caveat: {undated}. Date the section, or say the figure is "
            "historical. A number a reader can neither verify nor date is an "
            "assertion wearing evidence's clothes.",
        )

    def test_the_check_has_something_to_check(self):
        """Guard against passing because the regex stopped matching anything."""
        found = [
            m.group(0)
            for path in docs()
            for _, text in sections(path)
            for m in ESTATE_CLAIM_RE.finditer(text)
        ]
        self.assertTrue(
            found,
            "no estate claims found at all — ESTATE_CLAIM_RE has stopped matching "
            "the prose it was written for, so this test is now inert",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
