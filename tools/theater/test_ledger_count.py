"""The ledger count must match the ledger. Pinned, because it has drifted twice.

Ledger row 21, in the sense that matters: this file exists because the *count* of
the bug ledger was itself a signal that lied — twice, in the front door of a
repository whose thesis is that controls lie.

  1. `README.md` said "eleven" for six commits after the ledger reached seventeen.
     Corrected by hand.
  2. It then said "seventeen" once the ledger reached twenty, `PRINCIPLES.md`
     repeated "seventeen", and `.github/workflows/reusable-theater.yml` — the file
     every adopting repository calls — still said "eleven".

Correcting prose by hand is what failed, both times. So the count is derived from
the table and asserted against every file that narrates it.

Two shapes were tried and rejected before this one:

  * `grep -c` in the workflow, which is line-based. `README.md` wraps the phrase
    across a newline ("...the twenty times this\ntoolchain lied to us"), so a
    line-oriented check silently validated 2 of the 4 call sites and reported
    CLEAN when "seventeen" was deliberately reintroduced. A check that passes a
    planted defect is the exact defect class this tool is for.
  * Asserting a hardcoded expected count, which is just the stale number again in
    a new file.

Whitespace is therefore normalised across the whole file before matching.
"""

import pathlib
import re
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
LEDGER = REPO / "tools" / "theater" / "README.md"

# A ledger row: a markdown table row whose first cell is the entry number.
LEDGER_ROW = re.compile(r"^\| *(\d+) *\|", re.MULTILINE)

NUMBER_WORDS = [
    "zero", "one", "two", "three", "four", "five", "six", "seven", "eight",
    "nine", "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen",
    "sixteen", "seventeen", "eighteen", "nineteen", "twenty", "twenty-one",
    "twenty-two", "twenty-three", "twenty-four", "twenty-five", "twenty-six",
    "twenty-seven", "twenty-eight", "twenty-nine", "thirty",
]

# Any prose that narrates the count. Deliberately broad on the phrasing after
# "times" so a reworded sentence stays covered rather than silently dropping out
# of the check — the failure mode that let "eleven" survive in the workflow file.
NARRATION = re.compile(
    r"\b(" + "|".join(NUMBER_WORDS) + r")\s+times\b"
    r"(?=[^.]{0,80}?(lied|lie|signal|ledger|toolchain))",
    re.IGNORECASE,
)

# Files searched for a narrated count. Extensions, not a list of paths: a new
# doc that states the count is covered the day it lands.
SEARCH_SUFFIXES = (".md", ".yml", ".yaml")
SKIP_DIRS = {".git", "node_modules", "__pycache__"}


def ledger_rows():
    return LEDGER_ROW.findall(LEDGER.read_text(encoding="utf-8"))


def narrating_files():
    """Every tracked doc that states the count, with whitespace normalised."""
    for path in sorted(REPO.rglob("*")):
        if not path.is_file() or path.suffix not in SEARCH_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path == pathlib.Path(__file__):
            continue
        text = " ".join(path.read_text(encoding="utf-8", errors="ignore").split())
        found = NARRATION.findall(text)
        if found:
            yield path.relative_to(REPO), [w.lower() for w, _ in found]


class TestLedgerCount(unittest.TestCase):
    def test_ledger_table_parses(self):
        """If the table shape changes, fail loudly rather than deriving 0."""
        rows = ledger_rows()
        self.assertGreaterEqual(
            len(rows), 11,
            f"only {len(rows)} ledger rows parsed from {LEDGER} — the table shape "
            "changed and this check would otherwise silently derive a wrong count",
        )

    def test_row_numbers_are_sequential(self):
        """A duplicated or skipped entry number would corrupt the count."""
        nums = [int(n) for n in ledger_rows()]
        self.assertEqual(
            nums, list(range(1, len(nums) + 1)),
            "ledger entry numbers are not 1..N without gaps or repeats",
        )

    def test_a_word_form_exists_for_the_count(self):
        rows = len(ledger_rows())
        self.assertLess(
            rows, len(NUMBER_WORDS),
            f"ledger has {rows} rows but NUMBER_WORDS stops at "
            f"{len(NUMBER_WORDS) - 1} — extend the list",
        )

    def test_at_least_one_file_narrates_the_count(self):
        """Guard against the check passing because it found nothing to check."""
        files = list(narrating_files())
        self.assertTrue(
            files,
            "no file was found narrating the ledger count — either the phrasing "
            "moved outside NARRATION, or SEARCH_SUFFIXES no longer reaches it. "
            "A check with nothing to check is the failure this file guards.",
        )

    def test_every_narrated_count_matches_the_ledger(self):
        rows = len(ledger_rows())
        expected = NUMBER_WORDS[rows]
        stale = [
            (str(path), said)
            for path, words in narrating_files()
            for said in words
            if said != expected
        ]
        self.assertEqual(
            stale, [],
            f"the ledger has {rows} rows ({expected}), but these files say "
            f"otherwise: {stale}. Update the prose, or the count is a signal "
            "that lies — which is what this repository is about.",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
