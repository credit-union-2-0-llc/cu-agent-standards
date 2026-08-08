#!/usr/bin/env python3
"""
Unit tests for check_allowlist_drift.py.

These fixtures deliberately reproduce the SHAPE of the two real incidents
described in that file's module docstring and in
`skills/examples/sanitize-and-theater-gate-rollout.md`'s Landmines section:

  * `TestCommentRewordBreaksALineEntry` — a `line:` entry written to match one
    exact line (including a trailing comment) stops matching once an
    unrelated pull request rewords that comment, even though the sensitive
    substring the entry exists to excuse is still sitting right there.

  * `TestFileRenameBreaksAPathEntry` — a `path:` entry stops matching once the
    file it names is renamed or moved, a common side effect of an unrelated
    refactor.

Each class proves the "before" state is NOT drift (the control) and the
"after" state IS drift (the regression), so a change that made the checker
stop distinguishing the two would fail loudly rather than passing on a
tautology.

Run:
    python3 tools/sanitize/test_check_allowlist_drift.py
    python3 -m unittest discover -s tools/sanitize -v
"""

import io
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import check_allowlist_drift as drift  # noqa: E402


def write_tree(files):
    """Create a temp dir containing {relpath: content}; return the dir."""
    tmp = tempfile.mkdtemp(prefix="cu2driftcheck-")
    for rel, content in files.items():
        full = os.path.join(tmp, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as fh:
            fh.write(content)
    return tmp


def drifted_linenos(root):
    entries, errors = drift.parse_allowlist(
        drift.allowlist_path_for(root))
    found = drift.find_drift(entries, root, tracked_only=False)
    return {e.lineno for e in found}, errors


def run_cli(argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = drift.main(argv)
    return code, buf.getvalue()


# ---------------------------------------------------------------------------
# Incident 1 shape: a comment reword near/on an allowlisted line breaks the
# match, even though the finding it excuses is untouched.
# ---------------------------------------------------------------------------

class TestCommentRewordBreaksALineEntry(unittest.TestCase):

    ORG_SLUG = "credit-union-2-0-llc" + "/cu-agent-standards"

    # The comment text the allowlist entry was ORIGINALLY written against —
    # fixed, the way a real entry is fixed the day someone writes it. Only
    # the file's own comment text varies between the two tests below.
    ORIGINAL_COMMENT = "pinned mirror of the platform gate"

    def _tree(self, current_comment_text):
        workflow = (
            "jobs:\n"
            "  fetch:\n"
            "    steps:\n"
            f"      repository: {self.ORG_SLUG}  # {current_comment_text}\n"
        )
        allow = (
            "# self-reference: this workflow names its own source repo\n"
            f"line:repository: {self.ORG_SLUG}  # {self.ORIGINAL_COMMENT}\n"
        )
        return write_tree({
            "deploy.yml": workflow,
            drift.ALLOWLIST_FILENAME: allow,
        })

    def test_baseline_line_is_not_drifted(self):
        """Control: the entry as originally written still matches its
        exact line. This must pass before the regression case below means
        anything."""
        root = self._tree("pinned mirror of the platform gate")
        try:
            found, errors = drifted_linenos(root)
            self.assertEqual(errors, [])
            self.assertEqual(found, set(),
                              "an untouched allowlisted line must not be "
                              "reported as drifted")
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_rewording_the_trailing_comment_causes_drift(self):
        """Regression: a later, unrelated PR rewords ONLY the trailing
        comment. The sensitive org-slug substring is completely untouched,
        but the entry was written to match the exact line including the old
        comment text, so it silently stops matching -- this is exactly what
        broke a downstream repo's gate twice."""
        root = self._tree("source repo for the reusable workflow")
        try:
            found, errors = drifted_linenos(root)
            self.assertEqual(errors, [])
            self.assertEqual(found, {2},
                              "rewording the comment on an allowlisted line "
                              "must be caught as drift")
        finally:
            shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# Incident 2 shape (generalized): renaming/moving the file a path: entry
# names breaks the match.
# ---------------------------------------------------------------------------

class TestFileRenameBreaksAPathEntry(unittest.TestCase):

    ALLOW = (
        "# theater.yml is the reusable-workflow template; it must name its\n"
        "# own repo, so this path is exempt from the private-org-slug rule.\n"
        "path:^tools/theater/templates/theater\\.yml$\n"
    )
    CONTENT = "name: theater-gate-template\n"

    def test_baseline_path_is_not_drifted(self):
        """Control: the file still lives where the path: entry names it."""
        root = write_tree({
            "tools/theater/templates/theater.yml": self.CONTENT,
            drift.ALLOWLIST_FILENAME: self.ALLOW,
        })
        try:
            found, errors = drifted_linenos(root)
            self.assertEqual(errors, [])
            self.assertEqual(found, set(),
                              "a path: entry whose file still exists at "
                              "that path must not be reported as drifted")
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_renaming_the_file_causes_drift(self):
        """Regression: an unrelated refactor renames the templated file.
        Nothing about the file's CONTENT changed, but the path: entry now
        points at a path nothing in the tree has -- this is the file-rename
        analogue of incident 1's comment-reword drift."""
        root = write_tree({
            "tools/theater/templates/theater-gate.yml": self.CONTENT,
            drift.ALLOWLIST_FILENAME: self.ALLOW,
        })
        try:
            found, errors = drifted_linenos(root)
            self.assertEqual(errors, [])
            self.assertEqual(found, {3},
                              "renaming the file a path: entry names must "
                              "be caught as drift")
        finally:
            shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# Design-decision pin: a line: entry has no per-file scope. If the same
# matching text still exists ANYWHERE in the tracked tree, the entry is not
# drifted -- even if the one file the author had in mind changed shape. This
# is a direct consequence of the .cu2-sanitize-allow format itself (no entry
# ever names "its" file), documented in check_allowlist_drift's module
# docstring; this test pins the behavior deliberately rather than by accident.
# ---------------------------------------------------------------------------

class TestLineEntryMatchesAnywhereInTheTree(unittest.TestCase):

    # Assembled at runtime rather than written as a literal, same convention
    # as test_cu2_sanitize_scan.py and test_fixture_mutations.py use for any
    # sample that would otherwise read as a real *.cu-2.com host: this repo's
    # own sanitize gate runs `--profile public` on itself in CI, and a bare
    # literal here would flip that gate red on this file.
    HOST = "vendor-portal" + ".cu-2.com"

    def test_match_surviving_in_a_different_file_is_not_drift(self):
        root = write_tree({
            "a.md": f"old wording: {self.HOST} is customer-facing\n",
            "b.md": f"unrelated file, also mentions {self.HOST} here\n",
            drift.ALLOWLIST_FILENAME: "line:vendor-portal\\.cu-2\\.com\n",
        })
        try:
            # Reword a.md the way an unrelated PR would -- the match in
            # a.md breaks, but b.md still carries it, so the ENTRY (which
            # has no file scope) is not drifted.
            with open(os.path.join(root, "a.md"), "w", encoding="utf-8") as fh:
                fh.write("new wording, no mention of that host anymore\n")
            found, errors = drifted_linenos(root)
            self.assertEqual(errors, [])
            self.assertEqual(found, set(),
                              "a line: entry must be judged against the "
                              "whole tracked tree, not a single file")
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_removing_the_match_everywhere_is_drift(self):
        root = write_tree({
            "a.md": f"old wording: {self.HOST} is customer-facing\n",
            drift.ALLOWLIST_FILENAME: "line:vendor-portal\\.cu-2\\.com\n",
        })
        try:
            with open(os.path.join(root, "a.md"), "w", encoding="utf-8") as fh:
                fh.write("new wording, no mention of that host anymore\n")
            found, errors = drifted_linenos(root)
            self.assertEqual(errors, [])
            self.assertEqual(found, {1})
        finally:
            shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# Parsing: bare entries, invalid regex, no allowlist file at all.
# ---------------------------------------------------------------------------

class TestParsing(unittest.TestCase):

    def test_bare_entry_is_treated_as_line(self):
        root = write_tree({
            "x.txt": "contoso.vault.azure.net appears here\n",
            drift.ALLOWLIST_FILENAME: "contoso\\.vault\\.azure\\.net\n",
        })
        try:
            entries, errors = drift.parse_allowlist(
                drift.allowlist_path_for(root))
            self.assertEqual(errors, [])
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].kind, "line")
            found, _ = drifted_linenos(root)
            self.assertEqual(found, set())
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_invalid_regex_is_reported_not_raised(self):
        root = write_tree({
            "x.txt": "hello\n",
            drift.ALLOWLIST_FILENAME: "line:(unclosed[\n",
        })
        try:
            entries, errors = drift.parse_allowlist(
                drift.allowlist_path_for(root))
            self.assertEqual(entries, [])
            self.assertEqual(len(errors), 1)
            self.assertEqual(errors[0][0], 1)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_comments_and_blank_lines_are_skipped(self):
        root = write_tree({
            "x.txt": "example.org appears here\n",
            drift.ALLOWLIST_FILENAME: (
                "# a comment\n"
                "\n"
                "line:example\\.org\n"
            ),
        })
        try:
            entries, errors = drift.parse_allowlist(
                drift.allowlist_path_for(root))
            self.assertEqual(errors, [])
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].lineno, 3)
        finally:
            shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# CLI end to end
# ---------------------------------------------------------------------------

class TestCLI(unittest.TestCase):

    def test_no_allowlist_file_is_clean(self):
        root = write_tree({"x.txt": "nothing to see\n"})
        try:
            code, out = run_cli([root])
            self.assertEqual(code, 0)
            self.assertIn("nothing to check", out)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_drift_fails_the_cli_by_default(self):
        root = write_tree({
            "x.txt": "was here once\n",
            drift.ALLOWLIST_FILENAME: "line:no\\-longer\\-present\\-pattern\n",
        })
        try:
            code, out = run_cli([root])
            self.assertEqual(code, 1)
            self.assertIn("drifted entr", out)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_report_mode_never_fails(self):
        root = write_tree({
            "x.txt": "was here once\n",
            drift.ALLOWLIST_FILENAME: "line:no\\-longer\\-present\\-pattern\n",
        })
        try:
            code, out = run_cli([root, "--report"])
            self.assertEqual(code, 0)
            self.assertIn("report mode", out)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_clean_allowlist_passes_the_cli(self):
        root = write_tree({
            "x.txt": "example.org still here\n",
            drift.ALLOWLIST_FILENAME: "line:example\\.org\n",
        })
        try:
            code, out = run_cli([root])
            self.assertEqual(code, 0)
            self.assertIn("CLEAN", out)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_missing_target_is_bad_input(self):
        code, out = run_cli(["/no/such/path/at/all"])
        self.assertEqual(code, 2)


# ---------------------------------------------------------------------------
# Self-consistency: this repository's OWN .cu2-sanitize-allow, checked
# against this repository's OWN tracked files, must be clean. If it is ever
# not, the tool built to catch exactly this has caught it on its own home
# turf -- the strongest possible smoke test.
# ---------------------------------------------------------------------------

class TestSelfConsistency(unittest.TestCase):

    def test_this_repos_own_allowlist_has_not_drifted(self):
        repo_root = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", ".."))
        allow_path = drift.allowlist_path_for(repo_root)
        if not os.path.isfile(allow_path):
            self.skipTest("this checkout has no .cu2-sanitize-allow")
        entries, errors = drift.parse_allowlist(allow_path)
        self.assertEqual(errors, [],
                          f"this repo's own {drift.ALLOWLIST_FILENAME} has "
                          f"an entry that fails to parse: {errors}")
        found = drift.find_drift(entries, repo_root, tracked_only=True)
        self.assertEqual(
            [], [(e.lineno, e.raw) for e in found],
            "this repository's own .cu2-sanitize-allow has drifted -- an "
            "entry no longer matches any tracked file; see "
            "check_allowlist_drift.py's module docstring for what that "
            "means and how to fix it",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
