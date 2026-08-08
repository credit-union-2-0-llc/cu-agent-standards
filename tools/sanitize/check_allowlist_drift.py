#!/usr/bin/env python3
"""
check_allowlist_drift.py — detect a stale .cu2-sanitize-allow entry.

WHY THIS EXISTS

`.cu2-sanitize-allow` suppresses a finding by matching literal text (a `line:`
regex against file content, or a `path:` regex against a repo-relative path —
see `cu2_sanitize_scan.py`'s `load_allowlist()` and this repo's own
`.cu2-sanitize-allow` for real examples). Nothing ties an entry to the file it
was written against, and nothing re-checks that the text it was written
against still exists. Two consequences, both already lived through in this
org's estate, and both described (in general form, before this tool existed)
under "Landmines" in
`skills/examples/sanitize-and-theater-gate-rollout.md`:

  1. A `line:` entry is usually written to match one exact, specific line —
     often including a trailing comment. A later, unrelated pull request that
     rewords that comment (or the prose next to it) changes the line's text
     just enough that the entry's regex no longer matches it. The sensitive
     substring the entry was suppressing is still sitting right there,
     untouched — so the gate starts failing again, and the failure looks like
     a false alarm about unrelated code because the diff that broke it never
     touched the "finding." This happened for real, twice, in the same
     downstream repository: once when a comment near an allowlisted line was
     reworded, and again — during unrelated hostname-cleanup work — when a
     second CI file started tripping the same "private org repo slug" rule
     that a sibling file's line had been allowlisted for, but this file's own
     line never was. Both times, someone hand-wrote a one-off script to find
     the drift, used it once, and threw it away. This file is that script,
     kept.
  2. A `path:` entry anchors to a specific repo-relative path. Renaming or
     moving that file (a common side effect of an unrelated refactor) leaves
     the entry pointing at a path nothing in the repository has any more —
     silently. If the file still contains what the entry was written to
     excuse, the gate now flags it again under its NEW path; if the file was
     deleted outright, the entry is simply dead weight nobody will ever
     notice.

Both are the same root defect: an allowlist entry is a claim about live
content ("this exact text, currently, is fine to publish"), and nothing ever
re-verifies the claim after the day it was written. This tool re-verifies it.

WHAT "DRIFT" MEANS HERE

The `.cu2-sanitize-allow` format has no per-entry file reference — a `line:`
entry is free-floating: it suppresses ANY line, in ANY tracked file, that its
regex matches. So the right question to ask is not "does this entry still
match the one file someone had in mind" (the format cannot tell you what file
that was), it is the honest, format-faithful equivalent: **does this entry's
pattern still match ANYTHING in the repository's current tracked content?**

  - A `line:` entry drifts when no tracked file contains a line its regex
    matches, anymore.
  - A `path:` entry drifts when no tracked file's repo-relative path matches
    its regex, anymore.

A drifted entry means one of two things, and this tool deliberately does not
guess which: either the finding it was written for is genuinely gone (fixed,
deleted, moved out of scope) and the entry is now dead weight safe to delete,
or the surrounding content changed shape (a reword, a rename) and the entry
needs to be re-pointed at what the content looks like today. Either way, a
human has to look — that is the whole value of surfacing it, the same way an
`unused-suppression` lint surfaces a stale `# noqa`.

WHAT THIS DOES NOT DO

  - It does not re-run `cu2_sanitize_scan.py`'s own rules. A drifted entry
    might currently correspond to zero real findings (nothing there ever
    needed excusing again) or to a live leak (the gate is now un-suppressed
    and would catch it on the next run) — this tool does not distinguish
    those; run the sanitize gate itself to see which one you have.
  - It does not enforce the "broad pattern" / "unanchored path" policy that
    `cu2_sanitize_scan.py`'s own `load_allowlist()` already enforces (that is
    a "this entry is dangerously permissive" check; this is a "this entry no
    longer refers to anything" check — different question, already answered
    elsewhere).
  - It does not know which file an entry was "meant" for, because the format
    does not record one. See "WHAT DRIFT MEANS HERE" above.

USAGE

    python3 tools/sanitize/check_allowlist_drift.py .
    python3 tools/sanitize/check_allowlist_drift.py . --tracked-only
    python3 tools/sanitize/check_allowlist_drift.py . --report   # never fails

Exit codes: `0` clean (or no allowlist file present) · `1` drift found ·
`2` bad input.

This file has no dependency on any single caller repository. Any repository
that vendors `tools/sanitize/cu2_sanitize_scan.py` via the standard
sparse-checkout pattern (see `reusable-sanitize.yml`) gets this file the same
way and can run it standalone against its own `.cu2-sanitize-allow`.
"""

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Reuse the exact file-enumeration semantics the sanitize gate itself scans
# under (same SKIP_DIRS, same --tracked-only behaviour, same self-skip list)
# so this tool answers "is this entry live against what the gate actually
# looks at", not some independently-drifting notion of "the repo's files".
import cu2_sanitize_scan as gate  # noqa: E402

ALLOWLIST_FILENAME = gate.ALLOWLIST_FILENAME


class AllowlistEntry:
    __slots__ = ("lineno", "kind", "pattern", "regex", "raw")

    def __init__(self, lineno, kind, pattern, regex, raw):
        self.lineno = lineno
        self.kind = kind
        self.pattern = pattern
        self.regex = regex
        self.raw = raw


def allowlist_path_for(target):
    """Same lookup rule as gate.load_allowlist: the file lives next to
    `target` if target is a directory, or next to target's containing
    directory if target is a file."""
    base = target if os.path.isdir(target) else (os.path.dirname(target) or ".")
    return os.path.join(base, ALLOWLIST_FILENAME)


def parse_allowlist(allow_path):
    """Parse .cu2-sanitize-allow into entries, preserving line numbers.

    Mirrors the `line:` / `path:` / bare-line-means-`line:` syntax documented
    in tools/sanitize/.cu2-sanitize-allow.example and implemented in
    gate.load_allowlist. Kept as an independent, small parser (rather than
    calling gate.load_allowlist directly) because that function intentionally
    discards line numbers and entry text once it has compiled a regex list —
    exactly the information this tool needs to report *which* entry drifted.

    Returns (entries, parse_errors). parse_errors is a list of
    (lineno, message) for a line whose regex does not compile; such lines are
    skipped rather than crashing the run — cu2_sanitize_scan.py's own gate
    already surfaces an invalid or dangerously-broad allowlist line as a
    blocking "[config]" finding, so this tool does not need to re-adjudicate
    that policy to still usefully report on every entry that DOES compile.
    """
    entries = []
    parse_errors = []

    if not os.path.isfile(allow_path):
        return entries, parse_errors

    with open(allow_path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.rstrip("\n")
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            kind, pattern = "line", stripped
            if stripped.startswith("line:"):
                pattern = stripped[len("line:"):].strip()
            elif stripped.startswith("path:"):
                kind, pattern = "path", stripped[len("path:"):].strip()

            try:
                regex = re.compile(pattern)
            except re.error as exc:
                parse_errors.append((lineno, f"invalid regex ({exc}): {pattern!r}"))
                continue

            entries.append(AllowlistEntry(lineno, kind, pattern, regex, stripped))

    return entries, parse_errors


def find_drift(entries, root, tracked_only=False):
    """Return the subset of `entries` whose pattern matches nothing live.

    Single pass over the file set for efficiency: every `path:` entry is
    checked against every tracked path (cheap, no file I/O), and every
    `line:` entry is checked against every line of every tracked text file,
    stopping early per-entry the moment any match is found anywhere.
    """
    line_entries = [e for e in entries if e.kind == "line"]
    path_entries = [e for e in entries if e.kind == "path"]

    line_matched = {e.lineno: False for e in line_entries}
    path_matched = {e.lineno: False for e in path_entries}

    for full_path in gate.iter_files(root, tracked_only=tracked_only):
        rel = os.path.relpath(full_path, root).replace(os.sep, "/")

        for e in path_entries:
            if not path_matched[e.lineno] and e.regex.search(rel):
                path_matched[e.lineno] = True

        remaining_line_entries = [e for e in line_entries if not line_matched[e.lineno]]
        if not remaining_line_entries:
            continue

        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                for text_line in fh:
                    for e in remaining_line_entries:
                        if not line_matched[e.lineno] and e.regex.search(text_line):
                            line_matched[e.lineno] = True
                    if all(line_matched[e.lineno] for e in remaining_line_entries):
                        break
        except OSError:
            continue

    drifted = [e for e in line_entries if not line_matched[e.lineno]]
    drifted += [e for e in path_entries if not path_matched[e.lineno]]
    drifted.sort(key=lambda e: e.lineno)
    return drifted


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="check_allowlist_drift",
        description="Verify every .cu2-sanitize-allow entry still matches "
                    "live tracked content. Catches an allowlist that has "
                    "silently gone stale (reworded comment, renamed file) "
                    "-- see this file's module docstring for the two real "
                    "incidents this closes.",
    )
    p.add_argument("target", nargs="?", default=".",
                   help="repo root (or a file inside it) to check "
                        "(default: .)")
    p.add_argument("--tracked-only", action="store_true",
                   help="check against git-tracked files only, matching how "
                        "the sanitize gate itself runs in CI")
    p.add_argument("--report", action="store_true",
                   help="print findings but always exit 0 (for visibility, "
                        "not for CI)")
    p.add_argument("--quiet", action="store_true",
                   help="suppress per-entry output; print the summary only")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    target = args.target

    if not os.path.exists(target):
        sys.stderr.write(f"error: path not found: {target}\n")
        return 2

    root = target if os.path.isdir(target) else "."
    allow_path = allowlist_path_for(target)

    if not os.path.isfile(allow_path):
        if not args.quiet:
            print(f"check_allowlist_drift: no {ALLOWLIST_FILENAME} found at "
                  f"{allow_path} -- nothing to check.")
        return 0

    entries, parse_errors = parse_allowlist(allow_path)
    rel_allow = os.path.relpath(allow_path, root).replace(os.sep, "/")

    for lineno, message in parse_errors:
        if not args.quiet:
            print(f"{rel_allow}:{lineno}: [parse-error] {message}")

    drifted = find_drift(entries, root, tracked_only=args.tracked_only)

    for e in drifted:
        if not args.quiet:
            print(f"{rel_allow}:{e.lineno}: [{e.kind}] pattern no longer "
                  f"matches any tracked {'path' if e.kind == 'path' else 'line'}")
            print(f"    | {e.raw}")

    total_problems = len(drifted) + len(parse_errors)

    print()
    if total_problems == 0:
        print(f"check_allowlist_drift: CLEAN. {len(entries)} entr"
              f"{'y' if len(entries) == 1 else 'ies'} in {rel_allow}, "
              f"all still match live tracked content.")
        return 0

    print(f"check_allowlist_drift: {len(drifted)} drifted entr"
          f"{'y' if len(drifted) == 1 else 'ies'}, {len(parse_errors)} parse "
          f"error(s) in {rel_allow}.")
    print("A drifted entry means either the finding it excused is gone "
          "(delete the entry) or the content it pointed at changed shape "
          "(a reworded comment, a rename) and the entry needs updating -- "
          "see this file's module docstring. Either way it needs a human, "
          "not a re-run.")

    if args.report:
        print("  report mode: exiting 0 without failing.")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
