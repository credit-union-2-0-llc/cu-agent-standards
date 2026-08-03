#!/usr/bin/env python3
"""
theater_scan.py — CU 2.0 verification-theater detector.

Finds controls that exist, are relied upon, and do not check the thing everyone
believes they check. Pure Python 3 standard library: no dependencies, no
network, no secrets.

    sanitize gate  -> stops sensitive content leaving a repo
    theater gate   -> stops a control from lying about whether it ran

Seven detectors:

    T1  suppressed CI step        `|| true` on a step that is supposed to gate
    T2  continue-on-error         the declarative form of T1
    T3  silent-empty return       [] / {} / pass returned from except|catch
    T4  correctness rule off      F821, strict:false, noImplicitAny:false
    T5  skipped tests             coverage claimed but never executed
    T6  phantom npm/pnpm script   CI invokes a script that does not exist
    T7  red scheduled workflow    (needs the GitHub API — see workflow_health.py)
    T8  non-gating scanner        exit-code: '0' / soft_fail: true on a scan
    T12 unchecked HTTP failure  `if (!res.ok) return []` — a failed request
                                returns the same value as an empty result

WHY DECLARATION, NOT CLEVERNESS

`|| true` is correct on an advisory step and wrong on a gate. No regex can read
intent. So beyond a small built-in list of genuinely idempotent infrastructure
commands, this tool does not guess: an undeclared suppression is reported, and a
declared one passes and is inventoried.

    - run: pnpm audit --audit-level=high || true   # theater-ok: advisory, tracked RISK-123

A declaration needs a specific reason. "theater-ok: intentional" is rejected,
for the same reason the sanitize gate rejects an allowlist entry of `.*`.

THE BUG THAT JUSTIFIES THIS FILE

The first sweep written for this work reported 490 skipped tests. Its pattern
`xit(` was matching `exit(`. The real number was 39 — a 12x inflation, produced
by the tool built to find inflated signals. Every detector below therefore ships
with a false-positive regression test, not merely a positive one. See
test_theater_scan.py::TestFalsePositives.

Posture: fail closed. Exit 0 clean, 1 findings, 2 bad input.
"""

import argparse
import json
import os
import re
import sys
from collections import Counter, namedtuple

# ---------------------------------------------------------------------------
# Declared suppressions
# ---------------------------------------------------------------------------

# `#` for YAML/Python, `//` and `/* */` for JS/TS.
#
# Only `#` was accepted, so the declared-suppression convention has NEVER worked in a
# .ts/.js/.tsx file — for T3 and T4 as much as for T12. That is consistent with the
# estate census: all 39 declaration lines found across 9 repositories sit in GitHub
# workflow YAML, and not one is in application code. The convention was documented in
# SUPPRESSIONS.md as available everywhere while being silently unusable in half the
# estate's languages.
#
# Worse than merely unrecognised: for T12 a `//`-commented declaration prevented the
# finding from being detected AT ALL rather than annotating it, so declaring one
# deleted it from the count.
DECLARATION_RE = re.compile(
    r"(?:#|//|/\*)\s*theater-ok:\s*(?P<reason>.+?)\s*(?:\*/)?\s*$")

# A reason that explains nothing. Rejected so the convention cannot decay into
# a rubber stamp.
GENERIC_REASONS = {
    "advisory", "ok", "okay", "fine", "intentional", "intended", "known",
    "todo", "wip", "n/a", "na", "temporary", "temp", "by design", "expected",
    "needed", "required", "legacy", "later", "skip", "ignore",
}
MIN_REASON_CHARS = 12

# ---------------------------------------------------------------------------

SEVERITIES = ("high", "medium")

DETECTORS = ("T1", "T2", "T3", "T4", "T5", "T6", "T8", "T11", "T12")

PROFILES = {
    # The set worth failing a build over.
    "gate": {"T1", "T2", "T3", "T4", "T6", "T8"},
    "all": set(DETECTORS),
}
# T11 is deliberately NOT in `gate`. It was added with ~36 existing candidates measured
# across 11 repos; gating on a class before its backlog is triaged is how a gate gets
# switched off. Promote it once the standing count is declared or fixed — same path T5
# has never been promoted along, and for the same reason.

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".mypy_cache", ".pytest_cache", "dist", "build", ".idea", ".vscode",
    ".next", "coverage", ".turbo", "vendor",
}

SKIP_PATH_PREFIXES = (
    ".claude/worktrees/",
    ".playwright-mcp/",
    ".planning-temp/",
)

SELF_SKIP_NAMES = {"theater_scan.py", ".theater-allow"}

CODE_EXTS = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
MAX_TEXT_BYTES = 2_000_000

Finding = namedtuple("Finding", "path line detector severity message evidence declared reason")

# ---------------------------------------------------------------------------
# T1 — suppressed CI step
# ---------------------------------------------------------------------------

SUPPRESSION_RE = re.compile(r"(\|\|\s*true\b|\|\|\s*:\s*$|\|\|\s*exit\s+0\b|;\s*true\s*$)")

# Commands where a non-zero exit is genuinely expected and harmless: idempotent
# creates, best-effort deletes, and diagnostics. These are the ~13 of 15 hits in
# the baseline sweep that are correct as written.
IDEMPOTENT_PATTERNS = [
    re.compile(r"\baz\s+[\w-]+(?:\s+[\w-]+)?\s+delete\b"),
    re.compile(r"\baz\s+extension\s+add\b"),
    re.compile(r"\baz\s+[\w-]+\s+hostname\s+add\b"),
    re.compile(r"\bmkdir\b"),
    re.compile(r"\brm\s+-"),
    re.compile(r"\bunlink\b"),
    re.compile(r"\bdocker\s+(?:rmi|rm|stop|kill)\b"),
    re.compile(r"\b(?:kill|pkill|killall)\b"),
    re.compile(r"^\s*cat\s+\S"),
    re.compile(r"\bcat\s+/tmp/"),
    re.compile(r"\bnpm\s+cache\s+clean\b"),
    re.compile(r"\bgit\s+(?:branch|remote|tag)\s+-d\b"),
]


def _is_idempotent(line):
    return any(p.search(line) for p in IDEMPOTENT_PATTERNS)


# A trailing comment must not participate in code matching. Two real bugs came from
# matching the whole line: a `# theater-ok:` reason that happened to quote
# "az containerapp hostname add" satisfied IDEMPOTENT_PATTERNS and exempted its own
# line, which then vanished from --inventory entirely (declared-by-prose); and prose
# mentioning `|| true` in a trailing comment reads as a suppression.
_COMMENT_SPLIT_RE = re.compile(r"""
    ^(?P<code>(?:[^'"#]|'[^']*'|"[^"]*")*)   # code, with quoted spans kept intact
    (?P<comment>\#.*)?$                       # first unquoted # starts the comment
""", re.VERBOSE)


def _split_comment(line):
    """Split a shell line into (code, comment). A `#` inside quotes is not a comment."""
    m = _COMMENT_SPLIT_RE.match(line)
    if not m:
        return line, ""
    return m.group("code") or "", m.group("comment") or ""


# `printf '... || true ...'` / `echo "... || true ..."` — the suppression is INSIDE a
# string literal being emitted, so it belongs to whatever consumes that output, not to
# this step's exit status. cu2-billing/seed-kv.yml emits an ACA Job manifest this way and
# the `|| true` in it governs a container that runs later, elsewhere.
_EMITTED_LITERAL_RE = re.compile(r"^\s*(?:printf|echo)\s+[\'\"]")


def _is_emitted_literal(code):
    """True when the line's own command is printf/echo and the suppression sits in its
    quoted argument rather than in an executed command."""
    if not _EMITTED_LITERAL_RE.match(code):
        return False
    # Strip quoted spans; if no suppression survives, it was only ever inside the literal.
    bare = re.sub(r"'[^']*'", "", code)
    bare = re.sub(r'"[^"]*"', "", bare)
    return not SUPPRESSION_RE.search(bare)


def detect_t1(path, lines):
    if not _is_workflow(path):
        return []
    out = []
    for i, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        code, _comment = _split_comment(line)
        if not SUPPRESSION_RE.search(code):
            continue
        if _is_idempotent(code):
            continue
        if _is_emitted_literal(code):
            continue
        declared, reason = _declaration(line)
        out.append(_mk(path, i, "T1", "high",
                       "CI step cannot fail — suppression on a step that should gate",
                       line, declared, reason))
    return out


# ---------------------------------------------------------------------------
# T2 — continue-on-error
# ---------------------------------------------------------------------------

CONTINUE_RE = re.compile(r"^\s*continue-on-error:\s*true\s*(?:#.*)?$")


def detect_t2(path, lines):
    if not _is_workflow(path):
        return []
    out = []
    for i, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        if not CONTINUE_RE.match(line):
            continue
        # A declaration may sit on this line or on the step's `name:` line above.
        declared, reason = _declaration(line)
        if not declared:
            for back in lines[max(0, i - 6):i - 1]:
                d, r = _declaration(back.rstrip("\n"))
                if d:
                    declared, reason = d, r
                    break
        out.append(_mk(path, i, "T2", "high",
                       "Step failure is ignored — the job reports success regardless",
                       line, declared, reason))
    return out


# ---------------------------------------------------------------------------
# T3 — silent-empty return from an exception handler
# ---------------------------------------------------------------------------

# Two `except …: pass` shapes that are correct code, appear in the estate, and
# are mechanically distinguishable — so they belong here rather than in a human's
# triage queue. Measured at 3 of 30 sampled T3 rows, i.e. roughly 40 of 428.
#
#   1. pytest expected-exception: inside a test file, `except SomeError: pass`
#      after a call that is supposed to raise IS the assertion. Bare
#      `except Exception: pass` in a test is still reported — that swallows
#      everything and asserts nothing.
#   2. `except asyncio.CancelledError: pass` when awaiting a task during
#      shutdown. Cancellation is the expected outcome, not a swallowed failure.
TEST_PATH_RE = re.compile(r"(?:^|/)(?:tests?|__tests__)/|(?:^|/)(?:test_[^/]*|[^/]*_test|[^/]*\.spec|[^/]*\.test)\.[a-z]+$")
EXPECTED_EXC_RE = re.compile(
    r"^\s*except\s+(?!Exception\b|BaseException\b)"
    r"[A-Za-z_][\w.]*(?:\s*\([^)]*\))?(?:\s+as\s+\w+)?\s*:\s*$")
CANCELLED_RE = re.compile(r"^\s*except\s+(?:asyncio\.)?CancelledError(?:\s+as\s+\w+)?\s*:\s*$")


def _expected_exception_handler(path, opener):
    """True when a bare `pass` under `opener` is correct rather than swallowing."""
    if CANCELLED_RE.match(opener):
        return True
    return bool(TEST_PATH_RE.search(path) and EXPECTED_EXC_RE.match(opener))


HANDLER_RE = re.compile(r"^\s*(?:\}\s*)?(?:except\b[^:]*:|catch\s*(?:\([^)]*\))?\s*\{?)\s*$")
HANDLER_INLINE_RE = re.compile(r"^\s*(?:\}\s*)?(?:except\b[^:]*:|catch\s*(?:\([^)]*\))?\s*\{?)\s*(?P<body>.+)$")
EMPTY_RETURN_RE = re.compile(r"^\s*return\s*(?:\[\s*\]|\{\s*\}|\[\s*\]\s*;|\{\s*\}\s*;)\s*;?\s*$")
SWALLOW_RE = re.compile(r"^\s*pass\s*$")

# A `class`/`def` line is never itself a handler opener, but unlike an ordinary
# statement it marks a hard scope boundary: the backward window must not cross
# it to attribute a `pass`/`return` to some unrelated except/catch further back.
# Real case: `class BudgetExceeded(Exception):\n    pass` sitting a few blank
# lines below an unrelated `except Exception as exc:` block in the same file --
# the window found that distant except within its 4-line cap (skipping the two
# blank lines) and flagged the class body's own trivial `pass` as a swallowed
# exception. A class/def's `pass` is that construct's body, never a handler's.
_BLOCK_BOUNDARY_RE = re.compile(r"^\s*(?:class\s|def\s|async\s+def\s)")


def _strip_code_comment(line):
    """Strip a trailing `#...` or `//...` comment (whichever appears first, outside
    a quoted string) so T3's exact-match regexes see the code, not prose glued onto
    the same line. Three real, previously-invisible findings forced this:
    `except FooError:  # noqa: BLE001` failed HANDLER_RE (the trailing comment broke
    the `$` anchor, so the opener was never recognised at all); `pass  # explanation`
    failed SWALLOW_RE the same way; and `return []  # theater-ok: reason` failed
    EMPTY_RETURN_RE, which made a DECLARATION delete its own finding instead of
    annotating it — the single worst outcome for the convention. All three are now
    findable regardless of what a trailing comment says; `_declaration()` still runs
    against the ORIGINAL (unstripped) line so a same-line `theater-ok` is read
    correctly once the code beneath it is recognised."""
    in_squote = in_dquote = False
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if in_squote:
            in_squote = c != "'"
        elif in_dquote:
            in_dquote = c != '"'
        elif c == "'":
            in_squote = True
        elif c == '"':
            in_dquote = True
        elif c == "#" or (c == "/" and i + 1 < n and line[i + 1] == "/"):
            return line[:i]
        i += 1
    return line


def detect_t3(path, lines):
    if os.path.splitext(path)[1] not in CODE_EXTS:
        return []
    out = []
    for i, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        code = _strip_code_comment(line)

        # Same-line form: `catch { return []; }` / `except Exception: return []`
        m = HANDLER_INLINE_RE.match(code)
        if m and (EMPTY_RETURN_RE.match(" " + m.group("body").rstrip("}").strip())
                  or SWALLOW_RE.match(" " + m.group("body").rstrip("}").strip())):
            declared, reason = _declaration(line)
            out.append(_mk(path, i, "T3", "high",
                           "Exception handler returns empty — callers cannot tell "
                           "'nothing found' from 'lookup broke'",
                           line, declared, reason))
            continue

        # Block form: a handler opener within the previous 4 significant lines.
        if not (EMPTY_RETURN_RE.match(code) or SWALLOW_RE.match(code)):
            continue
        window, j = [], i - 2
        while j >= 0 and len(window) < 4:
            prev = lines[j].rstrip("\n")
            if prev.strip():
                prev_code = _strip_code_comment(prev)
                window.append(prev)
                if _BLOCK_BOUNDARY_RE.match(prev_code) and not HANDLER_RE.match(prev_code):
                    break  # crossed into an unrelated class/def; stop looking further back
            j -= 1
        window_code = [_strip_code_comment(w) for w in window]
        openers = [w for w in window_code if HANDLER_RE.match(w)]
        if not openers:
            continue
        if SWALLOW_RE.match(code) and _expected_exception_handler(path, openers[0]):
            continue
        declared, reason = _declaration(line)
        if not declared:
            for w in window:
                d, r = _declaration(w)
                if d:
                    declared, reason = d, r
                    break
        kind = "returns empty" if EMPTY_RETURN_RE.match(code) else "swallows the exception"
        out.append(_mk(path, i, "T3", "high",
                       f"Exception handler {kind} — the failure becomes indistinguishable "
                       "from a legitimate empty result",
                       line, declared, reason))
    return out


# ---------------------------------------------------------------------------
# T4 — correctness rule suppressed
# ---------------------------------------------------------------------------

CONFIG_NAMES = {
    "pyproject.toml", "setup.cfg", "ruff.toml", ".ruff.toml", "mypy.ini",
    "tsconfig.json", "tsconfig.base.json", ".eslintrc.json", ".eslintrc",
}

# Style preferences (F401 unused import, E501 line length) are not in here on
# purpose. These are rules whose violation is a runtime crash.
CORRECTNESS_SUPPRESSIONS = [
    (re.compile(r"\bF821\b"), "F821 (undefined name) suppressed — hides real NameErrors"),
    (re.compile(r'"strict"\s*:\s*false'), "TypeScript strict mode disabled"),
    (re.compile(r'"noImplicitAny"\s*:\s*false'), "noImplicitAny disabled"),
    (re.compile(r'"strictNullChecks"\s*:\s*false'), "strictNullChecks disabled"),
    (re.compile(r"ignore_errors\s*=\s*[Tt]rue"), "mypy ignore_errors enabled"),
    (re.compile(r"\bno-undef\b.*(?:off|0)\b"), "eslint no-undef disabled"),
]


def detect_t4(path, lines):
    if os.path.basename(path) not in CONFIG_NAMES:
        return []
    out = []
    for i, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        if line.strip().startswith("#"):
            continue
        for rx, msg in CORRECTNESS_SUPPRESSIONS:
            if rx.search(line):
                declared, reason = _declaration(line)
                out.append(_mk(path, i, "T4", "high", msg, line, declared, reason))
                break
    return out


# ---------------------------------------------------------------------------
# T5 — skipped tests
#
# `\bxit\(` is deliberate. Without the word boundary this matches `exit(`, which
# is what inflated the first sweep from 39 to 490.
# ---------------------------------------------------------------------------

JSON_ONLY_SKIP_RE = re.compile(r"passWithNoTests")

SKIP_PATTERNS = [
    re.compile(r"\b(?:it|test|describe|context)\.skip\s*\("),
    re.compile(r"\bxit\s*\("),
    re.compile(r"\bxdescribe\s*\("),
    re.compile(r"@pytest\.mark\.skip"),
    re.compile(r"\bunittest\.skip\b"),
    re.compile(r"passWithNoTests"),
]


# T1 and T4 already skip comment lines. T5 did not, so it reported six findings
# across the estate that were *documentation about* skipped tests rather than
# skipped tests — including a docstring reading "Converts Wave 0 it.skip() stubs
# to active passing tests", i.e. a note that the skips had been removed. A
# commented-out test is deleted code, not suppressed coverage.
COMMENT_LINE_RE = re.compile(r"^\s*(?:#|//|\*|/\*)")


def detect_t5(path, lines):
    ext = os.path.splitext(path)[1]
    if ext not in CODE_EXTS and ext != ".json":
        return []
    # JSON is scanned ONLY for `passWithNoTests`, which is why it was included
    # at all — it appears in jest config, not in code.
    #
    # THE FOURTEENTH PINNED BUG, found by dogfooding. Applying the code patterns
    # to .json meant that this project's own committed inventory —
    # sweep-results.json, verdicts_*.json — was detected as theater, because the
    # `evidence` field of a recorded T5 finding literally contains the text
    # `it.skip('...')`. 321 findings in one repo, every one a record OF a
    # finding. Test-skip syntax cannot be executable code inside JSON.
    patterns = [JSON_ONLY_SKIP_RE] if ext == ".json" else SKIP_PATTERNS
    out = []
    for i, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        if COMMENT_LINE_RE.match(line):
            continue
        for rx in patterns:
            if rx.search(line):
                declared, reason = _declaration(line)
                out.append(_mk(path, i, "T5", "medium",
                               "Test is skipped — coverage is claimed but not executed",
                               line, declared, reason))
                break
    return out


# ---------------------------------------------------------------------------
# T6 — phantom npm/pnpm script
# ---------------------------------------------------------------------------

SCRIPT_CALL_RE = re.compile(
    r"\b(?:pnpm|npm|yarn)\s+(?:run\s+)?(?P<script>[a-z][a-z0-9:_-]{2,})\b")

PACKAGE_MANAGER_BUILTINS = {
    "run", "install", "i", "ci", "add", "remove", "up", "update", "audit",
    "exec", "dlx", "why", "list", "ls", "outdated", "publish", "pack", "link",
    "config", "init", "create", "cache", "store", "prune", "rebuild", "dedupe",
    "workspace", "recursive", "filter", "version", "login", "logout", "whoami",
    "set", "get", "fund", "doctor", "deploy", "licenses", "patch", "approve",
    "install-test", "node", "npx", "test",
    # Added after the Phase 1 sweep: `npm view` and `npm sbom` are real
    # subcommands and were being reported as phantom scripts.
    "view", "sbom", "search", "ping", "star", "unstar", "team", "org", "owner",
    "access", "token", "profile", "hook", "diff", "explain", "explore", "edit",
    "bugs", "docs", "repo", "help", "completion", "shrinkwrap", "unpublish",
    "deprecate", "dist-tag", "pkg", "query", "env", "root", "prefix", "bin",
    "server", "start", "stop", "restart", "setup", "self-update", "import",
    "rebuild-lockfile", "fetch", "server-status",
}

# Binaries whose command name differs from the package that provides them. When
# a repo depends on the package, `pnpm <binary>` is a passthrough to
# node_modules/.bin, not a call to a package.json script.
BINARY_TO_PACKAGE = {
    "tsc": "typescript",
    "tsx": "tsx",
    "nest": "@nestjs/cli",
    "ng": "@angular/cli",
    "prisma": "prisma",
    "playwright": "@playwright/test",
    "cap": "@capacitor/cli",
    "wrangler": "wrangler",
    "biome": "@biomejs/biome",
}


def _read_package_json(path):
    """Parsed package.json, or None. Never {} — a parse failure is not an empty file."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def collect_package_scripts(root):
    """
    Names `pnpm <name>` may legitimately resolve to anywhere in the tree.

    Two kinds, deliberately merged into one set:

      1. package.json `scripts` keys — the obvious case.
      2. Binaries the dependency tree provides. `pnpm prisma migrate deploy` and
         `pnpm tsc --noEmit` are passthroughs to node_modules/.bin, not scripts.

    WHY (2) EXISTS — THE FOURTH SELF-INFLICTED BUG IN THIS TOOLCHAIN. The first
    full-estate sweep reported 11 T6 findings and every single one was wrong:
    `pnpm prisma` x5, `pnpm tsc`, `npm view`, `npm sbom`. A detector that is
    100% false positives is not a weak detector, it is theater — it manufactures
    the confident-but-untrue signal this taxonomy exists to eliminate. Modelling
    the package managers' resolution order was rejected as exactly the
    cleverness the README warns against; asking "did you install a thing by this
    name" is a fact on disk. See test_theater_scan.py::TestFalsePositives::
    test_t6_ignores_dependency_provided_binaries.
    """
    names = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if "package.json" not in filenames:
            continue
        data = _read_package_json(os.path.join(dirpath, "package.json"))
        if data is None:
            continue
        names.update((data.get("scripts") or {}).keys())

        deps = set()
        for field in ("dependencies", "devDependencies", "optionalDependencies",
                      "peerDependencies"):
            section = data.get(field)
            if isinstance(section, dict):
                deps.update(section.keys())

        for dep in deps:
            # An unscoped dep usually installs a binary of the same name.
            names.add(dep.rsplit("/", 1)[-1] if dep.startswith("@") else dep)
        for binary, package in BINARY_TO_PACKAGE.items():
            if package in deps:
                names.add(binary)
    return names


def detect_t6(path, lines, known_scripts=None):
    if not _is_workflow(path) or known_scripts is None:
        return []
    out = []
    for i, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        if line.strip().startswith("#"):
            continue
        for m in SCRIPT_CALL_RE.finditer(line):
            script = m.group("script")
            if script in PACKAGE_MANAGER_BUILTINS or script in known_scripts:
                continue
            if script.startswith("-") or "/" in script:
                continue
            declared, reason = _declaration(line)
            out.append(_mk(path, i, "T6", "high",
                           f"CI invokes '{script}', which no package.json defines — "
                           "the step cannot do what it claims",
                           line, declared, reason))
            break
    return out


# ---------------------------------------------------------------------------
# T8 — a scanner configured so it cannot fail
#
# Found during Phase 2 triage, in four repos. Neither T1 nor T2 sees it, because
# the step carries no `|| true` and no `continue-on-error` — the action's own
# options do the work:
#
#     - uses: aquasecurity/trivy-action@...
#       with:
#         severity: HIGH,CRITICAL
#         exit-code: '0'          # scans, reports, and cannot fail
#
# This is a purer instance of the defect class than either T1 or T2. The step is
# green, the SARIF uploads, the badge is present, and the threshold can never
# trip. Nothing about the workflow looks suppressed.
#
# `exit-code: '0'` is LEGITIMATE when a later step reads the SARIF and gates on
# it — cu2-billing does exactly that. As everywhere else in this tool, that is
# resolved by declaration rather than by cleverness.
# ---------------------------------------------------------------------------

NON_GATING_SCAN_RE = [
    (re.compile(r"^\s*exit[-_]code:\s*['\"]?0['\"]?\s*(?:#.*)?$"),
     "Scanner is configured with exit-code 0 — it reports findings and cannot "
     "fail the build"),
    (re.compile(r"^\s*soft[-_]fail:\s*true\s*(?:#.*)?$"),
     "Scanner is configured soft_fail — it reports findings and cannot fail "
     "the build"),
]


# NB the detector id is T11, not T9. T7 and T9 belong to workflow_health.py and T10 to
# orphan_tests.py — the taxonomy is shared across every tool under tools/, not per-file.
ECHO_SUPPRESSION_RE = re.compile(r"\|\|\s*echo\b")
# A `|| echo` that emits a GitHub annotation is a VISIBLE soft gate: it shows up in the
# run summary and the Files-changed view, so a human can see it fired. Plain-text echo
# goes to stdout only, where it is indistinguishable from `|| true` unless somebody opens
# the log. That distinction is the whole basis of this detector, and it is the same call
# CU2 made deliberately for `alembic check || echo '::warning::'` — kept, because the
# annotation is visible — versus the kirk-helper #365 hostname bind, which was fixed.
ANNOTATION_RE = re.compile(r"\|\|\s*echo\s*[\'\"]?::(?:warning|error|notice)\b")


def detect_t11(path, lines):
    """T11 — exit status discarded by `|| echo <plain text>`.

    T1's SUPPRESSION_RE matches `|| true`, `|| :`, `|| exit 0` and `; true`. It does NOT
    match `|| echo`, which swallows an exit status exactly as completely. That gap hid a
    real instance of the originating incident: Onramp-'s domain-setup.yml ended its
    `az containerapp hostname bind` with `|| echo "Bind may need retry after DNS fully
    propagates"`, and the step named "Verify domain binding" then printed a tick
    unconditionally. Identical shape to kirk-helper #365, invisible to T1.
    """
    if not _is_workflow(path):
        return []
    out = []
    for i, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        if line.strip().startswith("#"):
            continue
        code, _comment = _split_comment(line)
        if not ECHO_SUPPRESSION_RE.search(code):
            continue
        if ANNOTATION_RE.search(code):
            continue           # visible annotation — a soft gate, not a silent one
        if _is_idempotent(code):
            continue
        if _is_emitted_literal(code):
            continue
        declared, reason = _declaration(line)
        out.append(_mk(path, i, "T11", "medium",
                       "exit status discarded by `|| echo` — the step reports success "
                       "and prints a message no one is required to read",
                       line, declared, reason))
    return out


def detect_t8(path, lines):
    if not _is_workflow(path):
        return []
    out = []
    for i, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        if line.strip().startswith("#"):
            continue
        for rx, msg in NON_GATING_SCAN_RE:
            if rx.match(line):
                declared, reason = _declaration(line)
                out.append(_mk(path, i, "T8", "high", msg, line, declared, reason))
                break
    return out


# ---------------------------------------------------------------------------
# Plumbing
# ---------------------------------------------------------------------------

WORKFLOW_PATH_RE = re.compile(r"(?:^|/)\.github/workflows/")


def _is_workflow(path):
    """Matches both repo-root-relative and nested workflow paths."""
    norm = path.replace(os.sep, "/")
    return bool(WORKFLOW_PATH_RE.search(norm)) and norm.endswith((".yml", ".yaml"))


def _declaration(line):
    """Return (declared, reason). A generic reason does not count as declared."""
    m = DECLARATION_RE.search(line)
    if not m:
        return False, None
    reason = m.group("reason").strip()
    if reason.lower().rstrip(".") in GENERIC_REASONS or len(reason) < MIN_REASON_CHARS:
        return False, reason
    return True, reason


# ---------------------------------------------------------------------------
# T12 — HTTP failure branch that returns an empty value instead of raising
# ---------------------------------------------------------------------------
#
# THE GAP THIS CLOSES. T3 only looks inside `except`/`catch`, so it cannot see the
# branch that actually fires in a browser: `fetch` does NOT reject on 4xx/5xx, it
# resolves with `ok: false`. A wrapper written as
#
#     const res = await apiFetch(url);
#     if (!res.ok) return [];
#
# never throws, so there is no catch block for T3 to find — and the caller receives
# the same `[]` for "the server returned 500" as for "there are no rows".
#
# Found by hand in xdi-implementations-os: 28 sites of exactly this shape across
# apps/web/src/app/dashboard/**, none visible to T3, in a repo whose `apiFetch`
# never throws on a non-2xx. Fixing only that repo's catch blocks would have
# produced a clean T3 count over a UI that still renders empty tables when the API
# is down.
#
# NOT in the `gate` profile, for the same reason T11 is not: it lands with a real
# and unmeasured backlog, and a detector that turns 88 repos red on day one gets
# switched off rather than acted on. Promote once the standing count is declared.
HTTP_FAIL_COND_RE = re.compile(
    r"""^\s*if\s*\(?\s*
        (?:
            !\s*[A-Za-z_$][\w$]*\s*(?:\.|\?\.)ok\b
          | [A-Za-z_$][\w$]*\s*(?:\.|\?\.)ok\s*===?\s*false
          | [A-Za-z_$][\w$]*\s*(?:\.|\?\.)status\s*
                (?:!==?\s*(?:200|201|204)\b|>=\s*(?:400|300)\b)
        )
    """,
    re.VERBOSE)

# Returning an empty COLLECTION, null/undefined, or nothing at all. Deliberately NOT
# `return false` and NOT `return { error }`: a boolean or an error object is a
# sentinel a caller can branch on, which is a different and defensible design.
# Flagging those would bury the real finding in noise.
HTTP_FAIL_EMPTY_RE = re.compile(
    r"""^\s*return\s*
        (?:\[\s*\]|\{\s*\}|null|undefined|''|""|``|)\s*;?\s*$""",
    re.VERBOSE)

# An escape hatch that makes the failure observable is fine and must not be flagged.
HTTP_FAIL_OK_RE = re.compile(
    r"\b(?:throw|reject|process\.exit|assert|captureException|notifyError|"
    r"setError|toast|console\.(?:error|warn))\b")

JS_EXTS = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}


def detect_t12(path, lines):
    """T12 — a non-2xx response returns the same empty value as "no data"."""
    if os.path.splitext(path)[1] not in JS_EXTS:
        return []
    if TEST_PATH_RE.search(path):
        return []                      # a test asserting this shape is not the defect
    out = []
    for i, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        if COMMENT_LINE_RE.match(line):
            continue
        if not HTTP_FAIL_COND_RE.match(line):
            continue

        # Body: the rest of this line, else the next significant lines up to the
        # closing brace. Handles `if (!res.ok) return [];` and the braced form.
        after = line.split(")", 1)[1] if ")" in line else ""
        body = [after.strip().lstrip("{").strip()]
        j = i
        while j < len(lines) and len(body) < 4:
            nxt = lines[j].rstrip("\n")
            j += 1
            if not nxt.strip():
                continue
            body.append(nxt.strip())
            if nxt.strip().startswith("}"):
                break

        # Trailing braces/semicolons are stripped before matching: the single-line
        # braced form `if (r.status !== 200) { return {}; }` leaves a dangling `}` on
        # the extracted body, which silently defeated the match. It was the one shape
        # of five that the first version missed, and it is the most common one in the
        # xdi sites this detector was written for.
        def _strip_tail(b):
            # A trailing `// ...` comment must come off FIRST, or a declared site is
            # not merely undeclared — it is not FOUND. `if (!res.ok) return []; //
            # theater-ok: ...` failed to match at all, so declaring a T12 silently
            # deleted the finding instead of annotating it. That is the worst outcome
            # for a declaration convention: the count drops and nothing records why.
            b = re.split(r"//", b, 1)[0]
            return b.rstrip().rstrip("}").rstrip().rstrip(";").rstrip()

        # HTTP_FAIL_OK_RE must run against comment-stripped text too: two real sites
        # (dev-studio's RbacClient.tsx, xdi's SowPanel.tsx/TaskDefinitionEditor.tsx)
        # wrote a `theater-ok` REASON that happened to contain one of this regex's own
        # literal keywords ("...scanner can't see the setErr/toast side-effect...") —
        # explaining why the code ISN'T recognised as observable accidentally made the
        # PROSE match the regex that looks for real observable-failure code, and the
        # whole finding vanished before declaration was ever checked. Matching against
        # `joined` pre-strip conflated "the code calls toast()" with "a human wrote the
        # word toast in a comment" — those must not be the same signal.
        joined = " ".join(_strip_tail(b) for b in body if b)
        if HTTP_FAIL_OK_RE.search(joined):
            continue                   # raises, rejects, or reports — observable
        empty = next((b for b in body
                      if b and HTTP_FAIL_EMPTY_RE.match(" " + _strip_tail(b))), None)
        if empty is None:
            continue

        declared, reason = _declaration(line)
        if not declared:
            for b in body:
                d, r = _declaration(b)
                if d:
                    declared, reason = d, r
                    break
        out.append(_mk(path, i, "T12", "high",
                       "non-2xx response returns an empty value — fetch does not "
                       "reject on 4xx/5xx, so the caller cannot tell a failed request "
                       "from an empty result",
                       (line + " " + empty).strip(), declared, reason))
    return out


def _mk(path, line, detector, severity, message, evidence, declared, reason):
    evidence = evidence.strip()
    if len(evidence) > 160:
        evidence = evidence[:157] + "..."
    return Finding(path, line, detector, severity, message, evidence, declared, reason)


def iter_files(root, tracked_only=False):
    if os.path.isfile(root):
        yield root
        return

    if tracked_only:
        import subprocess
        try:
            out = subprocess.run(["git", "-C", root, "ls-files", "-z"],
                                 capture_output=True, check=True, text=True,
                                 timeout=60).stdout
            for rel in (p for p in out.split("\0") if p):
                full = os.path.join(root, rel)
                if os.path.basename(rel) not in SELF_SKIP_NAMES and os.path.isfile(full):
                    yield full
            return
        except (OSError, subprocess.SubprocessError):
            sys.stderr.write("warning: --tracked-only failed; scanning whole tree\n")

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        rel_dir = "" if rel_dir == "." else rel_dir + "/"
        if any(rel_dir.startswith(p) for p in SKIP_PATH_PREFIXES):
            dirnames[:] = []
            continue
        for name in filenames:
            if name in SELF_SKIP_NAMES:
                continue
            yield os.path.join(dirpath, name)


# ---------------------------------------------------------------------------
# Ratchet mode — report only theater introduced by a diff
#
# The estate carries 774 existing candidates. A gate that fails on all of them
# cannot be switched on, so it never gets switched on, and the backlog keeps
# growing — gandalf-protocol acquired a new T1 in the two days between the pilot
# and the full sweep. Ratchet mode decouples prevention from remediation: the
# build fails only on lines this change ADDED, so the backlog is frozen while
# Phases 2-3 work through it.
#
# THE FAILURE MODE THIS MUST NOT HAVE. A ratchet whose diff silently matches
# nothing reports a confident clean on every commit forever. That is exactly the
# `_is_workflow()` leading-slash bug, which matched no workflow paths at all and
# would have declared the whole estate clean. So every way the diff can fail --
# unknown ref, not a repo, unparseable output -- raises and exits 2. An empty
# diff is only ever reported as clean when git actually said the diff was empty.
# ---------------------------------------------------------------------------

DIFF_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,(?P<count>\d+))? @@")
DIFF_FILE_RE = re.compile(r"^\+\+\+ (?:b/)?(?P<path>.+)$")


class DiffError(RuntimeError):
    """The diff could not be computed. Raised — never degraded to 'no changes'."""


def changed_lines(root, base=None, staged=False):
    """
    {path relative to the git toplevel: set of line numbers added}.

    Two modes, because the two callers need genuinely different diffs:

      base=REF   three-dot `REF...HEAD` — the lines this BRANCH introduced,
                 measured against the merge base, so a busy base branch does not
                 pull unrelated lines into the gate. This is the CI mode.

      staged     `git diff --cached` — the lines this COMMIT is adding. This is
                 the pre-commit mode.

    THE TENTH BUG, CAUGHT BEFORE SHIPPING. The pre-commit hook was first written
    as `--diff-base HEAD`, which expands to `HEAD...HEAD`: the merge base of HEAD
    with itself is HEAD, so the diff is always empty and the hook reported CLEAN
    with theater sitting in the index. A ratchet that silently matches nothing
    passes every commit forever — precisely the failure this whole gate exists to
    prevent, rebuilt inside the gate. Hence an explicit flag rather than
    overloading a ref. test_staged_mode_sees_the_index pins it.

    Rename detection is on in both modes, so relocating a file does not present
    its whole contents as newly added.
    """
    import subprocess

    def git(*args):
        proc = subprocess.run(["git", "-C", root, *args],
                              capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            raise DiffError(f"git {' '.join(args)}: {proc.stderr.strip()[:200]}")
        return proc.stdout

    git("rev-parse", "--git-dir")

    if staged:
        out = git("diff", "--cached", "--unified=0", "--no-color", "-M")
    else:
        try:
            git("rev-parse", "--verify", "--quiet", base + "^{commit}")
        except DiffError as exc:
            raise DiffError(
                f"cannot resolve --diff-base {base!r}. In CI this usually means "
                f"a shallow clone: set fetch-depth: 0 on actions/checkout") from exc
        out = git("diff", "--unified=0", "--no-color", "-M", f"{base}...HEAD")

    added, current = {}, None
    for line in out.split("\n"):
        m = DIFF_FILE_RE.match(line)
        if m:
            path = m.group("path")
            current = None if path == "/dev/null" else path
            continue
        m = DIFF_HUNK_RE.match(line)
        if not m or current is None:
            continue
        start = int(m.group("start"))
        count = 1 if m.group("count") is None else int(m.group("count"))
        if count:
            added.setdefault(current, set()).update(range(start, start + count))
    return added


def repo_prefix(root):
    """Path of `root` relative to the git toplevel, '' at the toplevel."""
    import subprocess
    proc = subprocess.run(["git", "-C", root, "rev-parse", "--show-prefix"],
                          capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        raise DiffError(f"not a git repository: {root}")
    return proc.stdout.strip()


def load_allowlist(root):
    """`path:<regex>` entries only. Broad patterns are rejected and fail the run."""
    allow, errors = [], []
    base = root if os.path.isdir(root) else (os.path.dirname(root) or ".")
    candidate = os.path.join(base, ".theater-allow")
    if not os.path.isfile(candidate):
        return allow, errors
    with open(candidate, encoding="utf-8", errors="replace") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            pattern = line[len("path:"):].strip() if line.startswith("path:") else line
            if pattern in {".*", "^.*$", ".+", "^.+$", "(.*)"} or len(pattern) < 4:
                errors.append((lineno, "Dangerously broad allowlist entry"))
                continue
            if not (pattern.startswith("^") or "/" in pattern):
                errors.append((lineno, "Allowlist entry must be anchored or repo-relative"))
                continue
            try:
                allow.append(re.compile(pattern))
            except re.error:
                errors.append((lineno, "Invalid allowlist regex"))
    return allow, errors


def scan_file(path, active, root, known_scripts):
    rel = os.path.relpath(path, root).replace(os.sep, "/") if root else path
    try:
        if os.path.getsize(path) > MAX_TEXT_BYTES:
            return []
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except (OSError, UnicodeError):
        return []

    findings = []
    if "T1" in active:
        findings += detect_t1(rel, lines)
    if "T2" in active:
        findings += detect_t2(rel, lines)
    if "T3" in active:
        findings += detect_t3(rel, lines)
    if "T4" in active:
        findings += detect_t4(rel, lines)
    if "T5" in active:
        findings += detect_t5(rel, lines)
    if "T6" in active:
        findings += detect_t6(rel, lines, known_scripts)
    if "T8" in active:
        findings += detect_t8(rel, lines)
    if "T11" in active:
        findings += detect_t11(rel, lines)
    if "T12" in active:
        findings += detect_t12(rel, lines)
    return findings


def build_parser():
    p = argparse.ArgumentParser(
        prog="theater_scan",
        description="Find controls that exist, are relied upon, and do not check "
                    "what everyone believes they check.")
    p.add_argument("target", nargs="?", default=".")
    p.add_argument("--profile", choices=sorted(PROFILES), default="gate",
                   help="gate = T1,T2,T3,T4,T6 (default); all = adds T5")
    p.add_argument("--detector", action="append", choices=DETECTORS,
                   help="restrict to specific detector(s); repeatable")
    p.add_argument("--report", action="store_true",
                   help="print findings and a summary but always exit 0")
    p.add_argument("--inventory", action="store_true",
                   help="list declared suppressions instead of undeclared findings")
    p.add_argument("--tracked-only", action="store_true",
                   help="scan only git-tracked files")
    p.add_argument("--diff-base", metavar="REF",
                   help="ratchet mode: report only findings on lines this branch "
                        "added relative to REF (three-dot diff). Exits 2 if REF "
                        "cannot be resolved — it never degrades to 'no changes'.")
    p.add_argument("--staged", action="store_true",
                   help="ratchet mode against the git index — the lines this "
                        "COMMIT adds. For pre-commit hooks. Do not use "
                        "--diff-base HEAD for this: HEAD...HEAD is always empty.")
    p.add_argument("--quiet", action="store_true")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    target = args.target
    if not os.path.exists(target):
        sys.stderr.write(f"error: path not found: {target}\n")
        return 2

    active = PROFILES[args.profile]
    if args.detector:
        active = active & set(args.detector)

    root = target if os.path.isdir(target) else "."
    allow, allow_errors = load_allowlist(target)
    known_scripts = collect_package_scripts(root) if "T6" in active else set()

    added, prefix = None, ""
    if args.diff_base and args.staged:
        sys.stderr.write("error: --diff-base and --staged are different modes; "
                         "pick one\n")
        return 2
    if args.diff_base or args.staged:
        if not os.path.isdir(target):
            sys.stderr.write("error: ratchet mode needs a directory target\n")
            return 2
        try:
            prefix = repo_prefix(target)
            added = changed_lines(target, args.diff_base, staged=args.staged)
        except DiffError as exc:
            sys.stderr.write(f"error: {exc}\n")
            return 2

    all_findings = []
    for path in sorted(iter_files(target, tracked_only=args.tracked_only)):
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        if any(rx.search(rel) for rx in allow):
            continue
        found = scan_file(path, active, root, known_scripts)
        if added is not None:
            touched = added.get(prefix + rel, ())
            found = [f for f in found if f.line in touched]
        all_findings.extend(found)

    declared = [f for f in all_findings if f.declared]
    undeclared = [f for f in all_findings if not f.declared]

    if args.inventory:
        print(f"Declared suppressions: {len(declared)}\n")
        for f in sorted(declared, key=lambda x: (x.path, x.line)):
            print(f"{f.path}:{f.line}  [{f.detector}] {f.reason}")
        return 0

    total = len(undeclared) + len(allow_errors)
    for lineno, msg in allow_errors:
        if not args.quiet:
            print(f".theater-allow:{lineno}: [config] {msg}")

    if not args.quiet:
        for f in sorted(undeclared, key=lambda x: (x.detector, x.path, x.line)):
            print(f"{f.path}:{f.line}: [{f.detector}/{f.severity}] {f.message}")
            print(f"    | {f.evidence}")

    by_detector = Counter(f.detector for f in undeclared)
    print()
    if args.staged:
        scope = " [ratchet: staged lines]"
    elif args.diff_base:
        scope = f" [ratchet: lines added since {args.diff_base}]"
    else:
        scope = ""
    if total == 0:
        if added is not None:
            print(f"theater_scan: CLEAN — this change introduces no new theater "
                  f"(profile={args.profile}, {len(added)} file(s) changed).")
            return 0
        print(f"theater_scan: CLEAN (profile={args.profile}). "
              f"{len(declared)} declared suppression(s).")
        return 0

    breakdown = "  ".join(f"{d}={by_detector[d]}" for d in DETECTORS if by_detector[d])
    print(f"theater_scan: {total} undeclared finding(s) "
          f"[profile={args.profile}]{scope}")
    if breakdown:
        print(f"  by detector: {breakdown}")
    if declared:
        print(f"  plus {len(declared)} declared suppression(s) — see --inventory")

    if args.report:
        print("  report mode: exiting 0 without failing.")
        return 0

    print("Fix the control, or declare the suppression with a specific reason:")
    print("    # theater-ok: <why this cannot fail the build, and what tracks it>")
    return 1


if __name__ == "__main__":
    sys.exit(main())
