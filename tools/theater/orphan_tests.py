#!/usr/bin/env python3
"""
T10 — test files that no workflow runs.

A large, well-written, comprehensive test suite that CI never invokes is
verification theater in its most complete form: the signal exists, humans
consume it when reasoning about whether a change is safe, and it lies. Nothing
is red, because nothing runs.

Found by hand in ops-platform on 2026-07-28: 1,296 tests across 140 suites,
zero workflow invocations, 61 of them failing on main indefinitely. This tool
exists because one instance is an anecdote.

WHY THIS IS NOT A DETECTOR IN theater_scan.py
---------------------------------------------
Every T1-T8 detector answers a question about a LINE. This one answers a
question about a repository, so it does not fit `detect_tN(path, lines)`, and
more importantly it cannot ratchet: there is no "changed line" that introduces
an orphaned suite. Wiring it into the blocking gate would fail every pull
request in an affected repo until someone fixed a backlog, which is exactly the
un-adoptable gate the ratchet design exists to avoid. So it lives here with T7
and T9, in the reporting tier.

WHY PER-PACKAGE AND NOT PER-REPO
--------------------------------
A repo-level boolean is useless. ops-platform DOES invoke a test runner --
`pnpm --filter @cu2/e2e test:ci` -- so "does this repo run tests?" answers yes
and misses all 1,296. The question has to be asked of each unit that owns test
files: is THIS package's suite reachable from any workflow?

THE FALSE-POSITIVE PROBLEM IS THE WHOLE PROBLEM
-----------------------------------------------
Tests get invoked through package scripts, workspace fan-out, Makefiles, shell
scripts, composite actions, and reusable workflows in other repositories. A
naive grep for `jest` in .github/workflows would light up most of the estate
wrongly, and a detector that cries wolf gets ignored -- which is how this
toolchain has already burned itself several times over (see README's ledger).

So this tool follows indirection as far as it can READ, and where it cannot
read, it says so instead of guessing:

    wired       a workflow invocation demonstrably reaches this package
    orphaned    every invocation was resolved, and none reaches it   <- FINDING
    unknown     unresolvable indirection could plausibly reach it    <- NOT a
                finding, but counted and printed, never silently dropped

`unknown` is a first-class outcome, not a rounding error. A tool that collapses
"I could not check" into "clean" is committing the defect it is looking for.

Offline and stdlib-only, like theater_scan.py. No network, no gh, no PyYAML --
workflow YAML is read with a deliberately small structural parser (see
_parse_workflow) because the only shapes needed are jobs/steps/run/uses/
working-directory, and taking a dependency to get them is not worth it.
"""

import argparse
import fnmatch
import json
import os
import re
import sys
from collections import Counter, namedtuple

# --------------------------------------------------------------------------
# What counts as a test file
# --------------------------------------------------------------------------

JS_TEST_RE = re.compile(r"\.(spec|test)\.(ts|tsx|js|jsx|mts|cts)$")
PY_TEST_RE = re.compile(r"^(test_.+\.py|.+_test\.py)$")
# Ecosystems present in the estate but not modelled. Reported explicitly rather
# than dropped -- a repo that vanishes from the output is indistinguishable
# from a clean one.
CS_TEST_RE = re.compile(r"(Tests?\.cs|Spec\.cs)$")
GO_TEST_RE = re.compile(r"_test\.go$")
RB_TEST_RE = re.compile(r"_spec\.rb$")

PRUNE = {
    "node_modules", ".git", ".venv", "venv", "env", "vendor", "dist", "build",
    "__pycache__", ".next", ".nuxt", "out", "coverage", ".turbo", ".pytest_cache",
    "bin", "obj", "target", ".tox", ".mypy_cache", "site-packages", ".cache",
}

# --------------------------------------------------------------------------
# What counts as invoking a runner
# --------------------------------------------------------------------------

# Direct runner invocations. Word-boundaried, and `go test` / `dotnet test`
# style two-word forms are spelled out so a bare `test` never matches.
JS_RUNNER_RE = re.compile(
    r"(?<![\w.-])("
    # `--test` on its own covers node's built-in runner reached through a
    # spawn array -- dev-studio calls spawnSync("node", ["--import","tsx",
    # "--test", glob]), where the literal string `node --test` never appears.
    # Safe against jest's --testPathPattern etc: the trailing guard rejects a
    # following word character or hyphen.
    r"jest|vitest|mocha|ava|jasmine|karma|tap|--test|node:test|"
    r"playwright\s+test|cypress\s+run|wdio|"
    r"react-scripts\s+test|ng\s+test|vue-cli-service\s+test"
    r")(?![\w-])"
)
PY_RUNNER_RE = re.compile(
    r"(?<![\w.-])("
    r"pytest|py\.test|nose2|nosetests|"
    r"python[0-9.]*\s+-m\s+(pytest|unittest|nose2)|"
    r"manage\.py\s+test|"
    r"unittest\s+discover|"
    r"tox|nox"
    r")(?![\w-])"
)

# One shape for every package-manager call: optional flags, optional `run`,
# then the script name. Written as a single pattern because the previous pair
# of regexes could not express REPEATED selectors -- broflo's real command is
#   pnpm --filter './apps/**' --filter './packages/**' run test
# and the second `--filter` landed where the script name was expected, so the
# whole invocation matched nothing. A repo that tests everything on every push
# read as a repo that tests nothing.
#
# Only --filter/-F is treated as taking a value; other flags are valueless, so
# `pnpm install --frozen-lockfile` cannot swallow the following token.
PM_CALL_RE = re.compile(
    r"(?<![\w.-])(?:npm|pnpm|yarn|bun)\s+"
    r"((?:(?:--filter(?:-prod)?|-F)[=\s]+\S+\s+|--[\w-]+\s+|-\w\s+)*)"
    r"(?:run(?:-script)?\s+)?"
    r"([A-Za-z][\w:.-]*)"
)
FILTER_SEL_RE = re.compile(r"(?:--filter(?:-prod)?|-F)[=\s]+(['\"]?)([^\s'\"]+)\1")
# `yarn workspace <name> <script>`
YARN_WS_RE = re.compile(
    r"(?<![\w.-])yarn\s+workspace\s+(['\"]?)([^\s'\"]+)\1\s+"
    r"(?:run\s+)?([A-Za-z][\w:.-]*)")

# Workspace fan-out: one command, every package.
FANOUT_RE = re.compile(
    r"(?<![\w.-])("
    r"turbo\s+(?:run\s+)?([\w:.-]+)|"
    r"nx\s+run-many[^\n]*?--target[=\s]+([\w:.-]+)|"
    r"lerna\s+run\s+([\w:.-]+)|"
    r"(?:npm|pnpm|yarn|bun)\s+(?:-r|--recursive|--workspaces|-ws)\s+"
    r"(?:run(?:-script)?\s+)?([\w:.-]+)"
    r")"
)
# A workflow that cannot fire on this repository's own commits is not evidence
# that this repository's tests run. ops-platform ships `reusable-scan.yml` for
# OTHER repos to call; it is `on: workflow_call` only, so it never executes for
# an ops-platform push -- yet a config string inside it made the whole repo look
# covered and hid 145 orphaned suites. Same trap as T9's `declares_push`: the
# `on:` key parses as the boolean True under YAML 1.1, so match it textually.
SELF_TRIGGER_RE = re.compile(
    r"^\s{2,4}(push|pull_request|pull_request_target|schedule|"
    r"workflow_dispatch|merge_group)\s*:"          # block mapping
    r"|^on\s*:\s*\[?[^\n]*\b(push|pull_request|schedule|workflow_dispatch)\b",
    re.M)

# `grep -q "pytest"`, `echo "run jest"` -- a runner NAMED inside another
# command's argument is not a runner INVOKED.
QUOTED_TOKEN_RE = re.compile(
    r"(?<![\w.-])(?:grep|echo|printf|sed|awk|comm|diff)\b[^\n]*")

MAKE_RE = re.compile(r"(?<![\w.-])make\s+(?:-\w+\s+)*([\w:.-]+)")
# Committed scripts a workflow hands off to. Not just shell: dev-studio's CI
# gate is `node tools/test-kit.mjs unit`, a 300-line orchestrator that spawns
# vitest across the workspace. Following only *.sh reported 77 of its test files
# as unreachable when they run on every push.
SCRIPT_RE = re.compile(
    r"(?:^|[|&;]\s*)(?:bash|sh|zsh|source|\.)\s+(\S+\.sh)"
    r"|(?:^|\s)(\./[\w./-]+\.(?:sh|mjs|cjs|js|py))"
    r"|(?:^|[|&;]\s*)(?:node|npx\s+tsx|tsx|ts-node|python[0-9.]*|uv\s+run)\s+"
    r"([\w./-]+\.(?:mjs|cjs|js|ts|py))")

# A test script that is a no-op. `exit 0` masquerading as a suite.
# A test script that runs nothing at all. Deliberately narrow.
#
# An earlier version also matched jest's no-tests-is-fine flag, which was simply
# wrong: that command DOES run the runner, and broflo's 28-file suite -- which
# executes on every push -- was reported as a green check that cannot fail. A
# runner passing because it found no tests is a real defect, but a different
# one, and it belongs to T5.
NOOP_SCRIPT_RE = re.compile(
    r"^\s*(echo\b[^&|;]*(&&|;)\s*)?(exit\s+0|true)\s*$"
    r"|^\s*echo\b[^&|;]*$"
)

# A script name that CLAIMS to be a test. Used to separate two different
# defects: a package CI never touches (orphaned) from a package CI dutifully
# runs a `test` script for, where that script cannot fail (noop). The second is
# worse -- it produces a green check.
TEST_SCRIPT_RE = re.compile(r"(?:^|[:._-])tests?(?:[:._-]|$)", re.I)

MAX_DEPTH = 6  # script -> script resolution bound; cycles are the reason

Unit = namedtuple("Unit", "dir kind name test_files scripts")
Row = namedtuple(
    "Row",
    "repo unit kind name n_tests verdict severity confidence message "
    "covered_by unresolved noop_script",
)

FINDING_VERDICTS = ("orphaned", "noop", "partial", "non_gating")
SEVERITY = {"orphaned": "high", "noop": "high", "partial": "medium",
            "non_gating": "high"}

# CONFIDENCE, AND WHY IT IS NOT A FOURTH VERDICT.
#
# The first cut demoted any unit to `unknown` whenever the repo contained a
# single unfollowable indirection. That reads as rigorous and is actually
# useless: nearly every repo in the estate calls at least one reusable workflow
# from somewhere else, so ops-platform's 145 orphaned suites -- found by hand,
# known real -- were quietly filed under "could not check" by one unrelated
# theater-gate call.
#
# Swallowing a true finding is the same failure as inventing a false one. So an
# unresolved indirection lowers CONFIDENCE and is printed verbatim beside the
# finding, instead of erasing it. Headline counts report `high` only; `medium`
# is carried separately so the number stays honest in both directions.
CONFIDENCE = ("high", "medium")


# --------------------------------------------------------------------------
# Minimal workflow YAML reading
# --------------------------------------------------------------------------

def _parse_workflow(text):
    """
    Pull the shell commands and `uses:` refs out of a workflow, each tagged with
    whether the step that carries it can actually FAIL THE JOB.

    Returns (runs, uses) where
        runs = [(shell_text, working_directory, gating)]
        uses = [(ref, gating)]

    WHY GATING MATTERS, and why ignoring it made this tool lie. ops-platform's
    `reusable-scan.yml` runs each caller's configured test command in a step
    marked `continue-on-error: true`. Sixteen repositories point at it. Reading
    that workflow and seeing `$TEST_CMD` execute, an earlier version of this tool
    concluded those repos' tests were covered and reported them CLEAN -- when a
    failing test there cannot turn the check red. A test invocation inside a step
    that cannot fail is not coverage; it is the thing this tool exists to find.

    Steps are buffered so `continue-on-error` attaches to the step it belongs to
    rather than leaking across neighbours. A job-level `continue-on-error` (not
    part of a step's list item) is applied to the whole file: over-broad, but it
    errs toward reporting less coverage, and a false CLEAN is the failure mode
    that matters here.

    Still not a YAML parser. It needs run/uses/working-directory/
    continue-on-error and nothing else.
    """
    lines = text.splitlines()
    runs, uses = [], []

    STEP_KEY = re.compile(
        r"^-\s+(name|uses|run|id|with|if|shell|env|working-directory|"
        r"continue-on-error|timeout-minutes)\s*:")
    job_level_coe = False


    cur = None      # {"lines": [...], "wd": str}
    cur_wd = ""

    def flush(step):
        if not step:
            return
        body = "\n".join(step["lines"])
        coe = bool(re.search(r"^\s*(?:-\s+)?continue-on-error\s*:\s*true\s*$",
                             body, re.M))
        gating = not (coe or job_level_coe)
        wd = step["wd"]
        m = re.search(r"^\s*(?:-\s+)?working-directory\s*:\s*(.+?)\s*$", body, re.M)
        if m:
            wd = m.group(1).strip("'\"")
        for ref in re.findall(r"^\s*(?:-\s+)?uses\s*:\s*(.+?)\s*$", body, re.M):
            uses.append((ref.strip("'\""), gating))
        # `run:` -- inline or block scalar
        sl = step["lines"]
        for idx, ln in enumerate(sl):
            m = re.match(r"^(\s*)(?:-\s+)?run\s*:\s*(\|[-+]?|>[-+]?)?\s*(.*)$", ln)
            if not m:
                continue
            ind, block, inline = len(m.group(1)), m.group(2), m.group(3)
            if block:
                buf = []
                for nxt in sl[idx + 1:]:
                    if nxt.strip() and (len(nxt) - len(nxt.lstrip())) <= ind:
                        break
                    buf.append(nxt)
                runs.append(("\n".join(buf), wd, gating))
            elif inline:
                runs.append((inline, wd, gating))

    for ln in lines:
        st = ln.strip()
        if not st or st.startswith("#"):
            if cur:
                cur["lines"].append(ln)
            continue
        if STEP_KEY.match(st):
            flush(cur)
            cur = {"lines": [ln], "wd": cur_wd}
            continue
        if cur is not None:
            indent = len(ln) - len(ln.lstrip())
            first_indent = len(cur["lines"][0]) - len(cur["lines"][0].lstrip())
            if indent > first_indent:
                cur["lines"].append(ln)
                continue
            flush(cur)
            cur = None
        # Outside a step. Two things live here:
        #
        # 1. A JOB-LEVEL `uses:` -- how a reusable workflow is called. It has no
        #    leading dash, so the step regex above never sees it. Missing this
        #    broke every cross-repo resolution: `jobs: {t: {uses: org/x/...}}`
        #    simply vanished, and repos calling a reusable workflow that runs
        #    their tests came back `orphaned`. Its gating is the JOB's.
        # 2. defaults.run.working-directory, inherited by later steps.
        # A `continue-on-error` HERE is the job's, not a step's -- job-level
        # keys precede `steps:`, so this is set before any step is flushed.
        # Detecting it in this branch is what keeps a lint step's flag from
        # leaking onto the test step beside it.
        if re.match(r"^continue-on-error\s*:\s*true\s*$", st):
            job_level_coe = True
            continue
        m = re.match(r"^uses\s*:\s*(.+?)\s*$", st)
        if m:
            uses.append((m.group(1).strip("'\""), not job_level_coe))
            continue
        m = re.match(r"^working-directory\s*:\s*(.+?)\s*$", st)
        if m:
            cur_wd = m.group(1).strip("'\"")
    flush(cur)
    return runs, uses


# --------------------------------------------------------------------------
# Repo model
# --------------------------------------------------------------------------

def _read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _walk(root):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in PRUNE and not d.startswith(".git")]
        yield dp, dns, fns


def discover_units(root):
    """
    Every directory that owns test files, keyed to the package that would run
    them. JS tests belong to their nearest ancestor package.json; Python tests
    to their nearest project marker, or the repo root if there is none.
    """
    pkg_dirs, py_dirs = {}, set()
    for dp, _dns, fns in _walk(root):
        rel = os.path.relpath(dp, root)
        rel = "" if rel == "." else rel.replace(os.sep, "/")
        if "package.json" in fns:
            raw = _read(os.path.join(dp, "package.json"))
            try:
                data = json.loads(raw) if raw else {}
            except (ValueError, TypeError):
                data = {}
            if isinstance(data, dict):
                pkg_dirs[rel] = data
        if fns and ({"pyproject.toml", "setup.py", "setup.cfg", "tox.ini"} & set(fns)):
            py_dirs.add(rel)
    py_dirs.add("")

    def nearest(rel, candidates):
        best = None
        for c in candidates:
            if c == "" or rel == c or rel.startswith(c + "/"):
                if best is None or len(c) > len(best):
                    best = c
        return best if best is not None else ""

    tests = {}   # (dir, kind) -> [files]
    other = Counter()
    for dp, _dns, fns in _walk(root):
        rel = os.path.relpath(dp, root)
        rel = "" if rel == "." else rel.replace(os.sep, "/")
        for f in fns:
            full = f"{rel}/{f}" if rel else f
            if JS_TEST_RE.search(f):
                tests.setdefault((nearest(rel, pkg_dirs), "js"), []).append(full)
            elif PY_TEST_RE.match(f):
                tests.setdefault((nearest(rel, py_dirs), "py"), []).append(full)
            elif CS_TEST_RE.search(f):
                other["cs"] += 1
            elif GO_TEST_RE.search(f):
                other["go"] += 1
            elif RB_TEST_RE.search(f):
                other["rb"] += 1

    units = []
    for (d, kind), files in sorted(tests.items()):
        data = pkg_dirs.get(d, {}) if kind == "js" else {}
        scripts = data.get("scripts") or {}
        if not isinstance(scripts, dict):
            scripts = {}
        name = data.get("name") or (d or os.path.basename(os.path.abspath(root)))
        units.append(Unit(d, kind, name, sorted(files), scripts))
    return units, pkg_dirs, other


def _all_packages(pkg_dirs):
    return {d: (data.get("scripts") or {}) for d, data in pkg_dirs.items()
            if isinstance(data.get("scripts") or {}, dict)}


def _resolve_filter(sel, pkg_dirs):
    """
    `--filter` selector -> package dirs.

    pnpm accepts a package name (`@broflo/api`), a path (`apps/api`), a name
    glob (`@broflo/*`) and a PATH glob (`./apps/**`). Missing the last form made
    broflo's entire CI invisible -- `pnpm test` fans out through
    `--filter './apps/**' run test`, and with the glob unresolved a repo that
    tests everything on every push looked like it tested nothing.
    """
    hits = []
    clean = sel.strip().strip("'\"")
    if clean.startswith("./"):
        clean = clean[2:]
    clean = clean.rstrip("...").rstrip("^")
    for d, data in pkg_dirs.items():
        name = data.get("name") or ""
        if name and (name == sel or name == clean):
            hits.append(d)
        elif clean and (d == clean or d.endswith("/" + clean)):
            hits.append(d)
        elif "*" in clean and d and (fnmatch.fnmatch(d, clean)
                                     or fnmatch.fnmatch(d, clean.rstrip("/*") + "/*")):
            hits.append(d)
        elif "*" in clean and name and fnmatch.fnmatch(name, clean):
            hits.append(d)
    return hits


def analyse_command(text, cwd, root, pkg_dirs, depth=0, seen=None):
    """
    What does this shell text end up testing?

    Returns (covered_dirs, targeted_dirs, unresolved).

    `covered`  -- a real runner executes here. "" means the whole repo.
    `targeted` -- CI invokes something test-NAMED for this package, whether or
                  not a runner was underneath it. The gap between the two sets
                  is where `"test": "echo ok && exit 0"` lives, and that shape
                  needs its own verdict: it is not an untouched package, it is
                  a green check that cannot go red.
    `unresolved` -- indirection that could not be followed. Each entry is a
                  reason an `orphaned` verdict must be softened to `unknown`.
    """
    seen = seen if seen is not None else set()
    covered, targeted, unresolved = set(), set(), []
    if depth > MAX_DEPTH or not text:
        if text:
            unresolved.append(f"recursion limit at: {text.strip()[:60]}")
        return covered, targeted, unresolved

    cwd = (cwd or "").strip("./")
    all_pkgs = _all_packages(pkg_dirs)

    # Shell comments describe; they do not execute.
    text = "\n".join(l for l in text.splitlines()
                     if not l.lstrip().startswith("#"))

    # 1. Workspace fan-out -- covers every package declaring that script.
    for m in FANOUT_RE.finditer(text):
        script = next((g for g in m.groups()[1:] if g), None)
        if not script:
            continue
        for d, scripts in all_pkgs.items():
            if script in scripts:
                if (d, script) in seen:
                    continue
                seen.add((d, script))
                sub, subt, subun = analyse_command(scripts[script], d, root,
                                                   pkg_dirs, depth + 1, seen)
                covered |= sub
                targeted |= subt
                unresolved += subun
                if TEST_SCRIPT_RE.search(script):
                    targeted.add(d)
        if not any(script in s for s in all_pkgs.values()):
            unresolved.append(f"fan-out `{m.group(0).strip()}` matched no package script")

    # 2. Package-manager calls: filtered, or in the current directory.
    def _run_script(pkg_dir, script):
        """
        Run a package script, and decide whether the package it lives in was
        TARGETED -- meaning a test-named script ran for it and produced no
        runner, the `exit 0` shape.

        A script that delegates is not a no-op. broflo's root `test` is
        `pnpm --filter './apps/**' run test`: CI invokes it, it runs jest in two
        other packages, and the root's own 22 Playwright specs are simply never
        reached. Marking the root `noop` claimed its check "cannot go red" when
        that check genuinely tests two packages. The right answer is that the
        root's tests are orphaned. So targeting is recorded only when the whole
        expansion yields no coverage ANYWHERE.
        """
        body = all_pkgs.get(pkg_dir, {}).get(script)
        if body is None:
            return
        if (pkg_dir, script) in seen:
            return
        seen.add((pkg_dir, script))
        scripts = all_pkgs.get(pkg_dir, {})
        produced = set()
        for hook in (f"pre{script}", script, f"post{script}"):
            hbody = scripts.get(hook)
            if hbody is None:
                continue
            sub, subt, subun = analyse_command(hbody, pkg_dir, root, pkg_dirs,
                                               depth + 1, seen)
            produced.update(sub)
            covered.update(sub)
            targeted.update(subt)
            unresolved.extend(subun)
        if TEST_SCRIPT_RE.search(script) and not produced:
            targeted.add(pkg_dir)

    for m in list(YARN_WS_RE.finditer(text)) :
        for d in _resolve_filter(m.group(2), pkg_dirs) or []:
            _run_script(d, m.group(3))

    NON_SCRIPT_VERBS = {
        "install", "ci", "i", "add", "remove", "exec", "dlx", "why", "audit",
        "config", "set", "get", "fetch", "store", "publish", "pack", "version",
        "link", "unlink", "list", "ls", "outdated", "prune", "update", "up",
        "create", "init", "login", "logout", "workspace", "workspaces", "dedupe",
        "rebuild", "approve-builds", "licenses", "patch", "deploy", "env",
    }
    for m in PM_CALL_RE.finditer(text):
        flags, script = m.group(1) or "", m.group(2)
        if script in NON_SCRIPT_VERBS:
            continue
        sels = [g[1] for g in FILTER_SEL_RE.findall(flags)]
        if sels:
            for sel in sels:
                targets = _resolve_filter(sel, pkg_dirs)
                if not targets:
                    unresolved.append(f"--filter {sel} matched no package")
                    continue
                for d in targets:
                    _run_script(d, script)
        else:
            if cwd not in all_pkgs and script == "test":
                unresolved.append(
                    f"`{m.group(0).strip()}` in '{cwd or '.'}' -- no package.json here")
                continue
            _run_script(cwd, script)

    # 3. Direct runner in the current directory. Mentions inside grep/echo
    #    arguments are blanked first -- naming a runner is not running one.
    probe = QUOTED_TOKEN_RE.sub("", text)
    if JS_RUNNER_RE.search(probe) or PY_RUNNER_RE.search(probe):
        covered.add(cwd)
        targeted.add(cwd)

    # 4. Makefile targets.
    for m in MAKE_RE.finditer(text):
        target = m.group(1)
        mk = _read(os.path.join(root, cwd, "Makefile")) or _read(os.path.join(root, "Makefile"))
        if mk is None:
            unresolved.append(f"`make {target}` -- no Makefile found")
            continue
        body = _makefile_target(mk, target)
        if body is None:
            unresolved.append(f"`make {target}` -- target not in Makefile")
            continue
        sub, subt, subun = analyse_command(body, cwd, root, pkg_dirs, depth + 1, seen)
        covered |= sub
        targeted |= subt
        unresolved += subun

    # 5. Shell scripts committed to the repo.
    for m in SCRIPT_RE.finditer(text):
        rel = (m.group(1) or m.group(2) or m.group(3) or "").lstrip("./")
        body = _read(os.path.join(root, cwd, rel)) or _read(os.path.join(root, rel))
        if body is None:
            unresolved.append(f"`{rel}` -- script not in the repo")
            continue
        sub, subt, subun = analyse_command(body, cwd, root, pkg_dirs, depth + 1, seen)
        covered |= sub
        targeted |= subt
        unresolved += subun
        # Reading a script and not recognising a runner in it is NOT evidence
        # that it runs no tests. dev-studio's test-kit.mjs is 300 lines of
        # orchestration whose runner arrives as a spawn argument array; a tool
        # that treats "I read it and saw nothing" as "nothing is there" reports
        # a live suite as dead with full confidence, which is worse than
        # admitting it cannot tell.
        if not sub:
            unresolved.append(
                f"`{rel}` runs, but no recognisable test runner was found in it")

    # 6. Containerised runs -- opaque without building.
    if re.search(r"(?<![\w-])docker(?:\s+compose)?\s+(build|run|up)|docker-compose\s+(run|up)", text):
        unresolved.append("docker build/run could execute tests")

    return covered, targeted, unresolved


def _makefile_target(text, target):
    out, capture = [], False
    for line in text.splitlines():
        if re.match(rf"^{re.escape(target)}\s*:", line):
            capture = True
            continue
        if capture:
            if line.startswith("\t") or line.startswith("    "):
                out.append(line.strip())
            elif line.strip() and not line.startswith("#"):
                break
    return "\n".join(out) if out else (None if not capture else "")


def _classify_uses(ref, root):
    """
    A `uses:` step. Local composite actions are readable; anything else is not.
    Returns (covered_dirs, unresolved, readable_text).
    """
    ref = ref.strip()
    if ref.startswith("./"):
        base = os.path.join(root, ref[2:].rstrip("/"))
        for cand in ("action.yml", "action.yaml"):
            txt = _read(os.path.join(base, cand))
            if txt:
                return txt
        # local reusable workflow
        txt = _read(base)
        if txt:
            return txt
        return None
    return None


BENIGN_USES = re.compile(
    r"^(actions/|github/|docker/|azure/|Azure/|aws-actions/|hashicorp/|"
    r"pnpm/|denoland/|oven-sh/|ruby/|gradle/|softprops/|peter-evans/|"
    r"dorny/|codecov/|treosh/|slackapi/|8398a7/|tj-actions/|"
    r"stefanzweifel/|EndBug/|crazy-max/|sigstore/|anchore/|"
    r"returntocorp/|semgrep/|aquasecurity/|snyk/|step-security/)",
)


def make_resolver(search_dirs):
    """
    owner/name -> local checkout, for following `uses:` into other repos.

    Where a referenced repository is on disk, its workflow is READ rather than
    shrugged at. This matters more than it sounds: rolling the theater gate out
    to 88 repos put one unreadable cross-repo `uses:` into nearly every repo in
    the estate, which dropped almost every T10 finding to medium confidence --
    the rollout degraded the detector. Resolving locally removes the doubt
    instead of waving it away.
    """
    def resolve(owner_repo, relpath):
        """
        Returns (text, note). Keeps looking until it finds a checkout that
        actually CONTAINS the file: the first candidate matched here was a
        Phase-1 clone taken before the file existed, and returning it made a
        resolvable reference look unresolvable. "A checkout exists" and "the
        checkout has what I need" are different claims.
        """
        owner, _, name = owner_repo.partition("/")
        found_repo = False
        for d in search_dirs:
            for cand in (f"{owner}__{name}", name):
                full = os.path.join(d, cand)
                if not (os.path.isdir(os.path.join(full, ".git")) or
                        os.path.isdir(os.path.join(full, ".github"))):
                    continue
                found_repo = True
                txt = _read(os.path.join(full, relpath))
                if txt is not None:
                    return txt, None
        if found_repo:
            return None, f"local checkout of {owner_repo} has no {relpath} (stale?)"
        return None, None
    return resolve


def check_repo(root, repo_name=None, resolver=None):
    repo_name = repo_name or os.path.basename(os.path.abspath(root))
    units, pkg_dirs, other = discover_units(root)

    wfdir = os.path.join(root, ".github", "workflows")
    covered, targeted, unresolved = set(), set(), []
    nongating = set()   # invocations that run but CANNOT fail the job
    n_workflows = 0
    if os.path.isdir(wfdir):
        for f in sorted(os.listdir(wfdir)):
            if not f.endswith((".yml", ".yaml")):
                continue
            txt = _read(os.path.join(wfdir, f))
            if txt is None:
                unresolved.append(f"{f} unreadable")
                continue
            if not SELF_TRIGGER_RE.search(txt):
                # Reusable/callable-only. Read it if something local calls it,
                # never on its own account.
                continue
            n_workflows += 1
            runs, uses = _parse_workflow(txt)
            for body, wd, gating in runs:
                c, t, u = analyse_command(body, wd, root, pkg_dirs)
                (covered if gating else nongating).update(c)
                targeted |= t
                unresolved += [f"{f}: {x}" for x in u]
            for ref, gating in uses:
                inner = _classify_uses(ref, root)
                if inner is not None:
                    iruns, _ = _parse_workflow(inner)
                    for body, wd, inner_gating in iruns:
                        c, t, u = analyse_command(body, wd, root, pkg_dirs)
                        # Non-gating anywhere in the chain means non-gating: a
                        # blocking step inside a workflow that was CALLED with
                        # continue-on-error still cannot fail the job.
                        (covered if (gating and inner_gating)
                         else nongating).update(c)
                        targeted |= t
                        unresolved += [f"{f}->{ref}: {x}" for x in u]
                elif ref.startswith("./"):
                    unresolved.append(f"{f}: local `uses: {ref}` not readable")
                elif "/.github/workflows/" in ref:
                    body_txt, note = None, None
                    if resolver:
                        spec = ref.split("@")[0]
                        owner_repo, _, wfpath = spec.partition("/.github/workflows/")
                        body_txt, note = resolver(
                            owner_repo, os.path.join(".github", "workflows", wfpath))
                    if body_txt is None:
                        unresolved.append(
                            f"{f}: reusable workflow `{ref}` is in another repo"
                            + (f" -- {note}" if note else ""))
                    else:
                        # The called workflow runs against THIS repo's checkout,
                        # so its commands are analysed with this repo's tree.
                        iruns, _ = _parse_workflow(body_txt)
                        for b2, wd2, inner_gating in iruns:
                            c, t, u = analyse_command(b2, wd2, root, pkg_dirs)
                            (covered if (gating and inner_gating)
                             else nongating).update(c)
                            targeted |= t
                            unresolved += [f"{f}->{ref}: {x}" for x in u]
                elif not BENIGN_USES.match(ref) and "@" in ref:
                    unresolved.append(f"{f}: third-party action `{ref}`")

    def reaches(dirset, d):
        return sorted(c for c in dirset if c == "" or d == c or d.startswith(c + "/"))

    # COVERAGE IS A PROPERTY OF THE TEST FILES, NOT THE PACKAGE DIRECTORY.
    #
    # resistance-wine has no pyproject.toml, so all 104 of its Python tests are
    # attributed to the repo root -- while the workflow that runs them declares
    # `working-directory: backend`. Comparing the runner's directory against the
    # UNIT's directory said "backend does not cover ''" and reported a suite
    # that runs twice a day, on push and nightly, as dead. Comparing against the
    # files themselves gets it right, and as a bonus can see a suite that is
    # only partly wired -- which the directory comparison could never express.

    caveats = sorted(set(unresolved))

    def covers_file(prefixes, path):
        return any(c == "" or path == c or path.startswith(c + "/")
                   for c in prefixes)

    rows = []
    for u in units:
        run_files = [f for f in u.test_files if covers_file(covered, f)]
        dead = [f for f in u.test_files if not covers_file(covered, f)]
        hit = reaches(covered, u.dir) or (sorted(covered) if run_files else [])
        aimed = (reaches(targeted, u.dir)
                 or [c for c in sorted(targeted)
                     if any(covers_file([c], f) for f in u.test_files)])
        conf = "high" if not caveats else "medium"

        ng_files = [f for f in u.test_files if covers_file(nongating, f)]

        if run_files and not dead:
            verdict, conf, noop = "wired", "high", None
            msg = f"all {len(run_files)} test file(s) covered by '{hit[0] or '.'}'"
        elif not run_files and ng_files:
            # These tests DO execute; the step running them just cannot turn the
            # check red. Kept separate from `orphaned` because it is strictly
            # more misleading -- there is a green check that cites them.
            # ops-platform's reusable-scan.yml runs each caller's configured
            # test command under continue-on-error, which is the shape 16 repos
            # are in.
            verdict, noop = "non_gating", None
            msg = (f"{len(ng_files)} test file(s) ARE run, but only inside a step "
                   f"that cannot fail the job (continue-on-error) -- the check "
                   f"stays green when they fail")
        elif run_files:
            verdict, noop = "partial", None
            msg = (f"{len(dead)} of {len(u.test_files)} test file(s) are not "
                   f"reached by any workflow, though {len(run_files)} are; "
                   f"e.g. {dead[0]}")
        elif aimed and u.kind == "js" and u.scripts:
            # CI runs a test-named script for this package and no runner is
            # underneath it. Worse than an untouched suite: this one produces a
            # green check, so the absence of failures reads as health.
            noop = (u.scripts.get("test") or u.scripts.get("test:ci")
                    or next((v for k, v in u.scripts.items()
                             if TEST_SCRIPT_RE.search(k)), "")) or "(no script body)"
            verdict = "noop"
            msg = (f"{len(u.test_files)} test file(s). CI invokes a test script "
                   f"for '{u.dir or '.'}' but it runs no test runner: "
                   f"`{noop.strip()[:80]}` -- the check cannot go red")
        elif n_workflows == 0:
            verdict, conf, noop = "unknown", "high", None
            msg = (f"{len(u.test_files)} test file(s); this repo has no workflow "
                   f"that triggers on its own commits at all")
        else:
            verdict, noop = "orphaned", None
            msg = (f"{len(u.test_files)} test file(s) and no workflow invocation "
                   f"reaches them; {n_workflows} workflow(s) examined")
            if caveats:
                msg += (f" -- but {len(caveats)} indirection(s) could not be "
                        f"followed, so this is not certain")

        rows.append(Row(repo_name, u.dir or ".", u.kind, u.name, len(u.test_files),
                        verdict, SEVERITY.get(verdict, "info"), conf, msg,
                        hit, caveats[:12], noop))

    for kind, n in sorted(other.items()):
        rows.append(Row(repo_name, ".", kind, f"({kind} sources)", n,
                        "unsupported", "info", "high",
                        f"{n} {kind} test file(s); this ecosystem is not modelled "
                        f"-- not scanned, not clean", [], [], None))
    return rows


# --------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        description="T10 -- find test suites no workflow runs.")
    p.add_argument("targets", nargs="+", help="repo root(s)")
    p.add_argument("--report", action="store_true",
                   help="always exit 0 (inventory mode)")
    p.add_argument("--json", metavar="PATH")
    p.add_argument("--show-unknown", action="store_true",
                   help="print the unresolved indirections behind each unknown")
    p.add_argument("--resolve-repos", action="append", default=[], metavar="DIR",
                   help="directory of checkouts (owner__name or name) used to "
                        "follow `uses:` into other repositories. Repeatable.")
    p.add_argument("--min-tests", type=int, default=1,
                   help="ignore units with fewer than N test files (default 1)")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    resolver = make_resolver(args.resolve_repos) if args.resolve_repos else None
    rows = []
    for t in args.targets:
        if not os.path.isdir(t):
            sys.stderr.write(f"error: not a directory: {t}\n")
            return 2
        rows += check_repo(t, resolver=resolver)

    rows = [r for r in rows if r.n_tests >= args.min_tests or r.verdict == "unsupported"]
    findings = [r for r in rows if r.verdict in FINDING_VERDICTS]

    for r in sorted(findings, key=lambda x: (x.confidence != "high", -x.n_tests)):
        print(f"{r.repo}  {r.unit}  ({r.name})")
        print(f"    [T10/{r.verdict} · confidence {r.confidence}] {r.message}")
        if r.confidence != "high":
            for u in r.unresolved:
                print(f"    | could not follow: {u}")

    if args.show_unknown:
        for r in sorted((x for x in rows if x.verdict == "unknown"),
                        key=lambda x: -x.n_tests):
            print(f"{r.repo}  {r.unit}  ({r.name})")
            print(f"    [T10/unknown] {r.message}")
            for u in r.unresolved:
                print(f"    | {u}")

    hi = [r for r in findings if r.confidence == "high"]
    med = [r for r in findings if r.confidence != "high"]
    by = Counter(r.verdict for r in rows)
    tests_by = Counter()
    for r in rows:
        tests_by[r.verdict] += r.n_tests
    print(f"\norphan_tests T10: {len(hi)} finding(s) at high confidence "
          f"(+{len(med)} with unfollowed indirection) across "
          f"{len(set(r.repo for r in rows))} repo(s), {len(rows)} unit(s)")
    print(f"  test files behind high-confidence findings: "
          f"{sum(r.n_tests for r in hi)}  (+{sum(r.n_tests for r in med)} medium)")
    print("  units by verdict: " + "  ".join(f"{k}={v}" for k, v in sorted(by.items())))
    print("  test files:       " + "  ".join(f"{k}={v}" for k, v in sorted(tests_by.items())))
    if by.get("unknown"):
        print(f"  NOTE: {by['unknown']} unit(s) unknown -- indirection this tool "
              f"cannot follow. Not counted as clean. Use --show-unknown.")
    if by.get("unsupported"):
        print(f"  NOTE: {by['unsupported']} unit(s) in unmodelled ecosystems -- "
              f"not scanned, not clean.")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump([r._asdict() for r in rows], fh, indent=1)
        print(f"  json: {args.json}")

    if not findings:
        print("orphan_tests: CLEAN")
        return 0
    return 0 if args.report else 1


if __name__ == "__main__":
    sys.exit(main())
