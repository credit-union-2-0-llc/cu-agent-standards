#!/usr/bin/env python3
"""check_workflow_permissions.py — every reusable workflow must declare `permissions:`.

A reusable workflow (`on: workflow_call`) with no top-level `permissions:` block
inherits whatever scope its CALLER's token has. This repo's three reusable
workflows are called from 86+ repositories, most at `@main`, so an undeclared
block means the token scope of every one of those jobs is decided by 86
different callers instead of by the code that runs. Declaring it pins the
ceiling: a called workflow can only narrow the caller's permissions, never widen.

Rules, per file under .github/workflows/ that declares `workflow_call`:
  * a top-level (column 0) `permissions:` key must exist, and
  * it must not be `write-all`.
Plain text parsing, stdlib only, so it runs identically in CI and on a laptop.

Usage:  python3 tools/lint/check_workflow_permissions.py [REPO_ROOT]
Exit:   0 conforming, 1 violation, 2 usage error or no reusable workflow found
        (finding none is an error: a glob that matches nothing must not pass).
"""

import pathlib
import re
import sys


def _code_lines(text):
    """Lines with full-line and trailing comments removed (naive: no # inside quotes needed here)."""
    out = []
    for line in text.splitlines():
        out.append(re.sub(r"(^|\s)#.*$", "", line).rstrip())
    return out


def is_reusable(lines):
    """True when the top-level `on:` key lists workflow_call (block, flow or scalar form)."""
    in_on = False
    for line in lines:
        if re.match(r"""^(on|"on"|'on'|true)\s*:""", line):
            in_on = True
            if "workflow_call" in line:
                return True
            continue
        if in_on:
            if line and not line[0].isspace():
                in_on = False
                continue
            if re.match(r"^\s+workflow_call\s*:", line):
                return True
    return False


def check_text(text):
    """Return a list of violation strings for one workflow file's text (empty if fine)."""
    lines = _code_lines(text)
    if not is_reusable(lines):
        return []
    perms = [l for l in lines if re.match(r"""^("permissions"|'permissions'|permissions)\s*:""", l)]
    if not perms:
        return ["reusable workflow has no top-level `permissions:` block "
                "(it inherits the caller's token scope)"]
    if re.search(r"""^\S+\s*:\s*(["']?)write-all\1\s*$""", perms[0]):
        return ["top-level `permissions: write-all` is not least privilege"]
    return []


def main(argv):
    root = pathlib.Path(argv[1] if len(argv) > 1 else ".")
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        print(f"error: {wf_dir} not found", file=sys.stderr)
        return 2
    files = sorted(list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml")))
    reusable = 0
    bad = 0
    for f in files:
        text = f.read_text(encoding="utf-8")
        if is_reusable(_code_lines(text)):
            reusable += 1
        for v in check_text(text):
            bad += 1
            print(f"::error file={f.relative_to(root)}::{v}")
    print(f"reusable workflows checked: {reusable}, violations: {bad}")
    if reusable == 0:
        print("error: no reusable workflow found; refusing to report a pass", file=sys.stderr)
        return 2
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
