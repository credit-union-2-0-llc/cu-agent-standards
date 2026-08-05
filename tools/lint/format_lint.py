#!/usr/bin/env python3
"""format_lint.py — schema conformance for agent and skill artifacts.

Why this exists
---------------
This repository published `agents/AGENT-SPEC.schema.md` and `skills/SKILL.schema.md`
with nothing enforcing either. Both declared a "Required sections" list that was
prose: a reader was asked to comply, and CI never checked. The first skill schema
committed here silently dropped three of the nine sections it inherited from
upstream — *Output contract*, *Privacy and approval*, *Maintenance* — and both
example skills were then written to the reduced list. Every gate was green.

A declared shape that nothing verifies is a signal that lies, which is the failure
class `tools/theater` exists to name. This closes it on our own schemas.

How it differs from upstream
----------------------------
Adapted from `gates/scripts/format_lint.py` in the-agent-foundry/foundry by
Darryl Hicks (MIT) — the same upstream credited in LICENSE for parts of the
sanitizer. Two deliberate changes:

  1. **The schema files are the single source of truth.** Upstream hardcodes the
     required frontmatter keys and section headings in a `RULES` dict, so the
     schema doc and the linter are two copies of one list and can drift apart
     silently. Here both are parsed out of the schema markdown at runtime. Edit
     the schema, and the linter follows on the next run. This is the same
     single-source discipline that `test_ledger_count.py` applies to the ledger
     count, for the same reason: this repository has already been bitten twice by
     a number duplicated across files.

  2. **Presence is not enough.** Upstream checks that a heading exists. A file
     carrying all nine required headings with no content under any of them passes
     upstream CLEAN. Here a required section must contain at least
     `MIN_SECTION_WORDS` words of real content, so an outline cannot pass as a
     spec.

Pure Python 3 standard library, no dependencies, identical on a laptop and in CI.

Usage
-----
    python3 tools/lint/format_lint.py [PATH]     # PATH defaults to repo root

Exit codes
----------
    0   every artifact conforms
    1   one or more violations (see report)
    2   usage or runtime error, including an unparseable schema
"""

import os
import re
import sys

MIN_SECTION_WORDS = 8

# Which schema governs which directory. Adding an artifact kind means adding a
# line here and a schema file — not editing a rules table in this script.
KINDS = {
    "skill": {
        "schema": "skills/SKILL.schema.md",
        "match": ("skills/examples",),
    },
    "agent": {
        "schema": "agents/AGENT-SPEC.schema.md",
        "match": ("agents/archetypes",),
    },
}

# Schemas, templates and prose describe the shape; they are not instances of it.
EXEMPT_BASENAMES = {
    "README.md",
    "SKILL.schema.md", "SKILL.template.md",
    "AGENT-SPEC.schema.md", "AGENTS.template.md", "SOUL.template.md",
    "TOOL-SPEC.schema.md", "TOOL.template.md",
    "PRINCIPLES.md", "PRINCIPLES.template.md",
}

FRONTMATTER_RE = re.compile(r"^\s*---\s*\n(.*?)\n---\s*\n", re.DOTALL)
# A required-section bullet: "- **When to use** — the trigger..."
SECTION_BULLET_RE = re.compile(r"^\s*[-*]\s+\*\*(.+?)\*\*", re.MULTILINE)
# A frontmatter table row: "| `name` | Short, specific skill name. |"
FM_ROW_RE = re.compile(r"^\s*\|\s*`([A-Za-z0-9_-]+)`\s*\|", re.MULTILINE)
HEADING_RE = re.compile(r"^(#{1,6})\s+(.*\S)\s*$")

ENUMS = {
    "data_sensitivity": {"public", "internal", "confidential", "restricted"},
    "approval_required": {
        "none", "before_write", "before_external_send", "before_live_change",
    },
}


def section_between(text, start_heading, stop_heading):
    """Body text under `## start_heading`, up to the next `## stop_heading`."""
    pat = re.compile(
        rf"^##\s+{re.escape(start_heading)}\s*$(.*?)(?=^##\s+|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    m = pat.search(text)
    return m.group(1) if m else ""


def load_schema(repo, rel_path):
    """Parse required frontmatter keys and section headings out of a schema doc.

    Raises ValueError if either list comes back empty — a schema we cannot parse
    must fail loudly, never silently degrade to "nothing is required", which would
    turn this linter into the very thing it checks for.
    """
    path = os.path.join(repo, rel_path)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise ValueError(f"cannot read schema {rel_path}: {exc}") from exc

    fm_block = section_between(text, "Required frontmatter", "Required sections")
    keys = FM_ROW_RE.findall(fm_block)

    sec_block = section_between(text, "Required sections", "Canonical shape")
    sections = [s.strip() for s in SECTION_BULLET_RE.findall(sec_block)]

    if not keys:
        raise ValueError(
            f"{rel_path}: parsed 0 required frontmatter keys from its "
            "'## Required frontmatter' table — schema shape changed"
        )
    if not sections:
        raise ValueError(
            f"{rel_path}: parsed 0 required sections from its "
            "'## Required sections' list — schema shape changed"
        )
    return {"frontmatter": keys, "sections": sections}


def classify(repo, path):
    if os.path.basename(path) in EXEMPT_BASENAMES or not path.endswith(".md"):
        return None
    rel = os.path.relpath(path, repo).replace(os.sep, "/")
    for kind, spec in KINDS.items():
        if any(frag in rel for frag in spec["match"]):
            return kind
    return None


def parse_frontmatter(text):
    m = FRONTMATTER_RE.match(text)
    if not m:
        return None
    values = {}
    for line in m.group(1).splitlines():
        km = re.match(r"^([A-Za-z0-9_-]+)\s*:\s*(.*?)\s*$", line)
        if km:
            values[km.group(1).strip()] = km.group(2).strip().strip("\"'")
    return values


def heading_bodies(text):
    """Map lowercased heading text -> word count of the body beneath it."""
    bodies, current, buf = {}, None, []
    for line in text.splitlines():
        hm = HEADING_RE.match(line)
        if hm:
            if current is not None:
                bodies[current] = len(" ".join(buf).split())
            current, buf = hm.group(2).strip().lower(), []
        elif current is not None:
            buf.append(line)
    if current is not None:
        bodies[current] = len(" ".join(buf).split())
    return bodies


def lint_file(path, spec):
    problems = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        return [f"cannot read file: {exc}"]

    fm = parse_frontmatter(text)
    if fm is None:
        problems.append("missing YAML frontmatter block (--- ... ---)")
    else:
        for req in spec["frontmatter"]:
            if req not in fm:
                problems.append(f"missing frontmatter key: {req}")
        for key, allowed in ENUMS.items():
            if key in fm and fm[key] not in allowed:
                problems.append(
                    f"invalid frontmatter value for {key}: {fm[key]!r} "
                    f"(allowed: {', '.join(sorted(allowed))})"
                )
        if fm.get("owner", "").startswith("<"):
            problems.append(
                f"owner is still a template placeholder: {fm['owner']!r} — "
                "name a real role, an artifact without an owner has no one to fix it"
            )

    bodies = heading_bodies(text)
    for req in spec["sections"]:
        key = req.lower()
        if key not in bodies:
            problems.append(f"missing required section heading: {req}")
        elif bodies[key] < MIN_SECTION_WORDS:
            problems.append(
                f"section '{req}' has {bodies[key]} words of content "
                f"(minimum {MIN_SECTION_WORDS}) — a heading with nothing under it "
                "is an outline, not a spec"
            )
    return problems


def iter_markdown(root):
    skip = {".git", "node_modules", "__pycache__", ".venv"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for name in sorted(filenames):
            if name.endswith(".md"):
                yield os.path.join(dirpath, name)


def main(argv):
    root = os.path.abspath(argv[1] if len(argv) > 1 else ".")
    if not os.path.exists(root):
        sys.stderr.write(f"error: path not found: {root}\n")
        return 2

    try:
        schemas = {k: load_schema(root, v["schema"]) for k, v in KINDS.items()}
    except ValueError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2

    for kind, spec in schemas.items():
        print(
            f"format_lint: {kind} schema requires "
            f"{len(spec['frontmatter'])} frontmatter key(s), "
            f"{len(spec['sections'])} section(s)"
        )

    total = checked = 0
    for path in sorted(iter_markdown(root)):
        kind = classify(root, path)
        if kind is None:
            continue
        checked += 1
        for problem in lint_file(path, schemas[kind]):
            print(f"{os.path.relpath(path, root)}: [{kind}] {problem}")
            total += 1

    print()
    if total == 0:
        print(f"format_lint: CLEAN. {checked} artifact(s) conform to schema.")
        return 0
    print(
        f"format_lint: FAILED. {total} violation(s) across "
        f"{checked} checked artifact(s)."
    )
    print("Match the canonical schema in agents/ or skills/ and re-run.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
