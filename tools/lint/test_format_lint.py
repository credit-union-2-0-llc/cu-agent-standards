"""Regression tests for format_lint.py.

The linter's own failure mode is passing something it should have caught, so every
test here plants a defect and asserts it is reported. A linter tested only against
conforming input is a control with no negative case — the thing this repository's
theater detector exists to find.

The two behaviours that distinguish this linter from its upstream get explicit
coverage, because they are the reason it was written rather than copied:

  * required lists are parsed from the schema docs, not hardcoded
  * a required heading with no content underneath is a violation
"""

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
LINTER = HERE / "format_lint.py"

SKILL_SCHEMA = """\
# SKILL Schema

## Required frontmatter

| Key | Meaning |
| --- | --- |
| `name` | the name |
| `owner` | a role |

## Required sections

- **When to use** — the trigger.
- **Procedure** — the steps.

## Canonical shape

```markdown
whatever
```
"""

AGENT_SCHEMA = """\
# AGENT-SPEC Schema

## Required frontmatter

| Key | Meaning |
| --- | --- |
| `role` | the role |

## Required sections

- **Mission** — the one job.

## Canonical shape

```markdown
whatever
```
"""

GOOD_SKILL = """\
---
name: a-skill
owner: platform-eng
---

# A Skill

## When to use
Use this when a matching task shows up and the trigger conditions genuinely apply here.

## Procedure
1. Do the first thing carefully, then verify it before moving on to the next step.
"""


def run(target):
    proc = subprocess.run(
        [sys.executable, str(LINTER), str(target)],
        capture_output=True, text=True,
    )
    return proc.returncode, proc.stdout + proc.stderr


class Fixture:
    """A throwaway repo with its own schemas, so tests never depend on real ones."""

    def __enter__(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        (self.dir / "skills" / "examples").mkdir(parents=True)
        (self.dir / "agents" / "archetypes").mkdir(parents=True)
        (self.dir / "skills" / "SKILL.schema.md").write_text(SKILL_SCHEMA)
        (self.dir / "agents" / "AGENT-SPEC.schema.md").write_text(AGENT_SCHEMA)
        return self

    def skill(self, text, name="s.md"):
        p = self.dir / "skills" / "examples" / name
        p.write_text(textwrap.dedent(text))
        return p

    def __exit__(self, *exc):
        shutil.rmtree(self.dir, ignore_errors=True)


class TestConformingInput(unittest.TestCase):
    def test_good_skill_passes(self):
        with Fixture() as f:
            f.skill(GOOD_SKILL)
            code, out = run(f.dir)
            self.assertEqual(code, 0, out)
            self.assertIn("CLEAN", out)


class TestPlantedDefects(unittest.TestCase):
    def test_missing_section_is_reported(self):
        with Fixture() as f:
            f.skill(GOOD_SKILL.replace("## Procedure\n1. Do the first thing carefully, then verify it before moving on to the next step.\n", ""))
            code, out = run(f.dir)
            self.assertEqual(code, 1, out)
            self.assertIn("missing required section heading: Procedure", out)

    def test_missing_frontmatter_key_is_reported(self):
        with Fixture() as f:
            f.skill(GOOD_SKILL.replace("owner: platform-eng\n", ""))
            code, out = run(f.dir)
            self.assertEqual(code, 1, out)
            self.assertIn("missing frontmatter key: owner", out)

    def test_absent_frontmatter_block_is_reported(self):
        with Fixture() as f:
            f.skill("# A Skill\n\n## When to use\nx y z a b c d e f\n\n## Procedure\n1. a b c d e f g h\n")
            code, out = run(f.dir)
            self.assertEqual(code, 1, out)
            self.assertIn("missing YAML frontmatter", out)

    def test_placeholder_owner_is_reported(self):
        """All 13 upstream skills ship `owner: <YOUR_HANDLE>`; that must not pass."""
        with Fixture() as f:
            f.skill(GOOD_SKILL.replace("owner: platform-eng", "owner: <YOUR_HANDLE>"))
            code, out = run(f.dir)
            self.assertEqual(code, 1, out)
            self.assertIn("template placeholder", out)

    def test_invalid_enum_value_is_reported(self):
        with Fixture() as f:
            f.skill(GOOD_SKILL.replace(
                "owner: platform-eng", "owner: platform-eng\napproval_required: whenever_i_feel"))
            code, out = run(f.dir)
            self.assertEqual(code, 1, out)
            self.assertIn("invalid frontmatter value for approval_required", out)


class TestMinimumSubstance(unittest.TestCase):
    """The behaviour upstream lacks: presence is not conformance."""

    def test_empty_required_section_fails(self):
        with Fixture() as f:
            f.skill("""\
                ---
                name: hollow
                owner: platform-eng
                ---

                # Hollow

                ## When to use

                ## Procedure
                """)
            code, out = run(f.dir)
            self.assertEqual(code, 1, out)
            self.assertIn("is an outline, not a spec", out)

    def test_one_word_section_fails(self):
        with Fixture() as f:
            f.skill(GOOD_SKILL.replace(
                "1. Do the first thing carefully, then verify it before moving on to the next step.",
                "TODO"))
            code, out = run(f.dir)
            self.assertEqual(code, 1, out)
            self.assertIn("words of content", out)


class TestSchemaIsTheSourceOfTruth(unittest.TestCase):
    """Editing the schema must change what the linter enforces, with no code change."""

    def test_adding_a_required_section_to_the_schema_is_enforced(self):
        with Fixture() as f:
            f.skill(GOOD_SKILL)
            self.assertEqual(run(f.dir)[0], 0)

            schema = f.dir / "skills" / "SKILL.schema.md"
            schema.write_text(schema.read_text().replace(
                "- **Procedure** — the steps.",
                "- **Procedure** — the steps.\n- **Landmines** — the scar tissue.",
            ))
            code, out = run(f.dir)
            self.assertEqual(code, 1, out)
            self.assertIn("missing required section heading: Landmines", out)

    def test_unparseable_schema_exits_two_not_zero(self):
        """A schema we cannot read must fail loudly, never 'nothing is required'."""
        with Fixture() as f:
            f.skill(GOOD_SKILL)
            (f.dir / "skills" / "SKILL.schema.md").write_text("# no required sections here\n")
            code, out = run(f.dir)
            self.assertEqual(code, 2, out)
            self.assertIn("parsed 0 required", out)


class TestAgainstThisRepository(unittest.TestCase):
    def test_repo_is_clean(self):
        code, out = run(REPO)
        self.assertEqual(code, 0, f"this repository violates its own schemas:\n{out}")

    def test_repo_actually_has_artifacts_to_check(self):
        """Guard against a green run that checked nothing."""
        _, out = run(REPO)
        self.assertNotIn("0 artifact(s)", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
