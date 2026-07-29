#!/usr/bin/env python3
"""
Tests for orphan_tests (T10).

Run:
    python3 tools/theater/test_orphan_tests.py

STRUCTURE, and why the second half is longer than the first: T10's failure mode
is not missing a defect, it is inventing one. Tests reach their runner through
package scripts, workspace fan-out, Makefiles, shell scripts, composite actions
and reusable workflows in other repositories. Every one of those paths that the
tool fails to follow becomes a repo wrongly accused of having a dead test suite,
and a detector that cries wolf is worth less than no detector -- this toolchain
has already proved that several times over (README ledger).

So TestFalsePositives pins each indirection shape that MUST resolve to `wired`,
and TestUncertaintyIsRecordedNotSwallowed pins what happens when a path cannot
be followed: the finding survives at lowered confidence with the unfollowable
thing named, rather than being erased. Collapsing "I could not check" into
"clean" is the exact defect this programme exists to find, and shipping it
inside the detector for it would be humiliating -- but so is the opposite,
disposing of a true finding because something unrelated was unreadable. The
first cut did the second, and measuring against a known-real case is what
caught it.
"""

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import orphan_tests as ot  # noqa: E402


def write_tree(files):
    tmp = tempfile.mkdtemp(prefix="t10-")
    for rel, content in files.items():
        full = os.path.join(tmp, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as fh:
            fh.write(content)
    return tmp


def verdicts(files):
    """{unit_dir: verdict} for a synthetic repo."""
    root = write_tree(files)
    return {r.unit: r.verdict for r in ot.check_repo(root, "t")}, root


def rows(files):
    return {r.unit: r for r in ot.check_repo(write_tree(files), "t")}


SPEC = "describe('x', () => { it('works', () => {}); });\n"
PYTEST = "def test_x():\n    assert True\n"


# ---------------------------------------------------------------------------
# Positive: the defect is found
# ---------------------------------------------------------------------------

class TestFires(unittest.TestCase):

    def test_js_suite_with_no_workflow_invocation_is_orphaned(self):
        v, _ = verdicts({
            "package.json": '{"name":"app","scripts":{"build":"tsc","test":"jest"}}',
            "src/a.spec.ts": SPEC,
            ".github/workflows/ci.yml":
                "name: CI\non: [push]\njobs:\n  b:\n    steps:\n"
                "      - run: pnpm build\n",
        })
        self.assertEqual(v["."], "orphaned")

    def test_python_suite_with_lint_only_workflow_is_orphaned(self):
        v, _ = verdicts({
            "pyproject.toml": "[project]\nname='x'\n",
            "tests/test_a.py": PYTEST,
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  l:\n    steps:\n      - run: ruff check .\n",
        })
        self.assertEqual(v["."], "orphaned")

    def test_the_ops_platform_shape(self):
        """
        The case this tool was built for. A monorepo that DOES run tests -- but
        only for one package. A repo-level boolean answers "yes, tests run" and
        misses 1,296 of them.
        """
        v, _ = verdicts({
            "package.json": '{"name":"root","private":true}',
            "apps/api/package.json": '{"name":"@ops/api","scripts":{"test":"jest"}}',
            "apps/api/src/a.spec.ts": SPEC,
            "apps/api/src/b.spec.ts": SPEC,
            "e2e/package.json": '{"name":"@cu2/e2e","scripts":{"test:ci":"playwright test"}}',
            "e2e/x.spec.ts": SPEC,
            ".github/workflows/e2e.yml":
                "on: [push]\njobs:\n  e:\n    steps:\n"
                "      - run: pnpm --filter @cu2/e2e test:ci\n",
            ".github/workflows/deploy.yml":
                "on:\n  push:\n    branches: [main]\njobs:\n  t:\n    steps:\n"
                "      - run: pnpm --filter @ops/api exec tsc --noEmit\n",
        })
        self.assertEqual(v["apps/api"], "orphaned")
        self.assertEqual(v["e2e"], "wired")

    def test_noop_test_script_is_a_finding_even_though_ci_runs_it(self):
        """`exit 0` wearing a test suite's clothes. CI is green and cannot go red."""
        v, _ = verdicts({
            "package.json": '{"name":"app","scripts":{"test":"echo \\"no tests\\" && exit 0"}}',
            "src/a.spec.ts": SPEC,
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  t:\n    steps:\n      - run: pnpm test\n",
        })
        self.assertEqual(v["."], "noop")

    def test_a_delegating_root_script_is_not_a_noop(self):
        """
        broflo, hand-verified. Root `test` fans out to apps/**; CI runs it and
        two packages really are tested. The root's own specs are unreached --
        that is `orphaned`. Calling it `noop` asserted the check "cannot go
        red" about a check that tests two packages.
        """
        r = rows({
            "package.json": '{"name":"root","scripts":{"test":"pnpm --filter \'./apps/**\' run test"}}',
            "e2e/x.spec.ts": SPEC,
            "apps/api/package.json": '{"name":"@b/api","scripts":{"test":"jest"}}',
            "apps/api/a.spec.ts": SPEC,
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  t:\n    steps:\n      - run: pnpm test\n",
        })
        self.assertEqual(r["apps/api"].verdict, "wired")
        self.assertEqual(r["."].verdict, "orphaned")

    def test_exit_code_is_1_when_something_is_found(self):
        root = write_tree({
            "package.json": '{"name":"a","scripts":{"test":"jest"}}',
            "src/a.spec.ts": SPEC,
            ".github/workflows/ci.yml": "on: [push]\njobs:\n  b:\n    steps:\n      - run: pnpm build\n",
        })
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = ot.main([root])
        self.assertEqual(code, 1)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(ot.main([root, "--report"]), 0)


# ---------------------------------------------------------------------------
# False positives: every legitimate path to a runner must resolve to `wired`
# ---------------------------------------------------------------------------

class TestFalsePositives(unittest.TestCase):

    def _wired(self, files, unit="."):
        v, _ = verdicts(files)
        self.assertEqual(v.get(unit), "wired", f"expected wired, got {v}")

    def test_npm_test_script_indirection(self):
        self._wired({
            "package.json": '{"name":"a","scripts":{"test":"jest --ci"}}',
            "src/a.spec.ts": SPEC,
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  t:\n    steps:\n      - run: npm test\n",
        })

    def test_pretest_hook_carries_the_runner(self):
        self._wired({
            "package.json": '{"name":"a","scripts":{"pretest":"vitest run","test":"echo done"}}',
            "src/a.spec.ts": SPEC,
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  t:\n    steps:\n      - run: pnpm test\n",
        })

    def test_turbo_fanout_covers_every_package(self):
        v, _ = verdicts({
            "package.json": '{"name":"root","scripts":{"test":"turbo run test"}}',
            "apps/api/package.json": '{"name":"@x/api","scripts":{"test":"jest"}}',
            "apps/api/a.spec.ts": SPEC,
            "apps/web/package.json": '{"name":"@x/web","scripts":{"test":"vitest run"}}',
            "apps/web/b.spec.ts": SPEC,
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  t:\n    steps:\n      - run: pnpm test\n",
        })
        self.assertEqual(v["apps/api"], "wired")
        self.assertEqual(v["apps/web"], "wired")

    def test_pnpm_path_glob_filter(self):
        """
        broflo, verified by hand. `pnpm test` -> `--filter './apps/**' run test`
        -> apps/api runs jest over 28 spec files, on every push. Unresolved, the
        glob made a fully-tested repo look untested -- and the tool reported
        three findings for it, all false.
        """
        v, _ = verdicts({
            "package.json": '{"name":"root","scripts":{"test":"pnpm --filter \'./apps/**\' run test"}}',
            "apps/api/package.json": '{"name":"@b/api","scripts":{"test":"jest"}}',
            "apps/api/a.spec.ts": SPEC,
            "apps/web/package.json": '{"name":"@b/web","scripts":{"test":"vitest run"}}',
            "apps/web/b.spec.ts": SPEC,
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  t:\n    steps:\n      - run: pnpm test\n",
        })
        self.assertEqual(v["apps/api"], "wired")
        self.assertEqual(v["apps/web"], "wired")

    def test_jest_pass_with_no_tests_is_still_a_runner(self):
        """The flag changes what an EMPTY run means; it does not stop jest running."""
        v, _ = verdicts({
            # split so this file stays clean under T5 (ledger #15); the first
            # attempt split it INSIDE the JSON literal and silently produced
            # unparseable package.json, which the assertion then blamed on the
            # detector.
            "package.json": '{"name":"a","scripts":{"test":"jest --pass'
                            + 'WithNoTests"}}',
            "src/a.spec.ts": SPEC,
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  t:\n    steps:\n      - run: pnpm test\n",
        })
        self.assertEqual(v["."], "wired")

    def test_name_glob_filter(self):
        v, _ = verdicts({
            "package.json": '{"name":"root","scripts":{"test":"pnpm --filter @b/* run test"}}',
            "pkg/api/package.json": '{"name":"@b/api","scripts":{"test":"jest"}}',
            "pkg/api/a.spec.ts": SPEC,
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  t:\n    steps:\n      - run: pnpm test\n",
        })
        self.assertEqual(v["pkg/api"], "wired")

    def test_pnpm_recursive_fanout(self):
        v, _ = verdicts({
            "package.json": '{"name":"root"}',
            "pkg/package.json": '{"name":"p","scripts":{"test":"jest"}}',
            "pkg/a.spec.ts": SPEC,
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  t:\n    steps:\n      - run: pnpm -r test\n",
        })
        self.assertEqual(v["pkg"], "wired")

    def test_working_directory_scopes_a_bare_runner(self):
        v, _ = verdicts({
            "package.json": '{"name":"root"}',
            "backend/package.json": '{"name":"b","scripts":{"test":"jest"}}',
            "backend/a.spec.ts": SPEC,
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  t:\n    steps:\n"
                "      - name: run\n        working-directory: backend\n        run: npx jest\n",
        })
        self.assertEqual(v["backend"], "wired")

    def test_working_directory_covers_tests_below_it_even_with_no_project_marker(self):
        """
        resistance-wine, hand-verified. No pyproject.toml anywhere, so all 104
        Python tests attach to the repo root -- while the workflow that runs
        them twice a day declares `working-directory: backend`. Comparing the
        runner's directory to the UNIT's directory reported a live suite as
        dead. Coverage has to be judged against the test files.
        """
        v, _ = verdicts({
            "backend/tests/test_a.py": PYTEST,
            "backend/tests/test_b.py": PYTEST,
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  t:\n    steps:\n"
                "      - working-directory: backend\n        run: pytest tests/ -q\n",
        })
        self.assertEqual(v["."], "wired")

    def test_partially_covered_suite_is_reported_as_partial(self):
        """Half a suite running is not a pass and not a clean sheet."""
        r = rows({
            "backend/tests/test_a.py": PYTEST,
            "worker/tests/test_b.py": PYTEST,
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  t:\n    steps:\n"
                "      - working-directory: backend\n        run: pytest -q\n",
        })["."]
        self.assertEqual(r.verdict, "partial")
        self.assertIn("worker/tests/test_b.py", r.message)

    def test_makefile_target(self):
        self._wired({
            "pyproject.toml": "[project]\nname='x'\n",
            "tests/test_a.py": PYTEST,
            "Makefile": "lint:\n\truff check .\n\ntest:\n\tpytest -q\n",
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  t:\n    steps:\n      - run: make test\n",
        })

    def test_committed_shell_script(self):
        self._wired({
            "pyproject.toml": "[project]\nname='x'\n",
            "tests/test_a.py": PYTEST,
            "scripts/ci.sh": "#!/bin/bash\nset -e\npytest -q\n",
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  t:\n    steps:\n      - run: bash scripts/ci.sh\n",
        })

    def test_node_script_runner_is_followed(self):
        """
        dev-studio's CI gate is `node tools/test-kit.mjs unit`, a custom
        orchestrator that spawns vitest. Following only *.sh reported 77 of its
        test files as unreachable when they run on every push.
        """
        v, _ = verdicts({
            "package.json": '{"name":"a","scripts":{"x":"y"}}',
            "src/a.spec.ts": SPEC,
            "tools/test-kit.mjs":
                'import { spawnSync } from "node:child_process";\n'
                'spawnSync("npx", ["vitest", "run"], { stdio: "inherit" });\n',
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  t:\n    steps:\n"
                "      - run: node tools/test-kit.mjs unit\n",
        })
        self.assertEqual(v["."], "wired")

    def test_node_builtin_runner_via_spawn_array(self):
        """dev-studio: spawnSync("node", ["--import","tsx","--test", glob])."""
        v, _ = verdicts({
            "package.json": '{"name":"a","scripts":{"x":"y"}}',
            "src/a.spec.ts": SPEC,
            "tools/test-kit.mjs":
                'import { spawnSync } from "node:child_process";\n'
                'spawnSync("node", ["--import", "tsx", "--test", "src/**/*.spec.ts"]);\n',
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  t:\n    steps:\n"
                "      - run: node tools/test-kit.mjs unit\n",
        })
        self.assertEqual(v["."], "wired")

    def test_unreadable_runner_inside_a_followed_script_lowers_confidence(self):
        """Reading a script and recognising nothing is not proof of nothing."""
        r = rows({
            "package.json": '{"name":"a","scripts":{"x":"y"}}',
            "src/a.spec.ts": SPEC,
            "tools/kit.mjs": 'import x from "./x.mjs";\nx.runEverything();\n',
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  t:\n    steps:\n      - run: node tools/kit.mjs\n",
        })["."]
        self.assertEqual(r.confidence, "medium")
        self.assertTrue(any("no recognisable test runner" in c for c in r.unresolved))

    def test_jest_testpathpattern_is_not_the_node_test_flag(self):
        self.assertIsNone(ot.JS_RUNNER_RE.search("--testPathPattern=foo"))
        self.assertIsNone(ot.JS_RUNNER_RE.search("--test-timeout 5000"))

    def test_python_script_runner_is_followed(self):
        v, _ = verdicts({
            "pyproject.toml": "[project]\nname='x'\n",
            "tests/test_a.py": PYTEST,
            "ci/run.py": "import subprocess\nsubprocess.run(['pytest','-q'])\n",
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  t:\n    steps:\n      - run: python3 ci/run.py\n",
        })
        self.assertEqual(v["."], "wired")

    def test_local_composite_action(self):
        self._wired({
            "package.json": '{"name":"a","scripts":{"test":"jest"}}',
            "src/a.spec.ts": SPEC,
            ".github/actions/verify/action.yml":
                "runs:\n  using: composite\n  steps:\n    - run: pnpm test\n      shell: bash\n",
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  t:\n    steps:\n      - uses: ./.github/actions/verify\n",
        })

    def test_multiline_run_block(self):
        self._wired({
            "package.json": '{"name":"a","scripts":{"test":"jest"}}',
            "src/a.spec.ts": SPEC,
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  t:\n    steps:\n      - run: |\n"
                "          set -euo pipefail\n          pnpm install\n          pnpm test\n",
        })

    def test_python_module_invocation(self):
        self._wired({
            "pyproject.toml": "[project]\nname='x'\n",
            "tests/test_a.py": PYTEST,
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  t:\n    steps:\n      - run: python3 -m pytest tests/\n",
        })

    # -- token-boundary traps ------------------------------------------------
    # The ancestor of this class of bug: an `xit(` pattern that matched `exit(`
    # and inflated a sweep 12x. Same shape, new tokens.

    def test_ava_does_not_match_available(self):
        self.assertIsNone(ot.JS_RUNNER_RE.search("echo no runner available here"))
        self.assertIsNone(ot.JS_RUNNER_RE.search("java -jar app.jar"))

    def test_tap_does_not_match_bootstrap(self):
        self.assertIsNone(ot.JS_RUNNER_RE.search("./bootstrap.sh --tapered"))

    def test_tox_does_not_match_detoxify(self):
        self.assertIsNone(ot.PY_RUNNER_RE.search("pip install detoxify"))
        self.assertIsNone(ot.PY_RUNNER_RE.search("python -m toxicity_check"))

    def test_bare_word_test_is_not_a_runner(self):
        for s in ("npm run build:test-utils", "echo test", "cargo build",
                  "./deploy.sh --dry-run", "pnpm install"):
            self.assertIsNone(ot.JS_RUNNER_RE.search(s), s)
            self.assertIsNone(ot.PY_RUNNER_RE.search(s), s)

    def test_install_verbs_are_not_treated_as_scripts(self):
        """`pnpm install` must not be looked up as a script named 'install'."""
        v, _ = verdicts({
            "package.json": '{"name":"a","scripts":{"test":"jest"}}',
            "src/a.spec.ts": SPEC,
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  t:\n    steps:\n"
                "      - run: pnpm install --frozen-lockfile\n      - run: pnpm test\n",
        })
        self.assertEqual(v["."], "wired")

    def test_node_modules_specs_are_not_counted(self):
        root = write_tree({
            "package.json": '{"name":"a","scripts":{"test":"jest"}}',
            "node_modules/dep/x.spec.js": SPEC,
            ".github/workflows/ci.yml": "on: [push]\njobs:\n  b:\n    steps:\n      - run: pnpm build\n",
        })
        self.assertEqual([r for r in ot.check_repo(root, "t")], [])


# ---------------------------------------------------------------------------
# Unknown: indirection the tool cannot follow is never an accusation
# ---------------------------------------------------------------------------

class TestUncertaintyIsRecordedNotSwallowed(unittest.TestCase):
    """
    Indirection the tool cannot follow must LOWER CONFIDENCE and be printed --
    not erase the finding.

    The first cut of this class asserted `unknown` for each of these shapes. It
    was wrong, and measuring it is what proved it: ops-platform's 145 orphaned
    suites, confirmed by hand, were being filed under "could not check" because
    one unrelated theater-gate call sat in an unrelated workflow. Nearly every
    repo in the estate calls something it cannot read, so that rule quietly
    disposed of true findings estate-wide.

    Swallowing a real finding and inventing a false one are the same error.
    These tests now pin the harder property: the finding survives, the
    confidence drops, and the specific unfollowable thing is named in the
    output so a human can dismiss it in seconds.
    """

    def _caveated(self, files, needle, unit="."):
        r = rows(files)[unit]
        self.assertEqual(r.verdict, "orphaned")
        self.assertEqual(r.confidence, "medium")
        self.assertTrue(any(needle in c for c in r.unresolved),
                        f"caveat {needle!r} not recorded; got {r.unresolved}")

    def test_remote_reusable_workflow_is_a_recorded_caveat(self):
        self._caveated({
            "package.json": '{"name":"a","scripts":{"test":"jest"}}',
            "src/a.spec.ts": SPEC,
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  b:\n    steps:\n      - run: pnpm build\n",
            ".github/workflows/x.yml":
                "on: [push]\njobs:\n  t:\n    uses: some-org/infra/.github/workflows/verify.yml@main\n",
        }, "is in another repo")

    def test_uncommitted_script_is_a_recorded_caveat(self):
        self._caveated({
            "package.json": '{"name":"a","scripts":{"test":"jest"}}',
            "src/a.spec.ts": SPEC,
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  t:\n    steps:\n      - run: bash ci/run.sh\n",
        }, "script not in the repo")

    def test_docker_run_is_a_recorded_caveat(self):
        self._caveated({
            "package.json": '{"name":"a","scripts":{"test":"jest"}}',
            "src/a.spec.ts": SPEC,
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  t:\n    steps:\n      - run: docker compose run app\n",
        }, "docker")

    def test_third_party_action_is_a_recorded_caveat(self):
        self._caveated({
            "package.json": '{"name":"a","scripts":{"test":"jest"}}',
            "src/a.spec.ts": SPEC,
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  t:\n    steps:\n"
                "      - uses: some-vendor/test-runner@v3\n      - run: pnpm build\n",
        }, "third-party action")

    def test_clean_repo_finding_is_high_confidence(self):
        """No unfollowable indirection -> no hedging."""
        r = rows({
            "package.json": '{"name":"a","scripts":{"test":"jest"}}',
            "src/a.spec.ts": SPEC,
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  b:\n    steps:\n"
                "      - uses: actions/checkout@v5\n      - run: pnpm build\n",
        })["."]
        self.assertEqual((r.verdict, r.confidence), ("orphaned", "high"))

    def test_no_workflows_at_all_is_unknown_not_orphaned(self):
        """A repo with no CI is a different problem; calling it orphaned buries it."""
        v, _ = verdicts({
            "package.json": '{"name":"a","scripts":{"test":"jest"}}',
            "src/a.spec.ts": SPEC,
        })
        self.assertEqual(v["."], "unknown")

    def test_callable_only_workflow_is_not_evidence(self):
        """
        ops-platform ships reusable-scan.yml for OTHER repos. It is
        `on: workflow_call` only, never runs on an ops-platform push, and a
        config string inside it made the whole repo look covered -- hiding 145
        orphaned suites. Exactly the T9 `declares_push` trap.
        """
        v, _ = verdicts({
            "package.json": '{"name":"a","scripts":{"test":"jest"}}',
            "src/a.spec.ts": SPEC,
            ".github/workflows/reusable.yml":
                "on:\n  workflow_call:\n    inputs:\n      x:\n        type: string\n"
                "jobs:\n  t:\n    steps:\n      - run: pnpm test\n",
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  b:\n    steps:\n      - run: pnpm build\n",
        })
        self.assertEqual(v["."], "orphaned")

    def test_runner_named_inside_grep_is_not_a_runner_invoked(self):
        v, _ = verdicts({
            "package.json": '{"name":"a","scripts":{"test":"jest"}}',
            "src/a.spec.ts": SPEC,
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  t:\n    steps:\n"
                '      - run: echo "$CMD" | grep -q "pytest" && echo yes\n',
        })
        self.assertEqual(v["."], "orphaned")

    def test_unsupported_ecosystem_gets_a_row_not_a_silent_drop(self):
        r = ot.check_repo(write_tree({"go.mod": "module x\n", "a_test.go": "package x\n"}), "t")
        self.assertEqual([x.verdict for x in r], ["unsupported"])
        self.assertIn("not scanned, not clean", r[0].message)


class TestCrossRepoResolution(unittest.TestCase):
    """
    `--resolve-repos`. Added after the estate sweep showed 126 caveats that were
    just reusable workflows sitting in repos already on disk.

    Pinned because the first version of this code crashed on every invocation --
    a shadowed variable name -- and the 31 tests then in this file all passed,
    because not one of them exercised the resolver. New code with no test is
    how a detector ships broken.
    """

    def _estate(self, caller_files, other_files, other_name="org__infra"):
        import shutil
        estate = tempfile.mkdtemp(prefix="t10-estate-")
        caller = write_tree(caller_files)
        other = write_tree(other_files)
        shutil.move(other, os.path.join(estate, other_name))
        os.makedirs(os.path.join(estate, other_name, ".git"), exist_ok=True)
        return caller, ot.make_resolver([estate])

    CALLER = {
        "package.json": '{"name":"a","scripts":{"test":"jest"}}',
        "src/a.spec.ts": SPEC,
        ".github/workflows/ci.yml":
            "on: [push]\njobs:\n  t:\n"
            "    uses: org/infra/.github/workflows/verify.yml@main\n",
    }

    def test_reusable_workflow_that_runs_tests_makes_the_unit_wired(self):
        caller, res = self._estate(self.CALLER, {
            ".github/workflows/verify.yml":
                "on:\n  workflow_call:\njobs:\n  v:\n    steps:\n      - run: pnpm test\n",
        })
        r = {x.unit: x for x in ot.check_repo(caller, "t", resolver=res)}["."]
        self.assertEqual(r.verdict, "wired")

    def test_reusable_workflow_that_does_not_run_tests_gives_high_confidence(self):
        """The point of resolving: doubt REMOVED, not merely reported."""
        caller, res = self._estate(self.CALLER, {
            ".github/workflows/verify.yml":
                "on:\n  workflow_call:\njobs:\n  v:\n    steps:\n      - run: pnpm lint\n",
        })
        r = {x.unit: x for x in ot.check_repo(caller, "t", resolver=res)}["."]
        self.assertEqual((r.verdict, r.confidence), ("orphaned", "high"))
        self.assertEqual(r.unresolved, [])

    def test_stale_checkout_without_the_file_says_so(self):
        """
        A checkout existing is not the file existing. The first estate run
        resolved cu2-standards to a Phase-1 clone taken before the workflow was
        restored, found nothing, and reported plain "in another repo" -- hiding
        that the answer was on disk under a different path.
        """
        caller, res = self._estate(self.CALLER, {"README.md": "no workflows here\n"})
        r = {x.unit: x for x in ot.check_repo(caller, "t", resolver=res)}["."]
        self.assertEqual(r.confidence, "medium")
        self.assertTrue(any("stale?" in c for c in r.unresolved), r.unresolved)

    def test_second_search_dir_is_tried_when_the_first_lacks_the_file(self):
        import shutil
        estate_a = tempfile.mkdtemp(prefix="t10-a-")
        estate_b = tempfile.mkdtemp(prefix="t10-b-")
        stale = write_tree({"README.md": "x\n"})
        shutil.move(stale, os.path.join(estate_a, "org__infra"))
        os.makedirs(os.path.join(estate_a, "org__infra", ".git"), exist_ok=True)
        good = write_tree({".github/workflows/verify.yml":
                           "on:\n  workflow_call:\njobs:\n  v:\n    steps:\n"
                           "      - run: pnpm test\n"})
        shutil.move(good, os.path.join(estate_b, "org__infra"))
        os.makedirs(os.path.join(estate_b, "org__infra", ".git"), exist_ok=True)
        r = {x.unit: x for x in ot.check_repo(
            write_tree(self.CALLER), "t",
            resolver=ot.make_resolver([estate_a, estate_b]))}["."]
        self.assertEqual(r.verdict, "wired")

    def test_unresolvable_repo_still_degrades_confidence(self):
        r = {x.unit: x for x in ot.check_repo(
            write_tree(self.CALLER), "t",
            resolver=ot.make_resolver(["/nonexistent"]))}["."]
        self.assertEqual((r.verdict, r.confidence), ("orphaned", "medium"))


class TestFanoutRecursion(unittest.TestCase):

    def test_root_script_that_fans_out_to_itself_terminates_cleanly(self):
        """
        `"build": "turbo run build"` at the root fans out over every package
        WITH a build script -- including the root, whose build script is the
        fan-out. Before `seen` covered this path it burned MAX_DEPTH and emitted
        a bogus "recursion limit" caveat, which silently downgraded findings in
        23 repos.
        """
        r = rows({
            "package.json": '{"name":"root","scripts":{"build":"turbo run build","test":"turbo run test"}}',
            "apps/api/package.json": '{"name":"@x/api","scripts":{"build":"tsc"}}',
            "apps/api/a.spec.ts": SPEC,
            ".github/workflows/ci.yml":
                "on: [push]\njobs:\n  b:\n    steps:\n      - run: pnpm build\n",
        })["apps/api"]
        self.assertEqual(r.verdict, "orphaned")
        self.assertFalse([c for c in r.unresolved if "recursion limit" in c],
                         f"spurious recursion caveats: {r.unresolved}")
        self.assertEqual(r.confidence, "high")


class TestSelfConsistency(unittest.TestCase):

    def test_this_toolchain_is_not_itself_orphaned(self):
        """
        The tools directory has tests and they run in reusable-theater.yml. If
        T10 cannot see its own suite, it cannot see anyone's.
        """
        here = os.path.dirname(os.path.abspath(__file__))
        self.assertTrue(os.path.isfile(os.path.join(here, "test_theater_scan.py")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
