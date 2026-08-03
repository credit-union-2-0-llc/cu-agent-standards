#!/usr/bin/env python3
"""
Tests for theater_scan.

Run:
    python3 tools/theater/test_theater_scan.py
    python3 -m unittest discover -s tools/theater -v

NOTE ON SAMPLES: skip markers are assembled at runtime ("x" + "it(...") so this
file stays clean under its own detector without an allowlist exception.

STRUCTURE: every detector has BOTH a positive test (it fires on the real defect)
and a false-positive test (it stays silent on the legitimate lookalike). The FP
half is the point. The first sweep written for this work reported 490 skipped
tests because its `xit` pattern (with paren) matched `exit` — a 12x inflation, produced by
the tool built to find inflated signals. TestFalsePositives::test_xit_does_not
_match_exit is that bug, pinned.
"""

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import theater_scan as ts  # noqa: E402

WF = ".github/workflows/ci.yml"


def lines(text):
    return [l + "\n" for l in text.split("\n")]


def write_tree(files):
    tmp = tempfile.mkdtemp(prefix="theater-")
    for rel, content in files.items():
        full = os.path.join(tmp, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as fh:
            fh.write(content)
    return tmp


def run(argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = ts.main(argv)
    return code, buf.getvalue()


# ---------------------------------------------------------------------------
# Positive: each detector fires on the real defect
# ---------------------------------------------------------------------------

class TestDetectorsFire(unittest.TestCase):

    def test_t1_suppressed_gate(self):
        """The real finding in cu2-agent-studio deploy.yml:133."""
        f = ts.detect_t1(WF, lines("      - run: pnpm audit --audit-level=high || true"))
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].detector, "T1")
        self.assertEqual(f[0].severity, "high")

    def test_t1_other_suppression_forms(self):
        for form in ("npm test || :", "make check || exit 0", "./verify.sh ; true"):
            with self.subTest(form=form):
                self.assertTrue(ts.detect_t1(WF, lines(f"      - run: {form}")))

    def test_t2_continue_on_error(self):
        f = ts.detect_t2(WF, lines("        continue-on-error: true"))
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].detector, "T2")

    def test_t3_python_block_form(self):
        src = "def load():\n    try:\n        return fetch()\n    except Exception:\n        return []"
        f = ts.detect_t3("app.py", lines(src))
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].detector, "T3")

    def test_t3_inline_catch_form(self):
        """The real shape in cu2-standards/tools/claude-hooks/spark-stats.js."""
        f = ts.detect_t3("hook.js", lines("  catch { return {}; }"))
        self.assertEqual(len(f), 1)

    def test_t3_swallowed_exception(self):
        src = "try:\n    sync()\nexcept Exception:\n    pass"
        self.assertTrue(ts.detect_t3("job.py", lines(src)))

    def test_t3_except_opener_with_trailing_comment_is_still_recognised(self):
        """`except FooError:  # noqa: BLE001` used to fail HANDLER_RE outright — the
        trailing comment broke its `$`-anchored exact match, so the swallow below it
        was completely invisible (not undeclared, unscanned). Found live in
        misty-9000's cu3_client.py."""
        src = "try:\n    x()\nexcept FooError:  # noqa: BLE001\n    pass"
        f = ts.detect_t3("app.py", lines(src))
        self.assertEqual(len(f), 1)

    def test_t3_pass_with_trailing_comment_is_still_recognised(self):
        """`pass  # note` used to fail SWALLOW_RE outright, for the same reason.
        Found live in several misty-9000 route files."""
        src = "try:\n    x()\nexcept Exception:\n    pass  # swallow on purpose"
        f = ts.detect_t3("app.py", lines(src))
        self.assertEqual(len(f), 1)

    def test_t4_f821_suppressed(self):
        f = ts.detect_t4("pyproject.toml", lines('ignore = ["E501", "F821"]'))
        self.assertEqual(len(f), 1)
        self.assertIn("F821", f[0].message)

    def test_t4_typescript_strict_off(self):
        self.assertTrue(ts.detect_t4("tsconfig.json", lines('    "strict": false,')))

    def test_t5_skipped_tests(self):
        for form in ("it" + ".skip('x', () => {})", "describe" + ".skip('y', () => {})",
                     "@pytest.mark" + ".skip(reason='flaky')", "x" + "it('z', () => {})"):
            with self.subTest(form=form):
                self.assertTrue(ts.detect_t5("a.ts" if "(" in form and "pytest" not in form
                                             else "a.py", lines(form)))

    def test_t8_non_gating_scanner(self):
        """
        Found in four repos during Phase 2 triage. Neither T1 nor T2 sees it: no
        `|| true`, no continue-on-error — the action's own options make the scan
        unable to fail, so nothing about the step looks suppressed.
        """
        wf = ("      - uses: aquasecurity/trivy-action@0.20.0\n"
              "        with:\n"
              "          severity: HIGH,CRITICAL\n"
              "          exit-code: '0'\n")
        f = ts.detect_t8(WF, lines(wf))
        self.assertEqual(len(f), 1)
        self.assertEqual((f[0].detector, f[0].severity), ("T8", "high"))

    def test_t8_soft_fail_form(self):
        self.assertTrue(ts.detect_t8(WF, lines("          soft_fail: true")))

    def test_t6_phantom_script(self):
        f = ts.detect_t6(WF, lines("      - run: pnpm typecheck"), known_scripts={"build"})
        self.assertEqual(len(f), 1)
        self.assertIn("typecheck", f[0].message)

    def test_t11_echo_suppression_hides_an_exit_status(self):
        """
        THE GAP THAT HID A REAL INSTANCE OF THE ORIGINATING INCIDENT. T1's
        SUPPRESSION_RE matches `|| true`, `|| :`, `|| exit 0` and `; true` — not
        `|| echo`, which swallows an exit status just as completely. Onramp-'s
        domain-setup.yml ended `az containerapp hostname bind` with
        `|| echo "Bind may need retry after DNS fully propagates"`, and the step named
        "Verify domain binding" then printed a tick unconditionally. Identical shape to
        kirk-helper #365, and T1 could not see it.
        """
        wf = ('            --validation-method CNAME '
              '|| echo "Bind may need retry after DNS fully propagates"')
        self.assertEqual(ts.detect_t1(WF, lines(wf)), [], "T1 still must not match || echo")
        f = ts.detect_t11(WF, lines(wf))
        self.assertEqual(len(f), 1)
        self.assertEqual((f[0].detector, f[0].severity), ("T11", "medium"))

    def test_t11_visible_annotation_is_a_soft_gate_not_a_silent_one(self):
        """
        `|| echo '::warning::'` surfaces in the run summary, so a human can see it fired.
        CU2 deliberately KEPT `alembic check || echo '::warning::'` on exactly that
        reasoning while fixing the hostname bind. Encoding the distinction here so the
        detector cannot quietly erase a decision that was made on purpose.
        """
        for form in ("          alembic check || echo '::warning::drift detected'",
                     '          foo || echo "::error::bad"',
                     "          bar || echo ::notice::hi"):
            with self.subTest(form=form):
                self.assertEqual(ts.detect_t11(WF, lines(form)), [])

    def test_t11_is_reachable_through_the_scan_entry_point(self):
        """
        BUG 20, caught by disbelieving a zero. detect_t9 was correct and its unit tests
        passed, but the call landed INSIDE the `if "T8" in active:` block — so
        `--detector T11` produced active={T11}, T8 was inactive, detect_t11 never ran, and
        the CLI reported a confident CLEAN across the whole estate. A detector that is
        unreachable from the dispatch is worse than one that does not exist: it answers
        "nothing here" with authority. Unit-testing the function cannot see this; only
        exercising scan_file can.
        """
        import tempfile, os
        with tempfile.TemporaryDirectory() as d:
            wfdir = os.path.join(d, ".github", "workflows")
            os.makedirs(wfdir)
            f = os.path.join(wfdir, "x.yml")
            with open(f, "w") as fh:
                fh.write('      - run: deploy || echo "may need a retry"\n')
            # T11 alone — the exact invocation that silently found nothing.
            found = ts.scan_file(f, {"T11"}, d, set())
            self.assertTrue(any(x.detector == "T11" for x in found),
                            "T11 must fire when it is the ONLY active detector")
            # and it must not require T8 to be active
            self.assertEqual([x for x in ts.scan_file(f, {"T8"}, d, set())
                              if x.detector == "T11"], [],
                             "T11 must not piggyback on T8's guard")

    def test_t11_is_not_in_the_gate_profile(self):
        """Added with ~36 existing candidates measured across 11 repos. Gating on a class
        before its backlog is triaged is how a gate gets switched off."""
        self.assertIn("T11", ts.DETECTORS)
        self.assertNotIn("T11", ts.PROFILES["gate"])
        self.assertIn("T11", ts.PROFILES["all"])

    # ── T12 ────────────────────────────────────────────────────────────────
    #
    # The class T3 structurally cannot see: `fetch` does not reject on 4xx/5xx, so
    # `if (!res.ok) return []` never enters a catch block. Measured on
    # xdi-implementations-os: 44 T12 sites against 37 T3 — the invisible class is
    # LARGER than the tracked one in that repo.

    TS = "apps/web/src/lib/api.ts"

    def test_t12_fires_on_the_canonical_shape(self):
        f = ts.detect_t12(self.TS, lines("  if (!res.ok) return [];"))
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].detector, "T12")
        self.assertEqual(f[0].severity, "high")

    def test_t12_all_five_observed_forms(self):
        for form in (
            "  if (!res.ok) return [];",                        # bare, same line
            "  if (!r?.ok) return undefined;",                  # optional chaining
            "  if (r.status !== 200) { return {}; }",           # braced, same line
            "  if (r.status >= 400) return;",                   # bare return
            "  if (res.ok === false) return null;",             # explicit comparison
        ):
            with self.subTest(form=form):
                self.assertTrue(ts.detect_t12(self.TS, lines(form)), form)

    def test_t12_braced_multiline_form(self):
        f = ts.detect_t12(self.TS, lines(
            "  if (!res.ok) {\n"
            "    return null;\n"
            "  }"))
        self.assertEqual(len(f), 1)

    def test_t12_declaration_reason_containing_an_escape_keyword_still_finds_the_site(self):
        """A `theater-ok` REASON explaining that the scanner doesn't recognise this
        app's local helper (e.g. "...doesn't see this repo's local toast helper...")
        used to satisfy HTTP_FAIL_OK_RE itself — the whole un-stripped body,
        comment included, was checked for the escape-hatch keywords before any
        comment was removed. The prose describing the gap became indistinguishable
        from the gap being closed, and the finding vanished before declaration was
        ever checked. Found live in dev-studio's RbacClient.tsx (word: setError)
        and NotificationsForm.tsx (word: toast)."""
        f = ts.detect_t12(self.TS, lines(
            "  if (!res.ok) {\n"
            "    flash({kind: 'err', msg: 'failed'});\n"
            "    return []; // theater-ok: scanner doesn't recognise this repo's "
            "local toast helper, which already renders a visible banner\n"
            "  }"))
        self.assertEqual(len(f), 1)
        self.assertTrue(f[0].declared)

    # ── false positives ────────────────────────────────────────────────────

    def test_t12_a_real_escape_call_in_code_is_still_recognised_as_observable(self):
        """False-positive guard: an ACTUAL `toast.error(...)` call in code (not a
        comment merely mentioning the word) must still suppress the finding — the
        fix must not stop recognising the real escape hatch."""
        self.assertEqual(ts.detect_t12(self.TS, lines(
            "  if (!res.ok) {\n"
            "    toast.error('failed to load');\n"
            "    return [];\n"
            "  }")), [])

    def test_t12_throwing_is_not_a_finding(self):
        """The correct fix must not itself be flagged, or the detector fights it."""
        self.assertEqual(
            ts.detect_t12(self.TS, lines("  if (!res.ok) throw new Error(res.status);")), [])

    def test_t12_reporting_the_failure_is_not_a_finding(self):
        self.assertEqual(ts.detect_t12(self.TS, lines(
            "  if (!res.ok) { console.error('failed', res.status); return []; }")), [])

    def test_t12_a_sentinel_a_caller_can_branch_on_is_not_a_finding(self):
        """`false` and `{ error }` are designs, not silent-empties."""
        for form in ("  if (!res.ok) return false;",
                     "  if (!res.ok) return { error: res.status };"):
            with self.subTest(form=form):
                self.assertEqual(ts.detect_t12(self.TS, lines(form)), [], form)

    def test_t12_ignores_non_js_files(self):
        self.assertEqual(ts.detect_t12("backend/app/x.py",
                                       lines("  if (!res.ok) return [];")), [])

    def test_t12_ignores_test_files(self):
        """A test asserting this shape is describing the defect, not committing it."""
        self.assertEqual(ts.detect_t12("apps/web/src/lib/api.spec.ts",
                                       lines("  if (!res.ok) return [];")), [])

    def test_t12_respects_a_declaration(self):
        f = ts.detect_t12(self.TS, lines(
            "  if (!res.ok) return []; // theater-ok: 404 is the documented "
            "\"no such tenant\" answer and the caller checks a separate loaded flag"))
        self.assertEqual(len(f), 1)
        self.assertTrue(f[0].declared, "a declared T12 must still be FOUND, marked declared")

    def test_declaration_works_with_a_js_comment_marker(self):
        """`//` and `/* */`, not just `#`.

        Only `#` was accepted, so the convention had never worked in a .ts/.js file —
        for T3 and T4 as much as T12. All 39 declaration lines in the estate census
        are in workflow YAML, which is consistent with it being unusable elsewhere.
        """
        for form in ("// theater-ok: ",
                     "/* theater-ok: ",
                     "  //theater-ok: "):
            with self.subTest(form=form):
                d, r = ts._declaration(
                    "  if (!res.ok) return []; " + form +
                    "404 is the documented \"no such tenant\" answer and the caller "
                    "checks a separate loaded flag")
                self.assertTrue(d, f"{form!r} should be a valid declaration marker")
                self.assertIn("no such tenant", r or "")

    def test_declaration_still_works_with_a_hash(self):
        """The FP guard: the YAML/Python form must not regress."""
        d, r = ts._declaration(
            "  - run: pnpm audit || true  # theater-ok: report-only; the SARIF gate "
            "below is the enforcing step")
        self.assertTrue(d)

    def test_a_generic_js_declaration_still_does_not_count(self):
        d, r = ts._declaration("  if (!res.ok) return []; // theater-ok: known issue")
        self.assertFalse(d, "a generic reason must not satisfy the convention")

    def test_t12_is_not_in_the_gate_profile(self):
        """44 existing candidates in one repo alone. Gating a class before its backlog
        is triaged is how a gate gets switched off rather than acted on — same
        reasoning as T11."""
        self.assertIn("T12", ts.DETECTORS)
        self.assertNotIn("T12", ts.PROFILES["gate"])
        self.assertIn("T12", ts.PROFILES["all"])

    def test_t12_is_reachable_through_the_scan_entry_point(self):
        import tempfile, os as _os
        with tempfile.TemporaryDirectory() as d:
            f = _os.path.join(d, "api.ts")
            with open(f, "w") as fh:
                fh.write("export async function g() {\n  if (!res.ok) return [];\n}\n")
            found = [x for x in ts.scan_file(f, {"T12"}, d, set()) if x.detector == "T12"]
            self.assertEqual(len(found), 1,
                             "T12 must fire when it is the ONLY active detector")

    def test_explicit_detector_flag_overrides_gate_profile_exclusion(self):
        """
        THE FIFTH PINNED BUG. T12 (like T11) is deliberately excluded from the
        default "gate" profile so an untriaged backlog can't disable the whole
        build gate — but `main()` computed `active = PROFILES[args.profile] &
        set(args.detector)`, so an explicit `--detector T12` with no --profile
        (default "gate") intersected down to an EMPTY active set. `--detector`
        is documented as "restrict to specific detector(s)"; a user typing it
        has explicitly asked for that detector, not asked to further narrow
        whatever the default profile happens to allow. This is BUG 20's exact
        shape one layer up the stack (CLI parsing instead of scan_file
        dispatch): a detector unreachable from its own explicit flag, reporting
        a confident CLEAN. Found live: multiple parallel theater-fix runs
        across the CU2 fleet invoked `--detector T3 --detector T12` with no
        --profile and silently never checked T12 on any of them.
        """
        tree = write_tree({"api.ts": "export async function g() {\n  if (!res.ok) return [];\n}\n"})
        # No --profile given (defaults to "gate", which excludes T12).
        code, out = run([tree, "--detector", "T3", "--detector", "T12", "--report"])
        self.assertEqual(code, 0, "--report always exits 0")
        self.assertIn("1 undeclared finding", out, f"T12 must be checked when explicitly requested:\n{out}")
        self.assertIn("T12", out, f"the finding must be attributed to T12:\n{out}")

    def test_every_detector_has_coverage(self):
        covered = set()
        for name in dir(self):
            for d in ts.DETECTORS:
                if name.startswith(f"test_{d.lower()}_"):
                    covered.add(d)
        self.assertEqual(covered, set(ts.DETECTORS))


# ---------------------------------------------------------------------------
# False positives: the legitimate lookalikes must stay silent
# ---------------------------------------------------------------------------

class TestFalsePositives(unittest.TestCase):

    def test_a_declaration_cannot_exempt_its_own_line(self):
        """
        THE BUG. IDEMPOTENT_PATTERNS and SUPPRESSION_RE matched the WHOLE line, comment
        included. A `# theater-ok:` reason that quoted the command it was describing
        satisfied the idempotent allowlist and exempted its own line — so the finding
        vanished from --inventory entirely, passing for the wrong reason. Caught 2026-07-30
        by noticing the inventory reported 3 declarations where 4 were written; it would
        have flipped back to a finding the moment anyone reworded the comment.
        """
        line = ('            --resource-group "$RG" || true  # theater-ok: '
                'az containerapp hostname add is idempotent and on the exempt list')
        f = ts.detect_t1(WF, lines(line))
        self.assertEqual(len(f), 1, "the comment must not exempt the code")
        self.assertTrue(f[0].declared, "and it must still register as declared")

    def test_prose_mentioning_a_suppression_is_not_a_finding(self):
        """A trailing comment that merely talks about `|| true` is documentation."""
        self.assertEqual(
            ts.detect_t1(WF, lines('          run: make build  # never write || true here')),
            [])

    def test_suppression_inside_an_emitted_printf_literal_is_not_this_step(self):
        """
        cu2-billing/seed-kv.yml builds an ACA Job manifest with printf. The `|| true` in
        the emitted text governs a container that runs later, elsewhere — this step's own
        command is printf, which can and does fail on its own merits. Reported as a T1 in
        the 2026-07-30 sweep and triaged as a false positive by hand.
        """
        line = ("            printf '            tdnf install -y -q gawk grep sed "
                ">/dev/null 2>&1 || true\\n'")
        self.assertEqual(ts.detect_t1(WF, lines(line)), [])

    def test_a_real_suppression_on_a_printf_line_still_fires(self):
        """FP GUARD for the guard: printf itself being suppressed is still a finding."""
        line = "          printf 'hello' || true"
        self.assertEqual(len(ts.detect_t1(WF, lines(line))), 1)

    def test_xit_does_not_match_exit(self):
        """
        THE PINNED BUG. An `xit` pattern without a word boundary matches `exit`, which
        inflated the first sweep from 39 skipped tests to 490.
        """
        for line in ("    sys.exit(main())",
                     "  process.exit(1)",
                     "if (code) exit(code);",
                     "        return exit(0)"):
            with self.subTest(line=line):
                self.assertFalse(ts.detect_t5("a.py", lines(line)),
                                 f"`exit(` must not read as a skipped test: {line}")

    def test_xit_still_matches_real_xit(self):
        self.assertTrue(ts.detect_t5("a.ts", lines("x" + "it('pending case', () => {})")))

    def test_t5_ignores_prose_in_comments(self):
        """
        THE SEVENTH PINNED BUG. T1 and T4 skipped comment lines; T5 did not, so it
        reported six findings across the estate that were *documentation about*
        skipped tests. The best of them was a docstring announcing that the Wave 0
        stubs had been converted to active passing tests — a note that the skips
        had been REMOVED, counted as a skipped test.
        """
        skip = "it" + ".skip"
        for line in (f" * Implementations land in Plan 068-04. Each {skip}() names the D-XX.",
                     f" * Converts Wave 0 {skip}() stubs to active passing tests.",
                     f"// `d` resolves to describe() when DATABASE_URL is set, describe{skip[2:]}"
                     "() otherwise.",
                     "// --pass" + "WithNoTests. The helpers are covered elsewhere.",
                     f"# {skip} was removed in Plan 12"):
            with self.subTest(line=line):
                self.assertFalse(ts.detect_t5("a.ts", lines(line)),
                                 f"prose about a skip is not a skip: {line.strip()}")

    def test_t5_json_scanned_only_for_the_jest_flag(self):
        """
        THE FOURTEENTH PINNED BUG, found by dogfooding. This project commits its
        own inventory as JSON, and the `evidence` field of a recorded T5 finding
        literally contains the text of the skip it recorded. Applying the code
        patterns to .json made the inventory of findings register as 321
        findings. Test-skip syntax cannot be executable code inside JSON.
        """
        skip = "it" + ".skip"
        rec = '  {"detector": "T5", "evidence": "' + skip + "('[D-09] pending', () => {})\"}"
        self.assertFalse(ts.detect_t5("inventory.json", lines(rec)),
                         "a JSON record OF a skip is not a skip")
        flag = "pass" + "WithNoTests"
        self.assertTrue(ts.detect_t5("jest.config.json",
                                     lines('  "args": ["--' + flag + '"]')),
                        f"the {flag} flag in JSON must still fire")

    def test_t5_still_fires_on_a_skip_with_a_trailing_comment(self):
        """The fix must only skip comment-*only* lines, not code carrying a comment."""
        line = "  it" + ".skip('flaky in CI', () => {})  // TODO: fix the fixture"
        self.assertTrue(ts.detect_t5("a.ts", lines(line)))

    def test_t8_ignores_a_gating_scanner(self):
        """A scanner that CAN fail is the thing we want; it must stay silent."""
        for line in ("          exit-code: '1'",
                     '          exit-code: "1"',
                     "          exit-code: 1",
                     "          soft_fail: false",
                     "          # exit-code: '0'  <- was disabled, now gating"):
            with self.subTest(line=line):
                self.assertFalse(ts.detect_t8(WF, lines(line)),
                                 f"must not flag a gating scanner: {line.strip()}")

    def test_t8_only_applies_to_workflows(self):
        self.assertFalse(ts.detect_t8("scripts/scan.sh", lines("exit-code: '0'")))

    def test_t3_ignores_pytest_expected_exception(self):
        """
        THE EIGHTH PINNED FALSE POSITIVE. In a test file, `except SomeError: pass`
        after a call that is supposed to raise IS the assertion — the real shape
        in gandalf-protocol/test_retrieval_floor.py:70. Roughly 40 of the estate's
        428 T3 rows are this or the CancelledError shape below.
        """
        src = ("def test_raises():\n    try:\n        go()\n"
               "    except retrieval._NoRelevantLesson:\n        pass")
        self.assertFalse(ts.detect_t3("tests/test_retrieval_floor.py", lines(src)))
        self.assertFalse(ts.detect_t3("test_retrieval_floor.py", lines(src)))

    def test_t3_still_flags_bare_except_in_a_test(self):
        """`except Exception: pass` swallows everything and asserts nothing."""
        src = ("def test_x():\n    try:\n        go()\n"
               "    except Exception:\n        pass")
        self.assertTrue(ts.detect_t3("tests/test_x.py", lines(src)),
                        "a bare handler in a test is still a swallowed failure")

    def test_t3_expected_exception_only_excused_in_test_files(self):
        """The same shape in production code is a swallowed failure."""
        src = ("def load():\n    try:\n        go()\n"
               "    except ValueError:\n        pass")
        self.assertTrue(ts.detect_t3("app/loader.py", lines(src)))

    def test_t3_ignores_cancelled_error_on_shutdown(self):
        """
        THE NINTH PINNED FALSE POSITIVE. `except asyncio.CancelledError: pass`
        awaiting a task during shutdown — cancellation is the expected outcome.
        The real shape in misty-9000/backend/app/main.py:210,218.
        """
        for opener in ("    except asyncio.CancelledError:", "    except CancelledError:"):
            with self.subTest(opener=opener):
                src = f"async def stop():\n    try:\n        await t\n{opener}\n        pass"
                self.assertFalse(ts.detect_t3("app/main.py", lines(src)))

    def test_t3_cancelled_error_returning_empty_is_still_flagged(self):
        """Only a bare `pass` is excused. Returning [] still disguises the failure."""
        src = ("async def go():\n    try:\n        await t\n"
               "    except asyncio.CancelledError:\n        return []")
        self.assertTrue(ts.detect_t3("app/main.py", lines(src)))

    def test_t1_ignores_idempotent_infra(self):
        """The ~13 of 15 baseline hits that are correct as written."""
        for line in ("          az extension add --name containerapp --yes 2>/dev/null || true",
                     '          az containerapp delete -n "$APP" -g "$RG" --yes || true',
                     "          az containerapp hostname add -n $APP --hostname $H || true",
                     "          mkdir -p /tmp/out || true",
                     "          rm -f /tmp/stale.json || true",
                     "          docker rmi $IMAGE || true",
                     "          cat /tmp/body || true"):
            with self.subTest(line=line):
                self.assertFalse(ts.detect_t1(WF, lines(line)),
                                 f"idempotent infra must not be flagged: {line.strip()}")

    def test_t1_ignores_comments(self):
        comment = "      # errored 'command not found', `|| true` swallowed it, and the job"
        self.assertFalse(ts.detect_t1(WF, lines(comment)))

    def test_t1_only_applies_to_workflows(self):
        self.assertFalse(ts.detect_t1("scripts/deploy.sh", lines("pnpm audit || true")))

    def test_t3_ignores_nonempty_return(self):
        src = "try:\n    return fetch()\nexcept Exception:\n    return fallback_list()"
        self.assertFalse(ts.detect_t3("app.py", lines(src)))

    def test_t3_ignores_empty_return_outside_handler(self):
        src = "def empty():\n    if not rows:\n        return []\n    return rows"
        self.assertFalse(ts.detect_t3("app.py", lines(src)))

    def test_t3_ignores_distant_handler(self):
        """A handler 6 lines up is not the cause of this return."""
        src = ("try:\n    go()\nexcept Exception:\n    log()\n    a=1\n    b=2\n"
               "    c=3\n    d=4\n    return []")
        self.assertFalse(ts.detect_t3("app.py", lines(src)))

    def test_t3_does_not_cross_a_class_boundary_to_find_a_distant_handler(self):
        """Real false positive found live in dev-studio's forge_diagnose_job.py:
        `class BudgetExceeded(Exception): pass` sat 6 lines below an unrelated
        `except Exception as exc:` block (separated by two blank lines) — inside
        the 4-line window, so the class body's own trivial `pass` was flagged as
        a swallowed exception. A class/def boundary must stop the backward scan
        even when it would otherwise fit inside the window."""
        src = (
            "def f():\n"
            "    try:\n"
            "        g()\n"
            "    except Exception as exc:\n"
            "        _log(f'failed: {exc}')\n"
            "        return None\n"
            "\n"
            "\n"
            "class BudgetExceeded(Exception):\n"
            "    pass\n"
        )
        self.assertEqual(ts.detect_t3("app.py", lines(src)), [])

    def test_t3_still_flags_a_swallow_that_is_genuinely_inside_the_handler(self):
        """False-positive guard for the boundary fix: a `pass` that IS the
        except handler's own body, with a class/def appearing *before* the
        except block (not between it and the pass), must still be flagged."""
        src = (
            "class Foo:\n"
            "    pass\n"
            "\n"
            "\n"
            "def f():\n"
            "    try:\n"
            "        g()\n"
            "    except Exception:\n"
            "        pass\n"
        )
        f = ts.detect_t3("app.py", lines(src))
        self.assertEqual(len(f), 1)

    def test_t4_ignores_style_only_suppressions(self):
        """F401 and E501 are preferences. F821 is a runtime crash. Not the same."""
        self.assertFalse(ts.detect_t4("pyproject.toml", lines('ignore = ["E501", "F401"]')))

    def test_t4_ignores_strict_true(self):
        self.assertFalse(ts.detect_t4("tsconfig.json", lines('    "strict": true,')))

    def test_t4_ignores_commented_config(self):
        self.assertFalse(ts.detect_t4("pyproject.toml", lines('# ignore = ["F821"]')))

    def test_t4_only_applies_to_config_files(self):
        self.assertFalse(ts.detect_t4("notes.md", lines('we suppressed "strict": false once')))

    def test_t6_ignores_package_manager_builtins(self):
        for line in ("      - run: pnpm install --frozen-lockfile",
                     "      - run: npm audit --omit=dev",
                     "      - run: pnpm exec playwright test",
                     "      - run: pnpm dlx prisma generate"):
            with self.subTest(line=line):
                self.assertFalse(ts.detect_t6(WF, lines(line), known_scripts=set()))

    def test_t6_ignores_defined_scripts(self):
        self.assertFalse(ts.detect_t6(WF, lines("      - run: pnpm typecheck"),
                                      known_scripts={"typecheck"}))

    def test_t6_ignores_dependency_provided_binaries(self):
        """
        THE FOURTH PINNED BUG. The first full-estate sweep produced 11 T6
        findings and all 11 were false: `pnpm prisma` (x5), `pnpm tsc`,
        `npm view`, `npm sbom`. These are node_modules/.bin passthroughs and real
        npm subcommands, not calls to package.json scripts. A detector that is
        100% wrong is not weak, it is theater.
        """
        tree = write_tree({
            "package.json": '{"devDependencies":{"prisma":"^5","typescript":"^5"}}',
            WF: ("      - run: pnpm prisma migrate deploy\n"
                 "      - run: pnpm tsc --noEmit\n"
                 "      - run: npm view pkg version\n"
                 "      - run: npm sbom --sbom-format cyclonedx\n"),
        })
        code, out = run([tree, "--detector", "T6"])
        self.assertEqual(code, 0, f"all four are legitimate:\n{out}")

    def test_t6_collects_binaries_from_dependencies(self):
        tree = write_tree({
            "package.json": '{"devDependencies":{"typescript":"^5","@nestjs/cli":"^10"}}'})
        names = ts.collect_package_scripts(tree)
        self.assertIn("tsc", names, "typescript provides the tsc binary")
        self.assertIn("nest", names, "@nestjs/cli provides the nest binary")
        self.assertIn("typescript", names)

    def test_t6_still_catches_the_original_incident(self):
        """
        The fix must not disarm the detector. The incident it exists for was CI
        running `pnpm lint` / `pnpm typecheck` against a package defining neither
        — and neither name is a dependency, so both must still fire.
        """
        tree = write_tree({
            "package.json": '{"devDependencies":{"eslint":"^9","typescript":"^5"}}',
            WF: "      - run: pnpm lint\n      - run: pnpm typecheck\n",
        })
        code, out = run([tree, "--detector", "T6"])
        self.assertEqual(code, 1, "phantom scripts must still be reported")
        self.assertIn("lint", out)
        self.assertIn("typecheck", out)

    def test_t6_unparseable_package_json_is_skipped_not_treated_as_empty(self):
        tree = write_tree({"package.json": "{not json at all"})
        self.assertIsNone(ts._read_package_json(os.path.join(tree, "package.json")))


# ---------------------------------------------------------------------------
# Declared suppressions
# ---------------------------------------------------------------------------

class TestDeclaration(unittest.TestCase):

    def test_specific_reason_declares(self):
        line = "      - run: pnpm audit || true   # theater-ok: advisory, tracked RISK-123"
        f = ts.detect_t1(WF, lines(line))
        self.assertEqual(len(f), 1)
        self.assertTrue(f[0].declared)

    def test_generic_reason_rejected(self):
        for reason in ("intentional", "known", "by design", "wip", "temporary"):
            with self.subTest(reason=reason):
                line = f"      - run: pnpm audit || true   # theater-ok: {reason}"
                f = ts.detect_t1(WF, lines(line))
                self.assertFalse(f[0].declared,
                                 f"'{reason}' is not a reason and must not declare")

    def test_short_reason_rejected(self):
        line = "      - run: pnpm audit || true   # theater-ok: later"
        self.assertFalse(ts.detect_t1(WF, lines(line))[0].declared)

    def test_declaration_above_continue_on_error(self):
        src = ("      - name: Post scan   # theater-ok: telemetry only, never gates a deploy\n"
               "        continue-on-error: true")
        f = ts.detect_t2(WF, lines(src))
        self.assertEqual(len(f), 1)
        self.assertTrue(f[0].declared)

    def test_declared_findings_do_not_fail_the_run(self):
        tree = write_tree({WF: "      - run: pnpm audit || true  "
                               "# theater-ok: advisory only, tracked in RISK-123\n"})
        code, out = run([tree])
        self.assertEqual(code, 0)
        self.assertIn("1 declared suppression", out)

    def test_inventory_lists_declarations(self):
        tree = write_tree({WF: "      - run: pnpm audit || true  "
                               "# theater-ok: advisory only, tracked in RISK-123\n"})
        code, out = run([tree, "--inventory"])
        self.assertEqual(code, 0)
        self.assertIn("RISK-123", out)

    def test_t3_trailing_comment_declaration_now_works(self):
        """A `theater-ok` comment on the SAME line as `return {}` used to make the
        line stop matching EMPTY_RETURN_RE entirely (the trailing text broke the
        exact-line match) — the finding vanished UNDECLARED rather than being
        properly suppressed, the worst outcome for the convention. This was the
        first bug found this session (misty-9000's fang_batch_matcher.py) and is
        now fixed generally: a same-line trailing declaration is equivalent to one
        on the preceding line."""
        src = ("try:\n    x()\nexcept Exception:\n"
               "    return {}  # theater-ok: already logged above, not silently swallowed")
        f = ts.detect_t3("app.py", lines(src))
        self.assertEqual(len(f), 1)
        self.assertTrue(f[0].declared)

    def test_strip_code_comment_respects_quotes(self):
        """False-positive guard: a `#` or `//` inside a string literal must not be
        mistaken for a comment start."""
        self.assertEqual(ts._strip_code_comment('    x = "a // b # c"'),
                         '    x = "a // b # c"')
        self.assertEqual(ts._strip_code_comment("    pass  # note").strip(), "pass")
        self.assertEqual(ts._strip_code_comment("    pass  // note").strip(), "pass")


# ---------------------------------------------------------------------------
# Allowlist and CLI contract
# ---------------------------------------------------------------------------

class TestAllowlistAndCLI(unittest.TestCase):

    def test_broad_allowlist_rejected(self):
        for bad in (".*", "^.*$", ".+", "abc"):
            with self.subTest(pattern=bad):
                tree = write_tree({".theater-allow": bad + "\n"})
                _allow, errors = ts.load_allowlist(tree)
                self.assertTrue(errors, f"{bad!r} must be rejected")

    def test_unanchored_allowlist_rejected(self):
        tree = write_tree({".theater-allow": "somefile\n"})
        _allow, errors = ts.load_allowlist(tree)
        self.assertTrue(errors)

    def test_valid_allowlist_suppresses(self):
        tree = write_tree({
            ".theater-allow": "path:^legacy/\n",
            "legacy/.github/workflows/old.yml": "      - run: pnpm audit || true\n",
        })
        code, _ = run([tree, "--quiet"])
        self.assertEqual(code, 0)

    def test_profile_gate_excludes_t5(self):
        self.assertNotIn("T5", ts.PROFILES["gate"])
        self.assertIn("T5", ts.PROFILES["all"])

    def test_findings_exit_one(self):
        tree = write_tree({WF: "      - run: pnpm audit --audit-level=high || true\n"})
        code, out = run([tree])
        self.assertEqual(code, 1)
        self.assertIn("[T1/high]", out)

    def test_report_mode_exits_zero(self):
        tree = write_tree({WF: "      - run: pnpm audit --audit-level=high || true\n"})
        code, out = run([tree, "--report"])
        self.assertEqual(code, 0)
        self.assertIn("report mode", out)

    def test_clean_tree_exits_zero(self):
        tree = write_tree({WF: "      - run: pnpm build\n", "package.json": '{"scripts":{"build":"x"}}'})
        code, out = run([tree])
        self.assertEqual(code, 0)
        self.assertIn("CLEAN", out)

    def test_missing_target_exits_two(self):
        code, _ = run(["/nonexistent/theater/path"])
        self.assertEqual(code, 2)

    def test_scanner_is_clean_against_its_own_source(self):
        here = os.path.dirname(os.path.abspath(__file__))
        code, out = run([here, "--profile", "all"])
        self.assertEqual(code, 0, f"the theater tooling must be clean on itself:\n{out}")


# ---------------------------------------------------------------------------
# Ratchet mode
# ---------------------------------------------------------------------------

def git_repo(files, commit_msg="base"):
    """A real git repo with `files` committed on main. Returns its path."""
    import subprocess
    tmp = write_tree(files)

    def git(*args):
        subprocess.run(["git", "-C", tmp, *args], check=True,
                       capture_output=True, text=True)

    git("init", "-q", "-b", "main")
    git("config", "user.email", "t@example.invalid")
    git("config", "user.name", "t")
    git("config", "commit.gpgsign", "false")
    git("add", "-A")
    git("commit", "-q", "-m", commit_msg)
    return tmp


def git_commit(tmp, files, msg="change"):
    import subprocess

    def git(*args):
        subprocess.run(["git", "-C", tmp, *args], check=True,
                       capture_output=True, text=True)

    for rel, content in files.items():
        full = os.path.join(tmp, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as fh:
            fh.write(content)
    git("add", "-A")
    git("commit", "-q", "-m", msg)


class TestRatchet(unittest.TestCase):
    """
    Ratchet mode exists so the gate can be switched on against an estate carrying
    774 existing candidates: it fails only on theater the change ADDED. That
    freezes the backlog while Phases 2-3 work through it, instead of waiting for
    a clean estate that never arrives.
    """

    CLEAN_WF = "jobs:\n  a:\n    steps:\n      - run: echo hi\n"

    def test_new_theater_on_an_added_line_fails(self):
        tmp = git_repo({WF: self.CLEAN_WF})
        git_commit(tmp, {WF: self.CLEAN_WF +
                         "      - run: pnpm audit --audit-level=high || true\n"})
        code, out = run([tmp, "--diff-base", "main~1"])
        self.assertEqual(code, 1, out)
        self.assertIn("[T1/high]", out)
        self.assertIn("ratchet", out)

    def test_pre_existing_theater_on_untouched_lines_passes(self):
        """
        THE WHOLE POINT. A repo full of existing findings must go green so the
        gate can actually be switched on. cu2-standards has 47 T3s; if the gate
        failed on those it would never be enabled and the backlog would keep
        growing — gandalf-protocol gained a new T1 in two days.
        """
        dirty = ("jobs:\n  a:\n    steps:\n"
                 "      - run: pnpm audit --audit-level=high || true\n")
        tmp = git_repo({WF: dirty, "app.py": "x = 1\n"})
        git_commit(tmp, {"app.py": "x = 1\ny = 2\n"})

        full, _ = run([tmp, "--report"])
        self.assertEqual(full, 0)
        code, out = run([tmp, "--diff-base", "main~1"])
        self.assertEqual(code, 0, f"untouched pre-existing theater must not fail:\n{out}")
        self.assertIn("no new theater", out)

    def test_touching_a_file_does_not_resurface_its_old_findings(self):
        """Editing line 40 must not report the pre-existing finding on line 4."""
        dirty = ("jobs:\n  a:\n    steps:\n"
                 "      - run: pnpm audit --audit-level=high || true\n"
                 + "      # filler\n" * 30)
        tmp = git_repo({WF: dirty})
        git_commit(tmp, {WF: dirty + "      # one more line\n"})
        code, out = run([tmp, "--diff-base", "main~1"])
        self.assertEqual(code, 0, out)

    def test_unresolvable_ref_exits_two_and_never_reports_clean(self):
        """
        THE FAILURE MODE THIS MUST NOT HAVE. A ratchet whose diff silently matches
        nothing reports a confident clean on every commit forever — the
        `_is_workflow()` leading-slash bug, rebuilt. Every way the diff can fail
        must exit 2, never 0.
        """
        tmp = git_repo({WF: "      - run: pnpm audit || true\n"})
        code, out = run([tmp, "--diff-base", "origin/nonexistent-branch"])
        self.assertEqual(code, 2)
        self.assertNotIn("CLEAN", out)

    def test_shallow_clone_hint_is_given(self):
        tmp = git_repo({WF: self.CLEAN_WF})
        import io
        from contextlib import redirect_stderr
        buf = io.StringIO()
        with redirect_stderr(buf):
            ts.main([tmp, "--diff-base", "deadbeef"])
        self.assertIn("fetch-depth", buf.getvalue())

    def test_not_a_git_repo_exits_two(self):
        tree = write_tree({WF: "      - run: pnpm audit || true\n"})
        self.assertEqual(run([tree, "--diff-base", "main"])[0], 2)

    def test_renamed_file_does_not_present_as_all_new(self):
        """
        Rename detection is load-bearing. Without -M, moving a file shows every
        line as added, so a relocation would fail the gate on findings it did not
        introduce — and the fix would be to disable the gate.
        """
        import subprocess
        dirty = ("jobs:\n  a:\n    steps:\n"
                 "      - run: pnpm audit --audit-level=high || true\n")
        tmp = git_repo({".github/workflows/old.yml": dirty})
        subprocess.run(["git", "-C", tmp, "mv",
                        ".github/workflows/old.yml", ".github/workflows/new.yml"],
                       check=True, capture_output=True)
        subprocess.run(["git", "-C", tmp, "commit", "-q", "-m", "rename"],
                       check=True, capture_output=True)
        code, out = run([tmp, "--diff-base", "main~1"])
        self.assertEqual(code, 0, f"a pure rename introduces no new theater:\n{out}")

    def test_staged_mode_sees_the_index(self):
        """
        THE TENTH PINNED BUG, CAUGHT BEFORE SHIPPING. The pre-commit hook was
        first written as `--diff-base HEAD`. That expands to `HEAD...HEAD` — the
        merge base of HEAD with itself is HEAD — so the diff is always empty and
        the hook reported CLEAN with theater sitting in the index.

        A ratchet that silently matches nothing passes every commit forever: the
        exact failure this gate exists to prevent, rebuilt inside the gate. Hence
        an explicit --staged flag rather than overloading a ref.
        """
        import subprocess
        tmp = git_repo({WF: self.CLEAN_WF})
        with open(os.path.join(tmp, WF), "w", encoding="utf-8") as fh:
            fh.write(self.CLEAN_WF + "      - run: pnpm audit --audit-level=high || true\n")
        subprocess.run(["git", "-C", tmp, "add", "-A"], check=True, capture_output=True)

        code, out = run([tmp, "--profile", "gate", "--staged"])
        self.assertEqual(code, 1, f"staged theater must fail the hook:\n{out}")
        self.assertIn("[T1/high]", out)

        # And the spelling that silently passed is still empty, which is why the
        # flag exists rather than a documented convention.
        self.assertEqual(ts.changed_lines(tmp, "HEAD"), {})

    def test_staged_mode_passes_on_a_clean_index(self):
        import subprocess
        dirty = ("jobs:\n  a:\n    steps:\n"
                 "      - run: pnpm audit --audit-level=high || true\n")
        tmp = git_repo({WF: dirty, "a.py": "x = 1\n"})
        with open(os.path.join(tmp, "a.py"), "w", encoding="utf-8") as fh:
            fh.write("x = 1\ny = 2\n")
        subprocess.run(["git", "-C", tmp, "add", "-A"], check=True, capture_output=True)
        code, out = run([tmp, "--profile", "gate", "--staged"])
        self.assertEqual(code, 0, f"the backlog must not block a clean commit:\n{out}")

    def test_staged_and_diff_base_together_are_rejected(self):
        tmp = git_repo({WF: self.CLEAN_WF})
        self.assertEqual(run([tmp, "--staged", "--diff-base", "main"])[0], 2)

    def test_changed_lines_reports_added_line_numbers(self):
        tmp = git_repo({"a.py": "one\ntwo\nthree\n"})
        git_commit(tmp, {"a.py": "one\ntwo\nINSERTED\nthree\n"})
        added = ts.changed_lines(tmp, "main~1")
        self.assertEqual(added.get("a.py"), {3})

    def test_pure_deletion_adds_no_lines(self):
        tmp = git_repo({"a.py": "one\ntwo\nthree\n"})
        git_commit(tmp, {"a.py": "one\nthree\n"})
        self.assertEqual(ts.changed_lines(tmp, "main~1").get("a.py", set()), set())

    def test_declaration_still_works_in_ratchet_mode(self):
        tmp = git_repo({WF: self.CLEAN_WF})
        git_commit(tmp, {WF: self.CLEAN_WF + "      - run: pnpm audit || true  "
                             "# theater-ok: advisory only, tracked in RISK-123\n"})
        code, out = run([tmp, "--diff-base", "main~1"])
        self.assertEqual(code, 0, out)



if __name__ == "__main__":
    unittest.main(verbosity=2)
