#!/usr/bin/env python3
"""
Tests for workflow_health (detector T7).

Run:
    python3 tools/theater/test_workflow_health.py

STRUCTURE: as in test_theater_scan.py, every kind has BOTH a positive test and a
false-positive test. No test touches the network — `classify()` is pure over an
already-fetched run history, which is the whole reason it is factored that way.

THE FIXTURE IS REAL, AND IT IS THE POINT

fixtures/cache-stats-daily-runs.json is the verbatim Actions API history of
cu2-agent-studio's `cache-stats-daily`, captured 2026-07-28. That one file
carries both halves of the pair:

    as of 2026-07-25  ->  red, 19 consecutive scheduled failures
    as of 2026-07-28  ->  ok, fixed by a workflow_dispatch on 07-25

So the false-positive regression is not a hand-written lookalike. It is the same
real workflow after somebody fixed it, and a T7 that cannot tell those two dates
apart would report a live red finding against a repo that is green — which is
this taxonomy's own failure mode pointed at itself.

It also pins a second lesson. The knowledge base recorded this workflow as "red
15 consecutive days". Measured from the API it is 19 consecutive scheduled
failures, last green 2026-07-05. The inherited number was wrong, in the
direction of understating the problem.
"""

import json
import os
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import workflow_health as wh  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def load_fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return json.load(fh)


def at(date_str):
    return datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)


def run(conclusion, created_at, event="schedule", number=1):
    return {"run_number": number, "event": event, "status": "completed",
            "conclusion": conclusion, "created_at": created_at,
            "html_url": f"https://example.invalid/{number}"}


def classify(runs, as_of, declares=True, state="active", **kw):
    return wh.classify("acme/repo", "Nightly", ".github/workflows/nightly.yml",
                       state, runs, declares, at(as_of), **kw)


class _FakeGh:
    """
    A stand-in for Gh with one scheduled-but-never-run workflow. Subclasses
    override `get` for the one endpoint they are testing and defer the rest, so
    each test states only the condition it is about.
    """

    WORKFLOW = {"id": 1, "name": "Nightly",
                "path": ".github/workflows/nightly.yml", "state": "active"}

    def get(self, path, paginate=False):
        if "/actions/workflows?" in path:
            return [{"workflows": [self.WORKFLOW]}]
        if "/runs" in path:
            return {"total_count": 0, "workflow_runs": []}
        if "/contents/" in path:
            import base64
            body = "name: N\non:\n  schedule:\n    - cron: '0 5 * * *'\njobs: {}\n"
            return {"content": base64.b64encode(body.encode()).decode(),
                    "encoding": "base64"}
        raise AssertionError(f"unexpected request: {path}")

    def get_all(self, path, key):
        return wh.Gh.get_all(self, path, key)


# ---------------------------------------------------------------------------
# Positive: each kind fires on the real defect
# ---------------------------------------------------------------------------

class TestKindsFire(unittest.TestCase):

    def test_t7_red_on_real_history(self):
        """
        cu2-agent-studio cache-stats-daily, as of 2026-07-25 — the live instance
        this detector was specified against.
        """
        runs = load_fixture("cache-stats-daily-runs.json")
        h = wh.classify("credit-union-2-0-llc/cu2-agent-studio", "cache-stats-daily",
                        ".github/workflows/cache-stats-daily.yml", "active",
                        runs, True, at("2026-07-25"))
        self.assertEqual(h.kind, "red")
        self.assertEqual(h.severity, "high")
        self.assertEqual(h.consecutive_scheduled_failures, 19)
        self.assertEqual(h.days_since_last_scheduled_success, 19)
        self.assertEqual(h.most_recent_scheduled_conclusion, "failure")

    def test_t7_never_ran(self):
        """Declares a cron, has never fired. No red X exists anywhere to notice."""
        h = classify([run("success", "2026-07-20T00:00:00Z", event="push")],
                     "2026-07-28", declares=True)
        self.assertEqual(h.kind, "never_ran")
        self.assertEqual(h.severity, "high")

    def test_t7_disabled_while_declaring_a_cron(self):
        h = classify([run("success", "2026-05-01T00:00:00Z")], "2026-07-28",
                     declares=True, state="disabled_inactivity")
        self.assertEqual(h.kind, "disabled")
        self.assertIn("disabled_inactivity", h.message)

    def test_t7_stale_schedule_stopped_firing(self):
        h = classify([run("success", "2026-06-01T00:00:00Z")], "2026-07-28")
        self.assertEqual(h.kind, "stale")
        self.assertIn("stopped firing", h.message)
        self.assertIn("passing when it stopped", h.message)

    def test_t7_stale_says_whether_it_ever_worked(self):
        """
        `stale` reads very differently depending on how the workflow was doing
        when it stopped, and the message must say which. cu2-platform's
        `soc2-evidence-collector` ran on schedule exactly 10 times, failed all 10,
        and then stopped — a message that said only "stopped 53 days ago" buried
        the fact that the compliance evidence collector never once worked.
        """
        never_worked = classify(
            [run("failure", f"2026-06-{d:02d}T00:00:00Z", number=d) for d in (5, 4, 3, 2, 1)],
            "2026-07-28")
        self.assertEqual(never_worked.kind, "stale")
        self.assertEqual(never_worked.consecutive_scheduled_failures, 5)
        self.assertIn("never once succeeded", never_worked.message)

        was_green = classify([run("failure", "2026-06-05T00:00:00Z", number=3),
                              run("failure", "2026-06-04T00:00:00Z", number=2),
                              run("success", "2026-06-03T00:00:00Z", number=1)],
                             "2026-07-28")
        self.assertEqual(was_green.kind, "stale")
        self.assertIn("after 2 consecutive failures", was_green.message)
        self.assertNotIn("never once", was_green.message)

    def test_t7_red_escalates_by_duration(self):
        """Two days red is medium; two weeks red is high."""
        short = classify([run("failure", "2026-07-28T00:00:00Z", number=3),
                          run("failure", "2026-07-27T00:00:00Z", number=2),
                          run("success", "2026-07-26T00:00:00Z", number=1)],
                         "2026-07-28")
        self.assertEqual((short.kind, short.severity), ("red", "medium"))

        long = classify([run("failure", "2026-07-28T00:00:00Z", number=3),
                         run("failure", "2026-07-27T00:00:00Z", number=2),
                         run("success", "2026-07-10T00:00:00Z", number=1)],
                        "2026-07-28")
        self.assertEqual((long.kind, long.severity), ("red", "high"))

    def test_t7_never_succeeded_on_schedule_is_high(self):
        h = classify([run("failure", "2026-07-28T00:00:00Z", number=2),
                      run("failure", "2026-07-27T00:00:00Z", number=1)],
                     "2026-07-28")
        self.assertEqual(h.kind, "red")
        self.assertEqual(h.severity, "high")
        self.assertIsNone(h.days_since_last_scheduled_success)
        self.assertIn("never succeeded on schedule", h.message)

    def test_t7_api_failure_becomes_error_not_clean(self):
        """
        THE FAIL-CLOSED RULE. A repo we could not check is not a repo that is
        clean. check_repo must never degrade an API failure into an empty list.
        """
        class Broken(_FakeGh):
            def get(self, path, paginate=False):
                raise wh.GhError("403 rate limited")

        rows = wh.check_repo(Broken(), "acme/repo", at("2026-07-28"))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].kind, "error")
        self.assertIn("error", wh.FINDING_KINDS)

    def test_every_finding_kind_has_coverage(self):
        covered = set()
        for name in dir(self):
            for kind in wh.FINDING_KINDS:
                if name.startswith("test_t7_") and kind in name:
                    covered.add(kind)
        self.assertEqual(covered, set(wh.FINDING_KINDS),
                         f"uncovered kinds: {set(wh.FINDING_KINDS) - covered}")


# ---------------------------------------------------------------------------
# False positives: the legitimate lookalikes must stay silent
# ---------------------------------------------------------------------------

class TestFalsePositives(unittest.TestCase):

    def test_recovered_workflow_on_real_history_is_not_flagged(self):
        """
        THE PINNED FP, ON REAL DATA. Same fixture, three days later, after a
        workflow_dispatch fixed it. 19 failures are still in the history. A
        detector that counts failures instead of reading the head of the streak
        reports a red finding against a green workflow.
        """
        runs = load_fixture("cache-stats-daily-runs.json")
        h = wh.classify("credit-union-2-0-llc/cu2-agent-studio", "cache-stats-daily",
                        ".github/workflows/cache-stats-daily.yml", "active",
                        runs, True, at("2026-07-28"))
        self.assertEqual(h.kind, "ok", f"must not flag a recovered workflow: {h.message}")
        self.assertEqual(h.consecutive_scheduled_failures, 0)
        self.assertNotIn(h.kind, wh.FINDING_KINDS)

    def test_deliberately_descheduled_workflow_is_not_stale(self):
        """
        THE EIGHTH PINNED BUG, AND THE WORST CALL THIS TOOL HAS MADE.

        cu2-platform's `soc2-evidence-collector.yml` was migrated to an ACA Job on
        2026-06-05 and its trigger block reduced to `workflow_dispatch` — the file
        says so in a comment block headed "DEPRECATED FOR SCHEDULED RUNS". Its
        scheduled runs stop on exactly that date.

        Inferring "is this scheduled?" from run history reported that planned
        migration as a dead SOC 2 evidence collector, and it was escalated to Kirk
        as the finding worth acting on first. Historical scheduled runs prove a
        cron *used to* fire. Only the file says whether one is declared now.
        """
        history = [run("failure", f"2026-06-{d:02d}T00:00:00Z", number=d)
                   for d in (5, 4, 3, 2, 1)]
        h = classify(history, "2026-07-28", declares=False)
        self.assertEqual(h.kind, "descheduled")
        self.assertNotIn(h.kind, wh.FINDING_KINDS)
        self.assertIn("removed deliberately", h.message)

        # The same history with the cron still declared IS a finding.
        still_declared = classify(history, "2026-07-28", declares=True)
        self.assertEqual(still_declared.kind, "stale")

    def test_quarterly_cron_is_not_stale_at_69_days(self):
        """
        THE NINTH PINNED BUG. ncua-query-api's `quarterly-import.yml` fires on

            0 14 15,16,17,18,19,20 2,5,8,11 *

        — February, May, August and November only, because NCUA publishes about 45
        days after each quarter ends. The first estate run called it `stale` after
        69 days of silence against a fixed 30-day threshold, three weeks before its
        next window. A staleness threshold that ignores the schedule's own cadence
        is a check that does not check.
        """
        quarterly = "0 14 15,16,17,18,19,20 2,5,8,11 *"
        gap = wh.max_expected_gap_days([quarterly])
        self.assertEqual(gap, 87, "the quarterly cadence must be measured, not assumed")

        runs_ = [run("failure", "2026-05-20T15:09:20Z", number=6)]
        h = classify(runs_, "2026-07-28", expected_gap_days=gap)
        self.assertNotEqual(h.kind, "stale")

        # A daily cron silent for the same 69 days IS stale.
        daily_gap = wh.max_expected_gap_days(["0 5 * * *"])
        self.assertEqual(daily_gap, 1)
        h2 = classify(runs_, "2026-07-28", expected_gap_days=daily_gap)
        self.assertEqual(h2.kind, "stale")
        self.assertIn("at most 1 days apart", h2.message)

        # And the quarterly cron does go stale once it truly misses its windows.
        h3 = classify([run("failure", "2026-01-05T00:00:00Z", number=1)],
                      "2026-07-28", expected_gap_days=gap, lookback_days=400)
        self.assertEqual(h3.kind, "stale")

    def test_unparseable_cron_falls_back_to_the_fixed_threshold(self):
        """An unknown cadence must not silently disable the staleness check."""
        self.assertIsNone(wh.max_expected_gap_days(["not a cron"]))
        self.assertIsNone(wh.max_expected_gap_days([]))
        h = classify([run("success", "2026-06-01T00:00:00Z")], "2026-07-28",
                     expected_gap_days=None)
        self.assertEqual(h.kind, "stale")
        self.assertIn("could not be parsed", h.message)

    def test_cron_extraction_from_a_workflow_file(self):
        text = ("name: N\non:\n  schedule:\n"
                "    - cron: '0 5 * * *'    # nightly\n"
                '    - cron: "30 6 * * 1"\n  workflow_dispatch:\njobs: {}\n')
        self.assertEqual(wh.extract_crons(text), ["0 5 * * *", "30 6 * * 1"])
        self.assertEqual(wh.max_expected_gap_days(wh.extract_crons(text)), 1)

    def test_push_only_workflow_is_not_a_t7(self):
        """Ordinary CI has no cron. It is not a scheduled control and is not T7."""
        h = classify([run("failure", "2026-07-28T00:00:00Z", event="push")],
                     "2026-07-28", declares=False)
        self.assertEqual(h.kind, "not_scheduled")
        self.assertNotIn(h.kind, wh.FINDING_KINDS)

    def test_failing_push_runs_do_not_make_a_scheduled_workflow_red(self):
        """
        Event filtering. A workflow green on every scheduled run but red on a
        broken feature-branch push is not a broken nightly control. Counting all
        runs instead of scheduled runs is the obvious way to get this wrong.
        """
        h = classify([run("failure", "2026-07-28T09:00:00Z", event="push", number=4),
                      run("failure", "2026-07-28T08:00:00Z", event="pull_request", number=3),
                      run("success", "2026-07-28T02:00:00Z", number=2),
                      run("success", "2026-07-27T02:00:00Z", number=1)],
                     "2026-07-28")
        self.assertEqual(h.kind, "ok")
        self.assertEqual(h.consecutive_scheduled_failures, 0)

    def test_single_failure_is_below_threshold(self):
        """One failure last night may be in hand. Reported, but not a finding."""
        h = classify([run("failure", "2026-07-28T00:00:00Z", number=2),
                      run("success", "2026-07-27T00:00:00Z", number=1)],
                     "2026-07-28")
        self.assertEqual(h.kind, "single_failure")
        self.assertNotIn(h.kind, wh.FINDING_KINDS)
        self.assertEqual(h.consecutive_scheduled_failures, 1)

    def test_cancelled_run_is_not_a_failure(self):
        """`cancelled` and `skipped` are not assertions about the code."""
        h = classify([run("cancelled", "2026-07-28T00:00:00Z", number=3),
                      run("skipped", "2026-07-27T00:00:00Z", number=2),
                      run("success", "2026-07-26T00:00:00Z", number=1)],
                     "2026-07-28")
        self.assertEqual(h.kind, "ok")
        self.assertEqual(h.consecutive_scheduled_failures, 0)

    def test_future_runs_are_excluded_by_as_of(self):
        """--as-of must actually bound the history, or the fixture pair is a lie."""
        runs = [run("success", "2026-07-28T00:00:00Z", number=2),
                run("failure", "2026-07-20T00:00:00Z", number=1)]
        h = classify(runs, "2026-07-21")
        self.assertEqual(h.most_recent_scheduled_conclusion, "failure")

    def test_unparseable_timestamp_is_dropped_not_treated_as_epoch(self):
        runs = [{"run_number": 1, "event": "schedule", "conclusion": "failure",
                 "created_at": None, "html_url": ""},
                run("success", "2026-07-28T00:00:00Z", number=2)]
        h = classify(runs, "2026-07-28")
        self.assertEqual(h.kind, "ok")


# ---------------------------------------------------------------------------
# Schedule declaration — the YAML 1.1 trap
# ---------------------------------------------------------------------------

class TestDeclaresSchedule(unittest.TestCase):

    def test_on_key_parses_as_yaml_boolean(self):
        """
        THE PINNED YAML TRAP. YAML 1.1 reads the bare key `on` as the boolean
        True, so PyYAML gives {True: {...}} and a naive doc["on"] lookup misses
        every workflow ever written — reporting a confident "no schedule
        declared" across the whole estate. Exactly the shape of the
        `_is_workflow()` leading-slash bug in theater_scan.py.
        """
        import yaml
        parsed = yaml.safe_load("on:\n  schedule:\n    - cron: '0 5 * * *'\n")
        self.assertIn(True, parsed, "PyYAML no longer coerces `on` — revisit this")
        self.assertNotIn("on", parsed)
        self.assertTrue(wh.declares_schedule(
            "name: Nightly\non:\n  schedule:\n    - cron: '0 5 * * *'\njobs: {}\n"))

    def test_quoted_on_key_also_works(self):
        self.assertTrue(wh.declares_schedule(
            'name: N\n"on":\n  schedule:\n    - cron: "0 5 * * *"\njobs: {}\n'))

    def test_push_only_declares_no_schedule(self):
        self.assertFalse(wh.declares_schedule(
            "name: CI\non:\n  push:\n    branches: [main]\njobs: {}\n"))

    def test_list_form_trigger(self):
        self.assertFalse(wh.declares_schedule("on: [push, pull_request]\njobs: {}\n"))
        self.assertTrue(wh.declares_schedule("on: [push, schedule]\njobs: {}\n"))

    def test_the_word_schedule_elsewhere_is_not_a_trigger(self):
        """A job named `schedule-report` does not make the workflow scheduled."""
        self.assertFalse(wh.declares_schedule(
            "on:\n  push: {}\njobs:\n  schedule:\n    runs-on: ubuntu-latest\n"))

    def test_malformed_yaml_is_unknown_not_false(self):
        """
        Graceful degradation of a measurement into a false all-clear is the
        defect being eliminated. Unparseable must be None, never False.
        """
        result = wh.declares_schedule("on:\n  schedule:\n   - cron: [[[unclosed\n")
        self.assertIsNot(result, False)

    def test_unknown_schedule_with_no_runs_becomes_an_error_finding(self):
        h = classify([], "2026-07-28", declares=None)
        self.assertEqual(h.kind, "error")
        self.assertIn(h.kind, wh.FINDING_KINDS)


# ---------------------------------------------------------------------------
# Repo-level plumbing and CLI contract
# ---------------------------------------------------------------------------

class TestRepoAndCLI(unittest.TestCase):

    def test_dynamic_dependabot_workflows_are_skipped(self):
        """GitHub synthesises these; there is no file and no cron to audit."""
        self.assertTrue(wh.DYNAMIC_PATH_RE.match("dynamic/dependabot/dependabot-updates"))
        self.assertFalse(wh.DYNAMIC_PATH_RE.match(".github/workflows/ci.yml"))

    def test_busy_workflow_is_not_misread_as_never_ran(self):
        """
        THE THIRD SELF-INFLICTED BUG IN THIS TOOLCHAIN, PINNED.

        dev-studio's `SAST (semgrep)` has 1070 runs, all but a handful of them
        push and pull_request. The first version of _check_workflow fetched the
        newest 60 runs unfiltered and inferred "is this scheduled?" from whether
        any of them had event=schedule. For that workflow the answer was no — so
        it reported `never_ran`, with total confidence, about a cron that fires
        nightly and passed this morning.

        The fix is to ask the API for event=schedule so page depth cannot change
        the verdict. This test asserts the request carries that filter, because
        the bug lived in the request, not in the classification.
        """
        seen = []

        class Busy(_FakeGh):
            def get(self, path, paginate=False):
                seen.append(path)
                if "/runs" in path:
                    # Honour the filter the way the real API does.
                    if f"event={wh.SCHEDULE_EVENT}" not in path:
                        return {"total_count": 1070, "workflow_runs": [
                            run("failure", "2026-07-28T00:00:00Z", event="push", number=i)
                            for i in range(60)]}
                    return {"total_count": 2, "workflow_runs": [
                        run("success", "2026-07-28T00:00:00Z", number=2),
                        run("success", "2026-07-27T00:00:00Z", number=1)]}
                if "/actions/workflows?" in path:
                    return [{"workflows": [{"id": 1, "name": "SAST (semgrep)",
                                            "path": ".github/workflows/semgrep.yml",
                                            "state": "active"}]}]
                return super().get(path, paginate)

        rows = wh.check_repo(Busy(), "credit-union-2-0-llc/dev-studio", at("2026-07-28"))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].kind, "ok",
                         "a busy scheduled workflow must not read as never_ran")
        self.assertTrue(any(f"event={wh.SCHEDULE_EVENT}" in p for p in seen if "/runs" in p),
                        "the run query must filter server-side by event=schedule")

    def test_total_count_alone_proves_the_schedule_has_fired(self):
        """
        If the page is empty but total_count is non-zero (a lookback that excludes
        every run), that is `stale`, not `never_ran`. The two have different fixes.
        """
        class Sparse(_FakeGh):
            def get(self, path, paginate=False):
                if "/runs" in path:
                    return {"total_count": 40, "workflow_runs": [
                        run("success", "2026-01-01T00:00:00Z", number=1)]}
                if "/actions/workflows?" in path:
                    return [{"workflows": [{"id": 1, "name": "Nightly",
                                            "path": ".github/workflows/nightly.yml",
                                            "state": "active"}]}]
                return super().get(path, paginate)

        rows = wh.check_repo(Sparse(), "acme/repo", at("2026-07-28"))
        self.assertEqual(rows[0].kind, "stale")

    def test_listing_is_paginated(self):
        """
        THE FIFTH PINNED BUG. `bond` has 301 workflow records. The first estate
        run fetched `?per_page=100` without --paginate, audited the first 100, and
        reported a repo total as though it were complete. Silent truncation reads
        as coverage — the same defect the inventory rule about "not scanned" rows
        exists to prevent.
        """
        calls = []

        class Paged(_FakeGh):
            def get(self, path, paginate=False):
                calls.append((path, paginate))
                if "/actions/workflows?" in path:
                    if not paginate:
                        raise AssertionError("workflow listing must paginate")
                    return [
                        {"workflows": [self.wf(i) for i in range(100)]},
                        {"workflows": [self.wf(i) for i in range(100, 301)]},
                    ]
                return super().get(path, paginate)

            @staticmethod
            def wf(i):
                return {"id": i, "name": f"wf{i}",
                        "path": f".github/workflows/w{i}.yml", "state": "active"}

        rows = wh.check_repo(Paged(), "credit-union-2-0-llc/bond", at("2026-07-28"))
        self.assertEqual(len(rows), 301,
                         "every workflow record must get a row, not the first page")

    def test_deleted_workflow_file_is_orphaned_not_a_finding(self):
        """
        THE SIXTH PINNED BUG, AND THE LARGEST INFLATION SO FAR. GitHub keeps a
        workflow record after its file is deleted and still reports state
        "active". Treating "I could not read the file" as unknown turned 103
        deleted throwaway workflows into 103 T7 findings and took the estate
        total from 7 to 110 — a 15x inflation, produced by the tool built to find
        inflated signals, for the third time in this project.

        A record whose file is gone cannot run, so it is not a control that lies.
        It is litter, and it is reported as litter.
        """
        class Deleted(_FakeGh):
            def get(self, path, paginate=False):
                if "/contents/" in path:
                    raise wh.GhNotFound(f"{path}: 404")
                return super().get(path, paginate)

        rows = wh.check_repo(Deleted(), "credit-union-2-0-llc/bond", at("2026-07-28"))
        self.assertEqual(rows[0].kind, "orphaned")
        self.assertNotIn("orphaned", wh.FINDING_KINDS)
        self.assertIn("orphaned", wh.INFO_KINDS)

    def test_a_real_api_break_is_still_an_error_not_orphaned(self):
        """
        The 404/other-failure split must not collapse the other way either. A
        rate limit or a 500 is an absence of information, and unknown is a
        first-class state.
        """
        class Broken(_FakeGh):
            def get(self, path, paginate=False):
                if "/contents/" in path:
                    raise wh.GhError(f"{path}: 403 rate limited")
                return super().get(path, paginate)

        rows = wh.check_repo(Broken(), "acme/repo", at("2026-07-28"))
        self.assertEqual(rows[0].kind, "error")

    def test_clone_answers_file_existence_without_the_api(self):
        """With a clone present, the file question is answered offline."""
        import tempfile
        root = tempfile.mkdtemp(prefix="wh-clone-")
        os.makedirs(os.path.join(root, ".git"))
        os.makedirs(os.path.join(root, ".github", "workflows"))
        with open(os.path.join(root, ".github/workflows/nightly.yml"), "w") as fh:
            fh.write("name: N\non:\n  schedule:\n    - cron: '0 5 * * *'\njobs: {}\n")

        class NoContents(_FakeGh):
            def get(self, path, paginate=False):
                if "/contents/" in path:
                    raise AssertionError("must not call the API when a clone is present")
                return super().get(path, paginate)

        rows = wh.check_repo(NoContents(), "acme/repo", at("2026-07-28"),
                            clone_root=root)
        self.assertEqual(rows[0].kind, "never_ran")

        # And a file missing from a real clone is orphaned, with no API call.
        os.remove(os.path.join(root, ".github/workflows/nightly.yml"))
        rows = wh.check_repo(NoContents(), "acme/repo", at("2026-07-28"),
                            clone_root=root)
        self.assertEqual(rows[0].kind, "orphaned")

    def test_orphan_check_precedes_the_run_history_fetch(self):
        """
        The orphan short-circuit is a scale property, so it is asserted rather
        than assumed. A deleted workflow is not a finding whatever its history
        says, so fetching that history is a wasted call — and `bond` has 301
        workflow records for 8 live files. Checking the clone first takes that
        repo from 301 API calls to 8, which is the difference between a sweep
        that can run in CI and one that cannot.
        """
        import tempfile
        root = tempfile.mkdtemp(prefix="wh-orphan-")
        os.makedirs(os.path.join(root, ".git"))
        calls = []

        class CountingGh(_FakeGh):
            def get(self, path, paginate=False):
                calls.append(path)
                return super().get(path, paginate)

        rows = wh.check_repo(CountingGh(), "credit-union-2-0-llc/bond",
                            at("2026-07-28"), clone_root=root)
        self.assertEqual(rows[0].kind, "orphaned")
        self.assertFalse([p for p in calls if "/runs" in p],
                         f"no run history should be fetched for an orphan: {calls}")
        self.assertEqual(len(calls), 1, "only the workflow listing is needed")

    def test_repo_with_no_workflows_yields_a_row_not_nothing(self):
        class Empty(_FakeGh):
            def get(self, path, paginate=False):
                if "/actions/workflows?" in path:
                    return [{"workflows": []}]
                return super().get(path, paginate)

        rows = wh.check_repo(Empty(), "acme/repo", at("2026-07-28"))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].kind, "not_scheduled")

    def test_malformed_listing_is_an_error_not_a_clean_pass(self):
        class Weird:
            def get(self, path, paginate=False):
                return [{"unexpected": True}]

            def get_all(self, path, key):
                return wh.Gh.get_all(self, path, key)

        rows = wh.check_repo(Weird(), "acme/repo", at("2026-07-28"))
        self.assertEqual(rows[0].kind, "error")

    def test_bad_clones_dir_exits_two(self):
        self.assertEqual(wh.main(["acme/repo", "--clones-dir", "/nonexistent/clones"]), 2)

    def test_no_field_is_named_after_the_inference(self):
        """
        The `spark_reachable` lesson, enforced. That field reported a Redis ping
        and was read as Spark being up. This tool cannot observe whether a human
        is watching, so no field may be named as though it can.
        """
        for field in wh.Health._fields:
            self.assertNotIn("watch", field, f"{field} claims to measure attention")
        self.assertIn("consecutive_scheduled_failures", wh.Health._fields)
        self.assertIn("days_since_last_scheduled_success", wh.Health._fields)

    def test_bad_repo_argument_exits_two(self):
        self.assertEqual(wh.main(["not-a-repo-spec"]), 2)

    def test_no_repos_exits_two(self):
        self.assertEqual(wh.main([]), 2)

    def test_bad_as_of_exits_two(self):
        self.assertEqual(wh.main(["acme/repo", "--as-of", "yesterday"]), 2)

    def test_missing_repos_file_exits_two(self):
        self.assertEqual(wh.main(["--repos-file", "/nonexistent/repos.txt"]), 2)

    def test_finding_kinds_and_info_kinds_are_disjoint(self):
        self.assertFalse(set(wh.FINDING_KINDS) & set(wh.INFO_KINDS))




# ---------------------------------------------------------------------------
# T9 — default-branch CI red and ignored
# ---------------------------------------------------------------------------

def ci(runs, as_of, **kw):
    return wh.classify_ci("acme/repo", "CI", ".github/workflows/ci.yml",
                          runs, at(as_of), **kw)


class TestT9(unittest.TestCase):
    """
    T9 came from a T4 remediation walking into it: BusinessLoanReview's last 20
    runs on main had all failed, every one since 2026-05-19. Its typecheck step
    is NOT suppressed — it runs unguarded and correctly reports 150 real type
    errors. The control works. Nobody acts on it.

    Every other detector here assumes the problem is a signal that lies. This one
    is a signal telling the truth into an empty room.
    """

    def test_t9_red_for_twenty_runs(self):
        runs = [run("failure", f"2026-07-{d:02d}T00:00:00Z", event="push", number=d)
                for d in range(28, 8, -1)]
        h = ci(runs, "2026-07-28")
        self.assertEqual(h.kind, "red")
        self.assertEqual(h.severity, "high")
        self.assertEqual(h.consecutive_push_failures, 20)
        self.assertIsNone(h.days_since_last_push_success)
        self.assertIn("merged past", h.message)

    def test_t9_ignores_a_healthy_repo(self):
        runs = [run("success", "2026-07-28T00:00:00Z", event="push", number=2),
                run("failure", "2026-07-27T00:00:00Z", event="push", number=1)]
        h = ci(runs, "2026-07-28")
        self.assertEqual(h.kind, "ok")
        self.assertNotIn(h.kind, wh.CI_FINDING_KINDS)

    def test_t9_ignores_a_break_that_may_still_be_in_hand(self):
        """Two failures today is a Tuesday, not a 70-day habit."""
        runs = [run("failure", "2026-07-28T00:00:00Z", event="push", number=3),
                run("failure", "2026-07-28T01:00:00Z", event="push", number=2),
                run("success", "2026-07-27T00:00:00Z", event="push", number=1)]
        h = ci(runs, "2026-07-28")
        self.assertEqual(h.kind, "recent_failure")
        self.assertNotIn(h.kind, wh.CI_FINDING_KINDS)

    def test_t9_cancelled_runs_do_not_make_a_repo_red(self):
        runs = [run("cancelled", "2026-07-28T00:00:00Z", event="push", number=3),
                run("cancelled", "2026-07-27T00:00:00Z", event="push", number=2),
                run("success", "2026-07-26T00:00:00Z", event="push", number=1)]
        self.assertEqual(ci(runs, "2026-07-28").kind, "ok")

    def test_t9_a_repo_with_no_pushes_is_not_a_finding(self):
        h = ci([], "2026-07-28")
        self.assertEqual(h.kind, "no_runs")
        self.assertNotIn(h.kind, wh.CI_FINDING_KINDS)

    def test_t9_severity_rises_with_duration(self):
        short = ci([run("failure", "2026-07-28T00:00:00Z", event="push", number=4),
                    run("failure", "2026-07-27T00:00:00Z", event="push", number=3),
                    run("failure", "2026-07-26T00:00:00Z", event="push", number=2),
                    run("success", "2026-07-25T00:00:00Z", event="push", number=1)],
                   "2026-07-28")
        self.assertEqual((short.kind, short.severity), ("red", "medium"))
        long = ci([run("failure", "2026-07-28T00:00:00Z", event="push", number=4),
                   run("failure", "2026-07-27T00:00:00Z", event="push", number=3),
                   run("failure", "2026-07-26T00:00:00Z", event="push", number=2),
                   run("success", "2026-06-01T00:00:00Z", event="push", number=1)],
                  "2026-07-28")
        self.assertEqual((long.kind, long.severity), ("red", "high"))

    def test_t9_no_field_claims_to_measure_attention(self):
        """The `spark_reachable` rule, applied to the newest detector."""
        for f in wh.CIHealth._fields:
            self.assertNotIn("watch", f)
            self.assertNotIn("ignor", f)
        self.assertIn("consecutive_push_failures", wh.CIHealth._fields)
        self.assertIn("days_since_last_push_success", wh.CIHealth._fields)

    def test_t9_query_filters_to_push_on_the_default_branch(self):
        """
        The T7 lesson, pinned for T9 before it can bite: infer the event from an
        unfiltered page and a busy workflow gives the wrong verdict with total
        confidence. The filter must be in the request.
        """
        seen = []

        class Watcher(_FakeGh):
            def get(self, path, paginate=False):
                seen.append(path)
                if path.startswith("repos/acme/repo") and "/actions/" not in path:
                    return {"default_branch": "main"}
                if "/runs" in path:
                    return {"total_count": 0, "workflow_runs": []}
                return super().get(path, paginate)

        wh.check_repo_ci(Watcher(), "acme/repo", at("2026-07-28"))
        runq = [p for p in seen if "/runs" in p]
        self.assertTrue(runq, "no run query issued")
        self.assertTrue(all("event=push" in p and "branch=main" in p for p in runq),
                        f"run query must filter server-side: {runq}")

if __name__ == "__main__":
    unittest.main(verbosity=2)
