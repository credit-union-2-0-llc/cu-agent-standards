#!/usr/bin/env python3
"""
workflow_health.py — detector T7 of the CU 2.0 verification-theater taxonomy.

    T7  a scheduled workflow that everyone believes is running, and is not.
    T9  a default-branch CI that is red, honest, and ignored.

WHY THIS IS A SEPARATE FILE

`theater_scan.py` is deliberately stdlib-only, offline, and side-effect free, so
it can run in a pre-commit hook and in any CI job without credentials. T7 cannot
be answered from the contents of a repository at all: a workflow file can declare
a perfectly good `on: schedule` and still be failing nightly, or disabled by
GitHub, or never have fired once. Answering it requires the Actions API. Mixing a
network dependency into the offline scanner would compromise the one property
that makes it trustworthy, so T7 lives here.

THE FOUR WAYS A SCHEDULED CONTROL LIES

    red         it runs on schedule and has failed N times consecutively
    never_ran   it declares `on: schedule` and has never once run on schedule
    stale       it used to run on schedule and has silently stopped
    disabled    GitHub has switched it off while the file still declares a cron

All four present identically to a human reading the repo: a nightly scan exists.
`never_ran` and `disabled` are the purest form of the defect class, because there
is not even a red X anywhere to notice.

WHAT THIS TOOL DOES NOT MEASURE

It cannot measure whether a human is watching. Nothing in the API exposes that.
So no field here is named `watched` or `unwatched`. What it measures, and what
the fields are named after, is:

    consecutive_scheduled_failures      how many scheduled runs failed in a row
    days_since_last_scheduled_success   how long it has been broken

"Nobody is watching" is an *inference* the reader draws from a workflow that has
been red for 19 days. Naming the field after the inference rather than the
measurement is precisely the `spark_reachable` defect this taxonomy exists to
kill — that field reported a Redis ping and was read as Spark being up.

KNOWN BLIND SPOT, STATED RATHER THAN GLOSSED

A workflow whose only job is gated behind an `if:` that evaluates false reports
`conclusion: success` while doing nothing. This tool reads it as healthy. So does
the GitHub UI. Detecting it needs job-level inspection and is out of scope here;
it is recorded as a limitation rather than left for someone to discover.

Posture: fail closed. An API call that fails becomes an `error` finding, never an
empty result — a repo we could not check is not a repo that is clean. Exit 0
clean, 1 findings, 2 bad input.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter, namedtuple
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Conclusions that mean the control ran and did not pass. `cancelled` and
# `skipped` are excluded on purpose: they are not assertions about the code.
FAILING_CONCLUSIONS = frozenset({"failure", "timed_out", "startup_failure"})
PASSING_CONCLUSIONS = frozenset({"success"})

SCHEDULE_EVENT = "schedule"

# Kinds that constitute a finding, and their base severity.
FINDING_KINDS = {
    "red": "high",
    "never_ran": "high",
    "disabled": "high",
    "stale": "medium",
    "error": "medium",
}

# Kinds that are reported for completeness but are not findings. Every scheduled
# workflow gets a row in report mode; nothing is silently dropped.
#
# `orphaned` earns its place here rather than in FINDING_KINDS. GitHub keeps a
# workflow record after its file is deleted and still reports state "active":
# `bond` lists 301 workflow records for 8 files on main. Those records cannot
# run, so they are not controls that lie — they are Actions-UI litter, and
# counting them as findings would have inflated the estate's T7 total from 7 to
# 110 — the same shape of inflation as the `xit` pattern (with paren) matching
# `exit`.
INFO_KINDS = ("ok", "single_failure", "not_scheduled", "orphaned",
              "descheduled")

DEFAULT_MIN_CONSECUTIVE = 2
DEFAULT_LOOKBACK_DAYS = 90
DEFAULT_STALE_DAYS = 30
# Above this many days red, a medium becomes a high.
ESCALATE_DAYS = 7

# Workflows GitHub synthesises; there is no file and no cron to audit.
DYNAMIC_PATH_RE = re.compile(r"^dynamic/")

Health = namedtuple("Health", [
    "repo", "workflow", "path", "kind", "severity", "message",
    "consecutive_scheduled_failures", "days_since_last_scheduled_success",
    "most_recent_scheduled_conclusion", "most_recent_scheduled_at",
    "scheduled_run_count", "declares_schedule", "state", "evidence_url",
])


# ---------------------------------------------------------------------------
# Schedule declaration — parsed from the workflow file
# ---------------------------------------------------------------------------

def declares_schedule(text):
    """
    True when a workflow's trigger block declares `schedule:`.

    YAML 1.1 TRAP: PyYAML parses the bare key `on` as the boolean True, not the
    string "on", so a naive `doc["on"]` lookup misses every workflow ever
    written. Both keys are checked. test_on_key_parses_as_yaml_boolean pins it.

    Returns None when the document cannot be parsed — an explicit "unknown",
    not a False that would read as "no schedule declared".
    """
    parsed = _safe_yaml(text)
    if parsed is None:
        return _declares_schedule_textual(text)
    if not isinstance(parsed, dict):
        return None
    triggers = parsed.get("on", parsed.get(True))
    if triggers is None:
        return False
    if isinstance(triggers, dict):
        return "schedule" in triggers
    if isinstance(triggers, list):
        return "schedule" in triggers
    return triggers == "schedule"


def declares_push(text):
    """
    True when a workflow's trigger block declares `push`.

    THE SAME BUG T7 HAD, CAUGHT ON T9's FIRST SWEEP. GitHub records
    event=push runs against `workflow_call`-only workflows — zero jobs,
    conclusion "failure" — and T9 counted them as a red default-branch CI. Four
    of its first twenty findings were that, including ops-platform's
    reusable-scan.yml, which has no push trigger at all and is invoked by six
    other repositories.

    Run history proves what fired. Only the file says what is DECLARED. Same
    YAML 1.1 `on`-is-boolean trap as declares_schedule.
    """
    parsed = _safe_yaml(text)
    if parsed is None or not isinstance(parsed, dict):
        return None
    triggers = parsed.get("on", parsed.get(True))
    if triggers is None:
        return False
    if isinstance(triggers, dict):
        return "push" in triggers
    if isinstance(triggers, list):
        return "push" in triggers
    return triggers == "push"


def _safe_yaml(text):
    """Parse YAML, or return None. Never returns {} — see the T3 rule."""
    try:
        import yaml
    except ImportError:
        return None
    try:
        return yaml.safe_load(text)
    except Exception:  # noqa: BLE001 - a malformed workflow is an unknown, below
        return None


SCHEDULE_BLOCK_RE = re.compile(r"^\s{0,4}schedule:\s*$", re.MULTILINE)
CRON_RE = re.compile(r"^\s*-?\s*cron:\s*['\"]?[\d*]", re.MULTILINE)


def _declares_schedule_textual(text):
    """Fallback when YAML is unavailable or the document is malformed."""
    if SCHEDULE_BLOCK_RE.search(text) and CRON_RE.search(text):
        return True
    return None


# ---------------------------------------------------------------------------
# Cron cadence
#
# WHY THIS EXISTS. The first estate run reported ncua-query-api's
# quarterly-import.yml as `stale` because it had not run on schedule for 69 days,
# against a fixed 30-day threshold. Its cron is
#
#     0 14 15,16,17,18,19,20 2,5,8,11 *
#
# which fires only in February, May, August and November — NCUA publishes about
# 45 days after each quarter ends. 69 days of silence is exactly correct, and the
# next window was three weeks away. A fixed staleness threshold cannot judge a
# schedule without knowing the schedule's own cadence; asserting otherwise is a
# check that does not check.
# ---------------------------------------------------------------------------

CRON_LINE_RE = re.compile(r"^\s*-?\s*cron:\s*['\"]?(?P<expr>[^'\"#\n]+?)['\"]?\s*(?:#.*)?$",
                          re.MULTILINE)


def extract_crons(text):
    """Every cron expression in a workflow file, in order."""
    return [m.group("expr").strip() for m in CRON_LINE_RE.finditer(text)]


def _parse_field(field, low, high):
    """Expand one cron field to a set of ints, or None if unparseable."""
    if field == "*":
        return set(range(low, high + 1))
    values = set()
    for part in field.split(","):
        step = 1
        if "/" in part:
            part, _, raw_step = part.partition("/")
            if not raw_step.isdigit() or int(raw_step) == 0:
                return None
            step = int(raw_step)
        if part == "*":
            start, end = low, high
        elif "-" in part.lstrip("-"):
            a, _, b = part.partition("-")
            if not (a.isdigit() and b.isdigit()):
                return None
            start, end = int(a), int(b)
        elif part.isdigit():
            start = end = int(part)
        else:
            return None
        if start < low or end > high or start > end:
            return None
        values.update(range(start, end + 1, step))
    return values or None


def max_expected_gap_days(crons, sample_days=800):
    """
    The largest gap, in days, between consecutive firings of any of `crons`.

    Simulated at day granularity over a fixed window — enough to judge staleness,
    and deliberately not a full cron implementation. Returns None when no cron
    parses, which callers must treat as unknown rather than as "daily".

    The window starts at a fixed date, not today, so the result is reproducible.
    """
    matchers = []
    for expr in crons:
        parts = expr.split()
        if len(parts) != 5:
            continue
        _minute, _hour, dom, month, dow = parts
        dom_set = _parse_field(dom, 1, 31)
        month_set = _parse_field(month, 1, 12)
        dow_set = _parse_field(dow, 0, 7)
        if dom_set is None or month_set is None or dow_set is None:
            continue
        if 7 in dow_set:
            dow_set = (dow_set - {7}) | {0}
        matchers.append((dom_set, month_set, dow_set,
                         dom.strip() == "*", dow.strip() == "*"))
    if not matchers:
        return None

    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    fires = []
    for offset in range(sample_days):
        day = base + timedelta(days=offset)
        py_dow = day.weekday()          # Mon=0
        cron_dow = (py_dow + 1) % 7     # Sun=0
        for dom_set, month_set, dow_set, dom_any, dow_any in matchers:
            if day.month not in month_set:
                continue
            # Standard cron: when both day-of-month and day-of-week are
            # restricted, a day matching EITHER fires.
            if dom_any and dow_any:
                ok = True
            elif dom_any:
                ok = cron_dow in dow_set
            elif dow_any:
                ok = day.day in dom_set
            else:
                ok = day.day in dom_set or cron_dow in dow_set
            if ok:
                fires.append(offset)
                break
    if len(fires) < 2:
        return None
    return max(b - a for a, b in zip(fires, fires[1:]))


# ---------------------------------------------------------------------------
# Classification — pure, no network, fully unit-testable
# ---------------------------------------------------------------------------

def classify(repo, workflow_name, path, state, runs, schedule_declared,
             as_of, min_consecutive=DEFAULT_MIN_CONSECUTIVE,
             lookback_days=DEFAULT_LOOKBACK_DAYS,
             stale_days=DEFAULT_STALE_DAYS,
             expected_gap_days=None):
    """
    Decide the health of one workflow from its run history.

    `runs` is the Actions API `workflow_runs` list, newest first. `as_of` makes
    the verdict reproducible: the same history classified as of two dates gives
    two answers, and cache-stats-daily was red on 2026-07-25 and green on
    2026-07-28. A detector whose output silently depends on the wall clock
    cannot be regression-tested.
    """
    horizon = as_of - timedelta(days=lookback_days)
    scheduled = [
        r for r in runs
        if r.get("event") == SCHEDULE_EVENT
        and _parsed_at(r) is not None
        and _parsed_at(r) <= as_of
    ]
    in_window = [r for r in scheduled if _parsed_at(r) >= horizon]

    def mk(kind, message, severity=None, **over):
        newest = in_window[0] if in_window else None
        base = dict(
            repo=repo, workflow=workflow_name, path=path,
            kind=kind, severity=severity or FINDING_KINDS.get(kind, "info"),
            message=message,
            consecutive_scheduled_failures=_leading_failures(in_window),
            days_since_last_scheduled_success=_days_since_success(in_window, as_of),
            most_recent_scheduled_conclusion=(newest or {}).get("conclusion"),
            most_recent_scheduled_at=(newest or {}).get("created_at"),
            scheduled_run_count=len(in_window),
            declares_schedule=schedule_declared,
            state=state,
            evidence_url=(newest or {}).get("html_url"),
        )
        base.update(over)
        return Health(**base)

    # A workflow GitHub has switched off, while its file still promises a cron.
    if state in ("disabled_manually", "disabled_inactivity") and schedule_declared is not False:
        return mk("disabled",
                  f"Workflow state is '{state}' but the file still declares a "
                  f"cron — the schedule everyone believes in is switched off")

    if not scheduled:
        if schedule_declared is True:
            return mk("never_ran",
                      "Declares 'on: schedule' but has never run on schedule — "
                      "the cron has never fired (schedules only run on the "
                      "default branch)")
        if schedule_declared is None:
            return mk("error",
                      "Could not determine whether this workflow declares a "
                      "schedule, and it has no scheduled runs — unverified")
        return mk("not_scheduled", "Not a scheduled workflow", severity="info")

    # DELIBERATELY DE-SCHEDULED, NOT BROKEN. Historical scheduled runs prove the
    # cron *used to* fire; they say nothing about whether the file still declares
    # one. cu2-platform's soc2-evidence-collector.yml was migrated to an ACA Job
    # on 2026-06-05 and its trigger block reduced to workflow_dispatch — the
    # scheduled runs stop on exactly that date. Inferring "is scheduled" from run
    # history reported that planned migration as a dead SOC 2 control.
    if schedule_declared is False:
        return mk("descheduled",
                  "Ran on schedule historically, but the file no longer declares "
                  "a cron — the schedule was removed deliberately, not broken",
                  severity="info")

    newest = in_window[0] if in_window else scheduled[0]
    newest_at = _parsed_at(newest)
    age_days = (as_of - newest_at).days

    # A quarterly cron is not stale at 40 days. The threshold is the schedule's
    # own maximum expected gap, doubled to allow one missed window, floored at
    # stale_days for schedules whose cadence could not be parsed.
    effective_stale = stale_days
    if expected_gap_days:
        effective_stale = max(stale_days, expected_gap_days * 2)

    if not in_window or age_days > effective_stale:
        # A stale schedule reads very differently depending on how it was doing
        # when it stopped. cu2-platform's soc2-evidence-collector ran on schedule
        # exactly 10 times, failed all 10, and then stopped — reporting only
        # "stopped 53 days ago" would bury the fact that it never once worked.
        history = _leading_failures(scheduled)
        ever_passed = _days_since_success(scheduled, as_of) is not None
        if not ever_passed and history:
            tail = (f", and it failed all {history} of its scheduled runs — it has "
                    f"never once succeeded")
        elif history:
            tail = f", after {history} consecutive failures"
        else:
            tail = ", and it was passing when it stopped"
        cadence = (f" Its cron fires at most {expected_gap_days} days apart."
                   if expected_gap_days else
                   " Its cadence could not be parsed from the cron expression.")
        return mk("stale",
                  f"Last ran on schedule {age_days} days ago — the cron has "
                  f"stopped firing while the file still declares it{tail}."
                  f"{cadence}",
                  consecutive_scheduled_failures=history,
                  most_recent_scheduled_conclusion=newest.get("conclusion"),
                  most_recent_scheduled_at=newest.get("created_at"),
                  evidence_url=newest.get("html_url"))

    consecutive = _leading_failures(in_window)
    days_red = _days_since_success(in_window, as_of)

    if consecutive == 0:
        return mk("ok", "Most recent scheduled run passed", severity="info")

    if consecutive < min_consecutive:
        return mk("single_failure",
                  f"Most recent scheduled run failed ({consecutive} consecutive) "
                  f"— below the {min_consecutive}-run threshold, may be in hand",
                  severity="info")

    span = "never succeeded on schedule" if days_red is None else f"red for {days_red} days"
    severity = "high" if (days_red is None or days_red >= ESCALATE_DAYS) else "medium"
    return mk("red",
              f"{consecutive} consecutive scheduled runs failed, {span} — a "
              f"control that reports as present and has not passed since",
              severity=severity)


def _parsed_at(run):
    """Parse `created_at`, or None. An unparseable timestamp is not a zero date."""
    raw = run.get("created_at")
    if not isinstance(raw, str):
        return None
    try:
        return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _leading_failures(scheduled_newest_first):
    """Count failures at the head of the history, stopping at the first pass."""
    count = 0
    for run in scheduled_newest_first:
        conclusion = run.get("conclusion")
        if conclusion in FAILING_CONCLUSIONS:
            count += 1
            continue
        if conclusion in PASSING_CONCLUSIONS:
            break
        # cancelled / skipped / null: not an assertion either way, so skip it
        # without breaking the streak.
    return count


def _days_since_success(scheduled_newest_first, as_of):
    """Days since the last scheduled pass, or None if it has never passed."""
    for run in scheduled_newest_first:
        if run.get("conclusion") in PASSING_CONCLUSIONS:
            at = _parsed_at(run)
            if at is not None:
                return (as_of - at).days
    return None


# ---------------------------------------------------------------------------
# T9 — default-branch CI red and ignored
#
# A DIFFERENT DEFECT FROM EVERYTHING ELSE HERE, and the taxonomy missed it until
# a T4 remediation walked into it.
#
#   T1 / T2 / T8   a gate that CANNOT fail
#   T7             a SCHEDULED job that is red or absent
#   T9             a PUSH-triggered CI that is red, correct, and ignored
#
# BusinessLoanReview: 20 of its last 20 runs on main failed, every one since
# 2026-05-19. Seventy days. Its `pnpm typecheck` step is not suppressed — it runs
# unguarded and correctly reports 150 real type errors. The control is working
# perfectly. Nobody is acting on it, and every merge in that window went in on a
# red build.
#
# That is worth naming separately, because every other detector here assumes the
# problem is a signal that lies. This one is a signal that tells the truth into
# an empty room. No amount of making gates honest fixes it.
#
# NAMING, AGAIN. The fields are consecutive_push_failures and
# days_since_last_push_success. Not `ignored`, not `unwatched` — the API cannot
# see whether a human looked. "Ignored" is the inference a reader draws from 70
# days; it is not the measurement.
# ---------------------------------------------------------------------------

DEFAULT_MIN_CI_FAILURES = 3

CIHealth = namedtuple("CIHealth", [
    "repo", "workflow", "path", "kind", "severity", "message",
    "consecutive_push_failures", "days_since_last_push_success",
    "runs_examined", "evidence_url",
])


def classify_ci(repo, workflow_name, path, runs, as_of,
                min_failures=DEFAULT_MIN_CI_FAILURES):
    """
    Health of one workflow's default-branch push history. Pure; no network.

    `runs` must already be filtered to push events on the default branch — the
    same lesson as T7, where inferring the event from an unfiltered page called a
    live nightly cron `never_ran`.
    """
    dated = [r for r in runs if _parsed_at(r) is not None and _parsed_at(r) <= as_of]

    def mk(kind, message, severity):
        newest = dated[0] if dated else None
        return CIHealth(
            repo=repo, workflow=workflow_name, path=path, kind=kind,
            severity=severity, message=message,
            consecutive_push_failures=_leading_failures(dated),
            days_since_last_push_success=_days_since_success(dated, as_of),
            runs_examined=len(dated),
            evidence_url=(newest or {}).get("html_url"),
        )

    if not dated:
        return mk("no_runs", "No push runs on the default branch", "info")

    consecutive = _leading_failures(dated)
    if consecutive == 0:
        return mk("ok", "Most recent default-branch run passed", "info")
    if consecutive < min_failures:
        return mk("recent_failure",
                  f"{consecutive} recent failure(s) — below the {min_failures}-run "
                  f"threshold, plausibly still being fixed", "info")

    days = _days_since_success(dated, as_of)
    span = "has never passed" if days is None else f"last passed {days} days ago"
    # A repo can only be this red for this long if nobody is reading it.
    severity = "high" if (days is None or days >= 14 or consecutive >= 10) else "medium"
    return mk("red",
              f"Default-branch CI has failed {consecutive} consecutive runs and "
              f"{span} — the check is honest and is being merged past",
              severity)


CI_FINDING_KINDS = {"red"}


def check_repo_ci(gh, repo, as_of, default_branch=None, runs_per_workflow=30,
                  clone_root=None, **kw):
    """Classify default-branch push CI for every real workflow in one repo."""
    try:
        if default_branch is None:
            default_branch = gh.get(f"repos/{repo}", ).get("default_branch") or "main"
        workflows = gh.get_all(f"repos/{repo}/actions/workflows?per_page=100", "workflows")
    except GhError as exc:
        return [CIHealth(repo, "(repo)", "", "error", "medium",
                         f"could not read workflows: {exc}", 0, None, 0, "")]

    out = []
    for wf in workflows:
        path = wf.get("path") or ""
        if DYNAMIC_PATH_RE.match(path):
            continue
        # ONLY WORKFLOWS THAT DECLARE A PUSH TRIGGER. Anything else is not a
        # default-branch CI, whatever the run history says.
        declared, _ = _resolve_schedule(gh, repo, path, clone_root)
        if declared is ORPHANED:
            continue          # file deleted; T7 reports it as orphaned
        text = _workflow_text(gh, repo, path, clone_root)
        if text is not None and declares_push(text) is False:
            out.append(CIHealth(repo, wf.get("name") or "", path, "not_push_triggered",
                                "info", "Not a push-triggered workflow — T9 does not apply",
                                0, None, 0, ""))
            continue

        try:
            payload = gh.get(f"repos/{repo}/actions/workflows/{wf.get('id')}/runs"
                             f"?event=push&branch={default_branch}"
                             f"&per_page={runs_per_workflow}")
            runs = payload.get("workflow_runs") or []
        except GhNotFound:
            continue          # workflow file deleted; T7 reports it as orphaned
        except GhError as exc:
            out.append(CIHealth(repo, wf.get("name") or "", path, "error", "medium",
                                f"run history failed: {exc}", 0, None, 0, ""))
            continue
        out.append(classify_ci(repo, wf.get("name") or "", path, runs, as_of, **kw))
    return out


# ---------------------------------------------------------------------------
# GitHub API access
# ---------------------------------------------------------------------------

class GhError(RuntimeError):
    """A `gh api` call failed. Raised, never swallowed into an empty list."""


class GhNotFound(GhError):
    """
    A 404. Distinguished from every other failure on purpose: for a workflow
    file, "the file is gone" is a fact about the repo, while "the call broke" is
    an absence of information. Collapsing the two makes 103 orphaned workflow
    records look like 103 unverifiable ones.
    """


class Gh:
    """
    Thin `gh api` wrapper.

    GH_TOKEN SHADOWING, HANDLED RATHER THAN DOCUMENTED: `~/.zshrc` exports
    GH_TOKEN from a GitHub App installation token that expires hourly, and a dead
    GH_TOKEN silently shadows the working keyring credential. Every scripted run
    in this estate has to be prefixed `env -u GH_TOKEN`. Rather than make that
    the caller's problem, this class probes the credential once and drops a dead
    GH_TOKEN itself — but only if dropping it actually helps, so a CI runner
    where GH_TOKEN is the *only* credential keeps working.
    """

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.env = os.environ.copy()
        self.mode = self._probe()

    def _probe(self):
        if self._works(self.env):
            return "env"
        if "GH_TOKEN" in self.env:
            stripped = {k: v for k, v in self.env.items() if k != "GH_TOKEN"}
            if self._works(stripped):
                self.env = stripped
                sys.stderr.write(
                    "note: GH_TOKEN was rejected and is shadowing a working "
                    "credential; dropped it for this run\n")
                return "stripped"
        raise GhError("no working GitHub credential — run `gh auth status`")

    @staticmethod
    def _works(env):
        proc = subprocess.run(["gh", "api", "user", "--jq", ".login"],
                              capture_output=True, text=True, env=env, timeout=30)
        return proc.returncode == 0

    def get(self, path, paginate=False):
        cmd = ["gh", "api", path]
        if paginate:
            cmd += ["--paginate", "--slurp"]
        if self.verbose:
            sys.stderr.write(f"  GET {path}\n")
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              env=self.env, timeout=300)
        if proc.returncode != 0:
            stderr = proc.stderr.strip()
            if "HTTP 404" in stderr or "Not Found" in stderr:
                raise GhNotFound(f"{path}: 404")
            raise GhError(f"{path}: {stderr[:200]}")
        try:
            return json.loads(proc.stdout)
        except ValueError as exc:
            raise GhError(f"{path}: unparseable response ({exc})") from exc

    def get_all(self, path, key):
        """
        Every item under `key` across every page.

        PAGINATION IS NOT AN OPTIMISATION HERE EITHER. `bond` has 301 workflow
        records. A single `?per_page=100` request returns the first 100 and says
        nothing about the other 201, so the first estate run silently audited a
        third of that repo and reported a total as though it were complete —
        a truncation that reads as coverage. test_listing_is_paginated pins it.
        """
        pages = self.get(path, paginate=True)
        if isinstance(pages, dict):
            pages = [pages]
        if not isinstance(pages, list):
            raise GhError(f"{path}: expected pages, got {type(pages).__name__}")
        items = []
        for page in pages:
            if not isinstance(page, dict):
                raise GhError(f"{path}: page was {type(page).__name__}, not an object")
            chunk = page.get(key)
            if chunk is None:
                raise GhError(f"{path}: page had no '{key}' array")
            items.extend(chunk)
        return items


def check_repo(gh, repo, as_of, runs_per_workflow=60, clone_root=None, **kw):
    """
    Classify every workflow in one repo. Returns a list of Health rows.

    An API failure yields an `error` row for the repo. It does not yield [].
    """
    try:
        workflows = gh.get_all(f"repos/{repo}/actions/workflows?per_page=100",
                               "workflows")
    except GhError as exc:
        return [_repo_error(repo, f"workflow listing failed: {exc}")]

    if not workflows:
        return [Health(repo=repo, workflow="(none)", path="", kind="not_scheduled",
                       severity="info", message="Repo defines no Actions workflows",
                       consecutive_scheduled_failures=0,
                       days_since_last_scheduled_success=None,
                       most_recent_scheduled_conclusion=None,
                       most_recent_scheduled_at=None, scheduled_run_count=0,
                       declares_schedule=False, state="", evidence_url="")]

    out = []
    for wf in workflows:
        path = wf.get("path") or ""
        if DYNAMIC_PATH_RE.match(path):
            continue  # GitHub-synthesised (Dependabot); no file, no cron
        out.append(_check_workflow(gh, repo, wf, as_of, runs_per_workflow,
                                   clone_root=clone_root, **kw))
    return out


def _check_workflow(gh, repo, wf, as_of, runs_per_workflow, clone_root=None, **kw):
    wf_id = wf.get("id")
    name = wf.get("name") or ""
    path = wf.get("path") or ""
    state = wf.get("state") or ""

    # ORPHAN CHECK FIRST, WHEN A CLONE CAN ANSWER IT. A deleted workflow file is
    # not a finding whatever its run history says, so fetching that history is a
    # wasted call. `bond` alone has 301 workflow records for 8 live files, and
    # checking the clone up front takes it from 301 API calls to 8 -- the
    # difference between a sweep that can run in CI and one that cannot.
    if clone_root and _file_is_gone(clone_root, path):
        return _mk_info(repo, name, path, state, "orphaned",
                        "Workflow record exists but the file is gone from the "
                        "default branch — GitHub still lists it as 'active'; "
                        "it cannot run and is not a live control")

    # THE EVENT FILTER IS LOAD-BEARING, NOT AN OPTIMISATION.
    #
    # dev-studio's `SAST (semgrep)` has 1070 runs, of which all but a handful are
    # push and pull_request. Fetching the newest 60 runs unfiltered and looking
    # for scheduled ones among them returns nothing — so the tool would have
    # reported `never_ran` for a workflow whose cron fires nightly, and reported
    # it with total confidence. Asking the API for `event=schedule` makes the
    # page a page of scheduled runs, so pagination depth can no longer change the
    # verdict. test_busy_workflow_is_not_misread_as_never_ran pins it.
    #
    # `total_count` on the filtered query is then an authoritative answer to "has
    # this ever run on schedule", independent of page size.
    try:
        payload = gh.get(f"repos/{repo}/actions/workflows/{wf_id}/runs"
                         f"?event={SCHEDULE_EVENT}&per_page={runs_per_workflow}")
        runs = payload.get("workflow_runs") or []
        total_scheduled = payload.get("total_count")
    except GhError as exc:
        return _repo_error(repo, f"run history failed for {path}: {exc}",
                           workflow=name, path=path, state=state)

    # THE FILE IS ALWAYS CONSULTED. An earlier version short-circuited to
    # schedule_declared=True whenever any scheduled run existed, which conflates
    # "fired historically" with "declares a cron now" and reported a deliberate
    # de-scheduling as a dead control. With --clones-dir the read is free.
    resolved, crons = _resolve_schedule(gh, repo, path, clone_root)
    if resolved is ORPHANED:
        return _mk_info(repo, name, path, state, "orphaned",
                        "Workflow record exists but the file is gone from the "
                        "default branch — GitHub still lists it as 'active'; "
                        "it cannot run and is not a live control")
    schedule_declared = resolved
    if schedule_declared is None and (runs or total_scheduled):
        # Could not read the file, but the cron demonstrably fires. Fail closed
        # towards "this is a live schedule" rather than silently de-scoping it.
        schedule_declared = True

    gap = max_expected_gap_days(crons) if crons else None
    return classify(repo, name, path, state, runs, schedule_declared, as_of,
                    expected_gap_days=gap, **kw)


class _Orphaned:
    """Sentinel: the workflow file no longer exists. Not True, False, or unknown."""
    def __repr__(self):
        return "ORPHANED"


ORPHANED = _Orphaned()


def _file_is_gone(clone_root, path):
    """True only when the clone is real and definitely lacks the file."""
    if not path or not os.path.isdir(os.path.join(clone_root, ".git")):
        return False
    return not os.path.isfile(os.path.join(clone_root, path))


def _workflow_text(gh, repo, path, clone_root=None):
    """The workflow file's text, from a clone if given, else the API. None if unreadable."""
    if not path:
        return None
    if clone_root:
        local = os.path.join(clone_root, path)
        if os.path.isfile(local):
            with open(local, encoding="utf-8", errors="replace") as fh:
                return fh.read()
    try:
        blob = gh.get(f"repos/{repo}/contents/{path}")
    except GhError:
        return None
    import base64
    content = blob.get("content")
    if not isinstance(content, str):
        return None
    try:
        return base64.b64decode(content).decode("utf-8", errors="replace")
    except ValueError:
        return None


def _resolve_schedule(gh, repo, path, clone_root=None):
    """
    Returns (declared, crons). `declared` is True / False / None / ORPHANED;
    `crons` is the list of cron expressions found, possibly empty.

    A local clone is consulted first when one is given: it is free, offline, and
    it answers "does this file exist on the default branch" definitively, which
    the API only answers as a 404 that could equally mean a permissions problem.
    """
    if not path:
        return None, []

    if clone_root:
        local = os.path.join(clone_root, path)
        if os.path.isfile(local):
            with open(local, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            return declares_schedule(text), extract_crons(text)
        if os.path.isdir(os.path.join(clone_root, ".git")):
            # The clone is real and the file is not in it.
            return ORPHANED, []

    try:
        blob = gh.get(f"repos/{repo}/contents/{path}")
    except GhNotFound:
        return ORPHANED, []
    except GhError:
        return None, []

    import base64
    content = blob.get("content")
    if not isinstance(content, str):
        return None, []
    try:
        text = base64.b64decode(content).decode("utf-8", errors="replace")
    except ValueError:
        return None, []
    return declares_schedule(text), extract_crons(text)


def _mk_info(repo, workflow, path, state, kind, message):
    return Health(repo=repo, workflow=workflow, path=path, kind=kind,
                  severity="info", message=message,
                  consecutive_scheduled_failures=0,
                  days_since_last_scheduled_success=None,
                  most_recent_scheduled_conclusion=None,
                  most_recent_scheduled_at=None, scheduled_run_count=0,
                  declares_schedule=False, state=state, evidence_url="")


def _repo_error(repo, message, workflow="(repo)", path="", state=""):
    return Health(repo=repo, workflow=workflow, path=path, kind="error",
                  severity=FINDING_KINDS["error"], message=message,
                  consecutive_scheduled_failures=0,
                  days_since_last_scheduled_success=None,
                  most_recent_scheduled_conclusion=None,
                  most_recent_scheduled_at=None, scheduled_run_count=0,
                  declares_schedule=None, state=state, evidence_url="")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="workflow_health",
        description="T7 — find scheduled workflows that everyone believes are "
                    "running and are not.")
    p.add_argument("repos", nargs="*", metavar="OWNER/NAME")
    p.add_argument("--repos-file", help="file of OWNER/NAME, one per line")
    p.add_argument("--as-of", metavar="YYYY-MM-DD",
                   help="classify as of this date instead of now (reproducibility)")
    p.add_argument("--min-consecutive", type=int, default=DEFAULT_MIN_CONSECUTIVE,
                   help=f"consecutive scheduled failures before 'red' "
                        f"(default {DEFAULT_MIN_CONSECUTIVE})")
    p.add_argument("--lookback-days", type=int, default=DEFAULT_LOOKBACK_DAYS)
    p.add_argument("--stale-days", type=int, default=DEFAULT_STALE_DAYS)
    p.add_argument("--runs", type=int, default=60, help="run history depth per workflow")
    p.add_argument("--clones-dir", metavar="DIR",
                   help="directory of shallow clones laid out as DIR/{owner}__{name}; "
                        "used to answer 'does this workflow file still exist' offline")
    p.add_argument("--report", action="store_true",
                   help="print every workflow row and always exit 0")
    p.add_argument("--json", metavar="PATH", help="write full results as JSON")
    p.add_argument("--ci", action="store_true",
                   help="T9 instead of T7: default-branch CI red for N consecutive "
                        "push runs")
    p.add_argument("--min-ci-failures", type=int, default=DEFAULT_MIN_CI_FAILURES)
    p.add_argument("--verbose", action="store_true")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    repos = list(args.repos)
    if args.repos_file:
        if not os.path.isfile(args.repos_file):
            sys.stderr.write(f"error: no such file: {args.repos_file}\n")
            return 2
        with open(args.repos_file, encoding="utf-8") as fh:
            repos += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    if not repos:
        sys.stderr.write("error: no repos given\n")
        return 2
    bad = [r for r in repos if r.count("/") != 1]
    if bad:
        sys.stderr.write(f"error: not OWNER/NAME: {bad[:3]}\n")
        return 2

    if args.as_of:
        try:
            as_of = datetime.strptime(args.as_of, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            sys.stderr.write("error: --as-of must be YYYY-MM-DD\n")
            return 2
    else:
        as_of = datetime.now(timezone.utc)

    try:
        gh = Gh(verbose=args.verbose)
    except GhError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2

    if args.clones_dir and not os.path.isdir(args.clones_dir):
        sys.stderr.write(f"error: --clones-dir not a directory: {args.clones_dir}\n")
        return 2

    if args.ci:
        rows = []
        for i, repo in enumerate(repos, start=1):
            sys.stderr.write(f"[{i}/{len(repos)}] {repo}\n")
            croot = None
            if args.clones_dir:
                cand = os.path.join(args.clones_dir, repo.replace("/", "__"))
                if os.path.isdir(os.path.join(cand, ".git")):
                    croot = cand
            rows += check_repo_ci(gh, repo, as_of, clone_root=croot,
                                  min_failures=args.min_ci_failures)
        findings = [r for r in rows if r.kind in CI_FINDING_KINDS]
        for r in sorted(findings, key=lambda x: -x.consecutive_push_failures):
            print(f"{r.repo}  {r.path or r.workflow}")
            print(f"    [T9/{r.severity}] {r.message}")
            print(f"    consecutive_push_failures={r.consecutive_push_failures}  "
                  f"days_since_last_push_success={r.days_since_last_push_success}")
            if r.evidence_url:
                print(f"    {r.evidence_url}")
        by = Counter(r.kind for r in rows)
        print(f"\nworkflow_health T9: {len(findings)} finding(s) across {len(repos)} "
              f"repo(s), {len(rows)} workflow row(s) as of {as_of.date()}")
        print("  by kind: " + "  ".join(f"{k}={v}" for k, v in sorted(by.items())))
        if args.json:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump([r._asdict() for r in rows], fh, indent=1)
            print(f"  json: {args.json}")
        if not findings:
            print("workflow_health: CLEAN")
            return 0
        return 0 if args.report else 1

    rows = []
    for i, repo in enumerate(repos, start=1):
        sys.stderr.write(f"[{i}/{len(repos)}] {repo}\n")
        clone_root = None
        if args.clones_dir:
            candidate = os.path.join(args.clones_dir, repo.replace("/", "__"))
            if os.path.isdir(os.path.join(candidate, ".git")):
                clone_root = candidate
            else:
                sys.stderr.write(f"    note: no clone at {candidate}; using the API\n")
        rows += check_repo(gh, repo, as_of,
                           runs_per_workflow=args.runs,
                           clone_root=clone_root,
                           min_consecutive=args.min_consecutive,
                           lookback_days=args.lookback_days,
                           stale_days=args.stale_days)

    findings = [r for r in rows if r.kind in FINDING_KINDS]
    info = [r for r in rows if r.kind not in FINDING_KINDS]

    for r in sorted(findings, key=lambda x: (x.severity != "high", x.repo, x.path)):
        print(f"{r.repo}  {r.path or r.workflow}")
        print(f"    [T7/{r.kind}/{r.severity}] {r.message}")
        if r.kind == "red":
            print(f"    consecutive_scheduled_failures="
                  f"{r.consecutive_scheduled_failures}  "
                  f"days_since_last_scheduled_success="
                  f"{r.days_since_last_scheduled_success}")
        if r.evidence_url:
            print(f"    {r.evidence_url}")

    if args.report:
        print("\n--- scheduled workflows judged healthy (nothing dropped) ---")
        for r in sorted(info, key=lambda x: (x.repo, x.path)):
            if r.kind == "not_scheduled":
                continue
            print(f"{r.repo}  {r.path}  [{r.kind}] {r.message}")

    by_kind = Counter(r.kind for r in rows)
    print(f"\nworkflow_health: {len(findings)} T7 finding(s) across "
          f"{len(repos)} repo(s), {len(rows)} workflow row(s) as of "
          f"{as_of.date()}")
    print("  by kind: " + "  ".join(
        f"{k}={by_kind[k]}" for k in list(FINDING_KINDS) + list(INFO_KINDS)
        if by_kind[k]))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump([r._asdict() for r in rows], fh, indent=1)
        print(f"  json: {args.json}")

    if not findings:
        print("workflow_health: CLEAN")
        return 0
    if args.report:
        print("  report mode: exiting 0 without failing.")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
