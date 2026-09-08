#!/usr/bin/env python3
"""Fail when a dependency override pins a version that is STILL VULNERABLE.

THE DEFECT THIS CATCHES, AND WHY NOTHING ELSE DOES.

An override exists to force a transitive dependency PAST a patched version. It
stops doing that not when someone edits it, but when the advisory WIDENS
underneath it. The pin does not change; the range does. The result installs
cleanly, reads as remediation in review, and leaves the alert open.

Dependabot cannot rescue you: it has no way to raise a pull request against a
version you force. So the repository shows open alerts and zero Dependabot PRs,
every CI gate green, and nothing anywhere says why.

A point-in-time audit was tried first and fixed every dead pin it found. Weeks
later the count had grown back — not through neglect, but because advisories on
two widely-vendored packages widened afterwards. A periodic audit cannot keep up
with a failure mode whose trigger is an advisory published later. That is the
argument for a gate rather than a habit.

SCOPE IS DELIBERATELY NARROW. Only advisories on packages the repository itself
pins will fail the build. Everything else is printed for context and left to
Dependabot, which can actually fix it. A gate that goes red for reasons nobody
in the calling repository can act on is a gate they will switch off, and a
switched-off gate is worth nothing.

Usage:  python3 check_override_staleness.py [repo-root]

Exit 0  no override is holding an advisory open.
Exit 1  one is.
Exit 2  the check could not run. A check that did not run must never read as a
        check that passed, so this is loud rather than skipped.
"""

import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from semver_lite import satisfies, min_patched, is_exact_version  # noqa: E402


def split_override_key(raw_key):
    """Return the package an override key actually TARGETS, plus its selector.

        'fast-uri@>=3.0.0 <3.1.5'  -> ('fast-uri', '>=3.0.0 <3.1.5')
        '@xmldom/xmldom@<0.8.13'   -> ('@xmldom/xmldom', '<0.8.13')
        'minimatch@3>brace-expansion' -> ('brace-expansion', None)

    Two ways to get this wrong, both of which make the gate silently stop
    covering real pins — the exact defect class it exists to catch:

    1. pnpm's PARENT SELECTOR. 'qar@1>zoo' overrides `zoo`, but only where it
       is a dependency of qar@1. The overridden package is everything after the
       last '>', NOT the parent. Reading the parent instead means an advisory
       for `zoo` never matches, is filed as upstream, and the gate returns 0
       while the caller still forces a vulnerable `zoo`.
    2. SCOPED PACKAGES legitimately begin with '@', so the version separator is
       a LATER '@' — never the first one.
    """
    # Parent selector first: everything before it scopes the override and says
    # nothing about which package is pinned.
    #
    # Not every '>' is that separator — 'fast-uri@>=3.0.0 <3.1.5' contains two
    # that are comparison operators. The separator is a '>' NOT part of '>=' and
    # followed by something a package name can start with (letter, '@', '_'); a
    # comparison '>' is followed by a digit or a space. Take the LAST such
    # match, so 'foo@>1.0.0>bar' still resolves to 'bar'.
    matches = list(re.finditer(r">(?!=)(?=[A-Za-z@_])", raw_key))
    target = raw_key[matches[-1].end():] if matches else raw_key
    at = target.rfind("@")
    if at > 0:
        return target[:at], target[at + 1:]
    return target, None


def parse_yaml_overrides(text):
    """Read the `overrides:` block of a pnpm-workspace.yaml.

    A line parser rather than a YAML dependency: this runs before any install in
    the calling repository, and the block is a flat map of scalars by
    construction.
    """
    pins = {}
    in_block = False
    for line in text.splitlines():
        if re.match(r"^overrides:\s*$", line):
            in_block = True
            continue
        if not in_block:
            continue
        if re.match(r"^\S", line):  # next top-level key ends the block
            break
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = re.match(r"""^(?:'([^']+)'|"([^"]+)"|([^:]+)):\s*(.+?)\s*$""", stripped)
        if not m:
            continue
        raw_key = m.group(1) or m.group(2) or m.group(3)
        value = m.group(4).strip().strip("'\"")
        pins.setdefault(raw_key, []).append(value)
    return pins


def collect_overrides(root):
    """All three homes an override can live in, keyed by raw (selector) key.

    package.json's `pnpm.overrides` is included even though pnpm >= 10.16
    IGNORES it, because a repository on pnpm 9 depends on it entirely and a
    repository that has upgraded needs to be told its pins went dead.
    """
    homes = {}
    pkg_path = os.path.join(root, "package.json")
    if os.path.isfile(pkg_path):
        try:
            with open(pkg_path, encoding="utf-8") as fh:
                pkg = json.load(fh)
        except (ValueError, OSError):
            pkg = {}
        for label, obj in (
            ("package.json overrides", pkg.get("overrides")),
            ("package.json pnpm.overrides", (pkg.get("pnpm") or {}).get("overrides")),
            ("package.json resolutions", pkg.get("resolutions")),
        ):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, str):
                        homes.setdefault(k, []).append((v, label))

    ws_path = os.path.join(root, "pnpm-workspace.yaml")
    if os.path.isfile(ws_path):
        with open(ws_path, encoding="utf-8") as fh:
            for k, values in parse_yaml_overrides(fh.read()).items():
                for v in values:
                    homes.setdefault(k, []).append((v, "pnpm-workspace.yaml"))
    return homes


def pin_is_dead(pin_value, vulnerable_range, patched_range):
    """Is this pin holding the advisory open?

    An EXACT pin ('3.1.5') is dead when that exact version is still vulnerable.

    A RANGE pin ('^6.15.2', '>=3.1.5 <4.0.0', and partial X-ranges like '3.1')
    is dead only when it CANNOT REACH the patched version — '~3.1.5' cannot reach 3.2.0, but '^3.1.5' reaches
    3.1.6 and is therefore fine. Treating a range pin like an exact one by
    coercing it to its floor produces false positives, which is the fastest way
    to get a security gate disabled.
    """
    if is_exact_version(pin_value):
        return bool(satisfies(pin_value, vulnerable_range))
    floor = min_patched(patched_range)
    if floor is None:
        return False
    return not satisfies(floor, pin_value)


def evaluate(advisories, overrides):
    """Split advisories into ones our pins hold open and ones upstream owns."""
    held, upstream = [], []
    for adv in advisories:
        name = adv.get("module_name")
        vulnerable = adv.get("vulnerable_versions")
        patched = adv.get("patched_versions")
        matches = []
        for raw_key, entries in overrides.items():
            pkg, _selector = split_override_key(raw_key)
            if pkg != name:
                continue
            for value, home in entries:
                if pin_is_dead(value, vulnerable, patched):
                    matches.append({"key": raw_key, "pinned": value, "home": home})
        if matches:
            held.append({**adv, "pins": matches})
        else:
            upstream.append(adv)
    return held, upstream


def run_audit(root):
    """`pnpm audit --json` reads the LOCKFILE — no node_modules, no install.

    It exits non-zero when it FINDS vulnerabilities, which is a successful run
    for our purposes. Only output that will not parse is a real failure.
    """
    try:
        proc = subprocess.run(
            ["pnpm", "audit", "--json"],
            cwd=root, capture_output=True, text=True,
            env={**os.environ, "CI": "true"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("could not execute `pnpm audit`: %s" % exc)
    if not (proc.stdout or "").strip():
        raise RuntimeError(
            "`pnpm audit` produced no output. stderr: %s"
            % (proc.stderr or "").strip()[:400]
        )
    try:
        return json.loads(proc.stdout)
    except ValueError:
        raise RuntimeError("`pnpm audit` output was not valid JSON")


def main(argv):
    root = argv[1] if len(argv) > 1 else "."

    if not os.path.isfile(os.path.join(root, "pnpm-lock.yaml")):
        print("::notice::no pnpm-lock.yaml in %s — nothing for this gate to "
              "check, exiting clean." % os.path.abspath(root))
        return 0

    try:
        audit = run_audit(root)
    except RuntimeError as exc:
        print("::error::COULD NOT VERIFY overrides — %s" % exc)
        print("Failing rather than skipping: a check that did not run must not "
              "read as a check that passed.")
        return 2

    overrides = collect_overrides(root)
    advisories = list((audit.get("advisories") or {}).values())
    held, upstream = evaluate(advisories, overrides)

    print("Checked %d declared override key(s) against %d advisory/advisories."
          % (len(overrides), len(advisories)))

    if upstream:
        print("\n%d advisory/advisories on packages this repo does not pin — "
              "Dependabot's lane, listed for context:" % len(upstream))
        for adv in sorted(upstream, key=lambda a: a.get("module_name") or ""):
            print("   %-9s %s (vulnerable %s, patched %s)" % (
                adv.get("severity", "?"), adv.get("module_name"),
                adv.get("vulnerable_versions"), adv.get("patched_versions")))

    if not held:
        print("\nOK — no override is holding an advisory open.")
        return 0

    print("\n::error::%d advisory/advisories are held open by this repo's own "
          "override pins. Dependabot cannot fix these — it has no way to raise "
          "a PR against a version you force.\n" % len(held))
    for adv in held:
        print("   %s (%s)" % (adv.get("module_name"), adv.get("severity", "?")))
        for pin in adv["pins"]:
            print("     pinned to  : %s   (key '%s' in %s)"
                  % (pin["pinned"], pin["key"], pin["home"]))
        print("     vulnerable : %s" % adv.get("vulnerable_versions"))
        print("     patched    : %s" % adv.get("patched_versions"))
        if adv.get("url"):
            print("     advisory   : %s" % adv["url"])
        print("")

    print("   Fix: raise the pin, AND widen its selector key if it has one.\n"
          "   A key like 'fast-uri@<3.1.5' that stops below the current\n"
          "   vulnerable range leaves the tail unmatched — the same silent\n"
          "   failure one layer up. Then regenerate the lockfile.\n"
          "\n"
          "   Choose the OLDEST version that clears the advisory, not the\n"
          "   newest: with pnpm's minimumReleaseAge set, a version published\n"
          "   inside the cooldown is one pnpm will refuse, and the PR becomes\n"
          "   unmergeable.\n"
          "\n"
          "   If this repo runs pnpm >= 10.16, check WHERE the pins live —\n"
          "   package.json's `pnpm.overrides` is silently ignored from that\n"
          "   version on, and must move to pnpm-workspace.yaml.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
