"""A minimal semver range evaluator — enough for advisory ranges and pin values.

Deliberately dependency-free. This runs in a reusable workflow that must work in
any calling repository without an install step, so `pip install semver` is not
available and vendoring a library into a public standards repo is worse than
forty lines that are fully tested.

Handles exactly what is needed and nothing else:

  * comparators      <  <=  >  >=  =  ==  (and a bare version, meaning =)
  * caret and tilde  ^1.2.3   ~1.2.3
  * wildcard         *  x  (any version)
  * AND by space or comma   ">=3.0.0 <3.1.6"   ">= 3.0.0, < 3.1.6"
  * OR by ||                "^1.0.0 || ^2.0.0"

Prerelease versions are compared by ignoring the prerelease tag, which is
correct for the advisory ranges we see and wrong in general. That trade is
recorded here rather than hidden: an advisory expressed against a prerelease
would be evaluated against its release version. None of the CU2 estate's
advisories have been of that shape.
"""

import re

_NUM = re.compile(r"^\d+$")


def parse_version(text):
    """'3.1.6' -> (3, 1, 6). Tolerates 'v' prefixes, build/prerelease suffixes.

    Returns None when the input is not a concrete version — which is how the
    caller distinguishes an EXACT pin from a RANGE pin.
    """
    if text is None:
        return None
    s = str(text).strip().lstrip("v=")
    # Drop build metadata then any prerelease tag.
    s = s.split("+", 1)[0].split("-", 1)[0]
    parts = s.split(".")
    if not 1 <= len(parts) <= 3:
        return None
    out = []
    for p in parts:
        if not _NUM.match(p):
            return None
        out.append(int(p))
    while len(out) < 3:
        out.append(0)
    return tuple(out)


def _cmp(a, b):
    return (a > b) - (a < b)


def _satisfies_comparator(version, comp):
    """version is a parsed tuple; comp is one clause such as '>=3.1.6'."""
    comp = comp.strip()
    if not comp or comp in ("*", "x", "X"):
        return True

    m = re.match(r"^(>=|<=|==|=|>|<|\^|~)?\s*(.+)$", comp)
    if not m:
        return False
    op, rest = m.group(1) or "=", m.group(2)
    target = parse_version(rest)
    if target is None:
        return False

    if op in ("=", "=="):
        return version == target
    if op == ">":
        return _cmp(version, target) > 0
    if op == ">=":
        return _cmp(version, target) >= 0
    if op == "<":
        return _cmp(version, target) < 0
    if op == "<=":
        return _cmp(version, target) <= 0
    if op == "^":
        # ^1.2.3 -> >=1.2.3 <2.0.0 ; ^0.2.3 -> >=0.2.3 <0.3.0 ; ^0.0.3 -> =0.0.3
        if _cmp(version, target) < 0:
            return False
        if target[0] > 0:
            return version[0] == target[0]
        if target[1] > 0:
            return version[0] == 0 and version[1] == target[1]
        return version[:3] == target[:3]
    if op == "~":
        # ~1.2.3 -> >=1.2.3 <1.3.0
        if _cmp(version, target) < 0:
            return False
        return version[0] == target[0] and version[1] == target[1]
    return False


def _split_and(clause):
    """Split an AND clause on commas and on spaces that separate comparators.

    ">= 3.0.0, < 3.1.6" and ">=3.0.0 <3.1.6" must both yield two comparators,
    so a space after an operator must NOT split.
    """
    normalised = re.sub(r"(>=|<=|==|>|<|=|\^|~)\s+", r"\1", clause.replace(",", " "))
    return [p for p in normalised.split() if p]


def satisfies(version_text, range_text):
    """Does a concrete version satisfy a range? Unparseable input -> False."""
    version = parse_version(version_text)
    if version is None:
        return False
    if range_text is None:
        return False
    text = str(range_text).strip()
    if not text or text in ("*", "x", "X"):
        return True
    for or_branch in text.split("||"):
        clauses = _split_and(or_branch)
        if clauses and all(_satisfies_comparator(version, c) for c in clauses):
            return True
    return False


def min_patched(patched_range):
    """Lowest concrete version implied by a patched range like '>=3.1.6'.

    Used to ask whether a RANGE pin can reach the fix at all. Returns None when
    no lower bound is expressed, in which case the caller must not guess.
    """
    if not patched_range:
        return None
    for or_branch in str(patched_range).split("||"):
        for clause in _split_and(or_branch):
            m = re.match(r"^(>=|=|==|\^|~)?\s*(\d[\w.\-+]*)$", clause.strip())
            if m and parse_version(m.group(2)) is not None:
                return m.group(2).split("+", 1)[0].split("-", 1)[0]
    return None
