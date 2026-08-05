#!/usr/bin/env python3
"""
cu2_sanitize_scan.py — CU 2.0 fail-closed publication gate.

Scans a directory or file for content that must not leave a CU2 repo, or must
not leave the org at all. Pure Python 3 standard library: no dependencies, no
network, no secrets.

This is NOT a replacement for gitleaks. gitleaks already runs on cu2-agent-studio
and catches credentials across full git history. This gate covers what gitleaks
does not: internal operating context (Azure estate names, tenant credit union
identities, internal hostnames, real filesystem paths, org repo slugs) plus a
credential backstop and member-data PII.

    gitleaks       -> credentials, full history
    this gate      -> internal context, member PII, credential backstop

Three tiers, two profiles:

    secret    credentials, keys, connection strings, CU2 API keys
    pii       member/account IDs, SSN, emails, phones, CU tenant names
    internal  Azure resources, cu-2.com hosts, CGNAT IPs, home paths, repo slugs

    --profile internal  (default)  fails on secret + pii
    --profile public               fails on all three

The internal profile is safe to run on every private CU2 repo today. The public
profile gates anything headed for a public repository.

Posture: fail closed. Exit 0 clean, 1 findings, 2 bad input. Matched values are
redacted in output so CI logs never echo the sensitive value.

----------------------------------------------------------------------
Portions of this file (the allowlist loader, placeholder recognizer, redaction
helpers, and fail-closed exit contract) are adapted from sanitize_scan.py in
The Agent Foundry (https://github.com/the-agent-foundry/foundry), MIT licensed:

  MIT License. Copyright (c) 2026 Darryl Hicks.

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
----------------------------------------------------------------------
"""

import argparse
import os
import re
import sys
from collections import Counter, namedtuple

# ---------------------------------------------------------------------------
# Tunables. These are the two lists a maintainer actually edits.
# ---------------------------------------------------------------------------

# Live tenant / partner credit unions. Naming one of these publicly discloses a
# client relationship. Add every new tenant here on the day it signs.
CU2_TENANT_NAMES = [
    "MBFS",
    "Mission Federal",
    "Mission Fed",
    "PHCUSO",
    "Painted Hills",
]

# Email local-parts that are documentation placeholders or service accounts,
# not real people. "git" covers `git@github.com` in SSH clone URLs.
PLACEHOLDER_EMAIL_LOCALS = {
    "user", "you", "test", "inner", "outer", "u", "someone", "example",
    "noreply", "no-reply", "admin", "member", "agent", "handle",
    "git", "bot", "svc", "service", "ci", "build", "aider",
}

# RFC 2606 / RFC 6761 reserved TLDs. A real person's address cannot live here,
# so anything using them is a fixture by definition.
RESERVED_EMAIL_TLDS = {"local", "test", "invalid", "example", "localhost"}

ALLOWLIST_FILENAME = ".cu2-sanitize-allow"

# Identifiers that structurally look like a CU2 API key (`cu2_...`) but are
# ordinary names. Without this the gate flags its own module name everywhere it
# is referenced — in this README, in CI workflows, in import statements.
KNOWN_SAFE_CU2_IDENTIFIERS = {
    "cu2_sanitize_scan",
    "cu2_recognizers",
    "cu2_policy_plugin",
}

# ---------------------------------------------------------------------------

TIERS = ("secret", "pii", "internal")

PROFILES = {
    "internal": {"secret", "pii"},
    "public": {"secret", "pii", "internal"},
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".mypy_cache", ".pytest_cache", "dist", "build", ".idea", ".vscode",
    ".next", "coverage", ".turbo",
}

RISKY_BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip",
    ".gz", ".tar", ".tgz", ".7z", ".rar", ".woff", ".woff2", ".ttf",
    ".otf", ".eot", ".mp3", ".mp4", ".mov", ".ogg", ".wav", ".bin",
    ".so", ".dylib", ".dll", ".class", ".jar", ".pyc", ".sqlite",
    ".sqlite3", ".db", ".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx",
}

MAX_TEXT_BYTES = 2_000_000
SELF_SKIP_NAMES = {"cu2_sanitize_scan.py", ALLOWLIST_FILENAME, ".git"}

# Transient agent/tooling output that lives in the working tree but is never
# committed. Scanning it inflates counts with content the repo does not own.
# `--tracked-only` is the general answer; these cover the common cases.
SKIP_PATH_PREFIXES = (
    ".claude/worktrees/",
    ".playwright-mcp/",
    ".planning-temp/",
)

# Dependency lockfiles legitimately contain thousands of base64 integrity
# hashes and long numeric fields. Those rules are muted here — the credential
# rules (registry auth tokens, embedded URLs) still apply, which is the thing
# that actually leaks from a lockfile.
LOCKFILE_NAMES = {
    "pnpm-lock.yaml", "package-lock.json", "yarn.lock", "npm-shrinkwrap.json",
    "poetry.lock", "Cargo.lock", "uv.lock", "Gemfile.lock", "composer.lock",
}
LOCKFILE_MUTED_RULES = (
    "Long base64-ish secret",
    "Long all-digit ID",
    "Generic API/secret/token assignment",
)

PLACEHOLDER_TOKENS = [
    "example.com", "example.org", "example.net", "example.edu",
    "/path/to/", "/Users/<", "/home/<",
    "your-handle", "your_handle", "YOUR_HANDLE",
    "name@example", "user@example", "you@example",
    # CU2 additions: Presidio token shapes and generic CU stand-ins.
    "<CU2_", "<PERSON>", "contoso", "acme",
    "example credit union", "sample credit union", "anytown",
    # Local-only and self-describing values found in .env.example files and
    # setup docs across CU2 repos.
    "localhost", "127.0.0.1", "user:password", "postgres:postgres",
]

PLACEHOLDER_MATCH_RES = [
    re.compile(r"^<[^>]+>$"),
    re.compile(r"^0+$"),
    re.compile(r"^[Xx]+$"),
    re.compile(r"^1234567890$"),
    re.compile(r"^(?:123)+$"),
    re.compile(r"(?i)^(your|my|the)[-_].+"),
    re.compile(r"(?i)placeholder"),
    re.compile(r"(?i)example"),
    re.compile(r"(?i)redacted"),
    re.compile(r"(?i)change[-_]?me"),
    # "sk-ant-your-key-here", "GITHUB_TOKEN=your_token", etc.
    re.compile(r"(?i)your[-_](?:key|token|secret|password|value|api)"),
    re.compile(r"(?i)(?:key|token|secret|password)[-_]here\b"),
    re.compile(r"(?i)dummy"),
    re.compile(r"(?i)^<.*>$"),
    # All-zero GUID and similar null identifiers.
    re.compile(r"^[0-]+$"),
]

# A line must carry one of these signals before the short Azure resource-name
# prefixes (ca-, caj-, cae-, kv-, pg-) are treated as estate references. Without
# this, pattern filenames like "pat-ca-secretref-stale-resolution" false-positive.
AZURE_CONTEXT = re.compile(
    r"(?i)(?:\baz\s|containerapp|azurecontainerapps|azure|\brg-|container\s+app|acr\b|keyvault|key\s+vault)"
)

# A line must carry one of these before a bare 9-digit number is read as a
# routing/account number rather than an ordinary large integer.
FININST_CONTEXT = re.compile(
    r"(?i)(?:routing|\baba\b|account\s*(?:number|no|#)|member\s*(?:number|no|#)|share\s*id|nmls)"
)

Rule = namedtuple("Rule", "label tier regex context validator")


def rule(label, tier, pattern, flags=0, context=None, validator=None):
    assert tier in TIERS, f"unknown tier: {tier}"
    return Rule(label, tier, re.compile(pattern, flags), context, validator)


def luhn_valid(text):
    """True when the digits in text pass the Luhn checksum (card-like)."""
    digits = [int(c) for c in text if c.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def not_a_git_sha(text):
    """Suppress 40/64-char hex — those are commit SHAs and content hashes."""
    return not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", text)


def _email_parts(text):
    local, _, domain = text.partition("@")
    return local.lower(), domain.lower()


def _is_fixture_address(local, domain):
    if local in PLACEHOLDER_EMAIL_LOCALS:
        return True
    return domain.rsplit(".", 1)[-1] in RESERVED_EMAIL_TLDS


def own_org_email(text):
    """A CU2 staff address: fine in a private repo, must not be published."""
    local, domain = _email_parts(text)
    return domain.endswith("cu-2.com") and not _is_fixture_address(local, domain)


def external_email(text):
    """Any non-CU2 address — could be a member, vendor, or partner contact."""
    local, domain = _email_parts(text)
    return not domain.endswith("cu-2.com") and not _is_fixture_address(local, domain)


def real_cu2_key(text):
    """
    Distinguish a CU2 API key from an ordinary cu2_-prefixed identifier.

    A key looks like `cu2_test_internal_kirk_2026`: long, many segments.
    Database names, module names, and config prefixes (`cu2_billing_dev`,
    `cu2_agent_studio`) are short and two-segment. Without this the rule fired
    416 times on cu2-agent-studio, none of them a key.
    """
    if text in KNOWN_SAFE_CU2_IDENTIFIERS:
        return False
    suffix = text[len("cu2_"):]
    return len(suffix) >= 16 and suffix.count("_") >= 3


# A captured "secret value" that is really source code, a variable reference,
# a filesystem path, or a type annotation. Every one of these was a live false
# positive on the first run against cu2-standards.
CODE_VALUE_RE = re.compile(
    r"""^(?:
          [$~/]                                   # ${VAR}, $VAR, ~/path, /path
        | (?:os|process|import|self|this|req|request|ctx|context|contextvars
           |typing|env|config|settings|headers|argv|args|kwargs)\.
        | (?:Optional|Union|Any|Dict|List|Tuple|Token|Callable|str|int|bool
           |float|bytes|None|True|False)\b
        )""",
    re.X,
)

CODE_ACCESSOR_RE = re.compile(r"(?:getenv|environ|\.get\b|\.env\b|process\.env)")

# A CALL is not a literal.
#
# CODE_VALUE_RE works from an allowlist of module prefixes (os., process., self.
# ...), so it only recognises code it was told about. `re.` was not on the list,
# which made this scanner report two secrets in its OWN sibling detector:
#
#   tools/theater/orphan_tests.py:157  QUOTED_TOKEN_RE = re.compile(
#   tools/theater/orphan_tests.py:252  STEP_KEY        = re.compile(
#
# Both are regex constants whose NAMES contain TOKEN and KEY. Extending the
# prefix allowlist with `re.` would fix these two lines and leave the next
# module — and the plain `SESSION_KEY = build_key()` shape — still wrong.
#
# Keying on the call syntax instead generalises: a secret is a literal, and a
# literal does not contain a parenthesis. Real credential alphabets
# ([A-Za-z0-9._/+-], base64, hex, sk- prefixes, PEM bodies) have no '(' in them,
# so this cannot mask one.
CALL_EXPRESSION_RE = re.compile(r"[A-Za-z_][\w.]*\(")


def looks_like_a_literal_value(text):
    """False when the 'secret' is actually code, a reference, or a path."""
    if CODE_VALUE_RE.match(text):
        return False
    if CODE_ACCESSOR_RE.search(text):
        return False
    if CALL_EXPRESSION_RE.search(text):
        return False
    return True


# An isolated operator, a shell/template interpolation, or a backtick. A real
# secret contains none of these; source code that BUILDS a secret does.
#
# The boundary alternation matters: match_text() strips the captured value, so
# ` + pw + ` arrives here as `+ pw +` with the outer whitespace already gone. A
# pattern requiring whitespace on both sides silently missed it, and the first
# version of this regex did exactly that -- the rule kept firing on this
# scanner's own test file while the validator reported the value as legitimate.
# Isolated by whitespace OR by the value boundary, therefore.
#
# Unspaced `+` stays legal: base64 secrets contain it.
SOURCE_CONSTRUCTION_RE = re.compile(
    r"(?:^|\s)[-+.%,|](?:\s|$)|\$\{|\$\(|`|\{\{"
)


def looks_like_a_literal_secret(text):
    """`looks_like_a_literal_value`, plus: not a value assembled in source.

    The quoted-assignment rule spans from the opening quote to the closing quote,
    so in source that concatenates it can capture across a code boundary::

        "...;Password=" + pw + ";Encrypt=True"

    captures ``" + pw + "``, which is 8 characters and satisfies the length floor.
    Found immediately, because the first version of that rule flagged this
    scanner's own test file on exactly this shape -- the test suite runs the gate
    against its own source, which is why it surfaced within a minute rather than
    in somebody's repository.

    A real credential does not contain ` + `, `${...}`, `$(...)`, a backtick, or
    `{{...}}`. Source that builds one does. Note `+` alone is deliberately still
    allowed unspaced, because base64 secrets contain it.
    """
    if not looks_like_a_literal_value(text):
        return False
    if SOURCE_CONSTRUCTION_RE.search(text):
        return False
    return True


def looks_like_base64_blob(text):
    """
    True only for high-entropy base64-ish strings.

    The naive 40+ char rule matched slash-separated word lists
    ('refactor/migration/rewrite/...') and absolute paths. A real base64 secret
    mixes cases and digits and does not read as path segments.
    """
    if not not_a_git_sha(text):
        return False
    if "/" in text:
        return False
    return (any(c.isdigit() for c in text)
            and any(c.islower() for c in text)
            and any(c.isupper() for c in text))


def _tenant_alternation():
    return "|".join(re.escape(name) for name in CU2_TENANT_NAMES)


RULES = [
    # ---- secret -----------------------------------------------------------
    rule("Private key block", "secret",
         r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----"),
    rule("OpenAI/Anthropic-style secret key (sk-)", "secret",
         r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    rule("GitHub token (ghp_/gho_/ghu_/ghs_/ghr_)", "secret",
         r"\bgh[posur]_[A-Za-z0-9]{20,}\b"),
    rule("Slack token (xox...)", "secret",
         r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    rule("Google API key (AIza...)", "secret",
         r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    rule("AWS access key id (AKIA/ASIA...)", "secret",
         r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    rule("Bearer token in header", "secret",
         r"\bbearer\s+[A-Za-z0-9._-]{20,}\b", re.I),
    rule("CU2 API key (cu2_...)", "secret",
         r"\bcu2_[a-z0-9_]{8,}\b", validator=real_cu2_key),
    rule("Azure SAS token", "secret",
         r"[?&](?:sig|sv)=[A-Za-z0-9%+/=_-]{10,}"),
    rule("Credential-bearing connection string", "secret",
         r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqps?|smtp|smtps)"
         r"://[^\s:@/]+:[^\s@/]{8,}@[^\s]+", re.I),
    rule("JDBC credential-bearing URL", "secret",
         r"\bjdbc:[A-Za-z0-9:+.-]+://[^\s;]+;[^\n]*(?:password|pwd)=[^\s;]{8,}", re.I),
    rule("Webhook URL with embedded secret", "secret",
         r"https://(?:hooks\.slack\.com/services|discord(?:app)?\.com/api/webhooks"
         r"|api\.telegram\.org/bot)[A-Za-z0-9_./:-]{20,}"),
    rule("Package registry auth token", "secret",
         r"\b(?:_authToken|npm_token|pypi_token|twine_password|poetry_pypi_token_[A-Za-z0-9_-]+)\b"
         r"\s*[:=]\s*['\"]?([A-Za-z0-9._/+-]{12,})['\"]?", re.I),
    rule("netrc-style credential", "secret",
         r"\bmachine\s+\S+\s+login\s+\S+\s+password\s+\S{8,}", re.I),
    rule("Cloud/service-account private key marker", "secret",
         r"\b(?:private_key_id|client_secret|refresh_token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._/+-]{12,})['\"]?", re.I),
    rule("Kubeconfig credential marker", "secret",
         r"\b(?:client-certificate-data|client-key-data|token):\s*([A-Za-z0-9+/=._-]{20,})", re.I),
    # The trailing lookahead requires the value to END the expression. Without
    # it, `token = GH_TOKEN_FILE.read_text().strip()` reads as a secret because
    # the identifier before the call is 12+ legal characters.
    rule("Generic API/secret/token assignment", "secret",
         r"\b(?:api[_-]?key|secret|token|passwd|password|access[_-]?key)\b"
         r"\s*[:=]\s*['\"]?([A-Za-z0-9._/+-]{12,})(?=['\"]?(?:\s|$|[,;)\]}]))", re.I,
         validator=looks_like_a_literal_value),

    # The rule above cannot see a value containing punctuation outside
    # [A-Za-z0-9._/+-]. That class plus the terminator lookahead is what keeps
    # `token = FILE.read_text().strip()` from reading as a secret — a real fix
    # for a real false positive — but it also means a password meeting any
    # normal complexity policy is INVISIBLE to it:
    #
    #     Password=Hunter2Hunter2!   -> value stops at `Hunter2Hunter2`,
    #                                   then `!` fails the terminator, no match
    #
    # Verified 2026-08-05: that string passed `--profile public` CLEAN, exit 0,
    # while foundry's generic rule caught and redacted it. A hardening change
    # made to remove noise had removed signal, and nothing noticed because the
    # only fixtures were values the narrowed class still matched.
    #
    # Rather than widen the class above (which would reintroduce the call-
    # expression false positive it was added to kill), two narrower rules follow.
    # Each has exactly one capture group, because match_text() reads group(1).

    # When the value is quoted, the closing quote IS the terminator, so the value
    # may contain anything at all. This is the shape that hides a real password.
    rule("Quoted secret assignment (any characters in value)", "secret",
         r"\b(?:api[_-]?key|secret|token|passwd|password|access[_-]?key|client[_-]?secret)\b"
         r"\s*[:=]\s*[\"']([^\"'\r\n]{8,})[\"']", re.I,
         validator=looks_like_a_literal_secret),

    # Connection strings delimit with `;`, so the value is everything up to it.
    # This also closes a gap both this scanner and foundry's had: an Azure
    # Storage connection string whose AccountKey is under 40 base64 characters
    # was matched by NEITHER, because the only thing that ever caught one was the
    # generic 40+ char base64 rule, incidentally. `=` is deliberately allowed in
    # the value class so base64 padding is captured; `<` and `>` are excluded so
    # `Password=<your-password>` stays a placeholder.
    rule("Credential in connection string", "secret",
         r"\b(?:password|pwd|accountkey|sharedaccesssignature|accountsecret)\s*=\s*"
         r"([^;\s\"'<>]{8,})(?=\s*(?:[;\"']|$))", re.I,
         validator=looks_like_a_literal_secret),
    rule(".env-style sensitive KEY=VALUE", "secret",
         r"(?m)^\s*[A-Z][A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD|PASSWD|AUTH|CREDENTIAL|PRIVATE)"
         r"[A-Z0-9_]*\s*=\s*['\"]?([^\s'\"#]{8,})['\"]?\s*$",
         validator=looks_like_a_literal_value),
    rule("Long base64-ish secret (40+ chars)", "secret",
         r"\b[A-Za-z0-9+/]{40,}={0,2}\b", validator=looks_like_base64_blob),

    # ---- pii --------------------------------------------------------------
    rule("External email address", "pii",
         r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", validator=external_email),
    rule("Phone number", "pii",
         r"(?<![\w.])(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4}(?![\w])"),
    rule("Social security number", "pii",
         r"(?<![\w-])\d{3}-\d{2}-\d{4}(?![\w-])"),
    rule("Card-like PAN (Luhn-valid)", "pii",
         r"(?<![\w-])(?:\d{4}[ -]){3}\d{4}(?![\w-])", validator=luhn_valid),
    rule("Member / share / NMLS identifier", "pii",
         r"\b(?:member|share|nmls)[_ -]?(?:number|no|id|#)?\s*[:=#]\s*['\"]?(\d{4,})['\"]?", re.I),
    rule("Routing / account number in financial context", "pii",
         r"(?<![\w.])\d{9}(?![\w.])", context=FININST_CONTEXT),
    rule("Long all-digit ID (>=9 digits — member/account/chat ID)", "pii",
         r"(?<![\w.])-?\d{9,}(?![\w.])"),

    # ---- internal ---------------------------------------------------------
    # Tenant identity and staff addresses are normal business inside a private
    # repo. Naming a client credit union publicly discloses the relationship,
    # so these block at --profile public only.
    rule("CU2 staff email address", "internal",
         r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", validator=own_org_email),
    rule("Named credit union", "internal",
         r"\b(?:[A-Z][A-Za-z'’-]+\s+){1,3}Credit\s+Union\b"),
    rule("Live CU2 tenant name", "internal",
         r"\b(?:" + _tenant_alternation() + r")\b"),
    rule("Azure Container Apps FQDN", "internal",
         r"\b[A-Za-z0-9-]+\.[A-Za-z0-9-]+\.[a-z0-9]+\.azurecontainerapps\.io\b"),
    rule("Azure service FQDN", "internal",
         r"\b[A-Za-z0-9-]+\.(?:azurecr\.io|vault\.azure\.net|postgres\.database\.azure\.com"
         r"|database\.windows\.net|blob\.core\.windows\.net|servicebus\.windows\.net"
         r"|azurewebsites\.net)\b"),
    rule("Azure resource group name", "internal",
         r"(?<![A-Za-z0-9-])rg-[a-z0-9][a-z0-9-]{2,}"),
    rule("Azure resource name (container app / job / env / vault / pg)", "internal",
         r"(?<![A-Za-z0-9-])(?:ca|caj|cae|kv|pg)-[a-z0-9][a-z0-9-]{2,}",
         context=AZURE_CONTEXT),
    rule("Azure subscription / tenant GUID", "internal",
         r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I),
    rule("Internal cu-2.com host", "internal",
         r"\b[a-z0-9-]+\.cu-2\.com\b"),
    rule("Private org repo slug", "internal",
         r"\b(?:credit-union-2-0-llc|CU2CU2)/[A-Za-z0-9._-]+"),
    rule("Absolute home path (/Users/<name> or /home/<name>)", "internal",
         r"/(?:Users|home)/[A-Za-z0-9._-]+"),
    rule("Tailscale / mesh hostname (*.ts.net)", "internal",
         r"\b[A-Za-z0-9._-]+\.ts\.net\b"),
    rule("Tailscale CGNAT address (100.64.0.0/10)", "internal",
         r"\b100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b"),
    rule("Shared-services VNet address (10.40.0.0/16)", "internal",
         r"\b10\.40\.\d{1,3}\.\d{1,3}\b"),
]

BROAD_ALLOWLIST_PATTERNS = {".*", "^.*$", ".+", "^.+$", "(.*)", "^.*", ".*$"}


# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------

def is_broad_allow_pattern(pattern):
    stripped = pattern.strip()
    if stripped in BROAD_ALLOWLIST_PATTERNS:
        return True
    # Tiny unanchored fragments are lazy bypasses, not real exceptions.
    if len(stripped) < 4 and not stripped.startswith("^"):
        return True
    return False


def load_allowlist(root):
    """Read .cu2-sanitize-allow. Supports `line:<regex>` and `path:<regex>`."""
    line_allow, path_allow, errors = [], [], []
    base = root if os.path.isdir(root) else (os.path.dirname(root) or ".")
    candidate = os.path.join(base, ALLOWLIST_FILENAME)
    if not os.path.isfile(candidate):
        return line_allow, path_allow, errors

    with open(candidate, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            kind, pattern = "line", line
            if line.startswith("line:"):
                pattern = line[len("line:"):].strip()
            elif line.startswith("path:"):
                kind, pattern = "path", line[len("path:"):].strip()

            if is_broad_allow_pattern(pattern):
                errors.append((candidate, lineno,
                               "Dangerously broad allowlist regex",
                               "[allowlist entry redacted]"))
                continue
            if kind == "path" and not (pattern.startswith("^") or "/" in pattern):
                errors.append((candidate, lineno,
                               "Path allowlist entry must be anchored or repo-relative",
                               "[allowlist entry redacted]"))
                continue
            try:
                compiled = re.compile(pattern)
            except re.error:
                errors.append((candidate, lineno,
                               "Invalid allowlist regex",
                               "[allowlist entry redacted]"))
                continue
            (path_allow if kind == "path" else line_allow).append(compiled)
    return line_allow, path_allow, errors


# ---------------------------------------------------------------------------
# Placeholder detection and redaction
# ---------------------------------------------------------------------------

def spans_overlap(a, b):
    return max(a[0], b[0]) < min(a[1], b[1])


def is_placeholder(matched_text, line_text, span=None):
    """True only when the matched value itself is a placeholder."""
    for rx in PLACEHOLDER_MATCH_RES:
        if rx.search(matched_text):
            return True

    if span is not None:
        low_line = line_text.lower()
        for tok in PLACEHOLDER_TOKENS:
            low_tok = tok.lower()
            start = 0
            while True:
                idx = low_line.find(low_tok, start)
                if idx == -1:
                    break
                if spans_overlap(span, (idx, idx + len(tok))):
                    return True
                start = idx + 1

    if "<" in line_text and ">" in line_text:
        if re.search(r"<[^>]*" + re.escape(matched_text) + r"[^>]*>", line_text):
            return True
    return False


def redacted_snippet(line, match):
    line = line.rstrip("\n")
    spans = []
    if match.lastindex:
        for i in range(1, match.lastindex + 1):
            span = match.span(i)
            if span != (-1, -1):
                spans.append(span)
    if not spans:
        spans = [match.span(0)]
    redacted = line
    for start, end in sorted(spans, reverse=True):
        redacted = redacted[:start] + "[REDACTED]" + redacted[end:]
    snippet = redacted.strip()
    return snippet[:157] + "..." if len(snippet) > 160 else snippet


def redact_text(text):
    """Redact a string (used on paths, so CI never echoes a sensitive path)."""
    redacted = text
    for r in RULES:
        if r.label.startswith("Long base64-ish") and "://" in redacted:
            continue
        redacted = r.regex.sub("[REDACTED]", redacted)
    return redacted


def match_span(match):
    if match.lastindex and match.group(1):
        return match.span(1)
    return match.span(0)


def match_text(match):
    if match.lastindex and match.group(1):
        return match.group(1).strip()
    return match.group(0).strip()


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def active_rules(profile, tiers=None):
    allowed = PROFILES[profile]
    if tiers:
        allowed = allowed & set(tiers)
    return [r for r in RULES if r.tier in allowed]


def rule_hits(r, text):
    """Yield (matched_text, span, match) for real (non-placeholder) hits."""
    if r.label.startswith("Long base64-ish") and "://" in text:
        return
    if r.context is not None and not r.context.search(text):
        return
    for m in r.regex.finditer(text):
        matched = match_text(m)
        if not matched:
            continue
        if r.validator is not None and not r.validator(matched):
            continue
        if is_placeholder(matched, text, match_span(m)):
            continue
        yield matched, m


def git_tracked_files(root):
    """Repo-relative paths git knows about, or None if this isn't a git repo."""
    import subprocess
    try:
        out = subprocess.run(
            ["git", "-C", root, "ls-files", "-z"],
            capture_output=True, check=True, text=True, timeout=60,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return [p for p in out.split("\0") if p]


def iter_files(root, tracked_only=False):
    if os.path.isfile(root):
        yield root
        return

    if tracked_only:
        tracked = git_tracked_files(root)
        if tracked is None:
            sys.stderr.write(
                "warning: --tracked-only requested but this is not a git "
                "repository; scanning the whole tree instead\n")
        else:
            for rel in tracked:
                if os.path.basename(rel) in SELF_SKIP_NAMES:
                    continue
                full = os.path.join(root, rel)
                if os.path.isfile(full):
                    yield full
            return

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        rel_dir = "" if rel_dir == "." else rel_dir + "/"
        if any(rel_dir.startswith(p) for p in SKIP_PATH_PREFIXES):
            dirnames[:] = []
            continue
        for name in filenames:
            if name in SELF_SKIP_NAMES:
                continue
            yield os.path.join(dirpath, name)


def artifact_finding(path, rules):
    """
    Binary/oversized artifacts need human review before publication. This is an
    `internal`-tier concern, so it must respect the active profile like any
    other rule — otherwise `--profile internal` reports internal-tier findings.
    """
    if not any(r.tier == "internal" for r in rules):
        return None
    ext = os.path.splitext(path)[1].lower()
    if ext in RISKY_BINARY_EXTS:
        return (0, "internal", "Risky binary/archive artifact requires explicit review",
                "[artifact filename redacted]")
    try:
        size = os.path.getsize(path)
    except OSError:
        return None
    if size > MAX_TEXT_BYTES:
        return (0, "internal", "Large text artifact requires explicit review",
                "[large filename redacted]")
    return None


def path_findings(rel_path, rules):
    findings = []
    for r in rules:
        for _matched, _m in rule_hits(r, rel_path):
            findings.append((0, r.tier, f"Sensitive value in file path: {r.label}",
                             "[path segment redacted]"))
            break
    return findings


def scan_file(path, rules, line_allow, path_allow=None, root=None):
    path_allow = path_allow or []
    rel_path = os.path.relpath(path, root) if root else path
    rel_path = rel_path.replace(os.sep, "/")
    findings = []

    if any(rx.search(rel_path) for rx in path_allow):
        return findings

    findings.extend(path_findings(rel_path, rules))

    artifact = artifact_finding(path, rules)
    if artifact:
        findings.append(artifact)
        return findings

    if os.path.basename(rel_path) in LOCKFILE_NAMES:
        rules = [r for r in rules
                 if not r.label.startswith(LOCKFILE_MUTED_RULES)]

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except (OSError, UnicodeError):
        return findings

    for lineno, line in enumerate(lines, start=1):
        if any(rx.search(line) for rx in line_allow):
            continue
        for r in rules:
            for _matched, m in rule_hits(r, line):
                findings.append((lineno, r.tier, r.label, redacted_snippet(line, m)))
                break
    return findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="cu2_sanitize_scan",
        description="CU 2.0 fail-closed publication gate. Layers on gitleaks; "
                    "catches internal operating context and member PII.",
    )
    p.add_argument("target", nargs="?", default=".",
                   help="file or directory to scan (default: .)")
    p.add_argument("--profile", choices=sorted(PROFILES), default="internal",
                   help="internal = secret+pii (default); public = all tiers")
    p.add_argument("--tier", action="append", choices=TIERS,
                   help="restrict to specific tier(s); repeatable")
    p.add_argument("--report", action="store_true",
                   help="print findings and a tier summary but always exit 0 "
                        "(for sizing sanitization work, not for CI)")
    p.add_argument("--tracked-only", action="store_true",
                   help="scan only git-tracked files; skips untracked build "
                        "output, agent worktrees, and local logs")
    p.add_argument("--quiet", action="store_true",
                   help="suppress per-finding output; print the summary only")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    target = args.target

    if not os.path.exists(target):
        sys.stderr.write(f"error: path not found: {target}\n")
        return 2

    rules = active_rules(args.profile, args.tier)
    line_allow, path_allow, allow_errors = load_allowlist(target)
    root = target if os.path.isdir(target) else "."

    by_tier = Counter()
    total = 0
    flagged_files = 0

    for allow_path, lineno, label, snippet in allow_errors:
        rel = os.path.relpath(allow_path, root).replace(os.sep, "/")
        if not args.quiet:
            print(f"{redact_text(rel)}:{lineno}: [config] {label}")
            print(f"    | {snippet}")
        by_tier["config"] += 1
        total += 1
        flagged_files += 1

    for path in sorted(iter_files(target, tracked_only=args.tracked_only)):
        findings = scan_file(path, rules, line_allow, path_allow, root=root)
        if not findings:
            continue
        flagged_files += 1
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        safe_rel = redact_text(rel)
        for lineno, tier, label, snippet in findings:
            loc = f"{safe_rel}:{lineno}" if lineno else safe_rel
            if not args.quiet:
                print(f"{loc}: [{tier}] {label}")
                print(f"    | {snippet}")
            by_tier[tier] += 1
            total += 1

    print()
    if total == 0:
        print(f"cu2_sanitize_scan: CLEAN (profile={args.profile}). "
              f"No sensitive patterns found.")
        return 0

    breakdown = "  ".join(f"{t}={by_tier[t]}" for t in ("config",) + TIERS if by_tier[t])
    print(f"cu2_sanitize_scan: {total} finding(s) in {flagged_files} file(s) "
          f"[profile={args.profile}]")
    print(f"  by tier: {breakdown}")

    if args.report:
        print("  report mode: exiting 0 without failing.")
        return 0

    print("Scrub the items above before committing or publishing.")
    print(f"Use {ALLOWLIST_FILENAME} only for narrow, documented, justified exceptions.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
