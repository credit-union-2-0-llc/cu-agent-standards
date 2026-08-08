#!/usr/bin/env python3
"""
Fixture-mutation smoke test for cu2_sanitize_scan.

WHY THIS FILE EXISTS, AND WHY test_cu2_sanitize_scan.py WAS NOT ENOUGH

test_cu2_sanitize_scan.py already proves every rule fires on a positive
sample (`TestRulesFire`), and it does so systematically -- every entry in
`gate.RULES` is required to have one. What it does not do is what The Agent
Foundry's `gates/scripts/fixture_smoke.py` does for its own fixtures: start
from a document that is KNOWN GOOD, apply one deliberate, targeted mutation,
and assert that mutation alone is what flips the verdict. That is a stronger
claim than "this isolated string matches this regex" -- it proves the rule
still fires on bad input sitting inside an otherwise ordinary file, through
the real scan_file() pipeline (path handling, tier aggregation, redaction),
not just through the regex/validator layer in isolation.

This is the harness this repo was missing. The systemic failure it targets
already happened once: the "Quoted secret assignment" and "Credential in
connection string" rules were narrowed to kill a false positive
(`token = FILE.read_text().strip()` reading as a secret) and the narrowing
also made a real, complexity-policy-shaped password
(`Password=Hunter2Hunter2!`) invisible. Nothing caught it until a manual
scan on 2026-08-05, because every existing fixture at the time used a value
the narrowed character class still matched. `TestPunctuationBoundary` below
generalizes that one-off regression into a standing check across every rule
whose value class is permissive enough to be narrowed the same way again.

The mutation catalog (`MUTATIONS`) is checked bidirectionally against the
live `gate.RULES` table (`TestFixtureMutationsCoverTheFullRuleSet`), so a
new rule added without a mutation fails CI, and a rule renamed or removed
without updating this file also fails CI -- the catalog cannot silently
drift out of sync with what it claims to cover.

NOTE ON SAMPLES: as in test_cu2_sanitize_scan.py, every sensitive value
below is assembled at runtime from fragments rather than written as a
literal, so this file itself stays clean under the gate it tests.

Run:
    python3 tools/sanitize/test_fixture_mutations.py
    python3 -m unittest discover -s tools/sanitize -v
"""

import io
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cu2_sanitize_scan as gate  # noqa: E402


# ---------------------------------------------------------------------------
# The known-good fixture. Ordinary prose and code: comments, an env-var read,
# a placeholder path, an example.com contact. Verified clean below by
# TestFixtureMutationsCoverTheFullRuleSet.test_baseline_fixture_is_itself_clean
# before any mutation test is allowed to mean anything.
# ---------------------------------------------------------------------------

BASELINE_DOC = (
    "# Deployment notes\n"
    "\n"
    "This document describes how the pipeline authenticates using an\n"
    "environment variable, which is read at runtime and never stored in\n"
    "source. Configuration lives at /path/to/config and defaults reference\n"
    "example.com for illustration purposes only.\n"
    "\n"
    "def load_token():\n"
    "    return os.environ.get(\"OPS_API_KEY\")\n"
    "\n"
    "See CONTRIBUTING.md for the review process. Reach the on-call rotation\n"
    "at oncall@example.com if a deploy looks wrong, or open an issue in the\n"
    "public tracker. Build numbers and ticket IDs in this repo stay small\n"
    "(under a hundred) so none of them resemble an account or member ID.\n"
)


# ---------------------------------------------------------------------------
# One mutation per rule label. Each value is the minimal single line that,
# appended to BASELINE_DOC, must flip that rule from silent to firing. Keyed
# by the FULL rule label (not a prefix) so a rule rename is caught rather
# than silently matching nothing.
# ---------------------------------------------------------------------------

MUTATIONS = {
    "Private key block":
        "-----BEGIN " + "RSA PRIVATE KEY-----",
    "OpenAI/Anthropic-style secret key (sk-)":
        "key = " + "sk-" + "a" * 24,
    "GitHub token (ghp_/gho_/ghu_/ghs_/ghr_)":
        "token " + "ghp_" + "A" * 24,
    "Slack token (xox...)":
        "xox" + "b-" + "1234567890abcdef",
    "Google API key (AIza...)":
        "AIza" + "b" * 33,
    "AWS access key id (AKIA/ASIA...)":
        "AKIA" + "ABCDEFGHIJKLMNOP",
    "Bearer token in header":
        "Authorization: Bearer " + "c" * 30,
    "CU2 API key (cu2_...)":
        "cu2_" + "test_internal_kirk_2026",
    "Azure SAS token":
        "https://host/blob" + "?sv=" + "2021-08-06&x=1",
    "Credential-bearing connection string":
        "postgres" + "://svcuser:" + "s3cretpw99" + "@dbhost:5432/appdb",
    "JDBC credential-bearing URL":
        "jdbc:sqlserver" + "://h:1433;user=a;" + "password=" + "s3cretpw99",
    "Webhook URL with embedded secret":
        "https://hooks.slack.com/services/" + "T00/B00/" + "x" * 24,
    "Package registry auth token":
        "_authToken" + "=" + "npmtok" + "1" * 14,
    "netrc-style credential":
        "machine registry.internal login svc " + "password " + "hunter2hunter2",
    "Cloud/service-account private key marker":
        "client_secret" + ": " + "Zx8" + "q" * 20,
    "Kubeconfig credential marker":
        "client-key-data" + ": " + "LS0t" + "K" * 24,
    "Generic API/secret/token assignment":
        "api_key" + " = " + "abcd1234efgh5678",
    "Quoted secret assignment (any characters in value)":
        "password" + ': "' + "P@ss" + "w0rd!Complex" + '"',
    "Credential in connection string":
        "Server=db;Password=" + "Hunter2" + "Hunter2!" + ";Encrypt=True",
    ".env-style sensitive KEY=VALUE":
        "DATABASE_PASSWORD" + "=" + "hunter2hunter2",
    "Long base64-ish secret (40+ chars)":
        "blob " + "aB3" * 16,
    "External email address":
        "reach " + "auditor" + "@" + "auditfirm.co",
    "Phone number":
        "call " + "541" + "-" + "555" + "-" + "0142",
    "Social security number":
        "ssn " + "123" + "-" + "45" + "-" + "6789",
    "Public/routable IP address in infrastructure context":
        "ssh to " + "51.132" + ".44.9",
    "Card-like PAN (Luhn-valid)":
        "card " + "4111 1111 " + "1111 1111",
    "Member / share / NMLS identifier":
        "member_number" + ": " + "884213",
    "Routing / account number in financial context":
        "routing " + "32118" + "0379",
    "Long all-digit ID (>=9 digits — member/account/chat ID)":
        "chat " + "45887311" + "99",
    "CU2 staff email address":
        "reach " + "kdrake" + "@" + "cu-2.com",
    "Named credit union":
        "onboarding Mission " + "Federal " + "Credit Union" + " today",
    "Live CU2 tenant name":
        "tenant " + "MB" + "FS" + " only",
    "Azure Container Apps FQDN":
        "https://ca-" + "cu2-mcp.icyplant-45887311.westus2"
        + ".azurecontainerapps.io" + "/mcp/",
    "Azure service FQDN":
        "cu2registry" + ".azurecr.io" + "/img:1",
    "Azure resource group name":
        "deployed into " + "rg-" + "ops-platform",
    "Azure resource name (container app / job / env / vault / pg)":
        "az containerapp show -n " + "ca-" + "forge-studio",
    "Azure subscription / tenant GUID":
        "sub " + "3f2504e0-4f89-" + "11d3-9a0c-0305e82c3301",
    "Internal cu-2.com host":
        "see " + "ops" + ".cu-2.com",
    "Private org repo slug":
        "repo " + "credit-union-2-0-llc" + "/redvisor",
    "Absolute home path (/Users/<name> or /home/<name>)":
        "cd " + "/Users/" + "jdrake",
    "Tailscale / mesh hostname (*.ts.net)":
        "ssh box" + ".ts.net",
    # The rule labels below embed a literal example CIDR block in their own
    # text. Written as one contiguous string here, that label would trip
    # this file's own scan (the gate reads the example in its own source as
    # a live address) -- caught by test_gate_does_not_flag_its_own_source
    # while writing this file. Split so the runtime string still equals the
    # rule label exactly, but the two halves never sit adjacent in the
    # source text (not even inside a comment).
    "Tailscale CGNAT address (100." + "64.0.0/10)":
        "ping " + "100." + "90.241.40",
    "Shared-services VNet address (10.40." + "0.0/16)":
        "vnet " + "10.40." + "1.7",
}


# ---------------------------------------------------------------------------
# Punctuation-boundary mutations. Ledger row 20 (see module docstring): a
# rule's value class was narrowed to a safe-looking alphanumeric class, which
# quietly excluded any password meeting a normal complexity policy. These
# four rules delimit the captured value with something OTHER than a
# character-class boundary (a closing quote, a `;`, or plain whitespace), so
# the value itself may legitimately contain punctuation -- which makes them
# exactly the shape that regressed once and could regress again the same way.
# ---------------------------------------------------------------------------

_PUNCTUATION_SECRET = "Tr0ubl3!#$%^&()"

BOUNDARY_MUTATIONS = {
    "Quoted secret assignment (any characters in value)":
        "password" + ': "' + _PUNCTUATION_SECRET + '"',
    "Credential in connection string":
        "Server=db;Password=" + _PUNCTUATION_SECRET + ";Encrypt=True",
    "JDBC credential-bearing URL":
        "jdbc:sqlserver" + "://h:1433;user=a;" + "password=" + _PUNCTUATION_SECRET,
    "netrc-style credential":
        "machine registry.internal login svc " + "password " + _PUNCTUATION_SECRET,
}


# ---------------------------------------------------------------------------
# Harness plumbing
# ---------------------------------------------------------------------------

def scan_text(text, filename="fixture.md", profile="public"):
    """Write `text` to a throwaway file and run it through the real
    scan_file() pipeline -- not just rule_hits() -- so path handling, tier
    aggregation, and redaction are exercised the same way a real CI run
    would exercise them.
    """
    tmp = tempfile.mkdtemp(prefix="cu2sanitize-mutation-")
    try:
        path = os.path.join(tmp, filename)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        rules = gate.active_rules(profile)
        line_allow, path_allow, _errors = gate.load_allowlist(tmp)
        return gate.scan_file(path, rules, line_allow, path_allow, root=tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def mutated(trigger_line):
    return BASELINE_DOC + "\n" + trigger_line + "\n"


def run_gate(argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = gate.main(argv)
    return code, buf.getvalue()


# ---------------------------------------------------------------------------
# Coverage + mutation-rejection
# ---------------------------------------------------------------------------

class TestFixtureMutationsCoverTheFullRuleSet(unittest.TestCase):

    def test_baseline_fixture_is_itself_clean(self):
        """The known-good half of 'known-good fixture, mutate, assert reject'.

        If this ever fails, every test below it is meaningless: a mutation
        test only proves something when the un-mutated document was clean
        to begin with.
        """
        findings = scan_text(BASELINE_DOC)
        self.assertEqual(findings, [],
                          "the baseline fixture must be clean before mutation")

    def test_every_active_rule_has_a_mutation(self):
        """A rule added to gate.RULES without a matching mutation here is a
        rule this harness cannot vouch for. Fail loudly, not silently.
        """
        for r in gate.RULES:
            with self.subTest(rule=r.label):
                self.assertIn(r.label, MUTATIONS,
                               f"rule {r.label!r} has no fixture mutation")

    def test_every_mutation_targets_a_real_rule(self):
        """The inverse check: a mutation keyed to a label that no longer
        exists in gate.RULES (the rule was renamed or removed) must also
        fail, or this catalog could silently stop covering anything.
        """
        rule_labels = {r.label for r in gate.RULES}
        for label in MUTATIONS:
            with self.subTest(rule=label):
                self.assertIn(label, rule_labels,
                               f"mutation {label!r} does not match any "
                               "current rule label")

    def test_each_mutation_is_rejected_by_its_own_rule(self):
        """The core assertion: mutating the known-good fixture for rule X
        must produce a finding labeled X, through the real file-scan
        pipeline. If rule X's regex or validator silently stops matching
        (a bad refactor, an over-eager placeholder tweak, a validator that
        now rejects everything), this fails.
        """
        for label, trigger_line in MUTATIONS.items():
            with self.subTest(rule=label):
                findings = scan_text(mutated(trigger_line))
                found_labels = {f[2] for f in findings}
                self.assertIn(
                    label, found_labels,
                    f"mutating the fixture for rule {label!r} did not "
                    f"trigger a matching finding (got: {sorted(found_labels)}); "
                    "the detection rule may have silently stopped working",
                )

    def test_each_mutation_is_attributed_to_the_correct_tier(self):
        """Catches a rule whose regex still fires but whose tier got
        reassigned (e.g. a secret-tier rule quietly moved to pii), which
        would change which --profile catches it.
        """
        rules_by_label = {r.label: r for r in gate.RULES}
        for label, trigger_line in MUTATIONS.items():
            with self.subTest(rule=label):
                findings = scan_text(mutated(trigger_line))
                tiers_seen = {f[1] for f in findings if f[2] == label}
                self.assertIn(rules_by_label[label].tier, tiers_seen,
                               f"rule {label!r} fired but not under its "
                               "declared tier")


# ---------------------------------------------------------------------------
# Punctuation boundary — generalizes the ledger-row-20 regression
# ---------------------------------------------------------------------------

class TestPunctuationBoundaryDoesNotBlindTheGate(unittest.TestCase):
    """
    Regression class, not a regression instance. `Password=Hunter2Hunter2!`
    passed `--profile public` CLEAN on 2026-08-05 because a hardening pass
    had narrowed the generic secret-assignment rule's value class to
    `[A-Za-z0-9._/+-]` with a terminator lookahead -- a real fix for a real
    false positive (`token = FILE.read_text().strip()`), which incidentally
    made any password containing `!`, `#`, `$`, etc. invisible to it. Two
    narrower rules were added specifically to keep catching values with
    arbitrary punctuation, delimited by a closing quote or a `;` instead of
    a character class.

    These tests pin that those two rules (and the other loosely-delimited
    credential rules that share the same shape) still tolerate punctuation
    in the captured value. If a future change narrows any of these back to
    an alphanumeric-only class, this fails immediately instead of waiting
    for another manual scan to notice.
    """

    def test_punctuation_bearing_secret_is_still_caught(self):
        for label, trigger_line in BOUNDARY_MUTATIONS.items():
            with self.subTest(rule=label):
                findings = scan_text(mutated(trigger_line))
                found_labels = {f[2] for f in findings}
                self.assertIn(
                    label, found_labels,
                    f"a punctuation-bearing secret for {label!r} went "
                    "undetected -- this is exactly the regression class "
                    "documented in cu2_sanitize_scan.py's own history",
                )

    def test_boundary_catalog_only_covers_loosely_delimited_rules(self):
        """Sanity check on the catalog itself: every rule listed here must
        actually be loosely delimited (accepts punctuation by design),
        otherwise this class would be asserting a rule catches something
        it was never meant to catch, which is a false guarantee.
        """
        rule_labels = {r.label for r in gate.RULES}
        for label in BOUNDARY_MUTATIONS:
            with self.subTest(rule=label):
                self.assertIn(label, rule_labels)


# ---------------------------------------------------------------------------
# SSN space-separated variant — 2026-08-07 gap
#
# The SSN rule only ever matched the dash-separated shape; a space-separated
# SSN (three digits, a space, two digits, a space, four digits) passed clean
# at any profile. Widened to accept either shape (consistently, not mixed)
# without loosening the word-boundary
# discipline. This mirrors the mutation-catalog pattern above: prove the
# variant is caught through the real scan_file() pipeline, and prove the
# gate does not overreach into a same-shaped false positive.
# ---------------------------------------------------------------------------

SSN_SPACE_TRIGGER = "ssn " + "123" + " " + "45" + " " + "6789"

# Not an SSN: a run of numbers table-formatted with a mix of separators, or a
# single space between two otherwise unrelated numeric fields, must not
# collide with the widened rule. The rule requires a CONSISTENT separator
# across both gaps, so a dash-then-space (or space-then-dash) run is exactly
# the shape this guards against.
SSN_MIXED_SEPARATOR_NON_TRIGGER = "field " + "123" + "-" + "45" + " " + "6789"


class TestSSNSpaceSeparatedVariant(unittest.TestCase):

    def test_space_separated_ssn_is_now_caught(self):
        findings = scan_text(mutated(SSN_SPACE_TRIGGER))
        found_labels = {f[2] for f in findings}
        self.assertIn(
            "Social security number", found_labels,
            "a space-separated SSN went undetected -- this is the gap "
            "documented in cu2_sanitize_scan.py's SSN rule comment",
        )

    def test_mixed_separator_is_not_treated_as_an_ssn(self):
        findings = scan_text(mutated(SSN_MIXED_SEPARATOR_NON_TRIGGER))
        found_labels = {f[2] for f in findings}
        self.assertNotIn(
            "Social security number", found_labels,
            "a dash-then-space digit run false-positived as an SSN; the "
            "widened rule must require a consistent separator",
        )


# ---------------------------------------------------------------------------
# Public/routable IP rule — 2026-08-07 gap
#
# There was no rule at all for a hardcoded public IP (only CGNAT and the
# shared VNet range were covered), so a real CU2 VM's public address passed
# clean even at --profile public. The new rule is deliberately narrow --
# value must be a genuinely public, non-doc-example address (validator) AND
# the line must read like real infrastructure is being configured or
# connected to (context) -- specifically so it does NOT fire on the false
# positives called out in its code comment: DNS-doc examples, CDN/Front Door
# anycast mentions, and coincidental dotted-quad-shaped version strings.
# These tests pin both the detection and the restraint.
# ---------------------------------------------------------------------------

_TEST_PUBLIC_IP = "51.132" + ".44.9"  # fabricated; not a real CU2 asset

IP_NON_TRIGGERS = {
    "no infra context at all":
        "reach us for support at " + _TEST_PUBLIC_IP,
    "RFC 5737 documentation range":
        "curl http://" + "203.0.113" + ".5" + " for an example",
    "well-known public DNS resolver":
        "ssh through a box that forwards to " + "8.8.8.8",
    "CGNAT mesh address (covered by its own rule, not this one)":
        "ssh to " + "100." + "90.241.40",
    "shared VNet address (covered by its own rule, not this one)":
        "ssh to " + "10.40." + "1.7",
}


class TestPublicInfraIPRule(unittest.TestCase):

    def test_public_ip_in_infra_context_is_caught(self):
        findings = scan_text(mutated("ssh to " + _TEST_PUBLIC_IP))
        found_labels = {f[2] for f in findings}
        self.assertIn(
            "Public/routable IP address in infrastructure context",
            found_labels,
            "a hardcoded public IP referenced in an infra context "
            "(ssh/scp/firewall/etc.) went undetected",
        )

    def test_non_trigger_shapes_stay_clean(self):
        for reason, line in IP_NON_TRIGGERS.items():
            with self.subTest(reason=reason):
                findings = scan_text(mutated(line))
                found_labels = {f[2] for f in findings}
                self.assertNotIn(
                    "Public/routable IP address in infrastructure context",
                    found_labels,
                    f"false positive ({reason}): {line!r}",
                )


# ---------------------------------------------------------------------------
# Full-pipeline smoke: every rule tripped at once, through the real CLI
# ---------------------------------------------------------------------------

class TestFullPipelineSmoke(unittest.TestCase):
    """Foundry's fixture_smoke.py validates a whole fixture tree in one
    pass, not rule-by-rule in isolation. This is the equivalent here: one
    fixture that violates every rule at once, run through gate.main() the
    same way CI invokes it, asserting the aggregate behaviour end to end.
    """

    def test_every_mutation_together_fails_the_full_cli_gate(self):
        combined = BASELINE_DOC + "\n" + "\n".join(MUTATIONS.values()) + "\n"
        tmp = tempfile.mkdtemp(prefix="cu2sanitize-mutation-smoke-")
        try:
            path = os.path.join(tmp, "combined.md")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(combined)
            code, out = run_gate([tmp, "--profile", "public"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

        self.assertEqual(code, 1,
                          "a fixture violating every rule at once must fail "
                          f"the gate:\n{out}")
        for tier in gate.TIERS:
            with self.subTest(tier=tier):
                self.assertIn(f"[{tier}]", out,
                               f"no {tier}-tier finding surfaced when every "
                               "rule was tripped at once")
        self.assertIn("[REDACTED]", out,
                       "the combined smoke fixture's values must still be "
                       "redacted in gate output")

    def test_clean_baseline_alone_passes_the_full_cli_gate(self):
        """The control: the same pipeline, same profile, no mutation."""
        tmp = tempfile.mkdtemp(prefix="cu2sanitize-mutation-control-")
        try:
            path = os.path.join(tmp, "combined.md")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(BASELINE_DOC)
            code, out = run_gate([tmp, "--profile", "public"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        self.assertEqual(code, 0, f"the unmutated baseline must pass:\n{out}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
