#!/usr/bin/env python3
"""
Unit tests for cu2_sanitize_scan.

Run:
    python3 tools/sanitize/test_cu2_sanitize_scan.py
    python3 -m unittest discover -s tools/sanitize -v

NOTE ON SAMPLES: every sensitive sample below is assembled at runtime from
fragments (e.g. "ghp_" + "A" * 20) rather than written as a literal. That is
deliberate — it keeps this test file itself clean under the gate, so the gate's
own tooling needs no allowlist exception. If you add a test, assemble the
sample the same way.
"""

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cu2_sanitize_scan as gate  # noqa: E402


def find_rule(label_prefix):
    for r in gate.RULES:
        if r.label.startswith(label_prefix):
            return r
    raise AssertionError(f"no rule with label prefix {label_prefix!r}")


def hits(label_prefix, text):
    return [m for m, _ in gate.rule_hits(find_rule(label_prefix), text)]


def write_tree(files):
    """Create a temp dir containing {relpath: content}; return the dir."""
    tmp = tempfile.mkdtemp(prefix="cu2sanitize-")
    for rel, content in files.items():
        full = os.path.join(tmp, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as fh:
            fh.write(content)
    return tmp


def run_gate(argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = gate.main(argv)
    return code, buf.getvalue()


# ---------------------------------------------------------------------------
# Every rule fires on a positive sample
# ---------------------------------------------------------------------------

class TestRulesFire(unittest.TestCase):

    POSITIVES = [
        ("Private key block", "-----BEGIN " + "PRIVATE KEY-----"),
        ("OpenAI/Anthropic-style", "key = " + "sk-" + "a" * 24),
        ("GitHub token", "token " + "ghp_" + "A" * 24),
        ("Slack token", "xox" + "b-" + "1234567890abcdef"),
        ("Google API key", "AIza" + "b" * 33),
        ("AWS access key", "AKIA" + "ABCDEFGHIJKLMNOP"),
        ("Bearer token", "Authorization: Bearer " + "c" * 30),
        ("CU2 API key", "cu2_" + "test_internal_kirk_2026"),
        ("Azure SAS token", "https://host/blob" + "?sv=" + "2021-08-06&x=1"),
        ("Credential-bearing connection string",
         "postgres" + "://svcuser:" + "s3cretpw99" + "@dbhost:5432/appdb"),
        ("JDBC credential", "jdbc:sqlserver" + "://h:1433;user=a;" + "password=" + "s3cretpw99"),
        ("Webhook URL", "https://hooks.slack.com/services/" + "T00/B00/" + "x" * 24),
        ("Package registry auth token", "_authToken" + "=" + "npmtok" + "1" * 14),
        ("netrc-style credential",
         "machine registry.internal login svc " + "password " + "hunter2hunter2"),
        ("Cloud/service-account", "client_secret" + ": " + "Zx8" + "q" * 20),
        ("Kubeconfig credential", "client-key-data" + ": " + "LS0t" + "K" * 24),
        ("Generic API/secret/token assignment", "api_key" + " = " + "abcd1234efgh5678"),
        ("Quoted secret assignment", "password" + ': "' + "P@ss" + "w0rd!Complex" + '"'),
        ("Credential in connection string",
         "Server=db;Password=" + "Hunter2" + "Hunter2!" + ";Encrypt=True"),
        (".env-style sensitive", "DATABASE_PASSWORD" + "=" + "hunter2hunter2"),
        ("Long base64-ish", "blob " + "aB3" * 16),
        ("External email address", "reach " + "auditor" + "@" + "auditfirm.co"),
        ("CU2 staff email address", "reach " + "kdrake" + "@" + "cu-2.com"),
        ("Phone number", "call " + "541" + "-" + "555" + "-" + "0142"),
        ("Social security number", "ssn " + "123" + "-" + "45" + "-" + "6789"),
        ("Card-like PAN", "card " + "4111 1111 " + "1111 1111"),
        ("Member / share / NMLS", "member_number" + ": " + "884213"),
        ("Routing / account number",
         "routing " + "32118" + "0379"),
        ("Long all-digit ID", "chat " + "45887311" + "99"),
        ("Named credit union",
         "onboarding Mission " + "Federal " + "Credit Union" + " today"),
        ("Live CU2 tenant", "tenant " + "MB" + "FS" + " only"),
        ("Azure Container Apps FQDN",
         "https://ca-" + "cu2-mcp.icyplant-45887311.westus2"
         + ".azurecontainerapps.io" + "/mcp/"),
        ("Azure service FQDN", "cu2registry" + ".azurecr.io" + "/img:1"),
        ("Azure resource group", "deployed into " + "rg-" + "ops-platform"),
        ("Azure resource name",
         "az containerapp show -n " + "ca-" + "forge-studio"),
        ("Azure subscription / tenant GUID",
         "sub " + "3f2504e0-4f89-" + "11d3-9a0c-0305e82c3301"),
        ("Internal cu-2.com host", "see " + "ops" + ".cu-2.com"),
        ("Private org repo slug", "repo " + "credit-union-2-0-llc" + "/redvisor"),
        ("Absolute home path", "cd " + "/Users/" + "jdrake"),
        ("Tailscale / mesh hostname", "ssh box" + ".ts.net"),
        ("Tailscale CGNAT", "ping " + "100." + "90.241.40"),
        ("Shared-services VNet", "vnet " + "10.40." + "1.7"),
    ]

    def test_every_positive_sample_fires(self):
        for prefix, sample in self.POSITIVES:
            with self.subTest(rule=prefix):
                self.assertTrue(hits(prefix, sample),
                                f"rule {prefix!r} did not fire on its positive sample")

    def test_every_rule_has_a_positive_sample(self):
        covered = {p for p, _ in self.POSITIVES}
        for r in gate.RULES:
            with self.subTest(rule=r.label):
                self.assertTrue(any(r.label.startswith(p) for p in covered),
                                f"rule {r.label!r} has no positive sample")


# ---------------------------------------------------------------------------
# Placeholders and other negatives must NOT fire
# ---------------------------------------------------------------------------

class TestCallExpressionIsNotALiteral(unittest.TestCase):
    """
    THE EIGHTEENTH LEDGER ENTRY. This scanner reported two secrets in its own
    sibling detector:

        tools/theater/orphan_tests.py:157  QUOTED_TOKEN_RE = re.compile(
        tools/theater/orphan_tests.py:252  STEP_KEY        = re.compile(

    Regex constants whose NAMES contain TOKEN and KEY. `CODE_VALUE_RE` works from
    an allowlist of module prefixes and `re.` was not on it, so the scanner could
    only recognise code it had been told about.

    Fixed by keying on call SYNTAX rather than extending the prefix list: a
    secret is a literal and a literal has no parenthesis in it. That generalises
    to the next module and to bare calls like `build_key()`.
    """

    def test_the_two_real_false_positives(self):
        for line in ("QUOTED_TOKEN_RE = re.compile(", "STEP_KEY = re.compile("):
            with self.subTest(line=line):
                self.assertFalse(hits(".env-style sensitive KEY=VALUE", line))

    def test_call_shapes_are_not_literals(self):
        for value in ("re.compile(", "build_key()", "load_secret(path)",
                      "json.loads(", "Config.from_env()"):
            with self.subTest(value=value):
                self.assertFalse(gate.looks_like_a_literal_value(value))

    def test_generalises_beyond_the_re_module(self):
        # The point of the fix: an unknown module prefix must still be code.
        self.assertFalse(hits(".env-style sensitive KEY=VALUE",
                              "SESSION_KEY = somelib.derive("))

    # ---- false-positive guard on the guard -------------------------------
    # A validator that rejects everything would also pass the tests above, so
    # pin that real credential shapes are STILL flagged.

    def test_real_secrets_are_still_flagged(self):
        # Values are concatenated, not written whole: this file is itself scanned
        # by test_gate_does_not_flag_its_own_source, and a secret-SHAPED literal
        # here fails that check. It caught exactly this while the tests below
        # were being written. Also note no value may contain a placeholder
        # marker — is_placeholder() correctly discards anything saying EXAMPLE,
        # which is why AWS's documentation key cannot be used as a positive.
        for line in ("API_KEY = '" + "AKIA" + "J7Q2M4XZ" + "R9T1V3WB" + "'",
                     "SECRET_TOKEN=" + "sk-" + "9f3a2b7c" + "1d8e4a6f",
                     "DB_PASSWORD = " + "hunter2hunter2"):
            with self.subTest(line=line):
                self.assertTrue(hits(".env-style sensitive KEY=VALUE", line))

    def test_no_credential_alphabet_contains_a_parenthesis(self):
        # Why the rule is safe: '(' is not in any real credential alphabet.
        for value in ("AKIA" + "J7Q2M4XZ" + "R9T1V3WB",
                      "sk-" + "9f3a2b7c" + "1d8e4a6f",
                      "hunter2hunter2",
                      "dGhpcyBpcyBhIHRlc3Q=",
                      "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"):
            with self.subTest(value=value):
                self.assertTrue(gate.looks_like_a_literal_value(value))


class TestNegatives(unittest.TestCase):

    def test_placeholder_email_locals_are_ignored(self):
        for local in ("user", "you", "test", "inner", "outer", "noreply"):
            with self.subTest(local=local):
                self.assertFalse(hits("CU2 staff email address", local + "@" + "cu-2.com"))
                self.assertFalse(hits("External email address", local + "@" + "vendor.co"))

    def test_real_email_still_fires(self):
        self.assertTrue(hits("CU2 staff email address", "kdrake" + "@" + "cu-2.com"))

    def test_staff_and_external_emails_are_different_tiers(self):
        staff = "kdrake" + "@" + "cu-2.com"
        outside = "cfo" + "@" + "somecu.org"
        self.assertEqual(find_rule("CU2 staff email address").tier, "internal")
        self.assertEqual(find_rule("External email address").tier, "pii")
        # Each rule claims only its own side.
        self.assertFalse(hits("External email address", staff))
        self.assertFalse(hits("CU2 staff email address", outside))

    def test_example_domain_is_a_placeholder(self):
        self.assertFalse(hits("External email address", "jdoe" + "@" + "example.com"))

    def test_reserved_tlds_are_fixtures(self):
        """RFC 2606/6761 domains cannot belong to a real person."""
        for domain in ("bot.local", "mail.test", "host.invalid", "x.localhost"):
            with self.subTest(domain=domain):
                self.assertFalse(hits("External email address", "aperson" + "@" + domain))

    def test_ssh_clone_url_is_not_an_email(self):
        """Regression: git@github.com in an SSH remote matched the email rule."""
        url = '"git+ssh://' + "git" + "@" + 'github.com/org/lib.git#<sha>"'
        self.assertFalse(hits("External email address", url))

    def test_angle_bracket_placeholders_ignored(self):
        self.assertFalse(hits("Absolute home path", "cd /Users/<your-name>/work"))
        self.assertFalse(hits("Azure resource group", "az group show -n <rg-name>"))

    def test_git_sha_not_flagged_as_secret(self):
        sha40 = "a1b2c3d4" * 5
        sha64 = "0f1e2d3c" * 8
        self.assertFalse(hits("Long base64-ish", "commit " + sha40))
        self.assertFalse(hits("Long base64-ish", "digest " + sha64))

    def test_long_base64_still_fires_on_real_blob(self):
        self.assertTrue(hits("Long base64-ish", "blob " + "aB3" * 16))

    def test_slash_separated_word_lists_are_not_base64(self):
        """Regression: '/'-joined prose matched the naive 40+ char rule."""
        prose = "task contains " + "refactor/migration/rewrite/redesign/overhaul/architecture"
        self.assertFalse(hits("Long base64-ish", prose))

    def test_absolute_paths_are_not_base64(self):
        path = 'run_case "x" "' + "/Users/" + "someone/redvisor/apps/worker/Dockerfile" + '" 2'
        self.assertFalse(hits("Long base64-ish", path))

    def test_code_is_not_a_secret_value(self):
        """Regression: env reads and type annotations matched the generic rule."""
        for line in ("api_key = os.environ.get(" + '"OPS_API_KEY")',
                     "def reset_current_user(token: " + "contextvars.Token) -> None:",
                     "token = headers" + ".get('Authorization')",
                     "const secret = process" + ".env.APP_SECRET"):
            with self.subTest(line=line):
                self.assertFalse(hits("Generic API/secret/token assignment", line))

    def test_method_call_value_is_not_a_secret(self):
        """Regression: `token = GH_TOKEN_FILE.read_text().strip()`."""
        self.assertFalse(hits("Generic API/secret/token assignment",
                              "token = " + "GH_TOKEN_FILE.read_text" + "().strip()"))

    def test_hardcoded_literal_still_fires(self):
        self.assertTrue(hits("Generic API/secret/token assignment",
                             "api_key" + " = " + '"abcd1234efgh5678"'))

    def test_password_with_punctuation_is_caught(self):
        """Regression, ledger row 20: a complexity-policy password was INVISIBLE.

        The generic rule's value class is [A-Za-z0-9._/+-] and its terminator
        lookahead requires the value to end the expression. A password containing
        anything else -- which is to say, any password meeting a normal complexity
        policy -- matched neither. Verified 2026-08-05: this exact string passed
        `--profile public` CLEAN, exit 0, on a gate running across the estate,
        while foundry's looser generic rule caught and redacted it.

        The narrowed class was itself a fix, for `FILE.read_text().strip()`
        reading as a secret. Removing noise removed signal, and no fixture
        noticed because every existing sample used a value the narrow class still
        matched. Both directions are now pinned: this test, and the two above it.
        """
        pw = "Hunter2" + "Hunter2!"
        for line in (
            "Server=localhost,1433;User ID=svc;Password=" + pw + ";Encrypt=True",
            "password" + ': "' + pw + '"',
            "password" + ": '" + pw + "'",
            "client_secret" + ': "' + "abc!def" + "$ghi%jkl" + '"',
        ):
            with self.subTest(line=line):
                self.assertTrue(
                    hits("Quoted secret assignment", line)
                    or hits("Credential in connection string", line),
                    "a password containing punctuation went undetected",
                )

    def test_azure_storage_key_under_40_chars_is_caught(self):
        """Regression: NEITHER this scanner nor foundry's flagged this shape.

        An Azure Storage connection string was only ever caught incidentally, by
        the generic 40+ char base64 rule. Below that length both scanners passed
        it -- and per the estate review this is the most common Azure leak shape
        here. Caught now by the connection-string rule, on the key name rather
        than on the value's length.
        """
        key = "Zm9vYmFyYmF6cXV4MTIzNA=="          # 24 chars: under the 40+ rule
        conn = ("DefaultEndpointsProtocol=https;AccountName=stor;"
                "AccountKey=" + key + ";EndpointSuffix=core.windows.net")
        self.assertLess(len(key), 40, "fixture must stay under the base64 rule")
        self.assertTrue(hits("Credential in connection string", conn))

    def test_new_rules_do_not_reintroduce_the_call_expression_false_positive(self):
        """The narrowed class existed for a reason; the new rules must not undo it."""
        for line in ("token = " + "GH_TOKEN_FILE.read_text" + "().strip()",
                     "password = " + "get_password_from_vault" + "()",
                     "api_key = " + "config.get" + '("api_key")',
                     "secret = " + "os.environ" + '["MY_SECRET"]'):
            with self.subTest(line=line):
                self.assertFalse(hits("Quoted secret assignment", line))
                self.assertFalse(hits("Credential in connection string", line))

    def test_placeholder_credentials_stay_quiet(self):
        for line in ("Password=" + "<your-password>",
                     "password" + ': "' + "changeme-example" + '"',
                     "AccountKey=" + "<CU2_ACCOUNT_KEY>"):
            with self.subTest(line=line):
                self.assertFalse(hits("Quoted secret assignment", line))
                self.assertFalse(hits("Credential in connection string", line))

    def test_the_value_is_redacted_in_output(self):
        """A scanner that prints the secret it found has created a second leak."""
        pw = "Hunter2" + "Hunter2!"
        tmp = write_tree({"conn.cs": "var c = \"Password=" + pw + ";Encrypt=True\";\n"})
        code, out = run_gate([tmp, "--profile", "public"])
        self.assertEqual(code, 1, out)
        self.assertNotIn(pw, out, "the scanner leaked the value it was reporting")
        self.assertIn("[REDACTED]", out)

    def test_env_var_reference_is_not_a_secret(self):
        self.assertFalse(hits(".env-style sensitive", "OPS_API_KEY" + "=" + "${OPS_API_KEY}"))

    def test_key_file_path_is_not_a_key(self):
        self.assertFalse(hits(".env-style sensitive",
                              "MAC_SSH_KEY" + " = " + '"/home/' + 'someone/.ssh/id_ed25519"'))

    def test_change_me_is_a_placeholder(self):
        self.assertFalse(hits(".env-style sensitive",
                              "SECRET_KEY" + " = " + '"change-me-in-prod"'))

    def test_luhn_invalid_pan_ignored(self):
        self.assertFalse(hits("Card-like PAN", "num " + "4111 1111 1111 1112"))

    def test_luhn_valid_pan_fires(self):
        self.assertTrue(hits("Card-like PAN", "num " + "4111 1111 " + "1111 1111"))

    def test_all_zero_guid_is_placeholder(self):
        self.assertFalse(hits("Azure subscription / tenant GUID",
                              "sub " + "00000000-0000-0000-0000-000000000000"))


# ---------------------------------------------------------------------------
# Context qualification — the documented false-positive fixes
# ---------------------------------------------------------------------------

class TestContextQualification(unittest.TestCase):
    """
    Regression guard for the two real false positives found in cu2-standards:
    `pat-ca-secretref-stale-resolution` and `pat-ca-custom-domain-rebind` are
    pattern filenames, not Container Apps.
    """

    def test_pattern_filenames_do_not_fire_as_container_apps(self):
        for name in ("patterns/pat-ca-secretref-stale-resolution.md",
                     "patterns/pat-ca-custom-domain-rebind.md"):
            with self.subTest(name=name):
                self.assertFalse(hits("Azure resource name", name))

    def test_container_app_fires_with_azure_context(self):
        self.assertTrue(hits("Azure resource name",
                             "az containerapp update -n " + "ca-" + "forge-studio"))

    def test_container_app_silent_without_azure_context(self):
        self.assertFalse(hits("Azure resource name",
                              "the " + "ca-custom-domain" + " writeup covers this"))

    def test_routing_number_requires_financial_context(self):
        bare = "the build ran " + "32118" + "0379" + " iterations"
        self.assertFalse(hits("Routing / account number", bare))
        self.assertTrue(hits("Routing / account number",
                             "routing " + "32118" + "0379"))


# ---------------------------------------------------------------------------
# Profiles and tiers
# ---------------------------------------------------------------------------

class TestProfiles(unittest.TestCase):

    def test_internal_profile_excludes_internal_tier(self):
        labels = {r.label for r in gate.active_rules("internal")}
        self.assertNotIn("Absolute home path (/Users/<name> or /home/<name>)", labels)
        self.assertNotIn("CU2 staff email address", labels)
        self.assertIn("External email address", labels)

    def test_public_profile_includes_all_tiers(self):
        tiers = {r.tier for r in gate.active_rules("public")}
        self.assertEqual(tiers, set(gate.TIERS))

    def test_tier_filter_narrows_further(self):
        rules = gate.active_rules("public", ["secret"])
        self.assertTrue(rules)
        self.assertEqual({r.tier for r in rules}, {"secret"})

    def test_home_path_flagged_only_under_public_profile(self):
        tree = write_tree({"notes.md": "run from " + "/home/" + "kdrake" + "/work\n"})
        code_internal, _ = run_gate([tree, "--profile", "internal", "--quiet"])
        code_public, _ = run_gate([tree, "--profile", "public", "--quiet"])
        self.assertEqual(code_internal, 0)
        self.assertEqual(code_public, 1)


# ---------------------------------------------------------------------------
# Allowlist honesty
# ---------------------------------------------------------------------------

class TestAllowlist(unittest.TestCase):

    def _allow(self, body):
        tree = write_tree({gate.ALLOWLIST_FILENAME: body})
        return gate.load_allowlist(tree)

    def test_broad_wildcard_rejected(self):
        for bad in (".*", "^.*$", ".+", "(.*)"):
            with self.subTest(pattern=bad):
                _line, _path, errors = self._allow(bad + "\n")
                self.assertTrue(errors, f"{bad!r} should be rejected")
                self.assertIn("broad", errors[0][2].lower())

    def test_tiny_unanchored_fragment_rejected(self):
        _line, _path, errors = self._allow("ab\n")
        self.assertTrue(errors)

    def test_path_entry_must_be_anchored_or_relative(self):
        _line, _path, errors = self._allow("path:somefile\n")
        self.assertTrue(errors)
        self.assertIn("anchored", errors[0][2].lower())

    def test_valid_entries_load(self):
        body = (
            "# public marketing hosts\n"
            "line:redvisor\\.cu-2\\.com\n"
            "path:^docs/public/\n"
        )
        line_allow, path_allow, errors = self._allow(body)
        self.assertEqual(errors, [])
        self.assertEqual(len(line_allow), 1)
        self.assertEqual(len(path_allow), 1)

    def test_invalid_regex_rejected(self):
        _line, _path, errors = self._allow("line:[unclosed\n")
        self.assertTrue(errors)

    def test_broad_allowlist_entry_fails_the_run(self):
        tree = write_tree({gate.ALLOWLIST_FILENAME: ".*\n", "ok.md": "hello\n"})
        code, out = run_gate([tree, "--profile", "public"])
        self.assertEqual(code, 1)
        self.assertIn("[config]", out)

    def test_line_allow_suppresses_a_finding(self):
        tree = write_tree({
            gate.ALLOWLIST_FILENAME: "line:redvisor\\.cu-2\\.com\n",
            "docs.md": "public site " + "redvisor" + ".cu-2.com\n",
        })
        code, _ = run_gate([tree, "--profile", "public", "--quiet"])
        self.assertEqual(code, 0)


# ---------------------------------------------------------------------------
# Output contract
# ---------------------------------------------------------------------------

class TestOutput(unittest.TestCase):

    def test_clean_tree_exits_zero(self):
        tree = write_tree({"README.md": "Nothing sensitive here.\n"})
        code, out = run_gate([tree, "--profile", "public"])
        self.assertEqual(code, 0)
        self.assertIn("CLEAN", out)

    def test_findings_exit_one(self):
        tree = write_tree({"a.md": "mail " + "auditor" + "@" + "outsidefirm.co" + "\n"})
        code, out = run_gate([tree])
        self.assertEqual(code, 1)
        self.assertIn("[pii]", out)

    def test_report_mode_exits_zero_but_still_counts(self):
        tree = write_tree({"a.md": "mail " + "auditor" + "@" + "outsidefirm.co" + "\n"})
        code, out = run_gate([tree, "--report"])
        self.assertEqual(code, 0)
        self.assertIn("by tier", out)
        self.assertIn("report mode", out)

    def test_matched_value_is_redacted_in_output(self):
        secret_local = "auditor"
        tree = write_tree({"a.md": "mail " + secret_local + "@" + "outsidefirm.co" + "\n"})
        _code, out = run_gate([tree])
        self.assertIn("[REDACTED]", out)
        self.assertNotIn(secret_local + "@", out)

    def test_missing_target_exits_two(self):
        code, _ = run_gate(["/nonexistent/path/should/not/exist"])
        self.assertEqual(code, 2)

    def test_sensitive_filename_is_flagged_and_redacted(self):
        tree = write_tree({"notes-" + "auditor" + "@" + "outsidefirm.co" + ".md": "hi\n"})
        code, out = run_gate([tree])
        self.assertEqual(code, 1)
        self.assertIn("Sensitive value in file path", out)
        self.assertNotIn("auditor@", out)

    def test_binary_artifact_requires_review(self):
        tree = tempfile.mkdtemp(prefix="cu2sanitize-")
        with open(os.path.join(tree, "diagram.png"), "wb") as fh:
            fh.write(b"\x89PNG\r\n\x1a\n")
        code, out = run_gate([tree, "--profile", "public"])
        self.assertEqual(code, 1)
        self.assertIn("Risky binary", out)

    def test_gate_does_not_flag_its_own_source(self):
        here = os.path.dirname(os.path.abspath(__file__))
        code, out = run_gate([here, "--profile", "public"])
        self.assertEqual(code, 0, f"the sanitize tooling must be clean on itself:\n{out}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
