"""
ASM Platform — Unit Tests: Bug Bounty scope enforcement (bounty_scope.py)

is_target_in_scope is the hard gate that decides whether the bounty pipeline
is structurally allowed to test a value. These tests exist to prove the
fail-closed and explicit-deny-wins invariants hold across domain/IP/URL rule
types before any exploit module is allowed to depend on it.
"""
from app.services.bounty_scope import is_target_in_scope


# ── Fail-closed defaults ──────────────────────────────────────

class TestFailClosed:
    def test_no_rules_defined_is_not_in_scope(self):
        assert is_target_in_scope("app.example.com", []) is False

    def test_none_rules_is_not_in_scope(self):
        assert is_target_in_scope("app.example.com", None) is False

    def test_empty_value_is_not_in_scope(self):
        rules = [{"pattern": "*.example.com", "type": "domain", "in_scope": True}]
        assert is_target_in_scope("", rules) is False

    def test_only_out_of_scope_rules_defined_is_not_in_scope(self):
        rules = [{"pattern": "*.example.com", "type": "domain", "in_scope": False}]
        assert is_target_in_scope("app.example.com", rules) is False

    def test_malformed_rule_entries_are_ignored_not_fatal(self):
        rules = ["not-a-dict", {"pattern": "*.example.com", "type": "domain", "in_scope": True}]
        assert is_target_in_scope("app.example.com", rules) is True

    def test_rule_missing_pattern_does_not_match(self):
        rules = [{"type": "domain", "in_scope": True}]
        assert is_target_in_scope("app.example.com", rules) is False


# ── Domain rules ───────────────────────────────────────────────

class TestDomainRules:
    def setup_method(self):
        self.rules = [{"pattern": "*.example.com", "type": "domain", "in_scope": True}]

    def test_exact_apex_match(self):
        rules = [{"pattern": "example.com", "type": "domain", "in_scope": True}]
        assert is_target_in_scope("example.com", rules) is True

    def test_wildcard_subdomain_match(self):
        assert is_target_in_scope("api.example.com", self.rules) is True

    def test_wildcard_matches_bare_apex_too(self):
        assert is_target_in_scope("example.com", self.rules) is True

    def test_nested_subdomain_matches_wildcard(self):
        assert is_target_in_scope("deep.nested.api.example.com", self.rules) is True

    def test_unrelated_domain_not_in_scope(self):
        assert is_target_in_scope("evil.com", self.rules) is False

    def test_lookalike_suffix_domain_not_in_scope(self):
        # "notexample.com" must not match "*.example.com"
        assert is_target_in_scope("notexample.com", self.rules) is False

    def test_glob_pattern_match(self):
        rules = [{"pattern": "api-*.example.com", "type": "domain", "in_scope": True}]
        assert is_target_in_scope("api-prod.example.com", rules) is True
        assert is_target_in_scope("web-prod.example.com", rules) is False

    def test_url_value_extracts_host_for_domain_rule(self):
        assert is_target_in_scope("https://api.example.com/v1/users?id=1", self.rules) is True

    def test_domain_rule_case_insensitive(self):
        rules = [{"pattern": "*.Example.COM", "type": "domain", "in_scope": True}]
        assert is_target_in_scope("API.example.com", rules) is True


# ── IP / CIDR rules ────────────────────────────────────────────

class TestIpRules:
    def test_exact_ip_match(self):
        rules = [{"pattern": "203.0.113.5", "type": "ip", "in_scope": True}]
        assert is_target_in_scope("203.0.113.5", rules) is True

    def test_cidr_match(self):
        rules = [{"pattern": "203.0.113.0/24", "type": "ip", "in_scope": True}]
        assert is_target_in_scope("203.0.113.200", rules) is True

    def test_ip_outside_cidr_not_in_scope(self):
        rules = [{"pattern": "203.0.113.0/24", "type": "ip", "in_scope": True}]
        assert is_target_in_scope("198.51.100.7", rules) is False

    def test_domain_value_never_matches_ip_rule(self):
        rules = [{"pattern": "203.0.113.0/24", "type": "ip", "in_scope": True}]
        assert is_target_in_scope("api.example.com", rules) is False

    def test_ip_host_extracted_from_url_value(self):
        rules = [{"pattern": "203.0.113.0/24", "type": "ip", "in_scope": True}]
        assert is_target_in_scope("http://203.0.113.9:8080/admin", rules) is True


# ── URL rules ──────────────────────────────────────────────────

class TestUrlRules:
    def test_url_glob_match(self):
        rules = [{"pattern": "https://api.example.com/v1/*", "type": "url", "in_scope": True}]
        assert is_target_in_scope("https://api.example.com/v1/users", rules) is True

    def test_url_glob_does_not_match_different_path(self):
        rules = [{"pattern": "https://api.example.com/v1/*", "type": "url", "in_scope": True}]
        assert is_target_in_scope("https://api.example.com/v2/users", rules) is False

    def test_url_rule_matches_full_value_not_just_host(self):
        rules = [{"pattern": "https://api.example.com/*", "type": "url", "in_scope": True}]
        # bare host without the URL shape should not satisfy a url-type rule
        assert is_target_in_scope("api.example.com", rules) is False


# ── Explicit out-of-scope beats in-scope (the core invariant) ──

class TestExplicitDenyWins:
    def test_out_of_scope_exact_beats_in_scope_wildcard(self):
        rules = [
            {"pattern": "*.example.com", "type": "domain", "in_scope": True},
            {"pattern": "payments.example.com", "type": "domain", "in_scope": False},
        ]
        assert is_target_in_scope("payments.example.com", rules) is False
        assert is_target_in_scope("api.example.com", rules) is True

    def test_out_of_scope_wildcard_beats_in_scope_wildcard(self):
        rules = [
            {"pattern": "*.example.com", "type": "domain", "in_scope": True},
            {"pattern": "*.internal.example.com", "type": "domain", "in_scope": False},
        ]
        assert is_target_in_scope("admin.internal.example.com", rules) is False
        assert is_target_in_scope("app.example.com", rules) is True

    def test_out_of_scope_cidr_beats_in_scope_supernet(self):
        rules = [
            {"pattern": "203.0.113.0/24", "type": "ip", "in_scope": True},
            {"pattern": "203.0.113.128/25", "type": "ip", "in_scope": False},
        ]
        assert is_target_in_scope("203.0.113.200", rules) is False
        assert is_target_in_scope("203.0.113.10", rules) is True

    def test_rule_order_does_not_matter_deny_still_wins(self):
        rules = [
            {"pattern": "payments.example.com", "type": "domain", "in_scope": False},
            {"pattern": "*.example.com", "type": "domain", "in_scope": True},
        ]
        assert is_target_in_scope("payments.example.com", rules) is False


# ── Mixed multi-program style rule sets ─────────────────────────

class TestRealisticProgramScope:
    def test_typical_program_scope(self):
        rules = [
            {"pattern": "*.example.com", "type": "domain", "in_scope": True},
            {"pattern": "203.0.113.0/28", "type": "ip", "in_scope": True},
            {"pattern": "staging.example.com", "type": "domain", "in_scope": False},
            {"pattern": "https://api.example.com/internal/*", "type": "url", "in_scope": False},
        ]
        assert is_target_in_scope("www.example.com", rules) is True
        assert is_target_in_scope("203.0.113.5", rules) is True
        assert is_target_in_scope("staging.example.com", rules) is False
        assert is_target_in_scope("https://api.example.com/internal/debug", rules) is False
        assert is_target_in_scope("unrelated-target.net", rules) is False
