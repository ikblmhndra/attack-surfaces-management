"""
ASM Platform — Unit Tests: Security Utilities
Tests for JWT creation/validation, password hashing, API key generation.
"""
import time
from datetime import datetime, timedelta, timezone

import pytest

from app.core.security import (
    compute_finding_fingerprint,
    generate_api_key,
    get_password_hash,
    hash_token,
    is_valid_cidr,
    is_valid_domain,
    sanitize_domain,
    sanitize_ip,
    verify_api_key,
    verify_password,
)


# ── Password hashing ──────────────────────────────────────────

class TestPasswordHashing:
    def test_hash_is_different_from_plaintext(self):
        pw = "TestPassword123!"
        hashed = get_password_hash(pw)
        assert hashed != pw

    def test_verify_correct_password(self):
        pw = "SecurePass@456"
        hashed = get_password_hash(pw)
        assert verify_password(pw, hashed) is True

    def test_verify_wrong_password(self):
        hashed = get_password_hash("correct-horse")
        assert verify_password("wrong-horse", hashed) is False

    def test_same_password_different_hashes(self):
        """bcrypt uses random salt → different hash each time."""
        pw = "same-password"
        h1 = get_password_hash(pw)
        h2 = get_password_hash(pw)
        assert h1 != h2
        # But both should verify
        assert verify_password(pw, h1) is True
        assert verify_password(pw, h2) is True

    def test_empty_password_hashes(self):
        hashed = get_password_hash("")
        assert verify_password("", hashed) is True

    def test_long_password(self):
        pw = "A" * 200
        hashed = get_password_hash(pw)
        assert verify_password(pw, hashed) is True


# ── JWT tokens ────────────────────────────────────────────────

class TestJWTTokens:
    def setup_method(self):
        # Patch settings for tests
        import app.core.security as sec_module
        import app.core.config as cfg_module
        self._orig_secret = cfg_module.settings.SECRET_KEY
        cfg_module.settings.SECRET_KEY = "test-secret-key-that-is-long-enough-32c"

    def teardown_method(self):
        import app.core.config as cfg_module
        cfg_module.settings.SECRET_KEY = self._orig_secret

    def test_create_and_verify_access_token(self):
        from app.core.security import create_access_token, verify_token
        token = create_access_token("user-123", "ws-456", "analyst")
        payload = verify_token(token)
        assert payload is not None
        assert payload["sub"] == "user-123"
        assert payload["wid"] == "ws-456"
        assert payload["role"] == "analyst"
        assert payload["type"] == "access"

    def test_create_and_verify_refresh_token(self):
        from app.core.security import create_refresh_token, verify_token
        token = create_refresh_token("user-789")
        payload = verify_token(token)
        assert payload is not None
        assert payload["sub"] == "user-789"
        assert payload["type"] == "refresh"

    def test_invalid_token_returns_none(self):
        from app.core.security import verify_token
        assert verify_token("not.a.valid.token") is None
        assert verify_token("") is None
        assert verify_token("Bearer abc123") is None

    def test_tampered_token_invalid(self):
        from app.core.security import create_access_token, verify_token
        token = create_access_token("user-1", "ws-1", "viewer")
        # Tamper with the payload section
        parts = token.split(".")
        tampered = parts[0] + ".TAMPERED" + parts[2]
        assert verify_token(tampered) is None

    def test_extra_claims_included(self):
        from app.core.security import create_access_token, verify_token
        token = create_access_token("user-1", "ws-1", "admin", extra_claims={"custom": "value"})
        payload = verify_token(token)
        assert payload["custom"] == "value"

    def test_jti_is_unique(self):
        from app.core.security import create_access_token, verify_token
        t1 = create_access_token("user-1", "ws-1", "viewer")
        t2 = create_access_token("user-1", "ws-1", "viewer")
        p1 = verify_token(t1)
        p2 = verify_token(t2)
        assert p1["jti"] != p2["jti"]


# ── API key utilities ─────────────────────────────────────────

class TestAPIKeyUtils:
    def test_generate_returns_three_parts(self):
        raw, key_hash, prefix = generate_api_key()
        assert raw is not None
        assert key_hash is not None
        assert prefix is not None

    def test_raw_key_starts_with_asm(self):
        raw, _, _ = generate_api_key()
        assert raw.startswith("asm_")

    def test_prefix_is_first_12_chars(self):
        raw, _, prefix = generate_api_key()
        assert prefix == raw[:12]

    def test_hash_differs_from_raw(self):
        raw, key_hash, _ = generate_api_key()
        assert key_hash != raw

    def test_verify_correct_key(self):
        raw, key_hash, _ = generate_api_key()
        assert verify_api_key(raw, key_hash) is True

    def test_verify_wrong_key(self):
        _, key_hash, _ = generate_api_key()
        assert verify_api_key("wrong_key", key_hash) is False

    def test_unique_keys_each_call(self):
        r1, _, _ = generate_api_key()
        r2, _, _ = generate_api_key()
        assert r1 != r2

    def test_hash_token_deterministic(self):
        token = "some-refresh-token-value"
        h1 = hash_token(token)
        h2 = hash_token(token)
        assert h1 == h2

    def test_hash_token_different_inputs(self):
        assert hash_token("token-a") != hash_token("token-b")


# ── Fingerprint utilities ─────────────────────────────────────

class TestFingerprints:
    def test_same_inputs_same_fingerprint(self):
        f1 = compute_finding_fingerprint("org-1", "template-abc", "https://example.com")
        f2 = compute_finding_fingerprint("org-1", "template-abc", "https://example.com")
        assert f1 == f2

    def test_different_org_different_fingerprint(self):
        f1 = compute_finding_fingerprint("org-1", "template-abc", "https://example.com")
        f2 = compute_finding_fingerprint("org-2", "template-abc", "https://example.com")
        assert f1 != f2

    def test_different_template_different_fingerprint(self):
        f1 = compute_finding_fingerprint("org-1", "template-a", "https://example.com")
        f2 = compute_finding_fingerprint("org-1", "template-b", "https://example.com")
        assert f1 != f2

    def test_url_case_insensitive(self):
        f1 = compute_finding_fingerprint("org-1", "tpl", "https://EXAMPLE.COM")
        f2 = compute_finding_fingerprint("org-1", "tpl", "https://example.com")
        assert f1 == f2

    def test_fingerprint_is_hex_64(self):
        fp = compute_finding_fingerprint("org-1", "tpl", "target")
        assert len(fp) == 64
        assert all(c in "0123456789abcdef" for c in fp)


# ── Input validation ──────────────────────────────────────────

class TestInputValidation:
    def test_valid_domains(self):
        valid = [
            "example.com",
            "sub.example.com",
            "a.b.c.example.co.uk",
            "xn--nxasmq6b.com",
        ]
        for domain in valid:
            assert is_valid_domain(domain), f"Should be valid: {domain}"

    def test_invalid_domains(self):
        invalid = [
            "",
            "not-a-domain",
            "has space.com",
            "http://example.com",
            ".example.com",
            "example.",
        ]
        for domain in invalid:
            assert not is_valid_domain(domain), f"Should be invalid: {domain}"

    def test_sanitize_domain_lowercases(self):
        assert sanitize_domain("EXAMPLE.COM") == "example.com"

    def test_sanitize_domain_strips_dot(self):
        assert sanitize_domain("example.com.") == "example.com"

    def test_sanitize_domain_strips_whitespace(self):
        assert sanitize_domain("  example.com  ") == "example.com"

    def test_sanitize_ip_valid(self):
        assert sanitize_ip("192.168.1.1") == "192.168.1.1"
        assert sanitize_ip("::1")         == "::1"

    def test_sanitize_ip_invalid_raises(self):
        with pytest.raises(ValueError):
            sanitize_ip("not-an-ip")

    def test_valid_cidrs(self):
        valid = ["192.168.0.0/24", "10.0.0.0/8", "172.16.0.0/12"]
        for cidr in valid:
            assert is_valid_cidr(cidr), f"Should be valid: {cidr}"

    def test_invalid_cidrs(self):
        invalid = ["192.168.0.0", "not-a-cidr", "999.0.0.0/24"]
        for cidr in invalid:
            assert not is_valid_cidr(cidr), f"Should be invalid: {cidr}"
