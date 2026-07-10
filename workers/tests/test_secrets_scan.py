from workers.secrets_scan import find_endpoints, find_secrets, find_subdomains, mask_secret


def test_finds_aws_access_key():
    hits = find_secrets('aws_key = "AKIAABCDEFGHIJKLMNOP"')
    assert len(hits) == 1
    assert hits[0]["type"] == "aws_access_key"
    assert hits[0]["masked"] == "AKIA************MNOP"


def test_excludes_documented_example_key():
    # AWS's own docs example key — a real false-positive magnet for a naive regex.
    assert find_secrets("AKIAIOSFODNN7EXAMPLE") == []


def test_finds_generic_api_key_assignment():
    hits = find_secrets('api_key: "sk_live_abcdefghijklmnopqrstuvwx"')
    assert len(hits) == 1
    assert hits[0]["type"] == "generic_api_key"


def test_finds_jwt():
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    hits = find_secrets(token)
    assert any(h["type"] == "jwt" for h in hits)


def test_finds_pem_private_key_header():
    hits = find_secrets("-----BEGIN RSA PRIVATE KEY-----\nMIIEow...")
    assert any(h["type"] == "pem_private_key" for h in hits)


def test_excludes_placeholder_values():
    assert find_secrets('api_key = "changeme_1234567890ab"') == []
    assert find_secrets('token: "your_api_key_goes_here_1234"') == []


def test_never_stores_full_secret_value():
    info = mask_secret("AKIAABCDEFGHIJKLMNOP")
    assert "AKIAABCDEFGHIJKLMNOP" not in info["masked"]
    assert info["masked"].startswith("AKIA")
    assert info["masked"].endswith("MNOP")
    assert len(info["sha256"]) == 64


def test_dedupes_identical_secrets_by_hash():
    text = 'a="AKIAABCDEFGHIJKLMNOP" b="AKIAABCDEFGHIJKLMNOP"'
    assert len(find_secrets(text)) == 1


def test_find_endpoints_resolves_relative_paths():
    text = 'fetch("/api/v1/users"); axios.get("/internal/admin")'
    endpoints = find_endpoints(text, "https://example.com/static/app.js")
    assert "https://example.com/api/v1/users" in endpoints
    assert "https://example.com/internal/admin" in endpoints


def test_find_subdomains_only_matches_root_domain():
    text = "connect to api.example.com or admin.example.com, not other.com"
    subs = find_subdomains(text, "example.com")
    assert set(subs) == {"api.example.com", "admin.example.com"}


def test_find_subdomains_empty_for_missing_root():
    assert find_subdomains("nothing relevant here", "") == []
