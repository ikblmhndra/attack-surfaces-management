"""
ASM Platform — Security Utilities
JWT creation/validation, password hashing, API key generation.
"""
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

# ── Password hashing ──────────────────────────────────────────
_pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12,
)


def get_password_hash(password: str) -> str:
    """Hash a plaintext password with bcrypt."""
    return _pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against its bcrypt hash."""
    return _pwd_context.verify(plain_password, hashed_password)


# ── JWT tokens ────────────────────────────────────────────────

def create_access_token(
    subject: str,
    workspace_id: str,
    role: str,
    extra_claims: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Create a signed JWT access token.

    Claims:
        sub: user_id
        wid: workspace_id
        role: user role
        type: "access"
        exp: expiration timestamp
        iat: issued-at timestamp
    """
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    payload: Dict[str, Any] = {
        "sub": str(subject),
        "wid": str(workspace_id),
        "role": role,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": secrets.token_hex(16),  # JWT ID for revocation
    }

    if extra_claims:
        payload.update(extra_claims)

    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(subject: str) -> str:
    """
    Create a long-lived refresh token.
    Stored as a hash in the DB for single-use rotation.
    """
    now = datetime.now(timezone.utc)
    expire = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    payload: Dict[str, Any] = {
        "sub": str(subject),
        "type": "refresh",
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": secrets.token_hex(24),
    }

    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Decode and validate a JWT token.
    Returns payload dict or None on failure.
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={"verify_exp": True},
        )
        return payload
    except JWTError:
        return None


def decode_token_unsafe(token: str) -> Optional[Dict[str, Any]]:
    """
    Decode JWT without verifying expiry — for debugging only.
    Never use in auth flows.
    """
    try:
        return jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={"verify_exp": False},
        )
    except JWTError:
        return None


# ── API Key utilities ─────────────────────────────────────────

def generate_api_key() -> tuple[str, str, str]:
    """
    Generate a new API key.

    Returns:
        (raw_key, key_hash, key_prefix)

    Format: asm_<random_hex_48>
    Prefix stored in DB for identification, hash stored for verification.
    """
    raw = "asm_" + secrets.token_hex(32)
    key_prefix = raw[:12]  # "asm_" + 8 chars
    key_hash = hash_token(raw)
    return raw, key_hash, key_prefix


def verify_api_key(raw_key: str, stored_hash: str) -> bool:
    """Constant-time comparison of API key hash."""
    computed = hash_token(raw_key)
    return hmac.compare_digest(computed, stored_hash)


def hash_token(token: str) -> str:
    """SHA-256 hash of a token string (for storage)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ── Fingerprint utilities ─────────────────────────────────────

def compute_finding_fingerprint(org_id: str, template_id: str, target: str) -> str:
    """
    Stable fingerprint for deduplicating findings.
    Same org + template + target → same fingerprint.
    """
    payload = f"{org_id}:{template_id}:{target.lower().strip()}"
    return hashlib.sha256(payload.encode()).hexdigest()


def compute_asset_fingerprint(org_id: str, asset_type: str, value: str) -> str:
    """Stable fingerprint for asset deduplication."""
    payload = f"{org_id}:{asset_type}:{value.lower().strip()}"
    return hashlib.sha256(payload.encode()).hexdigest()


# ── Input sanitization ────────────────────────────────────────

def sanitize_domain(domain: str) -> str:
    """Normalize a domain name: lowercase, strip whitespace and trailing dots."""
    return domain.strip().lower().rstrip(".")


def sanitize_ip(ip: str) -> str:
    """Normalize an IP address string."""
    import ipaddress
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        raise ValueError(f"Invalid IP address: {ip}")


def is_valid_domain(domain: str) -> bool:
    """Validate a domain name."""
    import re
    pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    return bool(pattern.match(domain)) and len(domain) <= 253


def is_valid_cidr(cidr: str) -> bool:
    """Validate a CIDR range."""
    import ipaddress
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def is_valid_asn(asn: str) -> bool:
    """Validate an ASN (e.g., AS12345)."""
    import re
    return bool(re.match(r"^(AS)?\d{1,10}$", asn.strip(), re.IGNORECASE))


# ── Rate limiting helpers ─────────────────────────────────────

def get_rate_limit_key(identifier: str, endpoint: str) -> str:
    """Generate Redis key for rate limiting."""
    return f"ratelimit:{endpoint}:{hashlib.md5(identifier.encode()).hexdigest()}"
