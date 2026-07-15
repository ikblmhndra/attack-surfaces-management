"""
ASM Platform — CIS Controls v8 compliance mapping (display-only, no scoring effect)

Maps every Finding.category value (the same taxonomy risk_engine.py's
FINDING_CATEGORY_MAP already relies on -- reused here, not re-derived) to a
CIS Controls v8 Control + Safeguard, for the compliance report type.
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple

CIS_CONTROLS: Dict[str, str] = {
    "3": "Data Protection",
    "4": "Secure Configuration of Enterprise Assets and Software",
    "5": "Account Management",
    "6": "Access Control Management",
    "7": "Continuous Vulnerability Management",
    "9": "Email and Web Browser Protections",
    "10": "Malware Defenses",
    "12": "Network Infrastructure Management",
}

# category -> (control_id, safeguard_id, safeguard_title)
CATEGORY_TO_CIS_SAFEGUARD: Dict[str, Tuple[str, str, str]] = {
    # Control 3 -- Data Protection: encrypt sensitive data in transit
    "old_tls_version": ("3", "3.10", "Encrypt Sensitive Data in Transit"),
    "weak_cipher": ("3", "3.10", "Encrypt Sensitive Data in Transit"),
    "expired_certificate": ("3", "3.10", "Encrypt Sensitive Data in Transit"),
    "self_signed_certificate": ("3", "3.10", "Encrypt Sensitive Data in Transit"),
    "cert_expiring_soon": ("3", "3.10", "Encrypt Sensitive Data in Transit"),
    "wildcard_certificate": ("3", "3.10", "Encrypt Sensitive Data in Transit"),
    "tls_misconfiguration": ("3", "3.10", "Encrypt Sensitive Data in Transit"),
    "mixed_content": ("3", "3.10", "Encrypt Sensitive Data in Transit"),
    "http_only": ("3", "3.10", "Encrypt Sensitive Data in Transit"),

    # Control 3 -- Data Protection: access control on sensitive data stores
    "exposed_database": ("3", "3.3", "Configure Data Access Control Lists"),
    "exposed_storage": ("3", "3.3", "Configure Data Access Control Lists"),
    "cloud_public_exposure": ("3", "3.3", "Configure Data Access Control Lists"),
    "exposed_backup": ("3", "3.3", "Configure Data Access Control Lists"),
    "exposed_env_file": ("3", "3.3", "Configure Data Access Control Lists"),
    "credential_exposure": ("3", "3.3", "Configure Data Access Control Lists"),

    # Control 4 -- Secure Configuration of Enterprise Assets and Software
    "missing_hsts": ("4", "4.1", "Establish and Maintain a Secure Configuration Process"),
    "missing_csp": ("4", "4.1", "Establish and Maintain a Secure Configuration Process"),
    "missing_xframe": ("4", "4.1", "Establish and Maintain a Secure Configuration Process"),
    "missing_xcto": ("4", "4.1", "Establish and Maintain a Secure Configuration Process"),
    "missing_referrer_policy": ("4", "4.1", "Establish and Maintain a Secure Configuration Process"),
    "cors_misconfiguration": ("4", "4.1", "Establish and Maintain a Secure Configuration Process"),
    "clickjacking": ("4", "4.1", "Establish and Maintain a Secure Configuration Process"),
    "insecure_cookie": ("4", "4.1", "Establish and Maintain a Secure Configuration Process"),
    "directory_listing": ("4", "4.1", "Establish and Maintain a Secure Configuration Process"),
    "open_redirect": ("4", "4.1", "Establish and Maintain a Secure Configuration Process"),
    "exposed_git": ("4", "4.1", "Establish and Maintain a Secure Configuration Process"),
    "debug_endpoint": ("4", "4.1", "Establish and Maintain a Secure Configuration Process"),
    "stack_trace": ("4", "4.1", "Establish and Maintain a Secure Configuration Process"),
    "source_disclosure": ("4", "4.1", "Establish and Maintain a Secure Configuration Process"),

    # Control 5 -- Account Management
    "default_credentials": ("5", "5.2", "Use Unique Passwords"),

    # Control 6 -- Access Control Management
    "exposed_admin_panel": ("6", "6.8", "Define and Maintain Role-Based Access Control"),
    "exposed_api": ("6", "6.8", "Define and Maintain Role-Based Access Control"),

    # Control 7 -- Continuous Vulnerability Management
    "known_cve": ("7", "7.1", "Establish and Maintain a Vulnerability Management Process"),
    "outdated_software": ("7", "7.1", "Establish and Maintain a Vulnerability Management Process"),
    "eol_software": ("7", "7.1", "Establish and Maintain a Vulnerability Management Process"),

    # Control 9 -- Email and Web Browser Protections
    "missing_spf": ("9", "9.2", "Email Authentication and DNS Integrity"),
    "missing_dmarc": ("9", "9.2", "Email Authentication and DNS Integrity"),
    "dmarc_misconfiguration": ("9", "9.2", "Email Authentication and DNS Integrity"),
    "missing_dnssec": ("9", "9.2", "Email Authentication and DNS Integrity"),

    # Control 10 -- Malware Defenses (reputation signals)
    "malware_detected": ("10", "10.1", "Deploy and Maintain Anti-Malware Software"),
    "phishing_detected": ("10", "10.1", "Deploy and Maintain Anti-Malware Software"),
    "blacklisted_ip": ("10", "10.1", "Deploy and Maintain Anti-Malware Software"),
    "spam_reputation": ("10", "10.1", "Deploy and Maintain Anti-Malware Software"),

    # Control 12 -- Network Infrastructure Management
    "open_port": ("12", "12.2", "Establish and Maintain a Secure Network Architecture"),
    "exposed_service": ("12", "12.2", "Establish and Maintain a Secure Network Architecture"),
    "firewall_bypass": ("12", "12.2", "Establish and Maintain a Secure Network Architecture"),
    "rdp_exposed": ("12", "12.2", "Establish and Maintain a Secure Network Architecture"),
    "ssh_exposed": ("12", "12.2", "Establish and Maintain a Secure Network Architecture"),
    "telnet_exposed": ("12", "12.2", "Establish and Maintain a Secure Network Architecture"),
    "smb_exposed": ("12", "12.2", "Establish and Maintain a Secure Network Architecture"),
    "dangling_dns": ("12", "12.2", "Establish and Maintain a Secure Network Architecture"),
    "zone_transfer": ("12", "12.2", "Establish and Maintain a Secure Network Architecture"),
    "subdomain_takeover": ("12", "12.2", "Establish and Maintain a Secure Network Architecture"),
}


def get_cis_mapping(category: str) -> Optional[Tuple[str, str, str]]:
    """Return (control_id, safeguard_id, safeguard_title) for a Finding.category, or None."""
    return CATEGORY_TO_CIS_SAFEGUARD.get((category or "").lower())
