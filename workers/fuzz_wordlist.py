"""Shared content/directory-fuzzing wordlist for ffuf.

Used by web_crawl_worker.py and discovery_worker.py's ffuf invocations. Previously
each file hardcoded an identical, separate ~28-word Python literal as a "fallback"
in case a system wordlist (dirb/seclists) was installed — but neither is actually
installed in the worker image, so that 28-word list was, unconditionally, the
entire fuzzing surface in every scan that ever ran ffuf. Consolidated into one
shared, substantially expanded list rather than fixing the same duplicated literal
in two places independently.
"""
from pathlib import Path
from typing import Dict, Optional

DEFAULT_FUZZ_WORDS = [
    # Admin / management panels
    "admin", "administrator", "admin-panel", "admincp", "admin_area", "adminpanel",
    "cpanel", "panel", "dashboard", "manage", "management", "portal", "console",
    "controlpanel", "webadmin", "backend", "moderator",
    # Auth / session
    "login", "logout", "signin", "signup", "register", "auth", "sso", "oauth",
    "saml", "session", "password-reset", "forgot-password", "reset-password",
    "account", "profile", "user", "users",
    # API / docs
    "api", "api/v1", "api/v2", "api/v3", "graphql", "graphiql", "swagger",
    "swagger-ui", "swagger-ui.html", "api-docs", "openapi.json", "swagger.json",
    "docs", "redoc", "api/swagger.json", "api/docs",
    # Backups / dumps
    "backup", "backups", "backup.zip", "backup.tar.gz", "backup.sql", "dump",
    "dump.sql", "db.sql", "database.sql", "site-backup", "old", "old-site",
    "archive", "site.zip", "www.zip", "backup.rar", "export.sql",
    # VCS / config exposure
    ".git", ".git/config", ".git/HEAD", ".svn", ".hg", ".env", ".env.local",
    ".env.production", ".env.dev", "config", "config.php", "config.json",
    "configuration", "settings", "web.config", ".htaccess", ".htpasswd",
    "config.yml", "config.yaml", "appsettings.json", "settings.py",
    # CMS-specific
    "wp-admin", "wp-content", "wp-login.php", "wp-config.php", "wp-json",
    "xmlrpc.php", "typo3", "sites/default", "craft",
    "magento", "umbraco", "concrete5",
    # Cloud / infra hints
    ".aws", ".azure", ".gcp", ".kube", ".docker", "docker-compose.yml",
    "Dockerfile", ".terraform", "k8s", "kubernetes", ".dockerignore",
    # Dev / test / staging
    "test", "testing", "dev", "development", "staging", "stage", "qa", "uat",
    "demo", "sandbox", "beta", "internal", "debug", "test-api", "dev-api",
    # Monitoring / health / observability
    "health", "healthz", "status", "ping", "metrics", "actuator", "prometheus",
    "grafana", "actuator/health", "actuator/env", "actuator/info",
    # File storage
    "uploads", "upload", "files", "assets", "static", "media", "storage",
    "public", "private", "tmp", "temp", "cache", "logs", "log",
    # Misc well-known / discovery
    ".well-known", ".well-known/security.txt", "sitemap.xml", "robots.txt",
    "humans.txt", "crossdomain.xml", "security.txt", "version", "VERSION",
    "CHANGELOG", "CHANGELOG.md", "README.md", "LICENSE", "manifest.json",
    # CI/CD
    "jenkins", ".jenkins", "ci", "build", ".circleci", ".github",
    ".gitlab-ci.yml", "travis", ".travis.yml",
    # DB admin tools
    "phpmyadmin", "adminer", "pgadmin", "mongo-express", "redis-commander",
    # Secrets-adjacent paths (detection only — never fetched blindly beyond ffuf's probe)
    "secrets", "secret", "credentials", "keys", "id_rsa", ".ssh",
    "private.key", "server.key", "id_rsa.pub", "known_hosts",
    # Common app framework paths
    "debug/vars", "console/", "_profiler", "phpinfo.php",
    "info.php", "server-status", "server-info", "trace", "elmah.axd",
]


def resolve_fuzz_wordlist(tmpdir: Path, config: Dict, filename: str = "fuzz_words.txt") -> str:
    """Prefer a real installed wordlist (dirb/seclists) if present; otherwise write
    the shared curated fallback list to tmpdir and return its path."""
    candidates = [
        config.get("fuzz_wordlist", ""),
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return str(candidate)

    fallback = tmpdir / filename
    fallback.write_text("\n".join(DEFAULT_FUZZ_WORDS))
    return str(fallback)
