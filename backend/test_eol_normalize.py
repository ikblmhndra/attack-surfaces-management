import sys
sys.path.insert(0, "/app")
from app.services.eol_intel import resolve_product_slug, normalize_cycle

cases = [
    ("Apache HTTP Server", "2.4.62"),
    ("Bootstrap", "5.3.3"),
    ("OpenSSL", "1.0.2k"),
    ("OpenSSL", "1.1.1p"),
    ("OpenSSL", "3.5.7"),
    ("PHP", "7.4.33"),
    ("PHP", "8.3.28"),
    ("Nginx", "1.14.1"),
    ("WordPress", "6.8.2"),
    ("Drupal", "7"),
    ("Drupal", "8"),
    ("IIS", "10.0"),
]
for name, version in cases:
    slug = resolve_product_slug(name)
    cycle = normalize_cycle(slug, version) if slug else None
    print(f"{name!r:25} {version!r:10} -> slug={slug!r:22} cycle={cycle!r}")
