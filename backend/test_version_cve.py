import asyncio, sys
sys.path.insert(0, "/app")

async def main():
    from app.core.database import init_db
    import app.core.database as dbmod
    from app.services.version_cve_intel import get_matching_cves

    await init_db()
    cases = [
        ("Apache HTTP Server", "2.4.49"),
        ("Apache HTTP Server", "2.4.62"),
        ("Apache HTTP Server", "2.4.6"),
        ("OpenSSL", "1.0.2k"),
        ("PHP", "7.4.33"),
        ("Nginx", "1.14.1"),
        ("Bootstrap", "5.3.3"),  # unmapped product, should return []
    ]
    async with dbmod.AsyncSessionLocal() as db:
        for name, version in cases:
            matches = await get_matching_cves(db, name, version)
            print(f"{name} {version}: {len(matches)} matches")
            for m in matches[:3]:
                print(f"   {m['cve_id']} cvss={m['cvss_score']} desc={m['description'][:80]}")

asyncio.run(main())
