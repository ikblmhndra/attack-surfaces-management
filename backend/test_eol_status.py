import asyncio, sys
sys.path.insert(0, "/app")

async def main():
    from app.core.database import init_db
    import app.core.database as dbmod
    from app.services.eol_intel import get_eol_status

    await init_db()
    cases = [
        ("OpenSSL", "1.0.2k"),
        ("PHP", "7.4.33"),
        ("Nginx", "1.14.1"),
        ("Drupal", "7"),
        ("WordPress", "6.8.2"),
        ("Apache HTTP Server", "2.4.62"),  # eol: false expected
        ("PHP", "8.3.28"),  # not EOL yet expected
    ]
    async with dbmod.AsyncSessionLocal() as db:
        for name, version in cases:
            status = await get_eol_status(db, name, version)
            print(f"{name} {version}: {status}")

asyncio.run(main())
