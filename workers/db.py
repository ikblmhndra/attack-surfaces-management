"""
ASM Platform — Worker Database Session
Shared async DB session factory for all workers.
"""
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


def _build_url() -> str:
    host = os.getenv("POSTGRES_HOST", "postgres")
    port = os.getenv("POSTGRES_PORT", "5432")
    db   = os.getenv("POSTGRES_DB",   "asmdb")
    user = os.getenv("POSTGRES_USER", "asmuser")
    pw   = os.getenv("POSTGRES_PASSWORD", "")
    return f"postgresql+asyncpg://{user}:{pw}@{host}:{port}/{db}"


_engine = create_async_engine(
    _build_url(),
    echo=False,
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,
    pool_recycle=3600,
    connect_args={
        "command_timeout": 60,
        "server_settings": {"application_name": "asm-worker"},
    },
)

_SessionLocal = async_sessionmaker(
    bind=_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Context manager providing an async DB session to workers."""
    async with _SessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
