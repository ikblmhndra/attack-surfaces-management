"""
ASM Platform — Database Connection Management
Async SQLAlchemy engine with connection pooling, health checks, and migrations.
"""
import structlog
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool, AsyncAdaptedQueuePool

from app.core.config import settings

log = structlog.get_logger()

# ── Engine ─────────────────────────────────────────────────────
_engine: AsyncEngine | None = None
AsyncSessionLocal: async_sessionmaker[AsyncSession] | None = None


async def init_db() -> None:
    """Initialize async database engine and session factory."""
    global _engine, AsyncSessionLocal

    _engine = create_async_engine(
        settings.DATABASE_URL,
        echo=settings.DEBUG,
        pool_size=settings.POSTGRES_POOL_SIZE,
        max_overflow=settings.POSTGRES_MAX_OVERFLOW,
        pool_timeout=settings.POSTGRES_POOL_TIMEOUT,
        pool_pre_ping=True,
        pool_recycle=3600,
        connect_args={
            "command_timeout": 30,
            "server_settings": {
                "application_name": "asm-api",
                "jit": "off",  # Disable JIT for short queries
            },
        },
    )

    AsyncSessionLocal = async_sessionmaker(
        bind=_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )

    # Verify connection
    async with _engine.begin() as conn:
        await conn.execute(__import__("sqlalchemy").text("SELECT 1"))

    log.info(
        "database_initialized",
        host=settings.POSTGRES_HOST,
        db=settings.POSTGRES_DB,
        pool_size=settings.POSTGRES_POOL_SIZE,
    )


async def close_db() -> None:
    """Dispose database engine and close all connections."""
    global _engine
    if _engine:
        await _engine.dispose()
        _engine = None
        log.info("database_closed")


async def get_session() -> AsyncSession:
    """
    Dependency-injectable async database session.
    Used as FastAPI dependency via Depends(get_db).
    """
    if AsyncSessionLocal is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")

    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def get_db_engine() -> AsyncEngine:
    """Return the raw engine for migrations or bulk operations."""
    if _engine is None:
        raise RuntimeError("Database not initialized.")
    return _engine
