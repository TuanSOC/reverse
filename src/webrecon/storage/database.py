"""Async database engine + session management (SQLite via aiosqlite)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from ..core.errors import StorageError
from .models import Base


def _ensure_parent_dir(url: str) -> None:
    """For an on-disk SQLite URL, create the parent directory if missing.

    Avoids the opaque "unable to open database file" error when the target
    directory (e.g. ``scans/``) does not exist yet. In-memory URLs are skipped.
    """
    try:
        parsed = make_url(url)
    except Exception:  # pragma: no cover - defensive
        return
    if not parsed.drivername.startswith("sqlite"):
        return
    database = parsed.database
    if not database or database == ":memory:":
        return
    parent = Path(database).parent
    if parent and not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)


class Database:
    """Owns the async engine and hands out sessions."""

    def __init__(self, url: str = "sqlite+aiosqlite:///webrecon.db", *, echo: bool = False) -> None:
        self.url = url
        _ensure_parent_dir(url)
        try:
            self._engine: AsyncEngine = create_async_engine(url, echo=echo, future=True)
        except Exception as exc:  # pragma: no cover - misconfiguration
            raise StorageError(f"could not create engine for {url!r}: {exc}") from exc
        self._session_factory = async_sessionmaker(
            self._engine, expire_on_commit=False, class_=AsyncSession
        )

    @property
    def engine(self) -> AsyncEngine:
        return self._engine

    async def create_all(self) -> None:
        """Create tables if they do not exist."""
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def drop_all(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """Provide a transactional session scope."""
        session = self._session_factory()
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

    async def dispose(self) -> None:
        await self._engine.dispose()


async def init_db(url: str = "sqlite+aiosqlite:///webrecon.db") -> Database:
    """Create a :class:`Database` and ensure the schema exists."""
    db = Database(url)
    await db.create_all()
    return db
