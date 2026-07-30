"""Database engine and transaction helpers."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine
from sqlalchemy import create_engine as sqlalchemy_create_engine
from sqlalchemy.orm import Session, sessionmaker

from vuln_proof_claw.config.settings import Settings

SessionFactory = sessionmaker[Session]


def create_engine(
    database_url: str,
    *,
    echo: bool = False,
    pool_pre_ping: bool = True,
) -> Engine:
    """Create a synchronous SQLAlchemy engine."""
    return sqlalchemy_create_engine(
        database_url,
        echo=echo,
        pool_pre_ping=pool_pre_ping,
    )


def create_engine_from_settings(settings: Settings) -> Engine:
    """Create an engine without exposing the configured secret in logs."""
    return create_engine(
        settings.database.url.get_secret_value(),
        echo=settings.database.echo,
    )


def create_session_factory(engine: Engine) -> SessionFactory:
    """Create sessions with explicit transaction and expiration behavior."""
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


@contextmanager
def transaction(session_factory: SessionFactory) -> Iterator[Session]:
    """Commit a unit of work or roll it back on failure."""
    session = session_factory()
    try:
        with session.begin():
            yield session
    finally:
        session.close()
