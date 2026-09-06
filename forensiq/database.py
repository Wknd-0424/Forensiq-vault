"""
forensiq/database.py
--------------------
SQLAlchemy engine, session factory, and database initialisation.
All tables are created here via Base.metadata.create_all().

SQLite and UTC datetime note:
  SQLite stores all datetimes as text.  SQLAlchemy's DateTime(timezone=True)
  does NOT automatically re-attach UTC tzinfo on read from SQLite.
  UTCDateTime is a TypeDecorator that guarantees timezone-aware datetimes on
  both write and read.  All ORM models use UTCDateTime instead of
  DateTime(timezone=True) directly.
"""

import logging
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Generator, Optional

from sqlalchemy import DateTime, create_engine, event, types
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from forensiq.config import DB_URL

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# UTCDateTime — timezone-aware round-trip TypeDecorator for SQLite
# ---------------------------------------------------------------------------

class UTCDateTime(types.TypeDecorator):
    """
    A DateTime that always stores and returns timezone-aware UTC datetimes.

    - On write: naive datetimes are assumed UTC and stored as ISO-8601 UTC text.
    - On read:  the stored text is parsed and UTC tzinfo is re-attached.
    """
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: Optional[datetime], dialect) -> Optional[datetime]:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def process_result_value(self, value: Optional[Any], dialect) -> Optional[datetime]:
        if value is None:
            return None
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        # SQLite may return a string
        if isinstance(value, str):
            from forensiq.utils.utc_utils import from_iso8601
            try:
                return from_iso8601(value)
            except ValueError:
                dt = datetime.fromisoformat(value)
                return dt.replace(tzinfo=timezone.utc)
        return value



# ---------------------------------------------------------------------------
# Declarative base — all ORM models inherit from this
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Engine and session factory (module-level singletons)
# ---------------------------------------------------------------------------

_engine: Engine | None = None
_SessionLocal: sessionmaker | None = None


def get_engine() -> Engine:
    """Return the singleton SQLAlchemy engine, creating it if necessary."""
    global _engine
    if _engine is None:
        _engine = create_engine(
            DB_URL,
            connect_args={"check_same_thread": False},
            echo=False,
        )
        # Enable WAL mode for better concurrent read performance with SQLite
        @event.listens_for(_engine, "connect")
        def _set_sqlite_pragma(dbapi_conn, _connection_record):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        logger.debug("SQLAlchemy engine created: %s", DB_URL)
    return _engine


def get_session_factory() -> sessionmaker:
    """Return the singleton session factory."""
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=get_engine(),
        )
    return _SessionLocal


def get_session() -> Session:
    """
    Return a new database session.
    The caller is responsible for closing/committing/rolling back.
    Prefer the context manager `session_scope()` where possible.
    """
    return get_session_factory()()


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    """
    Provide a transactional scope around a series of operations.

    Usage::

        with session_scope() as session:
            session.add(some_model)
    """
    session = get_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db() -> None:
    """
    Create all tables.  Safe to call multiple times (idempotent).
    Must be called once at application startup before any ORM usage.
    """
    # Import all models to ensure they are registered with Base.metadata
    from forensiq.models import _import_all_models  # noqa: F401
    _import_all_models()

    engine = get_engine()
    Base.metadata.create_all(engine)
    logger.info("Database initialised.")
