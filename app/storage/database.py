"""Database connection management.

A single connection guarded by a lock is sufficient for a desktop application:
the monitoring thread and the UI thread never run long transactions, and
SQLite itself serialises writes. All statements use bound parameters — no
string-built SQL ever reaches the database.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from app.storage.schema import apply_migrations

logger = logging.getLogger(__name__)

__all__ = ["Database", "StorageError"]


class StorageError(Exception):
    """Raised when local storage cannot perform an operation."""


class Database:
    """Thread-safe handle to the local SQLite database.

    Parameters
    ----------
    path:
        Database file location. The parent directory is created on demand.
        Use ``":memory:"`` for tests.
    """

    def __init__(self, path: Path | str) -> None:
        self._path = ":memory:" if str(path) == ":memory:" else Path(path)
        self._lock = threading.RLock()
        self._connection: sqlite3.Connection | None = None

    # ------------------------------------------------------------- properties

    @property
    def path(self) -> Path | str:
        """Location of the database file."""
        return self._path

    @property
    def is_open(self) -> bool:
        """``True`` while the underlying connection is usable."""
        return self._connection is not None

    # ------------------------------------------------------------- lifecycle

    def open(self) -> Database:
        """Open the connection, create the schema and return ``self``."""
        with self._lock:
            if self._connection is not None:
                return self
            try:
                if self._path != ":memory:":
                    Path(self._path).parent.mkdir(parents=True, exist_ok=True)
                connection = sqlite3.connect(
                    str(self._path),
                    timeout=10.0,
                    check_same_thread=False,
                )
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA foreign_keys = ON")
                connection.execute("PRAGMA journal_mode = WAL")
                connection.execute("PRAGMA busy_timeout = 5000")
                version = apply_migrations(connection)
            except sqlite3.Error as exc:
                raise StorageError(f"cannot open database {self._path}: {exc}") from exc
            self._connection = connection
            logger.debug("database opened at %s (schema v%s)", self._path, version)
        return self

    def close(self) -> None:
        """Close the connection if it is open."""
        with self._lock:
            if self._connection is not None:
                try:
                    self._connection.close()
                except sqlite3.Error as exc:  # pragma: no cover - defensive
                    logger.warning("error while closing database: %s", exc)
                finally:
                    self._connection = None

    def __enter__(self) -> Database:
        return self.open()

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # ------------------------------------------------------------- operations

    @property
    def connection(self) -> sqlite3.Connection:
        """Return the open connection, opening it on first use."""
        if self._connection is None:
            self.open()
        assert self._connection is not None
        return self._connection

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Run a block atomically; rolls back on any exception."""
        with self._lock:
            connection = self.connection
            try:
                with connection:
                    yield connection
            except sqlite3.Error as exc:
                logger.error("database transaction failed: %s", exc)
                raise StorageError(str(exc)) from exc

    def execute(self, sql: str, parameters: tuple[object, ...] = ()) -> sqlite3.Cursor:
        """Execute one parameterised statement inside a transaction."""
        with self.transaction() as connection:
            return connection.execute(sql, parameters)

    def query(self, sql: str, parameters: tuple[object, ...] = ()) -> list[sqlite3.Row]:
        """Run a parameterised SELECT and return all rows."""
        with self._lock:
            try:
                cursor = self.connection.execute(sql, parameters)
                return cursor.fetchall()
            except sqlite3.Error as exc:
                raise StorageError(f"query failed: {exc}") from exc

    def query_one(self, sql: str, parameters: tuple[object, ...] = ()) -> sqlite3.Row | None:
        """Run a parameterised SELECT and return the first row, if any."""
        rows = self.query(sql, parameters)
        return rows[0] if rows else None

    @property
    def schema_version(self) -> int:
        """Version of the schema currently applied."""
        row = self.query_one("SELECT value FROM schema_meta WHERE key = 'schema_version'")
        try:
            return int(row[0]) if row else 0
        except (TypeError, ValueError):
            return 0
