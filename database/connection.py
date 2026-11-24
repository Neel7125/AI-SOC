"""Database connection helpers (SQLite fallback implemented; schema is portable to PostgreSQL)."""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager

import config
from database.models import SCHEMA


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(config.DB_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def session():
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(reset: bool = False) -> None:
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    if reset and config.DB_PATH.exists():
        config.DB_PATH.unlink()
    with session() as c:
        c.executescript(SCHEMA)
