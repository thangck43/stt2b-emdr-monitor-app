"""Lưu trữ SQLite: users (policy), events (log), alerts."""
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username            TEXT PRIMARY KEY,
    display_name        TEXT DEFAULT '',
    department          TEXT DEFAULT '',
    download_allowed    INTEGER NOT NULL DEFAULT 0,
    allowed_extensions  TEXT DEFAULT '',      -- vd: "pdf,xlsx" ; rỗng = mọi loại
    max_size_mb         REAL DEFAULT 0,       -- 0 = không giới hạn
    allow_until         TEXT DEFAULT '',      -- ISO time, quyền tạm thời; rỗng = vĩnh viễn
    login_allowed       INTEGER NOT NULL DEFAULT 1,
    note                TEXT DEFAULT '',
    created_at          TEXT,
    updated_at          TEXT
);
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    username    TEXT NOT NULL,
    type        TEXT NOT NULL,   -- login, logout, visit, download_allowed, download_blocked, agent_tamper
    url         TEXT DEFAULT '',
    filename    TEXT DEFAULT '',
    size_bytes  INTEGER DEFAULT 0,
    ip          TEXT DEFAULT '',
    device      TEXT DEFAULT '',
    source      TEXT DEFAULT '', -- extension | gateway
    detail      TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(username);
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    username    TEXT NOT NULL,
    severity    TEXT NOT NULL,   -- low, medium, high
    kind        TEXT NOT NULL,
    message     TEXT NOT NULL,
    event_id    INTEGER,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    ack_by      TEXT DEFAULT '',
    ack_at      TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    @contextmanager
    def tx(self):
        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def query(self, sql: str, params=()) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, params).fetchall()]

    def one(self, sql: str, params=()) -> dict | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    # ---- users ----
    def get_user(self, username: str) -> dict | None:
        return self.one("SELECT * FROM users WHERE username = ?", (username,))

    def upsert_user(self, username: str, **fields) -> dict:
        existing = self.get_user(username)
        ts = now_iso()
        with self.tx() as c:
            if existing is None:
                c.execute(
                    "INSERT INTO users (username, created_at, updated_at) VALUES (?, ?, ?)",
                    (username, ts, ts),
                )
            if fields:
                cols = ", ".join(f"{k} = ?" for k in fields)
                c.execute(
                    f"UPDATE users SET {cols}, updated_at = ? WHERE username = ?",
                    (*fields.values(), ts, username),
                )
        return self.get_user(username)  # type: ignore[return-value]

    def delete_user(self, username: str) -> None:
        with self.tx() as c:
            c.execute("DELETE FROM users WHERE username = ?", (username,))

    # ---- events / alerts ----
    def add_event(self, **e) -> int:
        e.setdefault("ts", now_iso())
        cols = ", ".join(e)
        qs = ", ".join("?" for _ in e)
        with self.tx() as c:
            cur = c.execute(f"INSERT INTO events ({cols}) VALUES ({qs})", tuple(e.values()))
            return int(cur.lastrowid)

    def add_alert(self, username: str, severity: str, kind: str, message: str,
                  event_id: int | None = None) -> int:
        with self.tx() as c:
            cur = c.execute(
                "INSERT INTO alerts (ts, username, severity, kind, message, event_id) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (now_iso(), username, severity, kind, message, event_id),
            )
            return int(cur.lastrowid)
