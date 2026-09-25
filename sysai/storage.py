from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .config import state_dir
from .redact import redact


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Storage:
    def __init__(self, path: Path | None = None):
        location = path or state_dir() / "sysai.db"
        location.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(location)
        self.db.row_factory = sqlite3.Row
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version > 1:
            raise RuntimeError("Database schema is newer than this SysAI version")
        if version == 1:
            return
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, request TEXT, started TEXT, ended TEXT, status TEXT, result TEXT);
            CREATE TABLE IF NOT EXISTS tool_calls (id INTEGER PRIMARY KEY, run_id TEXT, tool TEXT, arguments TEXT, result TEXT, timestamp TEXT);
            CREATE TABLE IF NOT EXISTS backups (id INTEGER PRIMARY KEY, run_id TEXT, original TEXT, backup TEXT, timestamp TEXT);
            CREATE TABLE IF NOT EXISTS scheduled_tasks (id INTEGER PRIMARY KEY, description TEXT, kind TEXT, schedule TEXT, payload TEXT, enabled INTEGER DEFAULT 1);
            CREATE TABLE IF NOT EXISTS task_runs (id INTEGER PRIMARY KEY, task_id INTEGER, timestamp TEXT, status TEXT, result TEXT);
            PRAGMA user_version=1;
        """)
        self.db.commit()

    def start(self, run_id: str, request: str) -> None:
        self.db.execute("INSERT INTO runs VALUES (?,?,?,NULL,'running',NULL)", (run_id, redact(request), now()))
        self.db.commit()

    def call(self, run_id: str, tool: str, arguments: str, result: str) -> None:
        self.db.execute("INSERT INTO tool_calls (run_id,tool,arguments,result,timestamp) VALUES (?,?,?,?,?)", (run_id, tool, redact(arguments), redact(result), now()))
        self.db.commit()

    def finish(self, run_id: str, status: str, result: str) -> None:
        self.db.execute("UPDATE runs SET ended=?,status=?,result=? WHERE id=?", (now(), status, redact(result), run_id))
        self.db.commit()

    def backup(self, run_id: str, original: str, backup: str) -> None:
        self.db.execute("INSERT INTO backups (run_id,original,backup,timestamp) VALUES (?,?,?,?)", (run_id, original, backup, now()))
        self.db.commit()
