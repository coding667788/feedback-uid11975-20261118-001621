"""SQLite 存储层。数据库只保存盐、哈希、算法参数与版本号，不保存明文或可逆密码。"""
import sqlite3
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username     TEXT PRIMARY KEY,
    algo         TEXT NOT NULL,
    salt         BLOB NOT NULL,
    hash         BLOB NOT NULL,
    params       TEXT NOT NULL,
    cred_version INTEGER NOT NULL CHECK (cred_version >= 1),
    session_gen  INTEGER NOT NULL CHECK (session_gen >= 1),
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash  BLOB PRIMARY KEY,   -- 只保存会话令牌的 SHA-256，不保存令牌本身
    username    TEXT NOT NULL,
    session_gen INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(username);
"""


def connect(db_path, readonly=False):
    if readonly:
        uri = Path(db_path).absolute().as_uri() + "?mode=ro"
        con = sqlite3.connect(uri, uri=True, timeout=10)
    else:
        con = sqlite3.connect(db_path, timeout=10, isolation_level=None)
        con.execute("PRAGMA busy_timeout = 10000")
    con.row_factory = sqlite3.Row
    return con


def init_db(db_path):
    con = connect(db_path)
    try:
        con.execute("PRAGMA journal_mode = WAL")
        con.executescript(SCHEMA)
    finally:
        con.close()


@contextmanager
def write_txn(con):
    """短写事务（BEGIN IMMEDIATE）。昂贵的口令计算禁止放在本事务内。"""
    con.execute("BEGIN IMMEDIATE")
    try:
        yield con
    except BaseException:
        con.execute("ROLLBACK")
        raise
    else:
        con.execute("COMMIT")
