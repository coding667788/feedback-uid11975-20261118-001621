"""预置测试用户（仅用于本地测试，全部为旧版 PBKDF2 凭据，便于演示在线升级）。

注意：这些是公开的测试夹具口令，绝不是生产凭据。日志与测试输出不得打印它们。
"""
import time

from . import config, crypto
from . import db as dbmod

SEED_USERS = (
    ("alice", "alice-旧口令-2026"),
    ("bob", "bob-旧口令-2026"),
    ("carol", "carol-旧口令-2026"),
    ("dave", "dave-旧口令-2026"),
)


def seed(db_path):
    con = dbmod.connect(db_path)
    try:
        now = int(time.time())
        with dbmod.write_txn(con) as cur:
            for username, password in SEED_USERS:
                rec = crypto.make_record(config.ALG_PBKDF2, password.encode("utf-8"))
                cur.execute(
                    "INSERT INTO users(username, algo, salt, hash, params, "
                    "cred_version, session_gen, created_at, updated_at) "
                    "VALUES(?,?,?,?,?,1,1,?,?)",
                    (username, rec.algo, rec.salt, rec.hash, rec.params_json, now, now),
                )
    finally:
        con.close()
