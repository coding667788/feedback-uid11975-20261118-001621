"""独立参考实现：测试专用，不经过 auth_service 的任何代码路径。

- 直接用 hashlib 重算哈希，与只读打开的数据库内容比对，
  验证存储的哈希确实对应某个口令、且只对应一个已提交版本。
- 数据库一律以 mode=ro 打开，测试不会意外改动被测数据。
"""
import hashlib
import hmac
import json
import sqlite3
from pathlib import Path


def ref_hash(algo, password: bytes, salt: bytes, params: dict) -> bytes:
    if algo == "pbkdf2-sha256":
        return hashlib.pbkdf2_hmac(
            params["hash"], password, salt, params["iterations"], params["dklen"]
        )
    if algo == "scrypt":
        return hashlib.scrypt(
            password, salt=salt, n=params["n"], r=params["r"], p=params["p"],
            dklen=params["dklen"], maxmem=params["maxmem"],
        )
    raise ValueError(f"参考实现不支持算法: {algo!r}")


def read_user_ro(db_path, username):
    uri = Path(db_path).absolute().as_uri() + "?mode=ro"
    con = sqlite3.connect(uri, uri=True)
    con.row_factory = sqlite3.Row
    try:
        return con.execute(
            "SELECT username, algo, salt, hash, params, cred_version, session_gen "
            "FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    finally:
        con.close()


def stored_password_matches(db_path, username, password: bytes) -> bool:
    """只读核对：数据库中存储的哈希是否等于该口令的独立参考计算结果。"""
    row = read_user_ro(db_path, username)
    if row is None:
        return False
    params = json.loads(row["params"])
    expected = ref_hash(row["algo"], password, row["salt"], params)
    return hmac.compare_digest(expected, row["hash"])
