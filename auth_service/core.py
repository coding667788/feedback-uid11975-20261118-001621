"""认证核心业务：登录（含在线升级）、改密、管理员重置、会话校验。

并发不变量：
- cred_version 与 session_gen 单调递增；改密/重置在同一写事务内同时
  推进两者并删除全部旧会话。
- 单纯哈希升级只改 algo/salt/hash/params，不碰版本号与会话。
- 所有昂贵口令计算都在写事务之外；没有任何全局互斥锁。
- 计算完成后落库前必须用 cred_version 做 CAS 复查：过时的验证结果
  不能覆盖新密码、不能把新哈希降级、不能在重置提交后签发旧代数会话。
"""
import hashlib
import secrets
import time

from . import config, crypto
from . import db as dbmod
from .syncpoints import syncpoint


class AuthError(Exception):
    def __init__(self, status, code, message=""):
        super().__init__(message or code)
        self.status = status
        self.code = code


class _Retry(Exception):
    """CAS 失败，需要重读重试。"""


def _now():
    return int(time.time())


def _validate_username(username):
    if not isinstance(username, str) or not username:
        raise AuthError(400, "bad_request", "用户名缺失")
    if len(username.encode("utf-8")) > config.MAX_USERNAME_BYTES:
        raise AuthError(400, "username_too_long")


def _validate_password(password):
    """密码按原始 UTF-8 字节处理：不 trim、不大小写转换、不 Unicode 规范化。"""
    if not isinstance(password, bytes):
        raise AuthError(400, "bad_request", "密码缺失")
    if len(password) > config.MAX_PASSWORD_BYTES:
        raise AuthError(400, "password_too_long")
    if len(password) < config.MIN_PASSWORD_BYTES:
        raise AuthError(400, "password_too_short")


def _load_record(row):
    try:
        return crypto.parse_and_validate(row["algo"], row["salt"], row["hash"], row["params"])
    except crypto.RecordError as exc:
        raise AuthError(500, "corrupt_record", str(exc))


class AuthService:
    def __init__(self, db_path):
        self.db_path = db_path

    def _connect(self):
        return dbmod.connect(self.db_path)

    # ---------------------------------------------------------------- 登录
    def login(self, username, password: bytes) -> str:
        _validate_username(username)
        _validate_password(password)
        con = self._connect()
        try:
            row = con.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if row is None:
                crypto.dummy_verify(password)
                raise AuthError(401, "invalid_credentials")
            rec = _load_record(row)
            if not crypto.verify(password, rec):
                raise AuthError(401, "invalid_credentials")
            cred_version = row["cred_version"]

            # 旧版验证成功 → 在线升级为新版。计算在事务外；失败登录不会走到这里。
            if rec.algo in config.LEGACY_ALGOS:
                syncpoint("login.after_verify.before_upgrade")
                new_rec = crypto.make_record(config.CURRENT_ALGO, password)
                syncpoint("login.before_upgrade_write")
                with dbmod.write_txn(con) as cur:
                    # CAS：仅当凭据仍是当时验证的那个版本且仍是旧算法时才替换。
                    # 并发改密/重置会推进 cred_version，本更新自然失效被丢弃，
                    # 不会用过时验证结果覆盖新密码，也不会把新哈希降级。
                    cur.execute(
                        "UPDATE users SET algo=?, salt=?, hash=?, params=?, updated_at=? "
                        "WHERE username=? AND cred_version=? AND algo=?",
                        (new_rec.algo, new_rec.salt, new_rec.hash, new_rec.params_json,
                         _now(), username, cred_version, rec.algo),
                    )

            # 签发会话：在写事务内复查凭据版本仍是当时验证的版本。
            # 若重置/改密已提交，cred_version 已变 → 拒绝签发，
            # 绝不在重置提交后签发可用会话。
            syncpoint("login.before_session_issue")
            token = secrets.token_urlsafe(config.TOKEN_BYTES)
            token_hash = hashlib.sha256(token.encode("ascii")).digest()
            now = _now()
            with dbmod.write_txn(con) as cur:
                cur_row = cur.execute(
                    "SELECT cred_version, session_gen FROM users WHERE username=?",
                    (username,),
                ).fetchone()
                if cur_row is None or cur_row["cred_version"] != cred_version:
                    raise AuthError(409, "credential_changed",
                                    "验证期间凭据已变更，请重新登录")
                cur.execute(
                    "INSERT INTO sessions(token_hash, username, session_gen, created_at, expires_at) "
                    "VALUES(?,?,?,?,?)",
                    (token_hash, username, cur_row["session_gen"], now,
                     now + config.SESSION_TTL_SECONDS),
                )
            return token
        finally:
            con.close()

    # ---------------------------------------------------------------- 改密
    def change_password(self, username, old_password: bytes, new_password: bytes):
        _validate_username(username)
        _validate_password(old_password)
        _validate_password(new_password)
        con = self._connect()
        try:
            for _attempt in range(3):
                row = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
                if row is None:
                    crypto.dummy_verify(old_password)
                    raise AuthError(401, "invalid_credentials")
                rec = _load_record(row)
                if not crypto.verify(old_password, rec):
                    raise AuthError(401, "invalid_credentials")
                syncpoint("change.after_verify.before_write")
                # 昂贵计算在事务外；改密同时把凭据升级到当前算法。
                new_rec = crypto.make_record(config.CURRENT_ALGO, new_password)
                try:
                    with dbmod.write_txn(con) as cur:
                        # CAS：只有凭据版本未变才提交，原子推进双版本并撤销全部旧会话。
                        update = cur.execute(
                            "UPDATE users SET algo=?, salt=?, hash=?, params=?, "
                            "cred_version=cred_version+1, session_gen=session_gen+1, updated_at=? "
                            "WHERE username=? AND cred_version=?",
                            (new_rec.algo, new_rec.salt, new_rec.hash, new_rec.params_json,
                             _now(), username, row["cred_version"]),
                        )
                        if update.rowcount == 0:
                            raise _Retry()
                        syncpoint("change.after_update.before_commit")
                        cur.execute("DELETE FROM sessions WHERE username=?", (username,))
                    return
                except _Retry:
                    continue  # 重读后重新验证旧密码；若已被并发修改则验证失败
            raise AuthError(409, "concurrent_modification", "并发修改冲突，请重试")
        finally:
            con.close()

    # ---------------------------------------------------------------- 管理员重置
    def admin_reset(self, username, new_password: bytes):
        _validate_username(username)
        _validate_password(new_password)
        con = self._connect()
        try:
            row = con.execute("SELECT username FROM users WHERE username=?", (username,)).fetchone()
            if row is None:
                raise AuthError(404, "user_not_found")
            # 昂贵计算在事务外。
            new_rec = crypto.make_record(config.CURRENT_ALGO, new_password)
            with dbmod.write_txn(con) as cur:
                # 重置总是生效：单事务原子推进双版本并撤销全部旧会话。
                cur.execute(
                    "UPDATE users SET algo=?, salt=?, hash=?, params=?, "
                    "cred_version=cred_version+1, session_gen=session_gen+1, updated_at=? "
                    "WHERE username=?",
                    (new_rec.algo, new_rec.salt, new_rec.hash, new_rec.params_json,
                     _now(), username),
                )
                cur.execute("DELETE FROM sessions WHERE username=?", (username,))
            # 提交之后、响应之前的崩溃点：事务已落库，客户端可能收不到响应，
            # 但重启后状态必须恰好对应这一个已提交版本。
            syncpoint("reset.after_commit.before_response")
        finally:
            con.close()

    # ---------------------------------------------------------------- 会话校验
    def check_session(self, token) -> dict:
        if not isinstance(token, str) or not token:
            return {"valid": False}
        try:
            token_hash = hashlib.sha256(token.encode("ascii")).digest()
        except (UnicodeEncodeError, ValueError):
            return {"valid": False}
        con = self._connect()
        try:
            row = con.execute(
                "SELECT s.username AS username, s.session_gen AS gen, s.expires_at AS exp, "
                "       u.session_gen AS cur_gen "
                "FROM sessions s JOIN users u ON u.username = s.username "
                "WHERE s.token_hash = ?",
                (token_hash,),
            ).fetchone()
            if row is None:
                return {"valid": False}
            # 双保险：会话行存在且代数仍等于用户当前会话代数。
            valid = row["exp"] > _now() and row["gen"] == row["cur_gen"]
            return {"valid": bool(valid), "username": row["username"] if valid else None}
        finally:
            con.close()
