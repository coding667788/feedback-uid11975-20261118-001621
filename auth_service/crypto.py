"""口令哈希与凭据记录校验。

安全不变量：
- 计算只使用 config 中的受信参数；数据库读出的参数必须先通过
  parse_and_validate 与受信参数逐一相等比较，否则 RecordError。
  因此内存/CPU 开销永远由服务端配置决定，而非数据库内容。
- 每条凭据独立随机盐；数据库只保存盐、哈希、算法参数与版本号。
"""
import hashlib
import hmac
import json
import secrets

from . import config


class RecordError(Exception):
    """凭据记录残缺、算法未知或参数超出受信范围。"""


class CredentialRecord:
    __slots__ = ("algo", "salt", "hash", "params")

    def __init__(self, algo, salt, hash_, params):
        self.algo = algo
        self.salt = salt
        self.hash = hash_
        self.params = params  # dict，等于 config.trusted_params(algo)

    @property
    def params_json(self):
        return json.dumps(self.params, sort_keys=True)


def _compute(algo, password: bytes, salt: bytes) -> bytes:
    """按受信配置计算哈希。algo 必须先通过校验。"""
    if algo == config.ALG_PBKDF2:
        return hashlib.pbkdf2_hmac(
            "sha256", password, salt,
            config.PBKDF2_ITERATIONS, config.PBKDF2_DKLEN,
        )
    if algo == config.ALG_SCRYPT:
        return hashlib.scrypt(
            password, salt=salt,
            n=config.SCRYPT_N, r=config.SCRYPT_R, p=config.SCRYPT_P,
            dklen=config.SCRYPT_DKLEN, maxmem=config.SCRYPT_MAXMEM,
        )
    raise RecordError(f"未知算法: {algo!r}")


def make_record(algo, password: bytes) -> CredentialRecord:
    """用受信参数与新的随机盐生成凭据记录。"""
    if algo not in config.KNOWN_ALGOS:
        raise RecordError(f"未知算法: {algo!r}")
    salt = secrets.token_bytes(config.SALT_LEN)
    return CredentialRecord(algo, salt, _compute(algo, password, salt),
                            config.trusted_params(algo))


def parse_and_validate(algo, salt, hash_, params_json) -> CredentialRecord:
    """校验数据库读出的一条凭据记录。任何不满足受信格式的记录都拒绝。"""
    if not isinstance(algo, str) or algo not in config.KNOWN_ALGOS:
        raise RecordError("未知算法")
    if not isinstance(salt, bytes) or len(salt) != config.SALT_LEN:
        raise RecordError("盐长度不符")
    expected_dklen = config.trusted_params(algo)["dklen"]
    if not isinstance(hash_, bytes) or len(hash_) != expected_dklen:
        raise RecordError("哈希长度不符")
    if not isinstance(params_json, str):
        raise RecordError("参数缺失")
    try:
        params = json.loads(params_json)
    except (ValueError, TypeError):
        raise RecordError("参数不是合法 JSON")
    if not isinstance(params, dict):
        raise RecordError("参数格式不符")
    # 关键防线：参数必须与服务端受信配置完全一致。
    # 不一致即拒绝，绝不按数据库中的值（例如巨大的 n）分配内存。
    if params != config.trusted_params(algo):
        raise RecordError("参数超出受信范围")
    return CredentialRecord(algo, salt, hash_, params)


def verify(password: bytes, rec: CredentialRecord) -> bool:
    expected = _compute(rec.algo, password, rec.salt)
    return hmac.compare_digest(expected, rec.hash)


def dummy_verify(password: bytes) -> None:
    """用户不存在时执行一次等价的伪计算，避免明显的用户枚举时序差。"""
    hashlib.pbkdf2_hmac(
        "sha256", password, b"\x00" * config.SALT_LEN,
        config.PBKDF2_ITERATIONS, config.PBKDF2_DKLEN,
    )
