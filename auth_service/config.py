"""服务端受信配置。

所有口令哈希参数以此模块为准。数据库中保存的参数仅作记录与审计，
验证前必须与本配置完全一致，否则记录被拒绝 —— 绝不按数据库中的
参数分配内存或执行计算。
"""
import os


def _env_int(name, default):
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise RuntimeError(f"环境变量 {name} 不是合法整数: {raw!r}")
    if value <= 0:
        raise RuntimeError(f"环境变量 {name} 必须为正整数")
    return value


# ---- 算法标识 ----
ALG_PBKDF2 = "pbkdf2-sha256"   # 旧版
ALG_SCRYPT = "scrypt"          # 新版
CURRENT_ALGO = ALG_SCRYPT
LEGACY_ALGOS = (ALG_PBKDF2,)
KNOWN_ALGOS = (ALG_PBKDF2, ALG_SCRYPT)

# ---- 口令与输入限制 ----
MAX_PASSWORD_BYTES = _env_int("AUTH_MAX_PASSWORD_BYTES", 1024)
MIN_PASSWORD_BYTES = 1
MAX_USERNAME_BYTES = 128
MAX_BODY_BYTES = 64 * 1024

# ---- 凭据格式 ----
SALT_LEN = 16
TOKEN_BYTES = 32

# ---- PBKDF2-HMAC-SHA256（旧版，受信参数）----
PBKDF2_ITERATIONS = _env_int("AUTH_PBKDF2_ITERATIONS", 210_000)
PBKDF2_DKLEN = 32

# ---- scrypt（新版，受信参数）----
SCRYPT_N = _env_int("AUTH_SCRYPT_N", 1 << 14)
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SCRYPT_MAXMEM = 64 * 1024 * 1024

# ---- 会话 ----
SESSION_TTL_SECONDS = _env_int("AUTH_SESSION_TTL_SECONDS", 3600)


def pbkdf2_params():
    return {"hash": "sha256", "iterations": PBKDF2_ITERATIONS, "dklen": PBKDF2_DKLEN}


def scrypt_params():
    return {
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
        "dklen": SCRYPT_DKLEN,
        "maxmem": SCRYPT_MAXMEM,
    }


def trusted_params(algo):
    if algo == ALG_PBKDF2:
        return pbkdf2_params()
    if algo == ALG_SCRYPT:
        return scrypt_params()
    raise ValueError(f"未知算法: {algo!r}")
