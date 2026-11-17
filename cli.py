"""管理命令：init（初始化+预置用户）/ reset（清空重建）/ check（只读校验）/ serve。"""
import argparse
import os
import sys

from auth_service import crypto
from auth_service import db as dbmod
from auth_service import seed as seedmod


def cmd_init(args):
    if os.path.exists(args.db):
        con = dbmod.connect(args.db)
        try:
            n = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        except Exception:
            n = 0
        finally:
            con.close()
        if n and not args.force:
            print(f"数据库已存在且含 {n} 个用户；如需重建请用 reset 或 --force", file=sys.stderr)
            return 2
    dbmod.init_db(args.db)
    con = dbmod.connect(args.db)
    try:
        n = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    finally:
        con.close()
    if n == 0:
        seedmod.seed(args.db)
    print(f"已初始化 {args.db}（预置 {len(seedmod.SEED_USERS)} 个测试用户，均为旧版凭据）")
    return 0


def cmd_reset(args):
    for suffix in ("", "-wal", "-shm"):
        path = args.db + suffix
        if os.path.exists(path):
            os.remove(path)
    dbmod.init_db(args.db)
    seedmod.seed(args.db)
    print(f"已重置 {args.db}（预置 {len(seedmod.SEED_USERS)} 个测试用户，均为旧版凭据）")
    return 0


def cmd_check(args):
    """只读打开数据库，逐条校验凭据记录是否符合受信格式。不输出任何哈希/盐内容。"""
    try:
        con = dbmod.connect(args.db, readonly=True)
    except Exception as exc:
        print(f"无法只读打开数据库: {exc}", file=sys.stderr)
        return 1
    ok = bad = 0
    problems = []
    try:
        rows = con.execute(
            "SELECT username, algo, salt, hash, params, cred_version, session_gen FROM users"
        ).fetchall()
        for row in rows:
            try:
                crypto.parse_and_validate(row["algo"], row["salt"], row["hash"], row["params"])
                if row["cred_version"] < 1 or row["session_gen"] < 1:
                    raise crypto.RecordError("版本号非法")
                ok += 1
            except crypto.RecordError as exc:
                bad += 1
                problems.append(f"{row['username']}: {exc}")
        sessions = con.execute(
            "SELECT token_hash, username FROM sessions"
        ).fetchall()
        usernames = {r["username"] for r in rows}
        bad_sessions = sum(
            1 for s in sessions
            if not isinstance(s["token_hash"], bytes) or len(s["token_hash"]) != 32
            or s["username"] not in usernames
        )
    finally:
        con.close()
    print(f"users={ok + bad} ok={ok} bad={bad} sessions={len(sessions)} bad_sessions={bad_sessions}")
    for p in problems:
        print(f"  损坏记录: {p}")
    return 0 if bad == 0 and bad_sessions == 0 else 1


def cmd_serve(args):
    from auth_service.server import run
    run(args.host, args.port, args.db)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="本地口令认证服务管理命令")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name, func in (("init", cmd_init), ("reset", cmd_reset), ("check", cmd_check)):
        p = sub.add_parser(name)
        p.add_argument("--db", required=True)
        if name == "init":
            p.add_argument("--force", action="store_true")
        p.set_defaults(func=func)
    p = sub.add_parser("serve")
    p.add_argument("--db", required=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.set_defaults(func=cmd_serve)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
