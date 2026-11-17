"""自动化测试：单元级（进程内）+ 多进程并发/崩溃（真实子进程共享同一 SQLite）。

约定：
- 不在任何输出中打印密码、完整会话令牌或预置的成功结果；
  口令是否匹配一律通过 tests/reference.py 的独立参考计算 + 只读数据库核对。
- 竞争构造全部使用文件同步点（barrier/gate）与真实进程退出，不用固定 sleep。
"""
import glob
import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

# 测试使用较快的受信参数（仍是服务端配置，子进程通过环境继承同一套）。
os.environ.setdefault("AUTH_PBKDF2_ITERATIONS", "20000")
os.environ.setdefault("AUTH_SCRYPT_N", "4096")
os.environ.setdefault("AUTH_SESSION_TTL_SECONDS", "3600")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from auth_service import config, core, crypto  # noqa: E402
from auth_service import db as dbmod  # noqa: E402
from auth_service import seed as seedmod  # noqa: E402
import reference  # noqa: E402

ADMIN_TOKEN = "test-admin-token-7f3c9"
SEED_PW = {u: p for u, p in seedmod.SEED_USERS}


def utf8(s):
    return s.encode("utf-8")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_for(cond, timeout=60, what="condition"):
    deadline = time.monotonic() + timeout
    while not cond():
        if time.monotonic() > deadline:
            raise TimeoutError(f"等待超时: {what}")
        time.sleep(0.01)


def api(port, path, payload=None, headers=None, timeout=30):
    """返回 (status, dict)。连接被杀死时抛异常由调用方处理。"""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    body = json.dumps(payload or {}).encode("utf-8")
    hdrs = {"Content-Type": "application/json"}
    hdrs.update(headers or {})
    conn.request("POST", path, body, hdrs)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, json.loads(data.decode("utf-8"))


class ServerProc:
    def __init__(self, db_path, port, extra_env=None):
        env = dict(os.environ)
        env["AUTH_ADMIN_TOKEN"] = ADMIN_TOKEN
        env.update(extra_env or {})
        self.log = tempfile.NamedTemporaryFile(
            mode="wb", suffix=".log", delete=False, prefix="authserver-")
        self.proc = subprocess.Popen(
            [sys.executable, os.path.join(REPO, "run_server.py"),
             "--db", db_path, "--port", str(port)],
            env=env, stdout=self.log, stderr=subprocess.STDOUT)
        self.port = port

    def wait_ready(self):
        def ready():
            if self.proc.poll() is not None:
                raise RuntimeError(f"服务进程提前退出，日志: {self.log.name}")
            try:
                conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
                conn.request("GET", "/health")
                if conn.getresponse().status == 200:
                    conn.close()
                    return True
            except OSError:
                return False
            return False
        wait_for(ready, what=f"server:{self.port} ready")

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)


class Cluster:
    """≥4 个独立服务进程共享同一数据库。"""

    def __init__(self, db_path, n=4, extra_env=None):
        self.servers = [ServerProc(db_path, free_port(), extra_env) for _ in range(n)]

    def __enter__(self):
        for s in self.servers:
            s.wait_ready()
        return self

    def __exit__(self, *exc):
        for s in self.servers:
            s.stop()

    @property
    def ports(self):
        return [s.port for s in self.servers]


class BaseCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="authtest-")
        self.db = os.path.join(self.tmp, "auth.db")
        dbmod.init_db(self.db)
        seedmod.seed(self.db)
        self.svc = core.AuthService(self.db)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---- 只读数据库断言（独立参考计算）----
    def assert_stored_password(self, username, password: bytes):
        self.assertTrue(
            reference.stored_password_matches(self.db, username, password),
            f"{username}: 存储哈希与参考计算不符")

    def assert_not_stored_password(self, username, password: bytes):
        self.assertFalse(
            reference.stored_password_matches(self.db, username, password),
            f"{username}: 存储哈希不应匹配该口令")

    def user_row(self, username):
        return reference.read_user_ro(self.db, username)


# ============================================================ 单元级（进程内）
class UnitTests(BaseCase):
    def test_legacy_login_upgrades_and_keeps_session(self):
        # dave 先登录拿到会话（同时被升级为 scrypt）
        token1 = self.svc.login("dave", utf8(SEED_PW["dave"]))
        row = self.user_row("dave")
        self.assertEqual(row["algo"], config.ALG_SCRYPT)
        self.assertEqual(row["cred_version"], 1, "单纯升级不得推进凭据版本")
        self.assertEqual(row["session_gen"], 1, "单纯升级不得推进会话代数")
        self.assert_stored_password("dave", utf8(SEED_PW["dave"]))

        # 测试侧把 dave 的存储记录改回旧版（用独立参考哈希），模拟“仍有旧凭据的用户”
        salt = os.urandom(config.SALT_LEN)
        legacy = reference.ref_hash("pbkdf2-sha256", utf8(SEED_PW["dave"]), salt,
                                    config.pbkdf2_params())
        con = dbmod.connect(self.db)
        con.execute("UPDATE users SET algo=?, salt=?, hash=?, params=? WHERE username='dave'",
                    (config.ALG_PBKDF2, salt, legacy,
                     json.dumps(config.pbkdf2_params(), sort_keys=True)))
        con.close()

        # 再次登录触发升级；升级前的旧会话必须仍然有效（升级不撤销会话）
        token2 = self.svc.login("dave", utf8(SEED_PW["dave"]))
        self.assertNotEqual(token1, token2)
        self.assertTrue(self.svc.check_session(token1)["valid"], "升级不得撤销已有会话")
        self.assertTrue(self.svc.check_session(token2)["valid"])
        row = self.user_row("dave")
        self.assertEqual(row["algo"], config.ALG_SCRYPT)
        self.assertEqual(row["cred_version"], 1)
        self.assert_stored_password("dave", utf8(SEED_PW["dave"]))

    def test_failed_login_does_not_upgrade(self):
        with self.assertRaises(core.AuthError) as cm:
            self.svc.login("alice", utf8("wrong-password"))
        self.assertEqual(cm.exception.status, 401)
        row = self.user_row("alice")
        self.assertEqual(row["algo"], config.ALG_PBKDF2, "失败登录不得升级")
        self.assert_stored_password("alice", utf8(SEED_PW["alice"]))

    def test_unknown_user(self):
        with self.assertRaises(core.AuthError) as cm:
            self.svc.login("nosuch", utf8("whatever"))
        self.assertEqual(cm.exception.status, 401)

    def test_password_bytes_exact_nonascii_and_spaces(self):
        pw = " 密码🔐 tail "  # 前后空格 + 非 ASCII
        self.svc.change_password("alice", utf8(SEED_PW["alice"]), utf8(pw))
        # 精确字节可登录
        self.svc.login("alice", utf8(pw))
        # trim 后、大小写变化、增删空格都必须失败（不做任何规范化）
        for variant in ("密码🔐 tail", " 密码🔐 tail", "密码🔐 tail ",
                        " 密码🔐  tail ", " 密码🔐 Tail "):
            with self.assertRaises(core.AuthError) as cm:
                self.svc.login("alice", utf8(variant))
            self.assertEqual(cm.exception.status, 401, f"变体不应通过: {variant!r}")
        self.assert_stored_password("alice", utf8(pw))
        self.assert_not_stored_password("alice", utf8("密码🔐 tail"))

    def test_password_length_limit(self):
        too_long = b"x" * (config.MAX_PASSWORD_BYTES + 1)
        with self.assertRaises(core.AuthError) as cm:
            self.svc.login("alice", too_long)
        self.assertEqual(cm.exception.status, 400)
        with self.assertRaises(core.AuthError):
            self.svc.change_password("alice", utf8(SEED_PW["alice"]), too_long)
        with self.assertRaises(core.AuthError):
            self.svc.admin_reset("alice", too_long)
        # 边界值可用
        edge = b"y" * config.MAX_PASSWORD_BYTES
        self.svc.change_password("alice", utf8(SEED_PW["alice"]), edge)
        self.svc.login("alice", edge)

    def test_corrupt_records_rejected(self):
        cases = {
            "evil_unknown_algo": ("md5", b"\x00" * 16, b"\x00" * 32, "{}"),
            "evil_huge_scrypt": (  # 数据库里的巨大参数必须被拒绝而非照单分配内存
                "scrypt", b"\x00" * 16, b"\x00" * 32,
                json.dumps({"n": 2 ** 30, "r": 8, "p": 1, "dklen": 32,
                            "maxmem": 2 ** 40})),
            "evil_weak_pbkdf2": (
                "pbkdf2-sha256", b"\x00" * 16, b"\x00" * 32,
                json.dumps({"hash": "sha256", "iterations": 5, "dklen": 32})),
            "evil_short_salt": (
                "scrypt", b"\x00" * 8, b"\x00" * 32,
                json.dumps(config.scrypt_params())),
            "evil_incomplete": ("scrypt", b"\x00" * 16, b"\x00" * 32, "{"),
        }
        con = dbmod.connect(self.db)
        now = int(time.time())
        for name, (algo, salt, h, params) in cases.items():
            con.execute(
                "INSERT INTO users VALUES(?,?,?,?,?,1,1,?,?)",
                (name, algo, salt, h, params, now, now))
        con.close()
        for name in cases:
            with self.assertRaises(core.AuthError) as cm:
                self.svc.login(name, utf8("any-password"))
            self.assertEqual(cm.exception.code, "corrupt_record", name)

    def test_change_password_revokes_sessions_and_bumps_versions(self):
        token = self.svc.login("bob", utf8(SEED_PW["bob"]))
        self.assertTrue(self.svc.check_session(token)["valid"])
        new_pw = "bob-新口令-✓"
        self.svc.change_password("bob", utf8(SEED_PW["bob"]), utf8(new_pw))
        row = self.user_row("bob")
        self.assertEqual(row["cred_version"], 2)
        self.assertEqual(row["session_gen"], 2)
        self.assertFalse(self.svc.check_session(token)["valid"], "改密必须撤销旧会话")
        with self.assertRaises(core.AuthError):
            self.svc.login("bob", utf8(SEED_PW["bob"]))
        self.svc.login("bob", utf8(new_pw))
        self.assert_stored_password("bob", utf8(new_pw))
        self.assert_not_stored_password("bob", utf8(SEED_PW["bob"]))

    def test_admin_reset_revokes_and_bumps(self):
        token = self.svc.login("carol", utf8(SEED_PW["carol"]))
        new_pw = "carol-重置-口令"
        self.svc.admin_reset("carol", utf8(new_pw))
        row = self.user_row("carol")
        self.assertEqual(row["cred_version"], 2)
        self.assertEqual(row["session_gen"], 2)
        self.assertFalse(self.svc.check_session(token)["valid"], "重置必须撤销旧会话")
        with self.assertRaises(core.AuthError):
            self.svc.login("carol", utf8(SEED_PW["carol"]))
        self.svc.login("carol", utf8(new_pw))
        with self.assertRaises(core.AuthError) as cm:
            self.svc.admin_reset("nosuch", utf8("x"))
        self.assertEqual(cm.exception.status, 404)

    def test_session_garbage_token(self):
        self.assertFalse(self.svc.check_session("not-a-token")["valid"])
        self.assertFalse(self.svc.check_session("")["valid"])


# ============================================================ CLI 命令
class CliTests(BaseCase):
    def run_cli(self, *argv):
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        return subprocess.run(
            [sys.executable, os.path.join(REPO, "cli.py"), *argv],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", env=env, timeout=60)

    def test_init_check_reset(self):
        db2 = os.path.join(self.tmp, "cli.db")
        r = self.run_cli("init", "--db", db2)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.run_cli("check", "--db", db2)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("bad=0", r.stdout)
        # 重复 init 应拒绝
        r = self.run_cli("init", "--db", db2)
        self.assertNotEqual(r.returncode, 0)
        # reset 后仍是旧版凭据
        r = self.run_cli("reset", "--db", db2)
        self.assertEqual(r.returncode, 0, r.stderr)
        row = reference.read_user_ro(db2, "alice")
        self.assertEqual(row["algo"], "pbkdf2-sha256")

    def test_check_detects_corruption(self):
        con = dbmod.connect(self.db)
        con.execute("UPDATE users SET algo='md5' WHERE username='alice'")
        con.close()
        r = self.run_cli("check", "--db", self.db)
        self.assertEqual(r.returncode, 1)
        self.assertIn("bad=1", r.stdout)


# ============================================================ 多进程并发
class ConcurrencyTests(BaseCase):
    def test_concurrent_legacy_upgrades_four_servers(self):
        """4 个进程同时对同一旧版用户登录升级：全部成功，只升级一次语义，版本不变。"""
        sync_dir = os.path.join(self.tmp, "sync")
        env = {"AUTH_SYNC_DIR": sync_dir,
               "AUTH_SYNC_BARRIERS": "login.before_upgrade_write=4"}
        results = [None] * 4
        with Cluster(self.db, 4, env) as cluster:
            def worker(i):
                results[i] = api(cluster.ports[i], "/login",
                                 {"username": "alice", "password": SEED_PW["alice"]})
            threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(60)
            for r in results:
                self.assertIsNotNone(r)
                self.assertEqual(r[0], 200, r[1])
            # 4 个会话都有效（升级不撤销会话）
            for i, r in enumerate(results):
                status, body = api(cluster.ports[i], "/session/check",
                                   {"token": r[1]["token"]})
                self.assertEqual(status, 200)
                self.assertTrue(body["valid"])
        row = self.user_row("alice")
        self.assertEqual(row["algo"], config.ALG_SCRYPT)
        self.assertEqual(row["cred_version"], 1)
        self.assertEqual(row["session_gen"], 1)
        self.assert_stored_password("alice", utf8(SEED_PW["alice"]))

    def test_login_upgrade_races_admin_reset(self):
        """登录算完旧哈希后被重置：升级必须被丢弃，不得签发会话。"""
        sync_dir = os.path.join(self.tmp, "sync")
        gate = "login.after_verify.before_upgrade"
        env = {"AUTH_SYNC_DIR": sync_dir, "AUTH_SYNC_GATES": gate}
        new_pw = "reset-后的口令"
        holder = {}
        with Cluster(self.db, 4, env) as cluster:
            def do_login():
                holder["login"] = api(cluster.ports[0], "/login",
                                      {"username": "alice",
                                       "password": SEED_PW["alice"]})
            t = threading.Thread(target=do_login)
            t.start()
            # 事件驱动：等登录进程确实到达“已验证、未升级”同步点
            wait_for(lambda: glob.glob(os.path.join(sync_dir, f"{gate}.*.reached")),
                     what="login reached gate")
            status, _ = api(cluster.ports[1], "/admin/reset",
                            {"username": "alice", "new_password": new_pw},
                            headers={"X-Admin-Token": ADMIN_TOKEN})
            self.assertEqual(status, 200)
            # 重置已提交后才放行登录
            open(os.path.join(sync_dir, f"{gate}.release"), "w").close()
            t.join(60)
            self.assertEqual(holder["login"][0], 409, holder["login"][1])
            self.assertEqual(holder["login"][1].get("error"), "credential_changed")
            # 旧口令必须失败，新口令必须成功
            s, _ = api(cluster.ports[2], "/login",
                       {"username": "alice", "password": SEED_PW["alice"]})
            self.assertEqual(s, 401)
            s, b = api(cluster.ports[3], "/login",
                       {"username": "alice", "password": new_pw})
            self.assertEqual(s, 200, b)
        row = self.user_row("alice")
        self.assertEqual(row["algo"], config.ALG_SCRYPT)
        self.assertEqual(row["cred_version"], 2)
        self.assertEqual(row["session_gen"], 2)
        self.assert_stored_password("alice", utf8(new_pw))
        self.assert_not_stored_password("alice", utf8(SEED_PW["alice"]))

    def test_two_change_passwords_race(self):
        """两个改密竞争：恰好一个提交成功，结果须符合一个完整顺序。"""
        sync_dir = os.path.join(self.tmp, "sync")
        env = {"AUTH_SYNC_DIR": sync_dir,
               "AUTH_SYNC_BARRIERS": "change.after_verify.before_write=2"}
        new_pws = ["竞争-口令-甲", "竞争-口令-乙"]
        results = [None, None]
        with Cluster(self.db, 4, env) as cluster:
            def worker(i):
                results[i] = api(cluster.ports[i], "/change-password",
                                 {"username": "alice",
                                  "old_password": SEED_PW["alice"],
                                  "new_password": new_pws[i]})
            threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(60)
        statuses = sorted(r[0] for r in results)
        self.assertEqual(statuses, [200, 401],
                         f"恰好一个改密应成功: {statuses}")
        winner = new_pws[0] if results[0][0] == 200 else new_pws[1]
        loser = new_pws[1] if results[0][0] == 200 else new_pws[0]
        # 最终存储必须恰好对应胜者的口令（完整顺序：先提交者生效）
        self.assert_stored_password("alice", utf8(winner))
        self.assert_not_stored_password("alice", utf8(loser))
        self.assert_not_stored_password("alice", utf8(SEED_PW["alice"]))
        row = self.user_row("alice")
        self.assertEqual(row["cred_version"], 2, "只能推进一次版本")
        self.assertEqual(row["session_gen"], 2)
        # 实际登录结果与之一致
        with Cluster(self.db, 1) as cluster:
            s, _ = api(cluster.ports[0], "/login",
                       {"username": "alice", "password": winner})
            self.assertEqual(s, 200)
            s, _ = api(cluster.ports[0], "/login",
                       {"username": "alice", "password": loser})
            self.assertEqual(s, 401)

    def test_upgrade_interleaved_with_change(self):
        """自动升级与改密交错：升级不得覆盖新密码、不得降级新哈希。"""
        sync_dir = os.path.join(self.tmp, "sync")
        gate = "login.after_verify.before_upgrade"
        env = {"AUTH_SYNC_DIR": sync_dir, "AUTH_SYNC_GATES": gate}
        new_pw = "改密-新口令-✓"
        holder = {}
        with Cluster(self.db, 4, env) as cluster:
            def do_login():
                holder["login"] = api(cluster.ports[0], "/login",
                                      {"username": "alice",
                                       "password": SEED_PW["alice"]})
            t = threading.Thread(target=do_login)
            t.start()
            wait_for(lambda: glob.glob(os.path.join(sync_dir, f"{gate}.*.reached")),
                     what="login reached gate")
            status, _ = api(cluster.ports[1], "/change-password",
                            {"username": "alice",
                             "old_password": SEED_PW["alice"],
                             "new_password": new_pw})
            self.assertEqual(status, 200)
            open(os.path.join(sync_dir, f"{gate}.release"), "w").close()
            t.join(60)
            self.assertEqual(holder["login"][0], 409, holder["login"][1])
        row = self.user_row("alice")
        self.assertEqual(row["algo"], config.ALG_SCRYPT, "不得被降级回旧算法")
        self.assertEqual(row["cred_version"], 2)
        self.assert_stored_password("alice", utf8(new_pw))
        self.assert_not_stored_password("alice", utf8(SEED_PW["alice"]))


# ============================================================ 崩溃恢复
class KillTests(BaseCase):
    def test_kill_change_after_write_before_commit(self):
        """新凭据已写入但事务未提交时进程真实退出：重启后旧状态完全保留。"""
        sync_dir = os.path.join(self.tmp, "sync")
        # 先由正常服务器建立一个有效会话
        with Cluster(self.db, 1) as c0:
            status, body = api(c0.ports[0], "/login",
                               {"username": "bob", "password": SEED_PW["bob"]})
            self.assertEqual(status, 200)
            old_token = body["token"]
        env = {"AUTH_SYNC_DIR": sync_dir,
               "AUTH_KILL_AT": "change.after_update.before_commit"}
        victim = ServerProc(self.db, free_port(), env)
        victim.wait_ready()
        marker = os.path.join(sync_dir,
                              f"change.after_update.before_commit.{victim.proc.pid}.reached")
        try:
            api(victim.port, "/change-password",
                {"username": "bob", "old_password": SEED_PW["bob"],
                 "new_password": "不应生效的口令"})
            self.fail("进程被杀时不应收到正常响应")
        except (ConnectionError, http.client.HTTPException, OSError):
            pass
        wait_for(lambda: os.path.exists(marker), what="kill marker")
        self.assertEqual(victim.proc.wait(timeout=30), 1, "进程应真实退出")
        # 重启干净服务器验证：未提交事务必须已回滚
        with Cluster(self.db, 1) as c1:
            s, _ = api(c1.ports[0], "/login",
                       {"username": "bob", "password": SEED_PW["bob"]})
            self.assertEqual(s, 200, "旧口令必须仍然有效")
            s, _ = api(c1.ports[0], "/login",
                       {"username": "bob", "password": "不应生效的口令"})
            self.assertEqual(s, 401, "未提交的新口令不得生效")
            s, b = api(c1.ports[0], "/session/check", {"token": old_token})
            self.assertTrue(b["valid"], "未提交的改密不得撤销会话")
        row = self.user_row("bob")
        self.assertEqual(row["cred_version"], 1)
        self.assertEqual(row["session_gen"], 1)
        self.assert_stored_password("bob", utf8(SEED_PW["bob"]))
        self.assert_not_stored_password("bob", utf8("不应生效的口令"))

    def test_kill_reset_after_commit_before_response(self):
        """重置已提交但响应未发出时进程真实退出：重启后新口令生效、旧会话不能复活。"""
        sync_dir = os.path.join(self.tmp, "sync")
        with Cluster(self.db, 1) as c0:
            status, body = api(c0.ports[0], "/login",
                               {"username": "carol", "password": SEED_PW["carol"]})
            self.assertEqual(status, 200)
            old_token = body["token"]
        new_pw = "重置-已提交-口令"
        env = {"AUTH_SYNC_DIR": sync_dir,
               "AUTH_KILL_AT": "reset.after_commit.before_response"}
        victim = ServerProc(self.db, free_port(), env)
        victim.wait_ready()
        marker = os.path.join(sync_dir,
                              f"reset.after_commit.before_response.{victim.proc.pid}.reached")
        try:
            api(victim.port, "/admin/reset",
                {"username": "carol", "new_password": new_pw},
                headers={"X-Admin-Token": ADMIN_TOKEN})
            self.fail("进程被杀时不应收到正常响应")
        except (ConnectionError, http.client.HTTPException, OSError):
            pass
        wait_for(lambda: os.path.exists(marker), what="kill marker")
        self.assertEqual(victim.proc.wait(timeout=30), 1, "进程应真实退出")
        # 重启干净服务器验证：已提交的重置必须生效且只对应这一个版本
        with Cluster(self.db, 1) as c1:
            s, _ = api(c1.ports[0], "/login",
                       {"username": "carol", "password": new_pw})
            self.assertEqual(s, 200, "已提交的新口令必须生效")
            s, _ = api(c1.ports[0], "/login",
                       {"username": "carol", "password": SEED_PW["carol"]})
            self.assertEqual(s, 401, "旧口令必须失效")
            s, b = api(c1.ports[0], "/session/check", {"token": old_token})
            self.assertFalse(b["valid"], "旧会话不得复活")
        row = self.user_row("carol")
        self.assertEqual(row["cred_version"], 2, "恰好一个已提交版本")
        self.assertEqual(row["session_gen"], 2)
        self.assert_stored_password("carol", utf8(new_pw))
        self.assert_not_stored_password("carol", utf8(SEED_PW["carol"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
