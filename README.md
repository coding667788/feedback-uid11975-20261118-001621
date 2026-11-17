# 本地口令认证服务（旧哈希在线升级 × 并发改密/重置）

纯 Python 3.12 标准库 + SQLite 实现的本地口令认证服务。重点解决：
**旧版 PBKDF2 凭据在线升级为 scrypt 时，与改密、管理员重置之间的竞争与崩溃一致性。**
不使用 Docker、外部身份服务或任何认证框架；仅需 CPU；预置测试用户，无注册/邮件/前端。

## 目录结构

```
auth_service/
  config.py      服务端受信配置（哈希参数、长度上限；可用环境变量覆盖）
  crypto.py      哈希计算与凭据记录校验（只按受信参数分配内存）
  db.py          SQLite 模式与短写事务（WAL，BEGIN IMMEDIATE）
  syncpoints.py  测试用可控同步点（barrier / gate / kill，默认关闭）
  core.py        登录（含在线升级）、改密、管理员重置、会话校验
  server.py      HTTP 服务（http.server 多线程，无全局锁）
  seed.py        预置测试用户（公开测试口令，均为旧版凭据）
cli.py           init / reset / check / serve 管理命令
run_server.py    启动一个服务进程（可起多个共享同一数据库）
tests/
  reference.py   独立参考哈希计算 + 只读数据库核对
  test_auth.py   17 个自动化测试（单元 / CLI / 4 进程并发 / 崩溃恢复）
```

## 安全设计要点

- **版本化凭据**：`pbkdf2-sha256`（旧）与 `scrypt`（新）。每条凭据独立随机盐；
  数据库只保存 盐、哈希、算法参数、cred_version、session_gen，不保存明文或可逆密码。
- **受信参数**：数据库中的参数必须与 `config.py` 完全一致，否则记录被拒绝
  （未知算法 / 残缺记录 / 巨大参数一律拒绝，绝不按数据库内容分配内存）。
- **口令字节**：按原始 UTF-8 字节处理，不 trim、不大小写转换、不 Unicode 规范化；
  超过 `AUTH_MAX_PASSWORD_BYTES`（默认 1024）直接拒绝。
- **在线升级**：旧版验证成功后自动重算为 scrypt；失败登录不升级；
  升级只改算法字段，不推进版本、不撤销会话。
- **并发不变量**：
  - 改密/重置在**同一写事务**内原子推进 cred_version 与 session_gen 并删除全部旧会话；
  - 所有昂贵哈希计算都在写事务之外，无全局互斥锁；
  - 升级落库用 `WHERE cred_version=? AND algo=?` CAS，过时的验证结果不会覆盖新密码、
    不会把新哈希降级；
  - 登录签发会话前在写事务内复查 cred_version，重置已提交后不会签发可用会话。
- **会话**：令牌只存 SHA-256；有效性 = 会话行存在 ∧ 未过期 ∧ 代数等于用户当前 session_gen。

## Windows 运行说明

```bat
:: 初始化（创建库并预置 4 个测试用户，均为旧版凭据）
python cli.py init --db auth.db

:: 启动 4 个独立服务进程共享同一数据库（另开 3 个窗口）
set AUTH_ADMIN_TOKEN=your-admin-token
python run_server.py --db auth.db --port 8001
python run_server.py --db auth.db --port 8002
python run_server.py --db auth.db --port 8003
python run_server.py --db auth.db --port 8004

:: 只读校验数据库（不输出任何哈希/盐内容）
python cli.py check --db auth.db

:: 清空并重新预置
python cli.py reset --db auth.db
```

HTTP API（均为 POST + JSON，另有 `GET /health`）：

| 路径 | 请求体 | 说明 |
|---|---|---|
| `/login` | `{username, password}` | 成功返回 `{token}`；旧版凭据自动升级 |
| `/change-password` | `{username, old_password, new_password}` | 原子推进双版本，撤销全部旧会话 |
| `/admin/reset` | `{username, new_password}` + 头 `X-Admin-Token` | 管理员重置，同上原子语义 |
| `/session/check` | `{token}` | 返回 `{valid, username?}` |

错误码：400 输入非法/口令超长，401 凭据或管理员令牌错误，404 用户不存在，
409 验证期间凭据已变更/并发冲突，500 记录损坏，503 未配置管理员令牌。

可调环境变量：`AUTH_PBKDF2_ITERATIONS`、`AUTH_SCRYPT_N`、`AUTH_MAX_PASSWORD_BYTES`、
`AUTH_SESSION_TTL_SECONDS`、`AUTH_ADMIN_TOKEN`（重置接口必需）。
测试同步点（仅测试用）：`AUTH_SYNC_DIR`、`AUTH_SYNC_BARRIERS`、`AUTH_SYNC_GATES`、`AUTH_KILL_AT`。

## 运行测试

```bat
python -m unittest discover -s tests -v
```

测试自动：用较快的受信参数（`AUTH_SCRYPT_N=4096` 等）；启动 ≥4 个真实服务子进程共享同一
SQLite 文件；用文件 barrier/gate 构造确定性竞争（不用固定 sleep）；用 `os._exit(1)`
在指定同步点真实终止进程；用 `tests/reference.py` 的独立 hashlib 参考计算 + 只读
（`mode=ro`）数据库连接核对存储哈希；不打印密码、完整令牌或预置成功结果。

覆盖场景：
- 旧版登录自动升级、失败登录不升级、升级不撤销已有会话；
- 非 ASCII 口令、前后空格不同的口令互不相同、超长口令拒绝、边界长度可用；
- 未知算法 / 巨大 scrypt 参数 / 弱 PBKDF2 参数 / 盐长度错误 / 残缺 JSON 记录全部拒绝；
- 改密与重置原子推进双版本并撤销旧会话；
- 4 进程同时升级同一旧版用户（barrier 同步）；登录算完旧哈希后被重置（gate 同步）；
  两个改密竞争（恰好一个生效，结果符合完整顺序）；升级与改密交错（不覆盖、不降级）；
- 在“新凭据已写入但未提交”和“重置已提交但响应未发出”两点真实杀死进程，
  重启后分别验证：未提交者完全回滚、已提交者恰好生效且旧会话不能复活；
- CLI init/reset/check（含损坏记录检出）。

## 实际测试结果

在 Windows 11 + Python 3.12（`D:/CC_Codex_FeedBack/runtimes/cc005-csv-python312/python.exe`）
上连续运行 4 次完整套件，结果一致：

```
Ran 17 tests in ~9.3s
OK
```

17 个测试：UnitTests×9、CliTests×2、ConcurrencyTests×4、KillTests×2，全部通过。
另做了 CLI + 单服务器冒烟验证：init/check/登录/会话校验/错误口令 401 均正常。

## 未完成项 / 已知限制

- 无登录速率限制与账户锁定（仅有未知用户的伪计算缓解枚举）；生产需加限流。
- 管理员令牌经环境变量明文配置、HTTP 未加 TLS（仅面向 localhost 使用）。
- 会话为固定 TTL，无滑动续期；改密/重置后不自动签发新会话，需重新登录。
- 改密冲突重试上限 3 次，极端竞争下返回 409 需客户端重试。
- 未做注册、邮件、前端（按题意从略）。
