"""可控同步点：仅供测试构造确定性竞争，生产不开启（不设环境变量即为空操作）。

通过环境变量控制（每个服务进程独立设置）：
- AUTH_SYNC_DIR        同步点状态目录。设置后每到达一个同步点会写入
                       ``<名称>.<pid>.reached`` 标记文件。
- AUTH_SYNC_BARRIERS   形如 ``name1=2,name2=4``：到达该点的进程阻塞，
                       直到该名称的 reached 标记数量达到指定值（含自己）。
- AUTH_SYNC_GATES      形如 ``name1,name2``：到达该点的进程阻塞，直到
                       ``<名称>.release`` 文件出现（由测试进程创建）。
- AUTH_KILL_AT         到达同名同步点时进程立即 os._exit(1) 真实退出，
                       用于模拟崩溃（未提交的事务由 SQLite 回滚）。

等待基于文件出现这一事件轮询，不依赖固定 sleep 假定竞争发生。
"""
import glob
import os
import time

_TIMEOUT_SECONDS = 120


class SyncPointTimeout(Exception):
    pass


def _wait_until(cond, name):
    deadline = time.monotonic() + _TIMEOUT_SECONDS
    while not cond():
        if time.monotonic() > deadline:
            raise SyncPointTimeout(f"同步点超时: {name}")
        time.sleep(0.005)


def _parse_barriers(spec):
    out = {}
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        name, _, count = item.partition("=")
        out[name.strip()] = int(count)
    return out


def syncpoint(name):
    sync_dir = os.environ.get("AUTH_SYNC_DIR")
    if not sync_dir:
        return
    os.makedirs(sync_dir, exist_ok=True)
    marker = os.path.join(sync_dir, f"{name}.{os.getpid()}.reached")
    with open(marker, "w") as f:
        f.write("1")

    if os.environ.get("AUTH_KILL_AT", "") == name:
        # 真实终止本进程：未提交事务随连接销毁回滚，已提交事务保留。
        os._exit(1)

    barriers = _parse_barriers(os.environ.get("AUTH_SYNC_BARRIERS", ""))
    if name in barriers:
        need = barriers[name]
        pattern = os.path.join(sync_dir, f"{name}.*.reached")
        _wait_until(lambda: len(glob.glob(pattern)) >= need, name)

    gates = {g.strip() for g in os.environ.get("AUTH_SYNC_GATES", "").split(",") if g.strip()}
    if name in gates:
        release = os.path.join(sync_dir, f"{name}.release")
        _wait_until(lambda: os.path.exists(release), name)
