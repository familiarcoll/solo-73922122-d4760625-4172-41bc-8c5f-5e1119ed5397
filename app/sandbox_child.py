"""
每请求独立的沙箱子进程入口（以 root 启动，自行降权 + chroot）。

调用契约：
    python -I sandbox_child.py <tree_root> <uid> <gid> <supp_gid1,gid2,...>
    stdin  : 一行 JSON —— {"path": "/请求的绝对路径"}
    stdout : 一行 JSON —— {"measured": true, ...} 或 {"measured": false, ...}

安全不变式（与运维需求逐条对应）：
  1. chroot 到本请求专属的临时树并 chdir 到新根，关闭所有树外目录句柄；
  2. 绝对软链接与 ".." 由内核在 chroot 根内解析，天然无法逃逸，不挂载任何宿主目录；
  3. 先 prctl(PR_SET_KEEPCAPS=0) 并遍历 PR_CAPBSET_DROP 在仍为 root 时清空
     capability bounding set（该操作需要 CAP_SETPCAP，必须先于 setuid），
     再 setgroups/setresgid/setresuid 设置真实/有效/保存 GID 与 UID；
     setuid 到非 0 用户后 permitted/effective/inheritable 全部清零；
  4. 只用 open(O_RDONLY) + fstat 实测，绝不执行快照里的任何内容；
  5. 不导入任何会从快照目录加载代码的模块，stdout 只输出一行受控 JSON。

本脚本刻意不 import 项目内任何模块，避免在降权/换根后依赖包路径。
"""

from __future__ import annotations

import ctypes
import errno
import json
import os
import stat
import sys

# ---- prctl / capability 常量（linux/prctl.h, uapi/linux/capability.h） ----
PR_SET_KEEPCAPS = 8
PR_CAPBSET_DROP = 24
# 本诊断只需要 DAC 语义，bounding set 里出现的全部 capability 一律清除。
# 覆盖主流内核 CAP_LAST_CAP（含较新版本的 40+ 项），多 drop 一个不存在的 cap
# 只会返回 EINVAL，按“本来就没有”处理。
CAP_COUNT = 64

_libc = ctypes.CDLL(None, use_errno=True)
_libc.prctl.restype = ctypes.c_int
_libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                        ctypes.c_ulong, ctypes.c_ulong]


def _emit(payload: dict) -> None:
    """结果只通过 stdout 一行 JSON 返回，随后立即退出。"""
    sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _fail(stage: str, message: str, errno_name: str | None = None) -> None:
    _emit({
        "measured": False,
        "stage": stage,
        "message": message,
        "errno": errno_name,
    })
    sys.exit(0)


def _errno_name(exc: OSError) -> str:
    try:
        return errno.errorcode[exc.errno]
    except KeyError:
        return f"ERRNO_{exc.errno}"


def _drop_all_capabilities() -> None:
    # 1) 不允许 setuid 后保留 capability
    if _libc.prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) != 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))
    # 2) 清空 bounding set：需要 CAP_SETPCAP（容器 compose 仅授予所需 cap）
    for cap in range(CAP_COUNT):
        rc = _libc.prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)
        if rc != 0:
            e = ctypes.get_errno()
            if e == errno.EINVAL:
                continue  # 该 cap 编号超出本内核范围，等同已不存在
            raise OSError(e, os.strerror(e))


def main() -> None:
    if len(sys.argv) != 5:
        _fail("sandbox_argv", "沙箱参数数量错误")
        return

    tree_root = sys.argv[1]
    try:
        uid = int(sys.argv[2])
        gid = int(sys.argv[3])
        supp = [int(g) for g in sys.argv[4].split(",") if g != ""]
        request = json.loads(sys.stdin.readline())
        target = request["path"]
    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        _fail("sandbox_argv", f"沙箱入参非法: {exc!r}")
        return

    if uid <= 0:
        _fail("sandbox_argv", "实测仅支持非 0 UID 的无特权进程")
        return
    if not isinstance(target, str) or not target.startswith("/") or "\x00" in target:
        _fail("sandbox_argv", "请求路径非法")
        return

    # ---- 1) 进入新根：先持有树根底目录句柄，chroot 后 fchdir 再关闭 -------
    # O_NOFOLLOW：树根本身不得是符号链接，防止换根目标被重定向到树外。
    try:
        root_fd = os.open(tree_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        _fail("isolate", f"无法打开临时树根: {exc}", _errno_name(exc))
        return
    try:
        try:
            os.fchdir(root_fd)
            os.chroot(".")
            os.chdir("/")
        except OSError as exc:
            _fail("isolate", f"chroot 失败: {exc}", _errno_name(exc))
            return
        finally:
            # 关闭树外（宿主）目录句柄：此后进程不再持有任何宿主路径引用
            os.close(root_fd)

        # ---- 2) 先在仍为 root 时清空 capability bounding set -------------
        # PR_CAPBSET_DROP 要求 effective 中含 CAP_SETPCAP；一旦 setresuid 到
        # 非 0 用户，effective/permitted 会被清空，那时再 drop 必然 EPERM。
        # 因此必须“先 drop bounding，后切换身份”。
        try:
            _drop_all_capabilities()
        except OSError as exc:
            _fail("drop_caps", f"清除 capability 失败: {exc}", _errno_name(exc))
            return

        # ---- 3) 身份：附加组 + 真实/有效/保存 GID/UID --------------------
        # setresuid 到非 0 用户后，permitted/effective/inheritable 全部清零，
        # 叠加上面已清空的 bounding set，进程不再持有任何 capability。
        try:
            # 去重；主 GID 同时放进附加组集合，模拟登录进程语义
            groups = sorted(set(supp) | {gid})
            os.setgroups(groups)
            os.setresgid(gid, gid, gid)
            os.setresuid(uid, uid, uid)
        except OSError as exc:
            _fail("set_identity", f"切换 UID/GID 失败: {exc}", _errno_name(exc))
            return

        # 校验降权确实生效（防止宿主编排误配仍带特权）
        if os.geteuid() != uid or os.getegid() != gid or os.getuid() != uid \
                or os.getgid() != gid:
            _fail("set_identity", "降权后身份与请求不符，中止实测")
            return

        # ---- 4) 实测 open(O_RDONLY)，再 fstat 确认普通文件 --------------
        # 不使用 O_NOFOLLOW：软链接由内核在 chroot 内按 namei 规则跟随，
        # 绝对链接与 .. 都被限制在新根内；不执行任何文件内容。
        try:
            fd = os.open(target, os.O_RDONLY)
        except OSError as exc:
            name = _errno_name(exc)
            _emit({
                "measured": True,
                "open_ok": False,
                "readable": False,
                "errno": name,
                "errno_int": exc.errno,
                "message": os.strerror(exc.errno),
                "is_regular_file": None,
                "bytes_read": 0,
                "identity": {"uid": os.geteuid(), "gid": os.getegid(),
                             "groups": sorted(os.getgroups())},
            })
            return

        try:
            st = os.fstat(fd)
            is_regular = stat.S_ISREG(st.st_mode)
            if not is_regular:
                # open 成功但不是普通文件（目录会在 open 阶段就 EISDIR，
                # 这里覆盖其它通过 O_RDONLY 打开的特殊类型）
                _emit({
                    "measured": True,
                    "open_ok": True,
                    "readable": False,
                    "errno": None,
                    "message": "open 成功但 fstat 确认不是普通文件",
                    "is_regular_file": False,
                    "st_mode": oct(st.st_mode & 0o7777),
                    "bytes_read": 0,
                    "identity": {"uid": os.geteuid(), "gid": os.getegid(),
                                 "groups": sorted(os.getgroups())},
                })
                return
            # 真正读取一次（空文件读到 0 字节也是成功），确认读授权端到端成立
            chunk = os.read(fd, 4096)
            _emit({
                "measured": True,
                "open_ok": True,
                "readable": True,
                "errno": None,
                "message": "open(O_RDONLY) 成功且 fstat 为普通文件",
                "is_regular_file": True,
                "st_mode": oct(st.st_mode & 0o7777),
                "bytes_read": len(chunk),
                "identity": {"uid": os.geteuid(), "gid": os.getegid(),
                             "groups": sorted(os.getgroups())},
            })
        finally:
            os.close(fd)
    except Exception as exc:  # 任何意外都不允许让子进程带异常退出而被误判
        _fail("sandbox_unexpected", f"沙箱内部错误: {exc!r}")


if __name__ == "__main__":
    main()
