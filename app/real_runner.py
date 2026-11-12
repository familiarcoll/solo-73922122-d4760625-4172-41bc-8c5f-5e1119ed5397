"""
内核实测编排：每请求独立临时树 + 独立子进程（chroot + 降权 + 清能力）。

生命周期保证：
  * 并发请求各自 mkdtemp 得到独立树根，身份/文件树绝不串用；
  * 子进程使用 close_fds 启动，不继承树外目录句柄；
  * 只有 wait() 确认子进程退出后才清理临时树，任何失败路径都回收；
  * 不具备 root/CAP_SYS_CHROOT（如本机非特权调试）或 setfacl 缺失时，
    返回 measured=false 的“无法实测”，绝不拿模拟结果冒充实测。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from typing import Any, Optional

from .engine import Snapshot
from .tree_builder import (
    SANDBOX_TMP_ROOT,
    SETFACL_BIN,
    TreeBuildError,
    build_tree,
    cleanup_tree,
)

CHILD_TIMEOUT_SECONDS = 10
_CHILD_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sandbox_child.py")


def _unmeasurable(stage: str, message: str, *, skipped: Optional[list] = None,
                  detail: Optional[str] = None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "measured": False,
        "stage": stage,
        "message": message,
        "skipped_nodes": skipped or [],
    }
    if detail:
        out["detail"] = detail
    return out


def _runtime_supported() -> Optional[str]:
    """返回无法实测的原因；None 表示环境具备实测条件。"""
    if os.geteuid() != 0:
        return "当前服务进程不是 root，无法 chroot/降权（容器内以 root 启动才支持实测）"
    if not os.path.exists(_CHILD_PATH):
        return "沙箱子进程脚本缺失"
    if shutil.which(SETFACL_BIN) is None:
        return "容器内缺少 setfacl，无法还原 POSIX ACL"
    return None


def _map_errno_to_category(errno_name: Optional[str]) -> Optional[str]:
    return {
        "EACCES": "permission_denied",
        "ENOENT": "path_missing",
        "ELOOP": "link_limit_exceeded",
        "ENOTDIR": "not_regular",
        "EISDIR": "not_regular",
        "ENAMETOOLONG": "name_too_long",
        "EROFS": "permission_denied",
        "ETXTBSY": "permission_denied",
    }.get(errno_name or "", None)


def _scan_skipped(snap: Snapshot) -> list[dict[str, str]]:
    """不触碰文件系统，预计算无法在影子树中还原的节点（type=other / 父链缺失）。"""
    from .tree_builder import _parent_chain_ok
    skipped: list[dict[str, str]] = []
    for node in snap.nodes.values():
        if node.path == "/":
            continue
        if node.type == "other":
            skipped.append({
                "path": node.path,
                "reason": "type=other 无法在影子树中还原设备/特殊节点",
            })
        elif not _parent_chain_ok(node, snap):
            skipped.append({
                "path": node.path,
                "reason": "父目录链不齐全（祖先缺失或不是目录），无法安全创建",
            })
    return skipped


def run_real_check(snap: Snapshot, req: dict[str, Any]) -> dict:
    """执行一次完整内核实测，返回结构化结果（永远带 measured 布尔）。

    顺序：先判断特权隔离条件（不具备则直接“无法实测”，并附上无需建树即可得到的
    跳过节点信息）；具备条件后再构建影子树并做 chroot 降权实测。任一步失败都明确
    标记“无法实测”，且临时树在 finally 中回收。
    """
    reason = _runtime_supported()
    if reason is not None:
        return _unmeasurable(
            "runtime_unsupported", reason, skipped=_scan_skipped(snap)
        )

    tree = None
    try:
        try:
            tree = build_tree(snap)
        except TreeBuildError as exc:
            return _unmeasurable("tree_build", f"影子树构建失败，已放弃实测：{exc}")
        except OSError as exc:
            return _unmeasurable("tree_build", f"临时目录不可用：{exc!r}")

        supp_csv = ",".join(str(g) for g in req["supp_groups"])
        try:
            proc = subprocess.Popen(
                [
                    sys.executable, "-I", _CHILD_PATH,
                    tree.root, str(req["uid"]), str(req["gid"]), supp_csv,
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                # 不继承任何额外句柄；新进程新会话，避免与服务进程共享控制终端
                close_fds=True,
                start_new_session=True,
                cwd="/",
            )
        except OSError as exc:
            return _unmeasurable(
                "isolate", "沙箱子进程启动失败",
                skipped=tree.skipped, detail=repr(exc),
            )

        try:
            stdout, stderr = proc.communicate(
                json.dumps({"path": req["path"]}),
                timeout=CHILD_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            return _unmeasurable(
                "timeout", f"沙箱实测超过 {CHILD_TIMEOUT_SECONDS}s 已终止",
                skipped=tree.skipped,
            )

        # 子进程已退出（wait 内含于 communicate），此后才允许清理树
        if proc.returncode != 0:
            return _unmeasurable(
                "sandbox_exit",
                f"沙箱子进程异常退出（code={proc.returncode}）",
                skipped=tree.skipped,
                detail=stderr.strip()[:500],
            )
        line = stdout.strip().splitlines()[-1] if stdout.strip() else ""
        try:
            result = json.loads(line)
        except json.JSONDecodeError:
            return _unmeasurable(
                "sandbox_output", "沙箱返回无法解析",
                skipped=tree.skipped, detail=(stderr.strip() or line)[:500],
            )
        if not isinstance(result, dict) or "measured" not in result:
            return _unmeasurable(
                "sandbox_output", "沙箱返回结构非法",
                skipped=tree.skipped,
            )

        # 构建期跳过的节点透传给前端；若跳过节点正好在模拟解析路径上，
        # 一致性判断会标注“无法对照”而不是给出伪一致结论
        result.setdefault("skipped_nodes", tree.skipped)
        result["tree_node_count"] = tree.node_count
        result["acl_applied"] = tree.acl_applied
        if result.get("measured") and result.get("errno"):
            result["kernel_category"] = _map_errno_to_category(result["errno"])
        elif result.get("measured") and result.get("readable"):
            result["kernel_category"] = "ok"
        elif result.get("measured"):
            result["kernel_category"] = "not_regular"
        return result
    finally:
        # 无论成功/失败/超时，确认子进程生命周期结束后回收临时树。
        # cleanup_tree 内部已能处理 000 权限与符号链接；再失败则尽力兜底，避免泄漏。
        if tree is not None:
            try:
                cleanup_tree(tree.root)
            except Exception:
                shutil.rmtree(tree.root, ignore_errors=True)


def cleanup_stale_trees() -> None:
    """服务启动时清理上一进程残留的临时树（仅清理本工具命名目录）。"""
    if not os.path.isdir(SANDBOX_TMP_ROOT):
        return
    real_base = os.path.realpath(SANDBOX_TMP_ROOT)
    for name in os.listdir(real_base):
        path = os.path.join(real_base, name)
        if name.startswith("tree-") and os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
