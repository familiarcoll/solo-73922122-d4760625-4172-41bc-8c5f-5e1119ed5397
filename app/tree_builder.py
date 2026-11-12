"""
按快照在临时目录构建每请求独立的“影子文件树”。

构建规则（严格受限，绝不跟随软链接写到树外）：
  * 只支持父目录链齐全（每一级祖先都在快照里且为 directory）的
    directory / file / symlink 三类节点；type=other 或父链缺失的节点跳过；
  * file 为空文件（O_CREAT|O_EXCL，内容不受信也不需要）；
  * 非链接节点还原 uid/gid、mode 与访问 ACL（POSIX.1e，setfacl）；
  * symlink 只还原 link_target，不设置属主/mode（Linux 上 lchmod 不生效、
    链接自身权限也不参与 namei 判定），os.symlink 本身不解析目标；
  * 所有创建都带 O_NOFOLLOW / O_DIRECTORY 校验，路径先做词法边界检查，
    任何一步试图穿越已存在的软链接都会失败并整体中止（标记无法实测）。
"""

from __future__ import annotations

import os
import posixpath
import subprocess
import tempfile
from dataclasses import dataclass, field

from .engine import Node, Snapshot

SANDBOX_TMP_ROOT = os.environ.get("DIAG_SANDBOX_TMP", "/tmp/diag-sandbox")
# setfacl 不在 PATH 或构建被禁用时，runner 会据此降级为“无法实测”
SETFACL_BIN = os.environ.get("DIAG_SETFACL_BIN", "setfacl")


class TreeBuildError(Exception):
    """构建影子树失败（含潜在越界写入），调用方应放弃实测。"""


@dataclass
class BuiltTree:
    root: str
    skipped: list[dict[str, str]] = field(default_factory=list)
    acl_applied: int = 0
    node_count: int = 0


def _local_path(root: str, snap_path: str) -> str:
    """把快照绝对路径映射到树内本地路径，并做词法边界保证。"""
    assert snap_path.startswith("/")
    rel = snap_path.lstrip("/")
    local = os.path.normpath(os.path.join(root, rel)) if rel else root
    if local != root and not local.startswith(root + os.sep):
        raise TreeBuildError(f"路径 {snap_path} 映射越出临时树根")
    return local


def _parent_chain_ok(node: Node, snap: Snapshot) -> bool:
    """祖先链每一级都必须存在于快照且为目录（根除外）。"""
    cur = posixpath.dirname(node.path)
    while cur and cur != "/":
        anc = snap.nodes.get(cur)
        if anc is None or anc.type != "directory":
            return False
        cur = posixpath.dirname(cur) or "/"
    return snap.nodes.get("/") is not None and snap.nodes["/"].type == "directory"


def _acl_spec(acl: list) -> str:
    """把快照 ACL 条目列表翻译成 setfacl --set 规格（access ACL，不含 default:）。"""
    parts: list[str] = []
    for e in acl:
        if e.type == "user_obj":
            parts.append(f"user::{_rwx(e.perms)}")
        elif e.type == "user":
            parts.append(f"user:{e.qualifier}:{_rwx(e.perms)}")
        elif e.type == "group_obj":
            parts.append(f"group::{_rwx(e.perms)}")
        elif e.type == "group":
            parts.append(f"group:{e.qualifier}:{_rwx(e.perms)}")
        elif e.type == "mask":
            parts.append(f"mask::{_rwx(e.perms)}")
        elif e.type == "other":
            parts.append(f"other::{_rwx(e.perms)}")
    return ",".join(parts)


def _rwx(bits: int) -> str:
    return (
        ("r" if bits & 4 else "-")
        + ("w" if bits & 2 else "-")
        + ("x" if bits & 1 else "-")
    )


def _safe_mkdir(local: str) -> None:
    # 父目录必须是真实目录（O_DIRECTORY 且 O_NOFOLLOW），杜绝沿链接创建
    parent = os.path.dirname(local)
    pfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.mkdir(os.path.basename(local), dir_fd=pfd)
    finally:
        os.close(pfd)


def _safe_create_file(local: str) -> None:
    parent = os.path.dirname(local)
    pfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        # O_EXCL：快照路径已保证唯一，重复出现即异常
        fd = os.open(
            os.path.basename(local),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=pfd,
        )
        os.close(fd)
    finally:
        os.close(pfd)


def _safe_symlink(target: str, local: str) -> None:
    parent = os.path.dirname(local)
    pfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        # os.symlink 只创建链接对象，不解析 target；O_NOFOLLOW 语义由
        # 父目录句柄 + 全新名字保证（target 指向树外也不会在构建期触碰）
        os.symlink(target, os.path.basename(local), dir_fd=pfd)
    finally:
        os.close(pfd)


def _apply_identity_and_mode(node: Node, local: str) -> None:
    # 先 chmod 再 chown；若带 ACL 稍后由 setfacl 统一重写（含 mask），
    # 与真实内核“chmod 同步改写扩展 ACL mask”的最终状态一致。
    os.chmod(local, node.mode & 0o7777)
    if os.geteuid() == 0:
        # 仅 root 能把属主改成任意 UID/GID（容器编排进程以 root 运行）
        os.chown(local, node.uid, node.gid, follow_symlinks=False)
    elif (node.uid, node.gid) != (os.getuid(), os.getgid()):
        # 非 root 仅用于结构级自测：无法还原属主，明确标记，避免静默失真
        raise TreeBuildError(
            f"非 root 无法还原节点 {node.path} 的属主 uid={node.uid}/gid={node.gid}，"
            "完整实测需在容器（root 编排 + 降权子进程）中进行"
        )


def _apply_acl(node: Node, local: str) -> None:
    spec = _acl_spec(node.acl)
    # --set 直接接逗号分隔的内联 acl_spec，并整体替换既有 ACL；
    # 不用 --set-file（后者参数是 ACL 文本文件路径而非规格串）。
    proc = subprocess.run(
        [SETFACL_BIN, "--set", spec, local],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
    )
    if proc.returncode != 0:
        raise TreeBuildError(
            f"setfacl 失败（节点 {node.path}）: {proc.stderr.strip() or proc.stdout.strip()}"
        )


def cleanup_tree(root: str) -> None:
    """子进程退出后回收整棵临时树；仅删除 mkdtemp 生成的 tree-* 目录。

    树内节点可能被还原成 000 权限或其它属主。采用显式递归：进入目录前先补回
    属主 rwx（保证可遍历、可解除条目），自下而上删除。编排进程为 root 时凭借
    DAC_OVERRIDE 与属主身份必然成功，非 root 自测环境也能回收自己的树。
    """
    import stat as _stat

    real = os.path.realpath(root)
    if not (os.path.isdir(real) and os.path.basename(real).startswith("tree-")):
        return

    def _rm(path: str) -> None:
        try:
            os.chmod(path, _stat.S_IRWXU)
        except OSError:
            pass
        try:
            entries = os.listdir(path)
        except OSError:
            # 无法列目录（root 下不应发生）；兜底直接删除，失败则抛出
            os.rmdir(path)
            return
        for name in entries:
            child = os.path.join(path, name)
            try:
                # lstat：清理阶段绝不跟随符号链接
                if _stat.S_ISDIR(os.lstat(child).st_mode):
                    _rm(child)
                else:
                    os.unlink(child)
            except FileNotFoundError:
                continue
        os.rmdir(path)

    _rm(real)


def build_tree(snap: Snapshot, tmp_root: str | None = None) -> BuiltTree:
    """在 tmp_root（默认 SANDBOX_TMP_ROOT）下创建唯一临时根并还原快照。"""
    base = os.path.realpath(tmp_root or SANDBOX_TMP_ROOT)
    os.makedirs(base, exist_ok=True)
    root = os.path.realpath(tempfile.mkdtemp(prefix="tree-", dir=base))
    built = BuiltTree(root=root)
    root_node: Node | None = None
    try:
        # 按路径深度排序，保证父先于子；跳过的节点不影响其它分支
        ordered = sorted(snap.nodes.values(), key=lambda n: n.path.count("/"))
        for node in ordered:
            if node.path == "/":
                if node.type != "directory":
                    raise TreeBuildError("根节点不是目录")
            elif node.type == "other":
                built.skipped.append({
                    "path": node.path, "reason": "type=other 无法在影子树中还原设备/特殊节点",
                })
                continue
            elif not _parent_chain_ok(node, snap):
                built.skipped.append({
                    "path": node.path,
                    "reason": "父目录链不齐全（祖先缺失或不是目录），无法安全创建",
                })
                continue

            local = _local_path(root, node.path)
            if node.path == "/":
                if node.type != "directory":
                    raise TreeBuildError("根节点不是目录")
                # 根节点即临时目录本身；其属主/mode/ACL 必须最后应用，
                # 否则提前把根改成请求用户不可遍历的权限会中断后续构建
                root_node = node
                continue
            elif node.type == "directory":
                _safe_mkdir(local)
            elif node.type == "file":
                _safe_create_file(local)
            elif node.type == "symlink":
                # 链接只还原目标；不 chown/chmod（Linux 链接权限不参与判定）
                _safe_symlink(node.link_target or "", local)
                built.node_count += 1
                continue
            else:  # 理论不可达（other 已在上面跳过）
                built.skipped.append({"path": node.path, "reason": f"不支持的类型 {node.type}"})
                continue

            # 非链接节点：还原 uid/gid、mode、访问 ACL
            _apply_identity_and_mode(node, local)
            if node.acl:
                _apply_acl(node, local)
                built.acl_applied += 1
            built.node_count += 1

        # 最后再把快照根节点 / 的属主、mode 与访问 ACL 落到临时树根
        if root_node is not None:
            _apply_identity_and_mode(root_node, root)
            if root_node.acl:
                _apply_acl(root_node, root)
                built.acl_applied += 1
            built.node_count += 1
    except TreeBuildError:
        cleanup_tree(root)
        raise
    except OSError as exc:
        cleanup_tree(root)
        raise TreeBuildError(f"构建节点时发生系统错误: {exc!r}") from exc
    except subprocess.TimeoutExpired as exc:
        cleanup_tree(root)
        raise TreeBuildError("setfacl 执行超时") from exc
    return built
