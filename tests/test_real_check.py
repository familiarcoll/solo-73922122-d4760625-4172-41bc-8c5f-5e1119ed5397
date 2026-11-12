"""
内核实测链路测试。

* 无 root 环境（CI/本机）：验证降级为“无法实测”、响应结构、模拟不被冒充、
  临时树构建的安全规则（不跟随软链接、跳过不支持节点）、一致性对照逻辑；
* root 环境（docker compose 容器内）：跑完整 chroot 沙箱，验证真实 open/fstat、
  errno、身份切换、能力清空与并发隔离。用 pytest marker 区分，缺权限自动 skip。
"""

from __future__ import annotations

import json
import os
import threading

import pytest

from app.compare import compare
from app.engine import build_request, build_snapshot
from app.real_runner import run_real_check
from app.tree_builder import (
    SANDBOX_TMP_ROOT,
    TreeBuildError,
    build_tree,
    cleanup_tree,
)

pytestmark = pytest.mark.realcheck

IS_ROOT = os.geteuid() == 0


def _snap(nodes, users=None, groups=None):
    return build_snapshot({"nodes": nodes, "users": users or {}, "groups": groups or {}})


def d(path, mode="755", uid=0, gid=0, **kw):
    base = {"path": path, "type": "directory", "uid": uid, "gid": gid, "mode": mode}
    base.update(kw)
    return base


def f(path, mode="644", uid=0, gid=0, **kw):
    base = {"path": path, "type": "file", "uid": uid, "gid": gid, "mode": mode}
    base.update(kw)
    return base


def l(path, target, **kw):
    base = {"path": path, "type": "symlink", "uid": 0, "gid": 0,
            "mode": "777", "link_target": target}
    base.update(kw)
    return base


BASIC = [d("/"), d("/data", "755"), f("/data/a.txt", "644")]
REQ = {"uid": 1001, "gid": 1001, "supp_groups": [], "path": "/data/a.txt"}


# --------------------------------------------------------------------------- #
# 1. 无特权环境：明确“无法实测”，结构完整，绝不冒充
# --------------------------------------------------------------------------- #
class TestUnprivilegedDegrades:
    def test_nonroot_returns_unmeasurable(self):
        if IS_ROOT:
            pytest.skip("仅在无 root 环境验证降级路径")
        out = run_real_check(_snap(BASIC), build_request(REQ))
        assert out["measured"] is False
        assert out["stage"] == "runtime_unsupported"
        assert "root" in out["message"]

    def test_api_response_keeps_simulation_and_real_separate(self):
        from fastapi.testclient import TestClient
        from app.main import app
        client = TestClient(app)
        r = client.post("/api/diagnose", json={
            "snapshot": {"nodes": BASIC}, "request": REQ,
        })
        body = r.json()
        assert body["ok"] is True
        # 模拟轨迹依旧完整
        assert body["result"]["readable"] is True
        assert body["result"]["steps"]
        # 实测独立字段，且无 root 时无法实测
        assert body["real_check"]["measured"] is False
        assert body["consistency"]["status"] == "unverifiable"


# --------------------------------------------------------------------------- #
# 2. 影子树构建安全（无 root 也能验证创建规则与跳过逻辑，不做 chown）
# --------------------------------------------------------------------------- #
class TestTreeBuildSafety:
    # 非 root 自测：非链接节点统一用当前进程 uid/gid，专注验证结构/跳过/空文件；
    # 属主、mode 与 ACL 的完整还原由 root 集成测试覆盖。
    def test_other_type_and_broken_parent_chain_are_skipped(self, tmp_path):
        base = str(tmp_path / "sb")
        u, g = os.getuid(), os.getgid()
        nodes = [
            d("/", uid=u, gid=g),
            {"path": "/dev/null", "type": "other", "uid": 0, "gid": 0, "mode": "666"},
            f("/orphan/f.txt"),  # 父目录 /orphan 不在快照
            d("/ok", uid=u, gid=g), f("/ok/f.txt", "644", uid=u, gid=g),
        ]
        tree = build_tree(_snap(nodes), tmp_root=base)
        try:
            skipped_paths = {s["path"] for s in tree.skipped}
            assert "/dev/null" in skipped_paths
            assert "/orphan/f.txt" in skipped_paths
            assert os.path.isdir(os.path.join(tree.root, "ok"))
            assert os.path.isfile(os.path.join(tree.root, "ok", "f.txt"))
            # 空文件
            assert os.path.getsize(os.path.join(tree.root, "ok", "f.txt")) == 0
        finally:
            cleanup_tree(tree.root)
        assert not os.path.exists(tree.root)

    def test_symlink_is_recreated_not_followed(self, tmp_path):
        base = str(tmp_path / "sb")
        u, g = os.getuid(), os.getgid()
        nodes = [d("/", uid=u, gid=g), d("/d", uid=u, gid=g),
                 f("/d/t", "644", uid=u, gid=g),
                 l("/d/ln", "t"), l("/escape", "/etc/passwd")]
        tree = build_tree(_snap(nodes), tmp_root=base)
        try:
            link = os.path.join(tree.root, "d", "ln")
            assert os.path.islink(link)
            assert os.readlink(link) == "t"
            esc = os.path.join(tree.root, "escape")
            assert os.path.islink(esc)
            # 指向树外的绝对链接只作为链接对象存在，构建期没有触碰 /etc/passwd
            assert os.readlink(esc) == "/etc/passwd"
        finally:
            cleanup_tree(tree.root)

    def test_files_are_empty(self, tmp_path):
        base = str(tmp_path / "sb")
        u, g = os.getuid(), os.getgid()
        nodes = [d("/", uid=u, gid=g), f("/empty.txt", "644", uid=u, gid=g)]
        tree = build_tree(_snap(nodes), tmp_root=base)
        try:
            assert os.path.getsize(os.path.join(tree.root, "empty.txt")) == 0
        finally:
            cleanup_tree(tree.root)

    def test_path_mapping_cannot_escape_root(self, tmp_path):
        from app.tree_builder import _local_path
        root = str(tmp_path / "root")
        os.makedirs(root)
        good = _local_path(root, "/a/b")
        assert good.startswith(root + os.sep)
        with pytest.raises(TreeBuildError):
            _local_path(root, "/../escape")


# --------------------------------------------------------------------------- #
# 2b. 真实 setfacl + 内核 ACL 落地（仅当环境提供 setfacl 时运行）
# --------------------------------------------------------------------------- #
def _setfacl_available() -> bool:
    import shutil
    return shutil.which("setfacl") is not None


@pytest.mark.skipif(not _setfacl_available(), reason="环境无 setfacl")
class TestTreeBuildRealACL:
    def test_acl_is_applied_and_kernel_enforces_owner_entry(self, tmp_path):
        u, g = os.getuid(), os.getgid()
        snap = _snap([
            d("/", uid=u, gid=g),
            f("/denied.txt", "600", uid=u, gid=g, acl=[
                {"type": "user_obj", "perms": "---"},
                {"type": "group_obj", "perms": "r--"},
                {"type": "other", "perms": "r--"},
            ]),
            f("/allowed.txt", "600", uid=u, gid=g, acl=[
                {"type": "user_obj", "perms": "r--"},
                {"type": "group_obj", "perms": "---"},
                {"type": "other", "perms": "---"},
            ]),
        ])
        tree = build_tree(snap, tmp_root=str(tmp_path / "sb"))
        try:
            assert tree.acl_applied == 2
            # 属主走 user_obj：--- 拒绝、r-- 放行（内核真实判定）
            assert os.access(os.path.join(tree.root, "denied.txt"), os.R_OK) is False
            assert os.access(os.path.join(tree.root, "allowed.txt"), os.R_OK) is True
        finally:
            cleanup_tree(tree.root)

    def test_extended_acl_mask_lands_on_disk(self, tmp_path):
        import subprocess
        u, g = os.getuid(), os.getgid()
        snap = _snap([
            d("/", uid=u, gid=g),
            f("/ext.txt", "640", uid=u, gid=g, acl=[
                {"type": "user_obj", "perms": "rw-"},
                {"type": "user", "qualifier": 1002, "perms": "rwx"},
                {"type": "group_obj", "perms": "r--"},
                {"type": "mask", "perms": "r--"},
                {"type": "other", "perms": "---"},
            ]),
        ])
        tree = build_tree(snap, tmp_root=str(tmp_path / "sb"))
        try:
            out = subprocess.run(
                ["getfacl", "-p", os.path.join(tree.root, "ext.txt")],
                capture_output=True, text=True, timeout=10,
            )
            assert out.returncode == 0
            assert "user:1002:rwx" in out.stdout
            assert "mask::r--" in out.stdout
        finally:
            cleanup_tree(tree.root)


# --------------------------------------------------------------------------- #
# 3. 一致性对照纯逻辑
# --------------------------------------------------------------------------- #
class TestCompareLogic:
    def test_both_allow_is_consistent(self):
        sim = {"readable": True, "errno": None, "steps": [], "final_node": None}
        real = {"measured": True, "readable": True, "errno": None, "skipped_nodes": []}
        assert compare(sim, real)["status"] == "consistent"

    def test_both_deny_matching_errno_is_consistent(self):
        sim = {"readable": False, "errno": "EACCES", "steps": [], "final_node": None}
        real = {"measured": True, "readable": False, "errno": "EACCES",
                "skipped_nodes": []}
        assert compare(sim, real)["status"] == "consistent"

    def test_both_deny_different_errno_is_divergent(self):
        sim = {"readable": False, "errno": "ENOENT", "steps": [], "final_node": None}
        real = {"measured": True, "readable": False, "errno": "EACCES",
                "skipped_nodes": []}
        assert compare(sim, real)["status"] == "divergent"

    def test_split_verdict_is_divergent(self):
        sim = {"readable": True, "errno": None, "steps": [], "final_node": None}
        real = {"measured": True, "readable": False, "errno": "EACCES",
                "skipped_nodes": []}
        assert compare(sim, real)["status"] == "divergent"

    def test_unmeasurable_is_unverifiable(self):
        sim = {"readable": True, "steps": [], "final_node": None}
        real = {"measured": False, "message": "no root", "skipped_nodes": []}
        c = compare(sim, real)
        assert c["status"] == "unverifiable"

    def test_skipped_node_on_path_blocks_comparison(self):
        sim = {"readable": True, "steps": [{"node": {"path": "/dev/null"}}],
               "final_node": {"path": "/dev/null"}}
        real = {"measured": True, "readable": True, "errno": None,
                "skipped_nodes": [{"path": "/dev/null", "reason": "type=other"}]}
        c = compare(sim, real)
        assert c["status"] == "unverifiable"
        assert "/dev/null" in c["reason"]

    def test_skipped_node_off_path_still_compares(self):
        sim = {"readable": True, "steps": [{"node": {"path": "/ok"}}],
               "final_node": {"path": "/ok"}}
        real = {"measured": True, "readable": True, "errno": None,
                "skipped_nodes": [{"path": "/elsewhere", "reason": "x"}]}
        assert compare(sim, real)["status"] == "consistent"


# --------------------------------------------------------------------------- #
# 4. root 环境端到端：真实 chroot + 降权 + open/fstat
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(not IS_ROOT, reason="内核实测需要 root（CAP_SYS_CHROOT/SETUID 等）")
class TestKernelSandboxRoot:
    def test_open_granted_real_kernel(self):
        out = run_real_check(_snap(BASIC), build_request(REQ))
        assert out["measured"] is True, out
        assert out["readable"] is True
        assert out["errno"] is None
        assert out["is_regular_file"] is True
        assert out["identity"]["uid"] == 1001
        assert out["kernel_category"] == "ok"
        assert out["consistency"] if "consistency" in out else True

    def test_eacces_on_unsearchable_dir(self):
        nodes = [d("/"), d("/secret", "700"), f("/secret/f.txt", "644")]
        req = {"uid": 1001, "gid": 1001, "supp_groups": [], "path": "/secret/f.txt"}
        out = run_real_check(_snap(nodes), build_request(req))
        assert out["measured"] is True
        assert out["readable"] is False
        assert out["errno"] == "EACCES"
        assert out["kernel_category"] == "permission_denied"

    def test_enoent_missing_path(self):
        req = {"uid": 1001, "gid": 1001, "supp_groups": [], "path": "/data/gone"}
        out = run_real_check(_snap(BASIC), build_request(req))
        assert out["measured"] is True
        assert out["errno"] == "ENOENT"

    def test_eloop_symlink_cycle(self):
        nodes = [d("/"), d("/loop", "755"), l("/loop/a", "b"), l("/loop/b", "a")]
        req = {"uid": 1001, "gid": 1001, "supp_groups": [], "path": "/loop/a"}
        out = run_real_check(_snap(nodes), build_request(req))
        assert out["measured"] is True
        assert out["errno"] == "ELOOP"

    def test_supplementary_groups_applied(self):
        # 文件 640 属组 2000；仅附加组含 2000 时可读
        nodes = [d("/"), f("/g.txt", "640", uid=0, gid=2000)]
        denied = run_real_check(
            _snap(nodes),
            build_request({"uid": 1001, "gid": 1001, "supp_groups": [], "path": "/g.txt"}),
        )
        granted = run_real_check(
            _snap(nodes),
            build_request({"uid": 1001, "gid": 1001, "supp_groups": [2000], "path": "/g.txt"}),
        )
        assert denied["errno"] == "EACCES"
        assert granted["readable"] is True
        assert 2000 in granted["identity"]["groups"]

    def test_acl_named_user_mask_enforced_by_kernel(self):
        acl = [
            {"type": "user_obj", "perms": "rw-"},
            {"type": "user", "qualifier": 1002, "perms": "rwx"},
            {"type": "group_obj", "perms": "r--"},
            {"type": "mask", "perms": "r--"},
            {"type": "other", "perms": "---"},
        ]
        nodes = [d("/"), f("/acl.txt", "640", uid=0, gid=0, acl=acl)]
        out = run_real_check(
            _snap(nodes),
            build_request({"uid": 1002, "gid": 1002, "supp_groups": [], "path": "/acl.txt"}),
        )
        # mask r-- 约束后仍可读
        assert out["measured"] is True, out
        assert out["readable"] is True

    def test_temp_tree_cleaned_after_run(self):
        before = set(os.listdir(SANDBOX_TMP_ROOT)) if os.path.isdir(SANDBOX_TMP_ROOT) else set()
        run_real_check(_snap(BASIC), build_request(REQ))
        after = set(os.listdir(SANDBOX_TMP_ROOT)) if os.path.isdir(SANDBOX_TMP_ROOT) else set()
        assert before == after

    def test_concurrent_requests_isolated(self):
        results = []
        errors = []

        def worker():
            try:
                results.append(run_real_check(_snap(BASIC), build_request(REQ)))
            except Exception as exc:  # pragma: no cover - 并发失败应显式暴露
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        assert len(results) == 6
        assert all(r["measured"] is True for r in results)

    def test_absolute_symlink_cannot_escape_chroot(self):
        # 绝对链接指向宿主 /etc/passwd；chroot 后应解析为树内 /etc/passwd（不存在）
        nodes = [d("/"), d("/jail"), l("/jail/abs", "/etc/passwd")]
        req = {"uid": 1001, "gid": 1001, "supp_groups": [], "path": "/jail/abs"}
        out = run_real_check(_snap(nodes), build_request(req))
        assert out["measured"] is True
        assert out["errno"] == "ENOENT"
