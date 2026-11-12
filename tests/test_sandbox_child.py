"""
sandbox_child.py 子进程契约测试（无需 root）。

真实 chroot/setuid/prctl 无法在无特权环境执行，这里通过独立子进程 + 打桩模块
注入 os 层特权调用与 child 模块的 _libc.prctl，驱动其全部控制流，验证：
  * argv/stdin/stdout 一行 JSON 契约；
  * open 放行（普通文件）/ EACCES / 非普通文件 / 隔离失败 / 清能力失败 / 非法 UID；
  * errno 名称与整数、降权身份回显。

真实特权系统调用的端到端行为由 test_real_check.py 中的 root marker 用例覆盖
（在 docker compose 容器内运行）。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

import pytest

pytestmark = pytest.mark.realcheck

CHILD = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "app", "sandbox_child.py",
)

_STUB = '''
import errno, os, stat as _stat
MODE = os.environ["STUB_MODE"]
_TREE = os.environ["STUB_TREE"]
if MODE in ("ok", "deny", "nonreg"):
    os.fchdir = lambda fd: None
    os.chroot = lambda p: None
    os.chdir = lambda p: None
    os.setgroups = lambda g: None
    os.setresgid = lambda *a: None
    os.setresuid = lambda *a: None
    os.geteuid = lambda: 1001
    os.getuid = lambda: 1001
    os.getegid = lambda: 1001
    os.getgid = lambda: 1001
    os.getgroups = lambda: [1001, 100]
    _real_open = os.open
    def _open(p, flags, *a, **k):
        if isinstance(p, str) and p.startswith("/") and not (flags & os.O_DIRECTORY):
            p = _TREE + p
        return _real_open(p, flags, *a, **k)
    os.open = _open
if MODE == "deny":
    def _deny(p, flags, *a, **k):
        if flags & os.O_DIRECTORY:
            return _real_open(p, flags, *a, **k)
        e = OSError(); e.errno = errno.EACCES; raise e
    os.open = _deny
if MODE == "nonreg":
    def _fstat(fd):
        class S: st_mode = _stat.S_IFDIR | 0o755
        return S()
    os.fstat = _fstat
if MODE == "chrootfail":
    os.fchdir = lambda fd: None
    def _cf(p):
        e = OSError(); e.errno = errno.EPERM; raise e
    os.chroot = _cf
'''


@pytest.fixture(scope="module")
def env_paths(tmp_path_factory):
    stub_dir = tmp_path_factory.mktemp("stubs")
    (stub_dir / "diag_stub.py").write_text(_STUB)
    tree = tmp_path_factory.mktemp("flow")
    (tree / "d").mkdir()
    (tree / "d" / "a.txt").write_text("")
    return str(stub_dir), str(tree)


def _run_child(stub_dir, tree, mode, prctl_fail=False, path="/d/a.txt"):
    child_argv = ["sandbox_child.py", tree, "1001", "1001", "100,1001"]
    if prctl_fail:
        prctl_patch = (
            "import errno as _e, ctypes as _ct\n"
            "def _bad(*a, **k):\n"
            "    _ct.set_errno(_e.EPERM)\n"
            "    return -1\n"
            "m._libc.prctl = _bad"
        )
    else:
        prctl_patch = "m._libc.prctl = lambda *a, **k: 0"
    wrapper = (
        "import sys, importlib.util\n"
        "sys.argv = %r\n"
        "sys.path.insert(0, %r)\n"
        "import diag_stub\n"
        "spec = importlib.util.spec_from_file_location('sandbox_child', %r)\n"
        "m = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(m)\n"
        "%s\n"
        "m.main()\n"
        % (child_argv, stub_dir, CHILD, prctl_patch)
    )
    proc = subprocess.run(
        [sys.executable, "-I", "-c", wrapper],
        input=json.dumps({"path": path}) + "\n",
        capture_output=True, text=True, timeout=15,
        env=dict(os.environ, STUB_MODE=mode, STUB_TREE=tree),
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_open_granted_regular_file(env_paths):
    stub_dir, tree = env_paths
    out = _run_child(stub_dir, tree, "ok")
    assert out["measured"] is True
    assert out["readable"] is True
    assert out["is_regular_file"] is True
    assert out["errno"] is None
    assert out["identity"]["uid"] == 1001
    assert out["identity"]["groups"] == [100, 1001]


def test_open_eacces_maps_errno(env_paths):
    stub_dir, tree = env_paths
    out = _run_child(stub_dir, tree, "deny")
    assert out["measured"] is True
    assert out["readable"] is False
    assert out["errno"] == "EACCES"
    assert out["errno_int"] == 13
    assert out["is_regular_file"] is None


def test_non_regular_file_detected_by_fstat(env_paths):
    stub_dir, tree = env_paths
    out = _run_child(stub_dir, tree, "nonreg")
    assert out["measured"] is True
    assert out["open_ok"] is True
    assert out["is_regular_file"] is False
    assert out["readable"] is False


def test_isolation_failure_is_unmeasurable(env_paths):
    stub_dir, tree = env_paths
    out = _run_child(stub_dir, tree, "chrootfail")
    assert out["measured"] is False
    assert out["stage"] == "isolate"
    assert out["errno"] == "EPERM"


def test_cap_drop_failure_is_unmeasurable(env_paths):
    stub_dir, tree = env_paths
    out = _run_child(stub_dir, tree, "ok", prctl_fail=True)
    assert out["measured"] is False
    assert out["stage"] == "drop_caps"
    assert out["errno"] == "EPERM"


def test_zero_uid_rejected(env_paths):
    _, tree = env_paths
    proc = subprocess.run(
        [sys.executable, "-I", CHILD, tree, "0", "1001", ""],
        input=json.dumps({"path": "/d/a.txt"}) + "\n",
        capture_output=True, text=True, timeout=15,
    )
    out = json.loads(proc.stdout.strip().splitlines()[-1])
    assert out["measured"] is False
    assert out["stage"] == "sandbox_argv"


def test_output_is_single_json_line(env_paths):
    stub_dir, tree = env_paths
    child_argv = ["sandbox_child.py", tree, "1001", "1001", "100,1001"]
    wrapper = (
        "import sys, importlib.util\n"
        "sys.argv = %r\nsys.path.insert(0, %r)\nimport diag_stub\n"
        "spec = importlib.util.spec_from_file_location('sandbox_child', %r)\n"
        "m = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(m)\n"
        "m._libc.prctl = lambda *a, **k: 0\nm.main()\n"
        % (child_argv, stub_dir, CHILD)
    )
    proc = subprocess.run(
        [sys.executable, "-I", "-c", wrapper],
        input=json.dumps({"path": "/d/a.txt"}) + "\n",
        capture_output=True, text=True, timeout=15,
        env=dict(os.environ, STUB_MODE="ok", STUB_TREE=tree),
    )
    # stdout 仅允许一行 JSON（runner 取最后一行，但正常应恰好一行）
    lines = [ln for ln in proc.stdout.strip().splitlines() if ln.strip()]
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["measured"] is True
