"""
模拟结论与内核实测结论的一致性对照。

原则：
  * 模拟（resolver.py 的纯快照推演）与实测（chroot 沙箱里的真实 open/fstat）
    是两条独立证据链，前端必须分别展示，绝不互相冒充；
  * 实测无法进行（measured=false）时一致性行为“无法对照”；
  * 构建期跳过的节点若落在模拟解析路径上，内核环境与快照不等价，同样标记
    “无法对照”并说明原因，而不是给出可能误导的“一致/不一致”。
"""

from __future__ import annotations

from typing import Any

# 模拟 errno（resolver.CATEGORY 的键）-> 内核可能返回的 errno 集合
_SIM_ERRNO_TO_KERNEL = {
    "EACCES": {"EACCES"},
    "ENOENT": {"ENOENT", "ENOTDIR"},
    "ELOOP": {"ELOOP"},
    "ENOTDIR": {"ENOTDIR"},
    "ENOTREG": {"EISDIR", "ENOTDIR"},
}


def _sim_path_set(sim_result: dict[str, Any]) -> set[str]:
    """模拟解析过程中实际触达的快照节点路径。"""
    paths: set[str] = set()
    for step in sim_result.get("steps", []):
        node = step.get("node")
        if node and node.get("path"):
            paths.add(node["path"])
    final = sim_result.get("final_node")
    if final and final.get("path"):
        paths.add(final["path"])
    return paths


def compare(sim_result: dict[str, Any], real: dict[str, Any]) -> dict[str, Any]:
    """返回 {status, label, reason}，status ∈ consistent|divergent|unverifiable。"""
    if not real.get("measured"):
        return {
            "status": "unverifiable",
            "label": "无法对照",
            "reason": real.get("message", "实测未执行"),
        }

    touched = _sim_path_set(sim_result)
    blocking_skips = [
        s for s in real.get("skipped_nodes", []) if s["path"] in touched
    ]
    if blocking_skips:
        return {
            "status": "unverifiable",
            "label": "无法对照",
            "reason": "解析路径上有未还原节点："
                      + "；".join(f"{s['path']}（{s['reason']}）" for s in blocking_skips),
        }

    sim_readable = bool(sim_result.get("readable"))
    kernel_readable = bool(real.get("readable"))

    if sim_readable and kernel_readable:
        return {
            "status": "consistent",
            "label": "一致",
            "reason": "模拟与内核均放行 open(O_RDONLY)，且 fstat 确认为普通文件",
        }

    if not sim_readable and not kernel_readable:
        sim_errno = sim_result.get("errno")
        kernel_errno = real.get("errno")
        # 模拟 ENOTREG（目标非普通文件）时，内核对目录 open 得到 EISDIR
        expected = _SIM_ERRNO_TO_KERNEL.get(sim_errno, set())
        if kernel_errno in expected:
            return {
                "status": "consistent",
                "label": "一致",
                "reason": f"模拟与内核均拒绝：模拟 {sim_errno} ↔ 内核 {kernel_errno}",
            }
        return {
            "status": "divergent",
            "label": "不一致",
            "reason": f"双方都拒绝但 errno 不同：模拟 {sim_errno} ↔ 内核 {kernel_errno}",
            "sim_errno": sim_errno,
            "kernel_errno": kernel_errno,
        }

    # 一方放行、一方拒绝：明确分歧
    return {
        "status": "divergent",
        "label": "不一致",
        "reason": (
            f"模拟判定{'放行' if sim_readable else '拒绝'}，"
            f"内核实测{'放行' if kernel_readable else '拒绝'}"
            f"（内核 errno={real.get('errno') or '—'}）"
        ),
        "sim_errno": sim_result.get("errno"),
        "kernel_errno": real.get("errno"),
    }
