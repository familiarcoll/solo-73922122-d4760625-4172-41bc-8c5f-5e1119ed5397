"""FastAPI 诊断服务：模拟链纯内存计算；实测链在每请求独立 chroot 子进程内访问影子树。"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from .engine import RequestError, SnapshotError, build_request, build_snapshot
from .resolver import diagnose
from .real_runner import cleanup_stale_trees, run_real_check
from .compare import compare as compare_verdict


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # 清理上次进程异常残留的临时树；当前请求的树由 real_runner 在用完后回收
    cleanup_stale_trees()
    yield


app = FastAPI(
    title="共享文件服务器读取权限离线诊断",
    version="2.0.0",
    lifespan=lifespan,
    description=(
        "基于运维采集的目录快照 JSON，先按 Linux 无特权进程规则模拟 namei 路径解析与"
        "DAC/POSIX.1e 判定，再在每请求独立的 chroot 临时树子进程中用真实内核 open/fstat "
        "复测并对照结论。模拟轨迹与内核实测分别呈现，互不冒充。"
    ),
)

STATIC_DIR = Path(__file__).resolve().parent / "static"


class DiagnosePayload(BaseModel):
    snapshot: Any
    request: Any


def _json_error(exc: SnapshotError | RequestError, status: int = 422) -> JSONResponse:
    kind = "snapshot_error" if isinstance(exc, SnapshotError) else "request_error"
    return JSONResponse(
        status_code=status,
        content={
            "ok": False,
            "error_type": kind,
            "message": exc.message,
            "loc": exc.loc,
            "loc_text": "$" + "".join(f"[{p!r}]" for p in exc.loc) if exc.loc else "$",
        },
    )


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/examples")
def examples() -> JSONResponse:
    data = json.loads((STATIC_DIR / "examples.json").read_text(encoding="utf-8"))
    return JSONResponse(data)


@app.post("/api/validate-snapshot")
def validate_snapshot(payload: dict[str, Any]) -> JSONResponse:
    try:
        snap = build_snapshot(payload.get("snapshot"))
    except SnapshotError as exc:
        return _json_error(exc)
    return JSONResponse(
        content={
            "ok": True,
            "node_count": len(snap.nodes),
            "warnings": snap.warnings,
            "paths": sorted(snap.nodes.keys()),
        }
    )


@app.post("/api/diagnose")
def diagnose_endpoint(payload: DiagnosePayload) -> JSONResponse:
    # 先校验快照（带定位），再校验请求
    try:
        snap = build_snapshot(payload.snapshot)
    except SnapshotError as exc:
        return _json_error(exc)
    try:
        req = build_request(payload.request)
    except RequestError as exc:
        return _json_error(exc)

    # 证据链一：纯快照模拟（不触碰文件系统），保留完整逐步轨迹
    simulation = diagnose(snap, req)
    simulation["snapshot_warnings"] = snap.warnings

    # 证据链二：每请求独立临时树 + chroot 子进程内核实测；
    # 环境不具备条件、构建或隔离失败时返回 measured=false（无法实测），
    # 绝不用模拟结果冒充实测
    real = run_real_check(snap, req)
    consistency = compare_verdict(simulation, real)

    return JSONResponse(content={
        "ok": True,
        "result": simulation,
        "real_check": real,
        "consistency": consistency,
    })
