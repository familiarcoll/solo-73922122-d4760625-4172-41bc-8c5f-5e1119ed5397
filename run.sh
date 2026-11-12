#!/usr/bin/env bash
# 本机直接启动（Docker 方式见 docker-compose.yml）。
# 注意：非 root 启动时仅模拟链可用，/api/diagnose 的内核实测会返回“无法实测”；
# 完整 chroot 实测请用 docker compose（容器以 root 编排、降权子进程执行）。
set -euo pipefail
cd "$(dirname "$0")"
exec python3 -m uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}"
