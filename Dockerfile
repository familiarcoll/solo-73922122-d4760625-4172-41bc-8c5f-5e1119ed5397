FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# acl：提供 setfacl，用于在影子树上还原快照中的 POSIX.1e 访问 ACL；
# 不安装任何多余组件。
RUN apt-get update \
    && apt-get install -y --no-install-recommends acl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app /app/app

# 编排进程必须以 root 启动才能 chroot/setuid；真正执行 open 的沙箱子进程
# 会按请求 UID/GID 降权、清空全部 capability（见 app/sandbox_child.py）。
# 容器本身在 compose 中仅授予所需 capability 且禁用 privileged。
USER root

# 影子树的工作根：compose 中以 tmpfs 挂载，不落宿主磁盘、不挂载宿主目录
ENV DIAG_SANDBOX_TMP=/tmp/diag-sandbox
RUN mkdir -p /tmp/diag-sandbox && chmod 700 /tmp/diag-sandbox

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status==200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
