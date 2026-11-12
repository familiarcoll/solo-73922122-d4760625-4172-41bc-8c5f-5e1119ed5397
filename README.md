# 共享文件服务器读取权限 · 诊断台（模拟 + 内核实测双证据）

运维排查「文件有读权限却打不开」时，用本工具在浏览器里编辑 **目录快照 JSON** 和 **读取请求 JSON**。
后端对同一份输入产出两条**相互独立**的证据链：

1. **模拟证据链（纯快照推演）**：在内存中按 Linux 无特权进程规则完整模拟路径解析（namei）
   与 DAC / POSIX.1e 判定，输出能否读取、首个失败原因、逐步解析过程与每一步采用的权限项。
   不触碰任何文件系统。
2. **内核实测证据链（真实系统调用）**：按快照在每请求独立的临时目录构建一棵**影子文件树**，
   并在**每请求独立的子进程**中 `chroot` 进该树、切换到请求的 UID/GID/附加组、清空全部
   capability，然后用真实内核 `open(O_RDONLY)` + `fstat` 复测，返回内核结论与 `errno`。

前端把两条证据链**分别展示**，并给出「一致 / 不一致 / 无法对照」判定；模拟结论**绝不冒充**实测。
准备或隔离失败时明确显示「无法实测」，此时页面上只有模拟推演。

## 一、内核实测的安全模型

| 需求 | 实现 |
| --- | --- |
| 独立文件树 | 每请求 `mkdtemp` 得到唯一临时根（`/tmp/diag-sandbox/tree-*`，tmpfs 内存盘），并发请求互不串用 |
| 仅支持受限节点 | 只还原父目录链齐全的目录 / 普通文件 / 软链接；`type=other`、父链缺失节点跳过并在结果中列出 |
| 文件为空 | 普通文件以 `O_CREAT|O_EXCL` 建为空文件，不写入任何快照内容 |
| 非链接节点属性 | 还原 uid/gid、mode、访问 ACL（`setfacl --set`，POSIX.1e access ACL） |
| 软链接 | 只还原 `link_target`（`symlink(2)` 不解析目标），不设置链接自身属主/mode（链接权限不参与 namei） |
| 不跟随链接写树外 | 父目录句柄一律 `O_DIRECTORY|O_NOFOLLOW`，配合快照层「父链必须是目录」校验，双层拦截越界写入 |
| 独立子进程隔离 | 每请求 `subprocess` 新进程，`close_fds` 不继承树外句柄，`start_new_session` 新会话 |
| chroot + chdir | 持有树根句柄 `fchdir` → `chroot(".")` → `chdir("/")`，随后关闭树根句柄 |
| 身份切换 | `setgroups` → `setresgid(r,e,s)` → `setresuid(r,e,s)`，并校验降权确实生效 |
| 清空能力 | `prctl(PR_SET_KEEPCAPS,0)` + 遍历 `prctl(PR_CAPBSET_DROP,…)` 清空 bounding set；setuid 到非 0 用户后其余集合随之为空 |
| 实测动作 | 仅 `open(O_RDONLY)` 后 `fstat` 确认普通文件并读一次；**不执行**任何快照内容 |
| 链接/`..` 不逃逸 | 绝对软链接与 `..` 由内核在 chroot 根内解析，天然无法指向树外；不挂载任何宿主目录 |
| 回收 | 仅在子进程 `wait()` 退出后清理临时树，成功/失败/超时路径都在 `finally` 中回收；启动时清理残留 |

## 二、启动

### 方式 A：Docker Compose（支持完整内核实测，推荐）

```bash
docker compose up --build
# 浏览器打开
#   http://localhost:8000/
```

容器以 **root 启动编排进程**（只有 root 能 `chroot`/`setuid`/`chown`），但：

- `privileged: false`，并 `cap_drop: ALL` 后**只加回所需的最小 capability**：
  `CHOWN`、`FOWNER`、`DAC_OVERRIDE`（建树还原属性/ACL）、
  `SETUID`、`SETGID`、`SETPCAP`（降权与清能力）、`SYS_CHROOT`（每请求换根）；
- 根文件系统只读，影子树写在 `tmpfs /tmp`（64m，内存，不落宿主磁盘）；
- `no-new-privileges` 且不挂载任何宿主目录/卷；
- 真正执行 `open` 的沙箱子进程会降权为请求的非 0 UID 并清空能力。

> 编排进程虽以 root 运行，但 root 身份只用于「为每个请求构建隔离环境并降权」，
> 不用于读取判定本身；所有读授权结论都由降权后的无能力子进程经真实内核得出。

### 方式 B：本机 Python（3.11+，仅模拟）

```bash
python3 -m pip install -r requirements.txt
./run.sh        # 等价于 uvicorn app.main:app --port 8000
# 打开 http://localhost:8000/
```

本机非 root 启动时，`/api/diagnose` 的实测部分会返回 `measured=false`（无法实测），
模拟轨迹照常工作；需要完整实测请用 Docker Compose。

健康检查：`GET /health`；OpenAPI 文档：`GET /docs`。

## 三、快照与请求格式

### 快照 snapshot（最多 100 个节点）

```json
{
  "users":  {"1001": "alice"},
  "groups": {"1000": "staff"},
  "nodes": [
    {
      "path": "/srv/secret.txt",          // 必须绝对、规范化、唯一
      "type": "file",                     // file | directory | symlink | other
      "uid": 0, "gid": 0,
      "mode": "640",                      // 3~4 位八进制字符串，也接受整数
      "link_target": "../etc/x",          // 仅 symlink 需要
      "acl": [                             // 可选，POSIX.1e 访问 ACL
        {"type": "user_obj",  "perms": "rw-"},
        {"type": "user",      "qualifier": 1001, "perms": "rwx"},
        {"type": "group_obj", "perms": "r--"},
        {"type": "group",     "qualifier": 1000, "perms": "r-x"},
        {"type": "mask",      "perms": "r--"},
        {"type": "other",     "perms": "---"}
      ]
    }
  ]
}
```

- `perms` 接受 `"rwx"` 三元组（无权限位写 `-`）或整数 `0..7`；
- 含命名 `user`/`group` 条目（扩展 ACL）时**必须**带 `mask`；
- 必须包含根目录 `/` 且类型为 `directory`；
- `type=other`（设备/FIFO/套接字等）无法在影子树中还原，会在实测结果的
  `skipped_nodes` 中列出；若它位于解析路径上，一致性判定为「无法对照」。

### 请求 request

```json
{ "uid": 1001, "gid": 1001, "supp_groups": [100, 1000], "path": "/srv/secret.txt" }
```

- `uid` 必须是**非 0 正整数**（root 拥有 cap_dac_override，不适用无特权诊断）；
- `path` 必须是绝对路径，允许 `.`、`..` 与软链接，按 Linux 规则物理解析。

## 四、判定语义（模拟链，与 Linux 对齐）

1. **逐级搜索权限**：进入/使用每个目录前检查 `--x`；`EACCES` 优先于 `ENOENT`。
2. **软链接**：相对目标按链接所在目录展开，绝对目标从 `/` 重新展开；链接自身 mode
   不参与判定；最多跟随 **40** 次（`MAXSYMLINKS`），第 41 次报 `ELOOP`。
3. **不提前折叠 `..`**：`..` 回退到当前物理目录的父目录。
4. **经典 mode**：属主 → 组（主组或任一附加组命中即用组位）→ other。
5. **POSIX ACL**：属主永远用 `user_obj`；命名 `user` 命中即终局且受 `mask` 约束、不退回；
   命中组条目权限取并集后再与 `mask`，命中即不退回 other；都不命中才走 other。
6. **结果分类**：`permission_denied`（EACCES）、`path_missing`（ENOENT）、
   `link_limit_exceeded`（ELOOP）、`not_regular`（非普通文件 / ENOTDIR）、`ok`。

## 五、HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET  | `/` | 浏览器诊断页面（单文件、零外部依赖，可离线） |
| GET  | `/health` | 健康检查 |
| GET  | `/api/examples` | 内置 6 个可编辑示例 |
| POST | `/api/validate-snapshot` | 仅校验快照，返回节点数与告警 |
| POST | `/api/diagnose` | 入参 `{snapshot, request}`，返回模拟结果 `result`、内核实测 `real_check`、一致性 `consistency` |

`/api/diagnose` 响应骨架：

```json
{
  "ok": true,
  "result":      { "readable": false, "errno": "EACCES", "steps": [ ... ] },
  "real_check":  { "measured": true, "readable": false, "errno": "EACCES",
                   "errno_int": 13, "is_regular_file": null,
                   "identity": {"uid": 1001, "gid": 1001, "groups": [1001]},
                   "kernel_category": "permission_denied",
                   "skipped_nodes": [], "tree_node_count": 3, "acl_applied": 0 },
  "consistency": { "status": "consistent", "label": "一致", "reason": "..." }
}
```

无法实测时 `real_check.measured=false` 且带 `stage`（`runtime_unsupported` /
`tree_build` / `isolate` / `set_identity` / `drop_caps` / `sandbox_exit` / `timeout` 等），
`consistency.status=unverifiable`。

## 六、测试

```bash
python3 -m pytest tests/ -q
```

- `test_engine.py`：模拟引擎的逐级 search、mode/ACL 分支、mask、不退回 other、
  物理 `..`、40/41 次链接边界、校验定位；
- `test_api.py`：HTTP 层错误定位、双证据响应结构、无 root 时「无法实测」不冒充；
- `test_sandbox_child.py`：以独立子进程 + 打桩驱动沙箱脚本全部控制流与一行 JSON 契约
  （放行 / EACCES / 非普通文件 / 隔离失败 / 清能力失败 / 非法 UID），无需 root；
- `test_real_check.py`：影子树安全（跳过规则、不跟随链接、空文件、路径不可越界）、
  一致性对照逻辑、真实 `setfacl`+内核 ACL 落地（环境有 setfacl 时），以及带 root
  marker 的完整 chroot 端到端用例（在 compose 容器内运行，普通环境自动 skip）。

## 七、目录结构

```
app/
  engine.py          # 快照校验 + mode/ACL 权限判定（模拟）
  resolver.py        # namei 风格路径解析（模拟，软链接/物理 ../40 次限制）
  tree_builder.py    # 影子文件树构建（受限节点、ACL、不跟随链接、回收）
  sandbox_child.py   # 每请求 chroot 子进程：降权、清能力、真实 open/fstat
  real_runner.py     # 实测编排：建树→起子进程→等待退出→回收
  compare.py         # 模拟与内核结论一致性对照
  main.py            # FastAPI 路由
  static/
    index.html       # 双证据诊断台
    examples.json    # 6 个可编辑示例
tests/               # pytest 测试
Dockerfile, docker-compose.yml, requirements.txt, run.sh, pytest.ini
```
