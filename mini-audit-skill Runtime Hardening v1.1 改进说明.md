# mini-audit-skill Runtime Hardening v1.1 改进说明

## 目标

v1.1 不新增更多漏洞知识库或审计角色，重点修复 Runtime Hardening v1 中的正确性问题，让 deterministic runtime 真正成为可信的状态、验证和执行边界。

目标原则：

```text
Agent 负责推理
Runtime 负责保证规则一定被执行
```

---

## P0：必须修复

### 1. 修复 Source Identity

当前 `tree_hash` 使用 `HEAD^{tree}`，无法识别未提交的工作区修改。

改进：

- 增加 `worktree_hash`
- hash 应覆盖 tracked diff 和 untracked files
- resume 比较 `commit + worktree_hash`
- source 发生变化时默认拒绝静默 resume

新增测试：

```text
clean → dirty
dirty file changed
untracked file added
```

以上情况都必须导致 `matches() == false`。

---

### 2. Phase Complete 必须强制 Gate

当前可以直接执行：

```bash
mini-audit-runtime phase complete L6
```

绕过 artifact gate。

改进：

```text
phase complete
    ↓
runtime 自动执行对应 gate
    ↓
PASS
    ↓
状态转为 complete
```

Gate 失败时必须保持 `in_progress` 或转为 `failed`。

禁止任何 phase 在未通过 gate 的情况下进入 `complete`。

---

### 3. Semantic Check 必须绑定具体 Artifact

当前 semantic check 会遍历多个 JSON，只要其中一个返回成功就可能通过。

改进 gate 配置：

```yaml
semantic_checks:
  - check: every_confirmed_has_verifier
    source: mini-audit/findings.json

  - check: coverage_no_planned
    source: mini-audit/coverage-ledger.json

  - check: audit_state_terminal_phases
    source: mini-audit/audit-state.json
```

每个 semantic check 只能检查声明的 source。

---

### 4. 修复 Glob Artifact 的语义验证

例如 L6：

```text
chamber-workspace/*/debate.json
```

当前只检查文件存在，没有加载内容供 semantic gate 使用。

改进：

```yaml
required_glob:
  - pattern: mini-audit/chamber-workspace/*/debate.json
    parse_json: true
    aggregate_as: chambers
```

Runtime 应：

```text
glob
→ parse JSON
→ aggregate
→ semantic validation
```

---

### 5. 真正执行 JSON Schema

当前 `schemas/*.json` 已存在，但 runtime 主要依赖手写 validator。

改进：

- Gate 对声明 schema 的 artifact 强制 schema validation
- `finding validate` 强制执行 `finding.schema.json`
- `coverage validate` 强制执行 coverage schema
- `state load/save` 执行 audit-state schema

避免长期维护两套不一致规则。

---

### 6. 修复 Scheduler Timeout

当前 timeout 只停止等待，后台 thread 仍然继续执行。

这可能造成：

```text
attempt 1 timeout
attempt 2 启动
attempt 1 仍然运行
```

改进：

- 可执行任务使用独立 subprocess/process group
- timeout 后先 terminate
- grace period 后 kill
- 进程真正结束后才能释放 concurrency lease

软线程 timeout 不得再视为真正的执行终止。

---

### 7. 修复 Scanner Scripts

`detect-tools.sh` 当前 Python 部分无法调用 Bash 中定义的 `probe_version()`。

改进：

- tool detection 全部放 Python 或全部放 Bash
- 为 shell scripts 增加独立测试

同时修正 Semgrep 参数：

```bash
--config p/security-audit
--config p/owasp-top-ten
```

不要把多个 config 作为一个字符串参数传入。

---

### 8. Scanner 执行必须经过 Sandbox Policy

CodeQL build、PoC 和任何 target-controlled execution 都不能直接在 host 上运行。

统一流程：

```text
sandbox-check
    ↓
capability PASS
    ↓
sandbox-run
    ↓
scanner / PoC
```

缺少关键 sandbox 能力时：

```text
execution_status = blocked
verdict = needs_validation
```

禁止自动降级为直接 host execution。

---

## P1：高优先级改进

### 9. Coverage Ledger 禁止空计划通过

当前：

```json
{"units":[]}
```

可能被认为 coverage complete。

增加：

```text
planning_status = complete
unit_count > 0
```

只有已完成 coverage planning 且不存在 `planned/in_progress` unit 时才能通过最终 gate。

---

### 10. 收紧 State Transition

删除对 `to == in_progress` 的特殊绕过。

所有 transition 必须严格遵守：

```python
ALLOWED_TRANSITIONS
```

同时强制 `max_attempts`。

超过最大尝试次数时禁止再次启动 phase，除非显式 reset。

---

### 11. 完善 Diff Mode

当前 diff runtime 主要覆盖：

```text
D0 baseline
D1 changed files
D2 risk score
部分 D4 caller search
```

下一步补：

```text
D3 git history / regression
D4 structured blast radius
D5 test gap analysis
D6 adversarial verification
```

并逐步用 AST / SCIP / language server 替代纯 grep caller search。

---

### 12. 把 Evals 变成真正的 Regression Suite

当前已有 30 个 fixture，但缺少 runner。

新增：

```text
evals/run.py
evals/score.py
```

输出：

```text
TP
FP
FN
Precision
Recall
F1
Needs Validation Rate
Hard Bug Recall
```

CI 设置最低质量阈值，防止 prompt/runtime 修改导致安全质量倒退。

---

### 13. 完善 Reference Provenance

当前 MANIFEST 只有：

```text
path
kind
size
sha256
```

补充：

```text
source_repo
source_commit
source_path
license
modified
imported_at
```

这样才能同时解决完整性、来源追踪和许可证问题。

---

### 14. 清理 SKILL / README Contract Drift

当前文档仍残留旧描述，例如：

```text
resumable state via memory
export = stub
99 reference files
6 first-class roles
```

这些已经和实际实现不一致。

v1.1 发布前统一更新：

```text
SKILL.md
README.md
command status
reference counts
runtime capabilities
```

数量信息尽量由脚本自动生成，不再手工维护。

---

# 建议实施顺序

第一批：

```text
1. Source identity
2. Mandatory phase gates
3. Artifact-bound semantic checks
4. JSON Schema enforcement
```

第二批：

```text
5. Scheduler hard timeout
6. Scanner scripts
7. Sandbox enforcement
8. Coverage empty-plan protection
```

第三批：

```text
9. Diff mode
10. Eval runner
11. Reference provenance
12. Documentation cleanup
```

---

# v1.1 Definition of Done

```text
[ ] dirty working tree 会使 resume source mismatch
[ ] phase complete 无法绕过 gate
[ ] semantic check 绑定指定 artifact
[ ] glob JSON artifact 可参与 semantic validation
[ ] JSON Schema 在 runtime 中真正执行
[ ] timeout 后任务进程真正终止
[ ] scanner scripts 有自动测试
[ ] target execution 必须经过 sandbox policy
[ ] empty coverage plan 无法通过 final gate
[ ] state transition 严格执行 transition table
[ ] eval corpus 可以自动运行并计算指标
[ ] reference manifest 包含 provenance/license
[ ] SKILL.md 与实际 runtime 状态一致
```

v1.1 完成后，`mini-audit-skill` 的重点将从“已有 deterministic runtime”升级为：

> **deterministic runtime 的规则无法被 agent 或异常执行路径绕过。**
---

# v1.1.1 — correctness pass（复审收口）

v1.1 的外部复审给出六条带代码证据的问题。v1.1.1 只做正确性收口，不新增漏洞知识库或审计角色。

## 六条问题的处置

### 1. L7 self-deadlock（阻塞级）

`runtime/cli.py::_run_phase_gate` 把「正在完成的 phase」也放进了
`required_phases`，于是 L7 的 `audit_state_terminal_phases` 永远看到 L7 自己还是
`in_progress`，通过 CLI 执行 `phase complete L7` 永远不可能成功。原有测试通过手工
构造 `ctx={"required_phases": ["L1"]}` 把这个问题掩盖了。

修复：`cli.py` 与 `gates.py` 双侧排除当前 phase（`name != phase` / `name != current`）。

回归测试（已确认在无修复时失败、修复后通过）：

```text
test_cli_l7_can_complete_when_siblings_are_terminal
test_cli_l7_completes_when_it_is_the_only_phase
test_cli_l7_still_blocked_by_a_genuinely_non_terminal_phase
```

### 2. Sandbox 并非真实隔离（阻塞级）

`runtime/sandbox.py` 在能力自检之后直接 `subprocess.Popen` 在宿主机上执行；
`bwrap` / `docker` / `sandbox-exec` 从未被调用，`sandbox_available` /
`external_network_disabled` / `environment_sanitized` 都是自报的环境变量。
原测试只证明「策略允许 → 命令在宿主机上跑起来」，不证明任何隔离。

修复：新增 `runtime/sandbox_backend.py`，实现 Docker / bwrap / macOS
`sandbox-exec` 三个后端，并用**差分 canary** 判定隔离是否真的生效：

```text
基线（不隔离）完成了被禁止的动作  AND  隔离运行没有完成  →  该 control 才算 demonstrated
```

`probe_document()` 为每个可用后端跑 canary，产出 `schema_version=2` 的 probe，
逐条记录 `controls` / `demonstrated` / `evidence`；`evaluate_probe()` 拒绝仅有
声明的 legacy probe，并要求所选后端展示该 kind 所需的全部 control。

本机实测（Docker 29.6.x + alpine:3.20）：`ESCAPE_WRITE denied` /
`SOURCE_WRITE denied` / `NETWORK denied` / `SCRATCH_WRITE succeeded`，
`isolation_verified: true`，宿主机上 `escaped.txt` 与 `mutated.txt` 均不存在。

同时证明「存在 ≠ 可用」：macOS 自带 `sandbox-exec` 存在但执行报
`Operation not permitted`，被正确判定为 `usable=False`。

#### 网络探测改为 hermetic（不依赖外网）

第一版 canary 用硬编码公网端点（`1.1.1.1:53`）判定 `network_denial`：只有当
**未隔离的基线真的连通了**、且隔离运行**明确连不通**时才记 `True`。方向是对的，
但在这个真实网络里直接翻车——实测同一台机器上 `1.1.1.1:53` 与 `1.1.1.1:80` 可连、
`1.1.1.1:443` 与 `8.8.8.8:53` 超时。基线连不上时按 fail-closed 只能报 `False`，
于是 `poc` 所需的 `network_denial` 随机缺失、docker 后端时有时无、测试随之 flaky。

修复：不再依赖任何公网目标，由 verifier 自己起一个临时 TCP 监听
（`_ProbeListener`，绑 `0.0.0.0:0`），并优先选**宿主机可路由地址**作为目标
（`_candidate_probe_hosts()`：默认路由源地址 → 主机名解析 → 最后才回退 `127.0.0.1`）。
差分仍然真实成立，已实测：

```text
宿主机进程            → <lan-ip>:<port>  连通
docker（默认 bridge） → <lan-ip>:<port>  连通   / host.docker.internal 亦连通
docker --network none → 两者均连不通
```

由此，「基线完成了被禁止的动作」由 verifier 的**直接连接**给出（同为未隔离进程），
不再依赖镜像里有没有 `python3`/`nc`；隔离侧若报 `undetermined` 则记 `False` 并在
detail 中说明原因。回归测试：

```text
test_probe_listener_is_reachable_without_egress
test_probe_host_prefers_a_routable_address_over_loopback
test_network_denial_is_not_credited_when_nothing_was_reachable
```

副作用是更准也更快：`network_denial` 不再受网络环境影响，单测总时长从 ~73s 降到 ~45s。

收尾验证时又发现一个真实缺陷：`SandboxSpec.for_kind` 会把调用者原样传入的路径
（含相对路径）塞进挂载列表，于是 `--repo-root repo` 会生成
`docker run -v repo:repo:ro`，docker 报 `exit=125 invalid mount path: 'repo'`，
而 probe 把它归类为「没有可用隔离后端」——一个会让**所有执行被静默禁用**的假阴性。

修复：`for_kind` 只产出绝对形式（`os.path.abspath` + `resolve()` 两种，后者用于
桥接 macOS 的 `/tmp` → `/private/tmp`）；三个后端的 `build_argv` 增加
`_require_absolute` 断言，遇到非绝对挂载路径立即以 `SandboxBackendError` 报错，
而不是让它退化成「后端不可用」。回归测试：

```text
test_spec_mount_paths_are_always_absolute
test_spec_mounts_both_absolute_and_resolved_forms
test_backends_refuse_relative_mounts[docker|bwrap]
```

### 3. Semgrep 的 host fallback

`scripts/run-semgrep.sh` 在找不到 `sandbox-run.sh` 时会直接在宿主机上跑 semgrep，
与文档承诺的「never fall back to host execution」矛盾。修复：fail closed，退出码 4；
`run-codeql.sh` 同步补 `--repo-root` 并移除同类回退。

### 4. coverage `planning_status` 未强制

`coverage-ledger.schema.json` 未把 `planning_status` 设为 required，语义检查对缺失
字段 fail-open，导致「从未记录过 planning 生命周期」的 ledger 也能通过 L7。

修复：schema 中 `planning_status` 变为 required；`coverage_no_planned` 改为严格
（`!= "complete"` 即失败）；`_validate_schema` 对「声明了 schema 但加载不到」从
「跳过并加 note」改为**失败**（fail closed）。

### 5. 非 balanced 模式没有 gate

`DEFAULT_PHASE_GATES` 只覆盖 balanced。修复：扩充到 **38 个 phase**，并新增
`MODE_PHASES` / `gated_phases()` / `ungated_phases()`。未加 gate 的 phase 是**显式
列名**的（写入共享文档、或没有 artifact 契约），见 SKILL.md § Gate coverage。

### 6. 没有真正的 CI，且文档漂移

新增 `.github/workflows/ci.yml`：Python 3.9 + 3.13 双版本跑单测 / manifest 校验 /
doc_counts / eval 自检 / shell 语法；第二个 job 拉取 `alpine:3.20` 后跑真实容器
隔离测试。README 中「private repository」改为 public（仓库实为 PUBLIC），
并在 `doc_counts.py` 中把「phase gate 数量」纳入派生与校对，避免同类漂移。

## 验证

```text
pytest tests/unit                              393 passed
scripts/manifest.py --check                    up to date (130 items)
scripts/check-manifest.py --strict             0 errors / 1 license warning
scripts/doc_counts.py --check                  consistent
evals/run.py --self-check                      30 fixtures, 0 errors
```
