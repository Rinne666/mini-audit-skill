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

#### 推送后复跑发现：没有 docker 的主机会直接崩溃

v1.1.1 第一次推送后复核 CI 结果时发现两个同源缺陷，都属于「只在特定环境下才暴露」的类型。

**缺陷 A（更严重）：`sandbox probe` 在未安装 docker 的主机上抛 `FileNotFoundError`。**
`verify_backend` 的后端不可用分支是 `image=getattr(backend, "image", "")`，而 `image`
是一个会去执行 `docker image inspect` 的 property；`getattr` 的默认值**不能**覆盖
property 自身抛出的异常。于是「docker 不存在」这条最该优雅处理的路径，反而直接抛
`FileNotFoundError: 'docker'` —— 文档里让用户第一步执行的 `sandbox probe`，在任何未安装
docker 的机器上都是完整 traceback。

之所以没被测试发现：本机与两个 CI runner 都装了 docker —— **我们在唯一一个能跑通的环境里测试它**。

修复：`_image_present` / `_daemon_up` 先 `shutil.which` 判存在并捕获 `OSError`，不存在即返回
`False`。对比验证（同一命令、同一受限 PATH）：

```text
修复前 → FileNotFoundError: [Errno 2] No such file or directory: 'docker'
修复后 → exit=1，reason: "no usable isolation backend on this host —
          docker: docker not found on PATH; bwrap: bwrap not found on PATH;
          sandbox-exec: sandbox_apply: Operation not permitted"
          host_fallback: false
```

**缺陷 B：`MINI_AUDIT_DOCKER_IMAGE` 覆盖值不经校验即被当作「可用」。**
`available()` 就是 `bool(self.image)`，而 env 分支把调用者给的 ref 原样返回，因此
`MINI_AUDIT_DOCKER_IMAGE=typo:1` 会让后端**谎报可用**。连带效果是 live 测试的 skip 守卫不可靠：
同一个 `skipif` 守卫用 `b.available()`，在本地（镜像存在但 env 被改成不存在的 ref → 守卫为真
→ 测试真的跑 → 断言失败）与 CI（无任何候选镜像 → 守卫为假 → 干净 skip）表现不同，同一套代码
一处硬失败一处静默跳过。

修复：env 覆盖值同样经 `_image_present` 校验，不在就返回 `""`；`unavailable_reason()` 明确
点出是覆盖值有问题（`MINI_AUDIT_DOCKER_IMAGE='typo:1' is not present locally`），而不是含糊地
说「没有可用镜像」。回归测试：

```text
test_docker_backend_without_a_docker_binary_reports_unavailable
test_env_image_override_is_not_taken_on_trust
```

同时给 CI 的 pytest 加上 `-rs`：skip 必须带原因打印，不能藏在绿色勾后面。

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
pytest tests/unit                              395 passed
scripts/manifest.py --check                    up to date (130 items)
scripts/check-manifest.py --strict             0 errors / 1 license warning
scripts/doc_counts.py --check                  consistent
evals/run.py --self-check                      30 fixtures, 0 errors
```

GitHub Actions（push `b32ba27`，run `34945876839`）三个 job 全绿：

```text
verify (py3.9)                390 passed, 3 skipped   ← 3 个 skip = live 容器测试（该 job 未预拉镜像）
verify (py3.13)               393 passed
sandbox containment           42 passed, 0 skipped    ← 真实容器隔离测试确实执行了
```

---

# Search Governance v1 — Phase A 落地（runtime 1.2.0）

Round 1 + Round 2 冻结后开始实现。本次只做 **Phase A**：research state 的地基，以及与既有
pipeline 的衔接。不包含 Governor、Saturation 硬 gate 与 long-horizon eval。

## 新增 / 扩展

```text
schemas/audit-objective.schema.json      控制面：审计要证明什么
schemas/search-ledger.schema.json        研究面：知道什么 / 怀疑什么 / 卡在哪 / 下一步
schemas/research-delta.schema.json       agent 唯一的写入通道
schemas/attack-graph.schema.json         能力及其转换

runtime/objective.py                     canonical objective、revision/supersedes、bootstrap
runtime/research_state.py                search ledger + 17 步 all-or-nothing 事务
runtime/attack_graph.py                  图数据层（id 分配、一致性、objective 引导）
runtime/search_lock.py                   SearchGovernanceLock（LOCK_EX / LOCK_SH）

tests/unit/test_search_governance.py     56 条
```

扩展：`candidate.schema.json` 增加 optional `research`；`finding.schema.json` 增加 optional
`boundary.capability_refs`；`gates.py` 的 L1 要求两个 canonical artifact、L6 新增
`every_review_candidate_has_research_metadata`；`cli.py` 增加 `objective {init,replace,show}`
与 `research {apply,status}`。

## 五个「冻结清单之外」的实现决定

1. **补了 `attack-graph.schema.json` 与 `attack_graph.py`。** 冻结的 delta 契约里有
   `capabilities_add` / `edges_add`，`research apply` 必然要写 `attack-graph.json`；若该 artifact
   没有 schema 和一致性检查，就等于把 v1.1.1 刚删掉的「声明了但校验不了」重新引入。图模块只做数据层
   （id、consistency、悬空引用、objective 引导），path 查询留 Phase B。

2. **结构化 identity 不允许换 key 重声明。** Round 2 的规则是「key 不同 → 不同对象」。对
   capability / edge 这类闭合词表 identity（`name+principal`、`from,to,relation,via_candidate`），
   实现上多加一条：新 key 若声明了已被别的 key 持有的 identity，报 `IDENTITY_ALREADY_BOUND` 并整条拒绝。
   否则同一能力会有两个节点，而「距目标几条边」「路径是否闭合」都会因此静默失真。自由文本
   identity（fact / assumption / question）不适用——散文相等不是可靠去重依据。

3. **`candidate_updates` 不适用冲突规则，但必须命中真实 candidate。** candidate 的 `research`
   块没有 identity 字段，因此 scalar 覆盖、list 并集；重新分类（`standalone` → `chain_seed`）
   正是它的用途。目标是孤儿 patch 则 `UNKNOWN_CANDIDATE` 整条拒绝。

4. **`init` 与 `replace` 对图刻意不对称。** `init` 播种 principal / initial_capabilities / goals；
   `replace` **不动图**，只写 supersedes 与 ledger 系统 fact——重新播种会让已研究出的 capability
   悬空。代价是 principal 变更后旧节点仍在，由系统 fact 记录，这是有意选择。

5. **L6 的 research 强制检查读 chamber 产物。** gate 的 source 是
   `chamber-workspace/*/debate.json`；若改成要求 `candidates/*.json` 存在，会让「没装扫描器」的审计
   无法通过 L6，而那条路径是仓库明确支持的。canonical candidate store 上的 `research` 由
   `candidate_updates` 负责。

## 实现中抓到的缺陷

- **search-ledger 的三处 if/then 少了 `required`**，缺字段时凭空通过：`deferred` 不带
  `reopen_if`、`resolved`/`refuted` 不带 `evidence_refs` 都曾判有效。这正是要防的那类 fail-open，
  已修并在测试里双向锁定（9 组参数化）。
- `_next_id` 对 `^(PRIN|CAP|GOAL)-(\d+)$` 取的是 group(1)（前缀）而非数字；且编号未按前缀隔离
  （goal 会吃掉 capability 的号）。已修。
- 一个 delta 新增多个 capability 时 id 分配会死循环——规划阶段图未变更，`next_node_id` 每次返回同值。
  改为按前缀计数。
- capability 省略 `principal` 时默认取 objective principal，但 identity 比对用的是空串，合法 delta
  被误判为 `RESEARCH_KEY_CONFLICT`。已修。
- `edge.via_candidate` 是 identity 字段、不在可变字段表内，创建边时没被带上，直到 schema 校验才报错。已修。
- `candidate_updates` 最初根本没接进事务；且回写时重新读文件会丢掉内存里的 patch。已修（保留 payload 引用）。

## 验证

```text
pytest tests/unit                              452 passed（既有 396 + 新增 56）
scripts/manifest.py --check                    up to date (130 items)
scripts/check-manifest.py --strict             0 errors / 1 license warning
scripts/doc_counts.py --check                  consistent
evals/run.py --self-check                      30 fixtures, 0 errors
```

手工 CLI 端到端（`/tmp/clitest`）：

```text
objective init                        → revision 1；图播种 PRIN-001 / CAP-001 / GOAL-001
objective init（第二次）               → 拒绝（already exists）
research apply                        → 前向引用解析：edge.from 以 key 声明、落盘为 CAP-001
objective replace --force --reason    → revision 2 + supersedes(previous_hash) + ledger 系统 fact
objective replace（内容相同）          → 拒绝：不虚增 revision
锁被占用 + MINI_AUDIT_SEARCH_LOCK_TIMEOUT=0.4
                                      → 退出码 3 + holder{pid,agent,operation,acquired_at}
L1 gate（无 objective/ledger）          → 拒绝并点名两个文件
L1 gate（三件齐）                       → 通过
L1 gate（objective 缺 security_invariants）→ 拒绝
```

## 尚未做

```text
Phase B  attack graph path / nearest-path 查询
Phase C  search_governor.py、search next、search saturation
Phase D  L5/L6/L7/P12/X1-X3/I1-I3 的 research delta 接入
         L7 reported_capability_paths_closed（7 条子条件）
Phase E  evals/long_horizon/ 重放评测器 E0 与三个优先指标
其他     ledger 内 ref 的解析约定：目前是不透明字符串（相对 audit root），agent 写的
         evidence_refs 更像 repo 相对路径，统一留给 Phase D 的 closure 检查定义
```
