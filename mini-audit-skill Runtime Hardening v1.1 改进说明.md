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