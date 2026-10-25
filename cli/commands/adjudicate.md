---
description: 审计出漏洞后，裁定哪些能报、报给谁（maintainer/CVE/CNVD/SRC），产出可申报总结
argument-hint: "[审计产物路径，如 ...\\security-audit-skill\\<项目>\\run-1\\findings.json；留空则自动定位最近一次审计]"
---

# /adjudicate — 审计后受理裁定

加载并严格按 `mini-adjudication` 技能执行（技能根目录：
`{{SKILL_DIR}}`，先读其 SKILL.md）。

## 第 0 步 — 技能新鲜度检查

```text
python {{SKILL_DIR}}\runtime\check_skill_loaded.py
```

非零退出 = 技能文件与 manifest 不一致，先报告用户，不要继续。

## 第 1 步 — 收单（Intake Gate）

- `$ARGUMENTS` 给了审计产物路径（findings.json / run 目录 / 报告）→ 用它。
- 没给 → 在用户主目录下找**最近修改**的审计运行产物
  （如 `security-audit-skill\*\run-*\findings.json`），列出候选让用户
  确认或直接取最新并说明。
- 找不到任何审计产物 → **停止**，告诉用户本技能只在审计出漏洞后触发，
  先运行 security-audit 审计。绝不自己去挖漏洞。

## 第 2 步 — 三阶段裁定（按 SKILL.md 执行）

1. **Adjudicate**：把每条 finding 登记为 claim，拆断言、做反证尝试，
   用 `runtime/evidence_log.py` 记录证据，产出 validity verdict。
2. **Assess**：对 holds 的 claim 回答三个受理问题；目标是开源项目时
   **必须**完成 OSS 核验（security 政策、commit 时间线、历史相似漏洞、
   开发者受理偏好），对照 `references/submission-targets.md` 的
   SRC/CNA/CNVD/众测平台受理标准。
3. **Deliver**：产出 `templates/submission-summary.md` 可申报总结——
   **按危害等级降序排列的漏洞表格**（critical→high→medium→low，
   每行含：危害等级/核心业务/开发者是否已知/是否需特殊配置/跨安全
   边界/目标平台，目标平台有且仅一个 primary），报告草稿用
   `templates/advisory.md`。

工作文件写到审计 run 目录旁的 `adjudication/` 子目录（adjudication-notes.md
+ evidence.jsonl + 产物），不要写进技能安装目录。

## 第 3 步 — 交付前硬门禁

```text
python {{SKILL_DIR}}\runtime\validate_adjudication.py <adjudication-notes.md> --evidence-ledger <evidence.jsonl>
```

非零退出 → 修复后重跑，不得带病交付。CVSS 向量必须过
`runtime/cvss31.py` 交叉校验。

## 红线

- 本命令/技能只裁定、不提交；任何对外提交动作需用户明确确认。
- 不成立的 claim 写 refutation，不写报告；`needs_more_evidence` 是正式
  结论，不许因为"代码看起来有问题"升级为 holds。
- 交付物最后附：按危害等级降序的可申报漏洞表格（含核心业务/开发者
  是否已知/特殊配置/跨边界/目标平台）+ 每条一个 primary 目标 + 阻塞事实。
