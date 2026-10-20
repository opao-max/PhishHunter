# 交付要求对照清单

> 用于评审快速定位实现。每条要求 → 代码/文档位置 → 验证方式。

## A. 设计思路文档（40%）

| 要求 | 位置 | 说明 |
|---|---|---|
| 架构图（感知→规划→行动→判断） | `docs/DESIGN.md` §3，`docs/architecture.mmd` | Mermaid 流程图 + 时序图 |
| 基座模型选型与理由 | `docs/DESIGN.md` §5.1 | 闭源/开源对比；Provider 抽象；离线 Mock 默认 |
| 外部工具调用方案 | `docs/DESIGN.md` §4.4、§5.3 | `BaseTool` + 白名单注册表 + 超时/审计 + Mock/真实适配 |
| 幻觉治理 | `docs/DESIGN.md` §7 | 证据只来自确定性来源、引用门控、结构化输出、±8 有界调整、硬地板 |
| Prompt Injection 防御 | `docs/DESIGN.md` §8 | 指令层级、数据隔离、注入检测、确定性规划、输出校验、对抗回归 |
| 评估指标 | `docs/DESIGN.md` §10 | 已实现 P/R/F1、FPR/FNR、P50/P95、对抗回归；成本加权/复核率/校准列为路线图 |
| 冲突裁决（LLM vs WhoIs） | `docs/DESIGN.md` §9 | 证据与地板优先，冲突写入报告 |

## B. 原型系统（60%）

| 要求 | 实现 | 验证命令 |
|---|---|---|
| 输入模拟钓鱼邮件 | `EmailMessage.from_dict`、`data/emails/*.json` | `python -m phishhunter.cli demo` |
| 系统自动调用工具 | `planner.py` + `tools/` + `agent.py` | 报告中的 `tool_calls` 审计 |
| 风险评分 0–100 | `scoring.py`（加权 + noisy-OR + 地板） | 任意报告 `risk_score` |
| 关键证据链 | `models.Evidence` + `agent._reasoning_steps` | 报告 `evidence_chain` |
| 最终建议 Block/Quarantine/Allow | `scoring.recommend_action` | 报告 `action` |
| 模块化、易扩展 | `detectors/ tools/ llm/ report.py web/` | `docs/DESIGN.md` §11 |
| 多模态 | 文本/头部/URL/附件/图片二维码 | `detectors/` 七个模块 |
| 可解释性 | 证据 ID、评分拆解、工具审计、冲突 | CLI/Rich/Web 报告 |
| Mock 工具 | `data/mock_intel.json` + `tools/intel.py` | 离线运行 |
| 测试 | `tests/` + `scripts/evaluate.py` | 15 封主回归 + 14 例红队回归，`python -m pytest -q` |
| 演示视频（可选） | `reports/demo/` | 4 分钟真实 Web 录屏 + AI 配音 + 中文字幕 |

## C. 运行入口

```bash
python -m phishhunter.cli demo
python -m phishhunter.cli analyze data/emails/email_001.json
python -m phishhunter.cli analyze data/emails/email_001.json --json
python -m phishhunter.cli evaluate
python -m phishhunter.cli serve
python -m pytest -q
```

## D. 设计要点

1. **证据优先**：LLM 不能创建证据，只能引用证据；结论可逐条追溯。
2. **策略地板**：单点强证据（恶意 URL、新域名+仿冒、凭据页）不会被其他类别的干净信号平均掉。
3. **有界 LLM**：±8 分调整、引用门控、地板禁止下调、动作由阈值决定。
4. **注入防御是架构性的**：默认确定性规划 + 工具白名单，正文无法改变系统能力。
5. **离线可复现**：Mock LLM + Mock 情报，无需 API Key/网络即可完整演示。
6. **误报校准**：数据集包含“内部安全宣导邮件引用注入话术”的负样本，避免把注入检测本身当判罪依据。