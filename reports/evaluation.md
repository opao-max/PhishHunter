# PhishHunter 离线评估报告

- 生成时间：`2026-10-20T10:40:57.841034+00:00`
- 运行模式：`mock LLM + heuristic planner`（完全离线、确定性）
- 正类：`phishing`；`Block` 与 `Quarantine` 均视为检出

## 总体指标

| 指标 | 数值 |
| --- | ---: |
| 样本数 | 15 |
| 有标签样本 | 15 |
| 准确率 Accuracy | 100.00% |
| 精确率 Precision | 100.00% |
| 召回率 Recall | 100.00% |
| F1 | 100.00% |
| 误报率 FPR | 0.00% |
| 漏报率 FNR | 0.00% |

## 混淆矩阵

| | 预测为钓鱼 | 预测为正常 |
| --- | ---: | ---: |
| 实际钓鱼 | TP=10 | FN=0 |
| 实际正常 | FP=0 | TN=5 |

## 延迟

| 均值 (ms) | 中位数 (ms) | P95 (ms) | 最大 (ms) |
| ---: | ---: | ---: | ---: |
| 23.85 | 5.39 | 247.03 | 247.03 |

## 质量门槛

| 门槛 | 要求 | 实际 | 结果 |
| --- | ---: | ---: | --- |
| Accuracy | >= 0.85 | 1.0000 | 通过 |
| Recall | >= 0.85 | 1.0000 | 通过 |
| FPR | <= 0.20 | 0.0000 | 通过 |

**总体结果：通过**

## 逐样本结果

| ID | 标签 | 期望动作 | 实际动作 | 风险分 | 证据数 | 做法正确 | 延迟 (ms) | 关键证据 |
| --- | --- | --- | --- | ---: | ---: | --- | ---: | --- |
| email_001 | phishing | Block | Block | 95.0 | 15 | 是 | 40.40 | 新注册域名 |
| email_002 | phishing | Block | Block | 82.0 | 6 | 是 | 4.92 | 命中相似历史钓鱼活动 |
| email_003 | phishing | Block | Block | 95.0 | 8 | 是 | 4.40 | 附件哈希被确认为恶意 |
| email_004 | phishing | Block | Block | 85.0 | 13 | 是 | 247.03 | 新注册域名 |
| email_005 | phishing | Block | Block | 95.0 | 13 | 是 | 6.64 | 已知恶意 URL |
| email_006 | phishing | Block | Block | 95.0 | 12 | 是 | 9.55 | 已知恶意 URL |
| email_007 | legit | Allow | Allow | 0.0 | 5 | 是 | 3.53 |  |
| email_008 | legit | Allow | Allow | 0.0 | 7 | 是 | 6.06 |  |
| email_009 | legit | Allow | Allow | 0.0 | 6 | 是 | 3.80 | 索取凭据/诱导登录 |
| email_010 | legit | Allow | Allow | 0.0 | 7 | 是 | 5.39 |  |
| email_011 | legit | Allow | Allow | 0.0 | 7 | 是 | 5.26 | 检测到提示注入/结论操纵指令 |
| email_012 | phishing | Block | Block | 95.0 | 10 | 是 | 4.89 | 新注册域名 |
| email_013 | phishing | Block | Block | 95.0 | 10 | 是 | 5.97 | 已知恶意 URL |
| email_014 | phishing | Block | Block | 95.0 | 11 | 是 | 5.77 | 已知恶意 URL |
| email_015 | phishing | Quarantine | Quarantine | 65.0 | 4 | 是 | 4.14 | 发件域使用 Punycode 混淆 |
