# 真实 LLM 运行记录

本目录保存了一次**真实模型调用**的完整报告（不是 `MockLLM`）。

- 接入方式：本地 Anthropic-compatible 代理（`http://127.0.0.1:15721`）
- 请求模型名：`claude-sonnet-4-6[1M]`（由代理映射到其配置的上游模型；本机环境显示为 `deepseek-v4.1-flash`）
- 规划器：确定性 `heuristic`（防止正文影响工具选择）
- 情报工具：Mock（题目允许，且不访问真实恶意站点）
- Key：仅在运行时从环境变量读取，**未写入本目录或项目任何文件**

| 样本 | 类型 | 风险分 | 动作 | 说明 |
|---|---|---:|---|---|
| `email_001` | 钓鱼 | 95.0 | Block | 模型引用了 7 条证据，覆盖仿冒域名、认证失败、短链→IP、沙箱凭据页 |
| `email_007` | 正常 | 0.0 | Allow | 模型引用了 5 条缓解证据，与确定性评分一致 |

文件：

- `email_001_real_llm.md` / `.json`
- `email_007_real_llm.md` / `.json`
- `transcript.json`（引擎信息、结果摘要、冲突与备注）

验证命令（需要你在本机配置可用的 Anthropic-compatible 代理/key）：

```bash
# 仅示例，不要把 Key 写进仓库
export ANTHROPIC_BASE_URL=http://127.0.0.1:15721
export ANTHROPIC_AUTH_TOKEN=<your-token>
export ANTHROPIC_DEFAULT_SONNET_MODEL=claude-sonnet-4-6[1M]
python - <<'PY'
import os
from phishhunter.agent import PhishHunterAgent
from phishhunter.config import Settings
from phishhunter.llm.anthropic_provider import AnthropicProvider
p = AnthropicProvider(os.environ['ANTHROPIC_AUTH_TOKEN'],
                      model=os.environ['ANTHROPIC_DEFAULT_SONNET_MODEL'],
                      timeout=120)
a = PhishHunterAgent(Settings(llm_provider='anthropic',
                              llm_model=os.environ['ANTHROPIC_DEFAULT_SONNET_MODEL']),
                     provider=p)
r = a.analyze_file('data/emails/email_001.json')
print(r.action, r.risk_score, r.summary)
PY
```

> 安全提示：不要把真实 API Key 提交到代码仓库或压缩包。若 Key 曾在聊天/日志中明文出现，使用后请轮换。