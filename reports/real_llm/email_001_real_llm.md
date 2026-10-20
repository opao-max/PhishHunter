# PhishHunter 钓鱼邮件分析报告

| 字段 | 值 |
| --- | --- |
| 邮件 ID | `email_001` |
| 主题 | Urgent: Password Expiry Notification |
| 发件人 | `Microsoft Support <support@micr0soft-security.com>` |
| **风险评分** | **95.0 / 100（Critical）** |
| **处置建议** | **Block（阻断）** |
| 置信度 | 0.97 |
| 分析耗时 | 10578.95 ms |
| 生成时间 | 2026-10-20T10:14:12.173019+00:00 |
| 引擎 | hybrid-llm / provider=anthropic / model=claude-sonnet-4-6[1M] / planner=heuristic |

## 摘要

该邮件是一封高度可信的钓鱼邮件：发件域 micr0soft-security.com 仅注册 0.3 天且被 8 个引擎判定为恶意，并以同形字仿冒 Microsoft 品牌 [E006][E007][E002]；邮件身份认证全面失败（SPF=fail、DKIM=none、DMARC=fail，且域名缺少有效 SPF 记录）[E001][E009]。正文使用“密码 2 小时后过期、账户将被锁定”等紧迫性话术 [E003]，链接 http://bit.ly/3xYz 经短链跳转至裸 IP http://192.168.1.15/login.php，采用明文 HTTP、路径含 login 关键词，被 12 个引擎判定为恶意 [E011][E005][E010]，沙箱进一步确认该页面存在密码输入表单并提交凭据，属凭据窃取 [E012][E013]。该邮件与历史“Microsoft 密码过期钓鱼”活动相似度 72% [E015]。bit.ly 域名注册时间长仅说明短链服务本身未被标记，不能为落地页开脱 [E014]。综合判定为凭据钓鱼，建议分数与确定性分数保持一致（95）。

## 证据链（15 条）

| ID | 极性 | 类别 | 严重度 | 置信度 | 标题 | 详情 |
| --- | --- | --- | --- | --- | --- | --- |
| E006 | 风险 | 威胁情报 | 0.95 | 0.95 | 新注册域名 | 域名 micr0soft-security.com 注册仅 0.3 天，属于典型的钓鱼基础设施特征。 |
| E010 | 风险 | 链接 | 0.95 | 0.95 | 已知恶意 URL | URL http://192.168.1.15/login.php 威胁情报：12 个引擎判定恶意，Safe Browsing=malicious，分类：phishing、credential-harvesting。 |
| E011 | 风险 | 链接 | 0.95 | 0.95 | 已知恶意 URL | URL http://bit.ly/3xYz 威胁情报：12 个引擎判定恶意，Safe Browsing=malicious，分类：phishing。 |
| E012 | 风险 | 链接 | 0.95 | 0.95 | 沙箱发现凭据窃取页面 | 沙箱访问 http://192.168.1.15/login.php 后发现：存在密码输入表单；页面请求提交凭据；沙箱判定为凭据窃取。 |
| E005 | 风险 | 链接 | 0.90 | 0.90 | 链接跳转至 IP 地址 | 原始链接：http://bit.ly/3xYz；实际目标：http://192.168.1.15/login.php；目标主机：192.168.1.15。发现：1) 实际目标为 IP 地址 192.168.1.15（短链接/原始域名 bit.ly 指向裸 IP；该 IP 属于私有/保留地址段；URL 路径包含凭据采集关键词），无法通过域名归属核验。；2) 声明的原始域名 bit.ly 实际跳转到 192.168.1.15，二者不属于同一站点。；3) 链接使用短链接服务 bit.ly，真实落地页被隐藏。；4) 路径/参数包含「login」，且目标域名 192.168.1.15 不属于该品牌自有域名。 同时使用明文 HTTP 传输，凭据可能被窃听。 |
| E001 | 风险 | 邮件认证 | 0.85 | 0.90 | 邮件身份认证失败 | SPF=fail、DKIM=none、DMARC=fail。发件域未能提供完整可信的邮件身份认证链，存在伪造发件人的可能。 |
| E007 | 风险 | 威胁情报 | 0.85 | 0.90 | 域名被威胁情报标记为恶意 | 域名 micr0soft-security.com 被 8 个引擎判定为恶意，分类为 phishing。 |
| E013 | 风险 | 链接 | 0.80 | 0.90 | 链接跳转至 IP 地址 | 沙箱观察到跳转链 http://bit.ly/3xYz -> http://192.168.1.15/login.php，最终落地到 IP 主机 192.168.1.15，绕过域名信誉检查。 |
| E015 | 风险 | 威胁情报 | 0.80 | 0.85 | 命中相似历史钓鱼活动 | 与历史活动「Microsoft 密码过期钓鱼」（CAM-2026-1018-A） 的相似度为 72%，命中关键词：password will expire、account will be locked。活动摘要：仿冒 Microsoft 的密码过期通知，诱导用户在伪造登录页输入凭据。 |
| E002 | 风险 | 发件人身份 | 0.75 | 0.86 | 发件人身份疑似品牌仿冒 | 发件域 micr0soft-security.com 疑似仿冒品牌：microsoft（品牌名同形，令牌“micr0soft”→“microsoft”）。显示名声称属于品牌 microsoft，但发件域 micr0soft-security.com 并非其官方域名。 |
| E003 | 风险 | 正文语义 | 0.68 | 0.90 | 紧迫感与威胁性话术 | 命中 4 个特征短语（强特征 2 个）：“account will be locked”、“will expire”、“immediately”、“urgent”。 |
| E008 | 风险 | 发件人身份 | 0.70 | 0.80 | 域名与声称的品牌归属不一致 | 情报显示该域名声称归属「microsoft」，但域名 micr0soft-security.com 并非该品牌的官方域名，存在品牌仿冒风险。 |
| E009 | 风险 | 邮件认证 | 0.55 | 0.85 | 域名认证策略缺失或过弱 | 域名 micr0soft-security.com：SPF 记录缺失或无效，无法约束发件服务器。 |
| E004 | 风险 | 正文语义 | 0.20 | 0.86 | 索取凭据/诱导登录 | 命中 1 个特征短语（强特征 0 个）：“password”。 |
| E014 | 缓解 | 威胁情报 | 0.45 | 0.80 | 域名注册时间较长 | 域名 bit.ly 已注册约 16.4 年，未见恶意情报记录，可作为降低风险的佐证。 |

**证据标签**

- `E006` 风险：domain_new
- `E010` 风险：known_malicious_url
- `E011` 风险：known_malicious_url
- `E012` 风险：credential_harvest
- `E005` 风险：ip_literal, redirect_ip, redirect, shortener, credential_path, plaintext_http
- `E001` 风险：auth_fail, spf_fail, dmarc_fail
- `E007` 风险：malicious_domain
- `E013` 风险：redirect_ip
- `E015` 风险：campaign_match
- `E002` 风险：brand_spoof
- `E003` 风险：urgency
- `E008` 风险：brand_spoof
- `E009` 风险：missing_spf
- `E004` 风险：credential_language
- `E014` 缓解：established_domain

## 推理过程（17 步）

1. 发件人 support@micr0soft-security.com，显示名「Microsoft Support」；SPF=fail，DKIM=none，DMARC=fail。
2. [E006] 新注册域名：域名 micr0soft-security.com 注册仅 0.3 天，属于典型的钓鱼基础设施特征。
3. [E010] 已知恶意 URL：URL http://192.168.1.15/login.php 威胁情报：12 个引擎判定恶意，Safe Browsing=malicious，分类：phishing、credential-harvesting。
4. [E011] 已知恶意 URL：URL http://bit.ly/3xYz 威胁情报：12 个引擎判定恶意，Safe Browsing=malicious，分类：phishing。
5. [E012] 沙箱发现凭据窃取页面：沙箱访问 http://192.168.1.15/login.php 后发现：存在密码输入表单；页面请求提交凭据；沙箱判定为凭据窃取。
6. [E005] 链接跳转至 IP 地址：原始链接：http://bit.ly/3xYz；实际目标：http://192.168.1.15/login.php；目标主机：192.168.1.15。发现：1) 实际目标为 IP 地址 192.168.1.15（短链接/原始域名 bit.ly 指向裸 IP；该 IP 属于私有/保留地址段；URL 路径包含凭据采集关键词），无法通过域名归属核验。；2) 声明的原始域名 bit.ly 实际跳转到 192.168.1.15，二者不属于同一站点。；3) 链接使用短链接服务 bit.ly，真实落地页被隐藏。；4) 路径/参数包含「login」，且目标域名 192.168.1.15 不属于该品牌自有域名。 同时使用明文 HTTP 传输，凭据可能被窃听。
7. [E001] 邮件身份认证失败：SPF=fail、DKIM=none、DMARC=fail。发件域未能提供完整可信的邮件身份认证链，存在伪造发件人的可能。
8. 关键证据触发策略下限 95 分：威胁情报确认该 URL 为恶意；沙箱发现凭据窃取页面；新注册域名叠加身份或认证异常；品牌仿冒叠加邮件认证失败；短链接跳转到 IP 地址或凭据页；短链接跳转到凭据页面；品牌仿冒叠加凭据索取话术；跳转链接指向凭据页面；认证失败叠加凭据窃取话术；发件域疑似品牌仿冒。该下限不可被模型下调。
9. 计入 3.6 分缓解信号（[E014] 域名注册时间较长）。
10. 模型综合：发件域 micr0soft-security.com 注册仅 0.3 天并被 8 个引擎标记为 phishing，属典型新注册钓鱼基础设施 [E006][E007]，且用同形字“micr0soft”仿冒 Microsoft，显示名与真实归属不符 [E002][E008]。
11. 模型综合：邮件身份认证链完全失败：SPF=fail、DKIM=none、DMARC=fail，且该域 SPF 记录缺失或无效，无法约束发件服务器 [E001][E009]，与品牌仿冒结论相互印证。
12. 模型综合：正文命中“account will be locked”“will expire”“immediately”“urgent”等紧迫威胁话术，并出现“password”等凭据诱导语言 [E003][E004]。
13. 模型综合：链接 http://bit.ly/3xYz 使用短链隐藏真实落地页，实际跳转至裸 IP http://192.168.1.15/login.php，路径含 login 且走明文 HTTP，无法通过域名归属核验 [E005][E013]。
14. 模型综合：该落地 URL 被 12 个引擎判定为恶意（Safe Browsing=malicious，分类 phishing、credential-harvesting）[E010]，短链亦被判定为恶意 [E011]。
15. 模型综合：沙箱访问确认目标页面存在密码输入表单并请求提交凭据，判定为凭据窃取页面 [E012]，完成“诱导—跳转—窃取”的完整攻击链。
16. 模型综合：行为与历史活动「Microsoft 密码过期钓鱼」（CAM-2026-1018-A）相似度 72%，命中同类关键词，符合已知钓鱼活动模式 [E015]。
17. 综合评分 95.0/100（Critical），置信度 0.97，处置建议：Block。

## 评分明细

| 项目 | 数值 |
| --- | --- |
| 原始证据分 | 61.9 |
| 缓解扣减 | -3.6 |
| 策略下限 | 95.0 |
| 下限原因 | 威胁情报确认该 URL 为恶意；沙箱发现凭据窃取页面；新注册域名叠加身份或认证异常；品牌仿冒叠加邮件认证失败；短链接跳转到 IP 地址或凭据页；短链接跳转到凭据页面；品牌仿冒叠加凭据索取话术；跳转链接指向凭据页面；认证失败叠加凭据窃取话术；发件域疑似品牌仿冒 |
| 下限前得分 | 95.0 |
| 模型调整 | +0.0 |
| **最终得分** | **95.0（Critical）** |

**分类贡献**

| 类别 | 贡献 | 类别风险系数 |
| --- | --- | --- |
| 链接 | 22.00 | 1.00 |
| 发件人身份 | 15.19 | 0.84 |
| 邮件认证 | 12.25 | 0.87 |
| 正文语义 | 8.14 | 0.68 |
| 威胁情报 | 7.94 | 0.99 |

## 工具调用（7 次）

| ID | 工具 | 状态 | 耗时 | 原因 | 错误 |
| --- | --- | --- | --- | --- | --- |
| C01 | `whois_lookup` | 成功 | 0.13 ms | 核实发件域名的注册时间与注册信息（新域名是强钓鱼信号） | - |
| C02 | `dns_auth_check` | 成功 | 0.06 ms | 检查发件域发布的 SPF/DKIM/DMARC 策略与邮件头声明是否一致 | - |
| C03 | `url_reputation` | 成功 | 0.02 ms | 查询目标 URL 的多引擎信誉、分类与首次发现时间 | - |
| C04 | `url_reputation` | 成功 | 0.03 ms | 查询短链接/原始链接本身的信誉（可能存在跳转包装） | - |
| C05 | `url_sandbox` | 成功 | 0.05 ms | 在隔离沙箱中观察跳转链、登录表单与下载行为 | - |
| C06 | `whois_lookup` | 成功 | 0.03 ms | 核实链接落地域名的注册时间与归属 | - |
| C07 | `retrieve_similar_campaigns` | 成功 | 0.09 ms | 检索历史攻击活动库，判断是否命中已知钓鱼战役 | - |

## 冲突与分歧

- E014 将 bit.ly 标记为 mitigating（注册 16.4 年、无恶意记录），但该短链在本次事件中被用于跳转至恶意凭据窃取页面 [E005][E011]，故不构成对整体风险的实质性抵消。
- E010/E012/E005 中出现的 192.168.1.15 属私有/保留地址段，说明该落地地址为沙箱或受控环境中的复现地址，但恶意 URL 与凭据窃取的判定仍以威胁情报与沙箱结果为准。

## 处置建议

1. 立即隔离并拦截该邮件，阻止同批次投递
2. 将发件域名与已提取的 URL 加入临时阻断名单
3. 通知 SOC 检索同主题/同发件人的其他收件人
4. 对已交互用户强制重置密码并吊销会话令牌

## 备注

无

## 分析流水线

| 阶段 | 步骤 | 耗时 | 说明 |
| --- | --- | --- | --- |
| perceive | 感知：解析并静态检测邮件 | 39.20 ms | 解析出 1 个链接、0 个附件、0 张图片；静态检测产生 5 条证据。 |
| plan | 规划：选择调查工具 | 0.24 ms | 规划策略 heuristic，计划调用 7 个工具：whois_lookup, dns_auth_check, url_reputation, url_reputation, url_sandbox, whois_lookup, retrieve_similar_campaigns |
| act | 行动：执行外部调查 | 2.18 ms | 执行 7 个工具调用，成功 7，失败 0；新增 10 条工具证据。 |
| judge | 判断：确定性证据融合 | 0.09 ms | 证据加权得分 61.9，缓解扣减 3.6，策略下限 95.0。 |
| judge | 判断：模型综合分析与策略校验 | 10533.54 ms | 分析器 anthropic/deepseek-v4.1-flash，引用证据 15 条，评分调整 +0.0，最终 95.0 分。 |
| report | 报告：生成证据链与处置建议 | 10578.95 ms | 风险 95.0/100（Critical），建议 Block。 |

---
发现与分析耗时 10578.95 ms；所有结论均可追溯到证据 ID 或工具返回结果。