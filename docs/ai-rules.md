# 独立 AI 服务规则与定时更新

这些规则用于 Surge 的 `RULE-SET`，每个服务一个文件，不含策略列。由 [`config/rule_sources.json`](../config/rule_sources.json) 定义服务范围与来源，由 [`scripts/sync_rules.py`](../scripts/sync_rules.py) 生成。

## 服务划分

| 规则文件 | 范围 / 限制 |
| --- | --- |
| [Muse.list](../rules/ai/Muse.list) | macOS `/Applications/Muse.app/` 应用目录内进程；需要 Surge Mac 6.0.0+。尚未确认可用的域名源。 |
| [ChatGPT.list](../rules/ai/ChatGPT.list) | ChatGPT、OpenAI API、专属静态资源；Sora 单独分类。 |
| [Claude.list](../rules/ai/Claude.list) | Claude 网页、桌面、Claude Code 及 Anthropic API。它们共享域名，不能仅按域名区分客户端。 |
| [Grok.list](../rules/ai/Grok.list) | Grok / xAI；不包含整个 X/Twitter，也不包含 Grokipedia。 |
| [Gemini.list](../rules/ai/Gemini.list) | Gemini 网页及专属后端。 |
| [GoogleAIStudio.list](../rules/ai/GoogleAIStudio.list) | AI Studio / Gemini API；同一 API 的不同客户端会命中相同规则。 |
| [NotebookLM.list](../rules/ai/NotebookLM.list) | NotebookLM 专属入口及接口。 |
| [Antigravity.list](../rules/ai/Antigravity.list) | Antigravity 专属入口及接口，另需 GoogleAIShared 中的共用开发后端。 |
| [GoogleAIShared.list](../rules/ai/GoogleAIShared.list) | Cloud Code 等 Google AI 开发共用后端；可能被 Antigravity、Gemini CLI 和其他 Google 开发工具共同使用。 |
| [Copilot.list](../rules/ai/Copilot.list) | GitHub Copilot 专属接口，不是微软 Copilot；不接管整个 GitHub API。 |
| [Cursor.list](../rules/ai/Cursor.list) | Cursor 官网、编辑器、专属 CDN / VM 域名。 |
| [Windsurf.list](../rules/ai/Windsurf.list) | Windsurf / Codeium。 |
| [Perplexity.list](../rules/ai/Perplexity.list) | Perplexity 搜索与 API。 |
| [DeepSeek.list](../rules/ai/DeepSeek.list) | DeepSeek；独立分类不代表必须代理，可指定 DIRECT。 |
| [OpenRouter.list](../rules/ai/OpenRouter.list) | OpenRouter；自建网关需另加自己的域名。 |
| [Sora.list](../rules/ai/Sora.list) | Sora 专属域名；登录及 OpenAI 共用资源仍使用 ChatGPT 规则。 |
| [MetaAI.list](../rules/ai/MetaAI.list) | Meta AI；不接管整个 Facebook / Instagram。 |
| [Dify.list](../rules/ai/Dify.list) | Dify 公共服务；自建 Dify 不在本集合中。 |
| [Groq.list](../rules/ai/Groq.list) | Groq 推理平台，与 Grok / xAI 分开。 |

## Surge 接入

将以下片段放入现有 `[Rule]` 段，位于 **AIGC / Apple / Microsoft / Google / GlobalMedia / Proxy 等通用规则之前**。保留自己的 Tailscale、异常地址拒绝、局域网例外与广告拦截在更前面。示例使用已有的 `ChatGPT`、`智能助理`、`🇺🇲 美国节点` 策略，可逐行改成独立策略组；这里不定义或更改你的节点。

```ini
# Muse 只适用于 macOS，目录匹配需要 Surge Mac 6.0.0+
RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/ai/Muse.list,"🇺🇲 美国节点"

RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/ai/ChatGPT.list,ChatGPT
RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/ai/Claude.list,智能助理
RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/ai/Grok.list,智能助理
RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/ai/Gemini.list,智能助理
RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/ai/GoogleAIStudio.list,智能助理
RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/ai/NotebookLM.list,智能助理
RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/ai/Antigravity.list,智能助理
RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/ai/GoogleAIShared.list,智能助理
RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/ai/Copilot.list,智能助理
RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/ai/Cursor.list,智能助理
RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/ai/Windsurf.list,智能助理
RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/ai/Perplexity.list,智能助理
RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/ai/DeepSeek.list,DIRECT
RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/ai/OpenRouter.list,智能助理
RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/ai/Sora.list,ChatGPT
RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/ai/MetaAI.list,智能助理
RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/ai/Dify.list,智能助理
RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/ai/Groq.list,智能助理
```

接入上述片段后，删除或注释旧的顶部 Muse `PROCESS-NAME` 行、旧根目录 `ChatGPT.list` / `AIGC.list` 引用，以及已 404 的 MetaMuse 引用，避免重复分流。根目录历史 AI 地址已停用；新配置应使用分类目录中的独立服务文件。其他服务、拦截规则和完整顺序见 [完整 Rule 模板](../examples/Rule.template.conf) 与 [迁移说明](rules-migration.md)。

如果只用其中几个服务，只引用对应文件即可。运行在网关或 iOS 上时无法依赖本机 Muse 进程规则；其他服务的域名规则仍可使用。进程规则只覆盖 Surge 能识别到的应用目录内进程，应用转交给目录外程序或独立代理的流量不保证被识别为 Muse。

## 上游与范围控制

选择与核查详见 [上游记录](upstreams.md) 和 [第三方声明](../THIRD_PARTY_NOTICES.md)。

- MetaCubeX 独立服务列表为主；Sukka、Rabbit-Spec 聚合 AI 列表只做受限补充。
- `allowed_suffixes` 接收该域及其子域的 DOMAIN / DOMAIN-SUFFIX 规则；`allowed_domains` 只接收指定主机，必要时收窄上游后缀规则为精确 DOMAIN。
- 不自动引入 DOMAIN-KEYWORD、IP / ASN、全 Google / Microsoft / GitHub、`node` / `python` 等泛进程规则。
- 不引入整个 `auth0.com`、`stripe.com`、`sentry.io`、`challenges.cloudflare.com`、`livekit.cloud` 等共享平台。经核对的服务专属云主机可精确保留，例如 OpenAI 专属 Azure 主机。
- 新增的专属子域会随上游自动纳入；新出现的根域名需要先审查并修改配置中的允许范围，防止上游混入其他服务后自动扩大分流。
- Muse 暂时只有人工确认的应用路径，不从其他同名产品猜域名。修改应用路径请编辑配置后重新生成，不要手改产物。
- `api.github.com` 是共享 GitHub API，不放入 Copilot 核心集合。若实际日志表明需要同出口，可在本机额外精确添加，代价是全部 GitHub API 请求都会使用该策略。
- 域名规则按请求目的地分类，不能判断每个 API 请求由哪个 Agent 发出。第三方网关、插件、自定义 MCP、浏览器打开的网站及共享登录服务仍需按实际请求另行分流。

## 自动更新

[同步工作流](../.github/workflows/sync-ai-rules.yml) 每 6 小时运行一次：UTC `00:17 / 06:17 / 12:17 / 18:17`，对应北京时间 `08:17 / 14:17 / 20:17 / 次日02:17`。GitHub 的计划任务可能延迟，并非准点定时器。也可在 Actions 页面选择 **Sync routing rules → Run workflow**。

流程为：离线测试 → 抓取全部来源 → 解析 / 范围过滤 / 去重 → 离线校验 → 仅提交自动生成的规则和清单。

- URL 超时、404、HTML、空内容、未知格式、非法域名或服务集合为空时，整轮失败，不写入规则、不提交。
- 全部来源抓取和校验通过后才写文件；单文件用原子替换。磁盘写入异常不保证多个文件之间的事务，但工作流失败后不会提交半成品。
- 规则只在内容或来源说明变化时更新头部时间，规则和来源内容均无变化时不产生提交。清单保留上游原始 SHA-256，因此上游只改注释也可能更新清单。
- 同步写入 `rules/ai/`、`rules/services/`、`rules/security/` 和来源清单，并生成分类合集；手工源只更新元数据头，不改规则正文、节点、策略组或 Surge 本机配置。
- GitHub Actions `GITHUB_TOKEN` 仅同步 job 使用 `contents: write`，无须另存 PAT；PR 校验流程只有读取权限，不执行联网更新。
- 若默认分支禁止 bot 直接推送，需要调整同步为 PR 模式或按仓库保护策略放行；公开仓库连续 60 天没有活动时，GitHub 可能停用计划任务，需在 Actions 中恢复。

## 本地维护

依赖 Python 3.10+ 标准库；Actions 固定使用 Python 3.12。

```bash
# 在仓库根目录：抓取并生成
python3 scripts/sync_rules.py
python3 scripts/stamp_custom.py
python3 scripts/build_collections.py

# 联网检查，不修改文件：0 无变化；2 有变化；1 失败
python3 scripts/sync_rules.py --check

# 纯离线校验配置、输出、SHA-256 和规则范围
python3 scripts/sync_rules.py --validate

# 离线测试
python3 -m unittest discover -s tests -v
```

[manifest](../rules/manifest.json) 包含配置及上游摘要、各文件规则数量、AI 逐条来源和镜像的紧凑来源关系。若要更改服务允许范围、加自己的网关域名或调整 Muse 路径，应编辑配置、运行生成器并提交配置与产物。`--check` 不负责重写输出；`--validate` 不访问外网，也不证明真实客户端网络连通。
