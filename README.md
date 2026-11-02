# Surge 代理规则库

Surge 代理客户端的自定义规则和配置文件集合。

## AI 服务独立规则（自动更新）

新增 19 类服务的独立规则生成配置：Muse、ChatGPT、Claude、Grok、Gemini、Google AI Studio、NotebookLM、Antigravity、Google AI 共用开发接口、GitHub Copilot、Cursor、Windsurf、Perplexity、DeepSeek、OpenRouter、Sora、Meta AI、Dify、Groq。首次成功运行同步命令后，生成下述规则与来源清单；仅添加工作流文件不代表已发布或已启用定时任务。

- [规则目录](rules/ai/)：Surge `RULE-SET` 格式，策略由你的主配置分别指定。
- [接入示例和维护说明](docs/ai-rules.md)：包含完整可复制的 Surge 片段、规则顺序和服务边界。
- [上游选型记录](docs/upstreams.md)：MetaCubeX、Sukka、Rabbit-Spec 的文件提交证据与来源。
- [同步工作流](.github/workflows/sync-ai-rules.yml)：每 6 小时抓取，有内容变化才提交，也支持手动运行。
- [来源清单](rules/manifest.json)：配置与来源 SHA-256、各文件规则数量、逐条来源。
- [第三方声明](THIRD_PARTY_NOTICES.md)：保留上游出处及许可证副本。

AI 规则只从已审查的专属域名范围中提取，不将全 Google / GitHub、共享认证支付平台、整个 ASN 或泛进程自动归入 AI。Muse 暂无可靠公共域名源，使用独立的 macOS 应用目录进程规则，需要 Surge Mac 6.0.0+。

根目录原有规则保留兼容，仍为人工维护，**不在新的自动更新范围内**。启用独立 AI 规则后，应移除主配置中旧的聚合 AIGC、旧 ChatGPT 及失效 MetaMuse 引用，详见接入说明。

## 项目说明

本仓库包含了用于 Surge 代理的各种规则列表（`.list`）和配置文件（`.yaml`），用于管理网络流量的路由转发。规则按照服务类型和使用场景进行组织。

## 规则文件

### 服务特定规则

| 文件 | 大小 | 说明 |
|------|------|------|
| **GoogleVoice.list** | 178B | Google Voice 路由规则 |
| **OpenAI.list** | 1.4K | OpenAI 服务路由规则 |
| **Plex.list** | 121B | Plex 媒体服务器规则 |
| **PrivateTracker.list** | 4.1K | 私密追踪器服务规则 |
| **MtProviders.list** | 1.4K | MT 提供商规则 |
| **Parsec.list** | 34B | Parsec 云游戏服务规则 |
| **oracle.list** | 861B | Oracle Cloud 服务规则 |
| **talkatone.list** | 418B | Talkatone VoIP 服务规则 |
| **xptv.list** | 179B | XPTV 流媒体规则 |
| **SynologyDDNS.list** | 157B | 群晖 DDNS 规则 |
| **WebsiteProxy.list** | 75B | 常规网站代理规则 |
| **Speacial.list** | 1.4K | 特殊服务规则 |

### 配置文件

| 文件 | 说明 |
|------|------|
| **hot.yaml** | 热加载配置文件 |

## 使用方法

1. 将规则文件导入到 Surge 配置中
2. 在 Surge 配置文件中引入所需的 `.list` 规则文件
3. 根据需要配置路由策略
4. 测试验证代理规则是否正常工作

## 规则格式

规则遵循 Surge 兼容的格式标准，常见的规则类型包括：
- 域名路由
- IP 路由
- 进程路由
- DNS 策略配置

## 版本信息

- 最后更新：2026-06-21
- 适用于 Surge 4.x 及更高版本

## 注意事项

- 定期检查并更新规则以确保兼容性
- 在生产环境使用前充分测试规则
- 保留工作配置的备份副本