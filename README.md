# Surge 代理规则库

按服务分类维护的 Surge 规则。自动同步 42 份规则（19 类 AI、21 类其他服务、2 类安全拦截），手工规则集中维护，旧根目录地址保留为自动生成的兼容入口。

## 目录

| 位置 | 用途 | 维护方式 |
| --- | --- | --- |
| [rules/ai](rules/ai/) | Muse、ChatGPT、Claude、Grok、Gemini、Copilot、Cursor、Windsurf 等 19 类 AI | 受服务专属域名范围约束，自动同步 |
| [rules/services](rules/services/) | Apple、Microsoft、Google、GitHub、Telegram、WeChat、Oracle、流媒体等 21 类 | 从指定上游规范化同步，GoogleVoice 额外限域 |
| [rules/security](rules/security/) | Sukka 广告 / 隐私 / 恶意域名拦截 | 自动转换为 Surge RULE-SET |
| [rules/custom](rules/custom/) | Metatube、Plex、PT、群晖 DDNS、小说、自建 API 等自定义规则 | 手工维护，自动校验 |
| [examples/Rule.template.conf](examples/Rule.template.conf) | 完整 `[Rule]` 通用模板 | 手工维护，检查链接与关键匹配顺序 |
| [config/rule_sources.json](config/rule_sources.json) | 上游、服务范围与输出路径 | 同步配置 |
| [config/compatibility.json](config/compatibility.json) | 根目录旧文件名到规范规则的映射 | 兼容配置 |
| [rules/manifest.json](rules/manifest.json) | 配置 / 来源 / 输出 SHA-256 和规则数量 | 自动生成 |
| [archive/legacy-2026-11-02](archive/legacy-2026-11-02/) | 整理前的旧 AI 集合及其他历史副本 | 仅供回溯，不建议加载 |

根目录 `.list` 地址仍可使用，但不要直接修改生成的兼容入口，应修改其头部标记的 canonical 源文件。没有使用 GitHub Raw 不能正确加载的软链接或重定向文件。

## 使用

参照 [完整通用模板](examples/Rule.template.conf)，将其中的 `[Rule]` 段替换到自己的 Surge 配置。模板不含节点和策略组定义；请保留现有策略组，并替换 tailnet 示例后缀、添加自己的服务器 IP。模板使用的策略名称沿用既有配置。

所有新目录中的 `.list` 均使用 **Surge RULE-SET 格式**。China 和广告域名集已经从 Domainset 转换，所以也应使用 `RULE-SET`，而不是 `DOMAIN-SET`：

```ini
RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/security/RejectDomain.list,REJECT
RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/ai/ChatGPT.list,ChatGPT
RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/ai/Grok.list,智能助理
RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/services/Spotify.list,Spotify
RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/services/China.list,DIRECT
```

模板的关键顺序为：Tailnet → 异常地址防护 / 固定服务器 / 内网 → QUIC 与安全拦截 → Muse 进程策略 → 自定义服务及独立 AI → 专用平台 / 流媒体 → Google / 通用代理 → 国内域名 / 内网 / 国内 CIDR → FINAL。Spotify 位于 GlobalMedia 之前，Copilot 专属端点位于 GitHub 之前。

Muse 目前只匹配 `/Applications/Muse.app/` 应用目录内进程，需要 **Surge Mac 6.0.0+**；没有猜测其域名。其他服务的域名规则不能判断每个请求来自哪个本地 Agent；Google AI 共用开发接口另列，第三方网关 / MCP / 插件仍需补充自己的域名。详见 [AI 接入说明](docs/ai-rules.md)。

## 每 6 小时自动更新

[Sync routing rules 工作流](.github/workflows/sync-ai-rules.yml) 于北京时间每天 **02:17、08:17、14:17、20:17** 检查更新，支持手动运行。手动运行可选择功能分支，在合并前生成并校验全部产物；定时任务运行于默认分支。GitHub 调度可能延迟。

流程：测试 → 抓取所有源 → 按正确格式解析 / 筛选 / 去重 → 生成规则 → 重建根目录兼容入口 → 离线校验与模板冒烟 → 仅提交变化的产物。

- 抓取失败、HTML、空文件、非法格式或空服务集合会使本轮失败，不提交半成品。
- AI 仅从审查过的域名范围提取，不自动纳入宽关键词、整个 ASN、共享登录支付平台或泛进程。
- 其他服务采用上游镜像模式，保留原有共享域名、IP / ASN 等服务范围，不等于做过与 AI 同样的收窄；专用规则应放在这些通用集合之前。
- 规则不写运行时间；来源或规则均无变化时不重复提交。来源 SHA-256 的变化可能只来自上游注释更新。
- 广告等大型镜像只保存紧凑来源关系；AI 继续保存逐条来源，避免清单膨胀。
- 手工源、历史归档、个人节点与策略组不会被上游内容覆盖。同步任务会重建根目录兼容文件。

## 本地维护

依赖 Python 3.10+ 标准库；Actions 使用 Python 3.12。

```bash
python3 scripts/sync_rules.py
python3 scripts/build_compat.py
python3 scripts/sync_rules.py --validate
python3 scripts/build_compat.py --validate
python3 scripts/validate_profile.py --smoke
python3 -m unittest discover -s tests
```

`sync_rules.py --check` 联网比较、不写文件：0 无变化、2 有变化、1 失败。`build_compat.py --check` 同样返回 0 / 2 / 1，但完全离线。修改手动规则后也需重建并提交相应兼容入口。

## 本次整理

- 自定义列表迁入 [rules/custom](rules/custom/)，清除相同条目，保留已有站点和进程规则；`Speacial` 的规范文件名为 [Special.list](rules/custom/Special.list)，旧根文件名和策略组名不变。
- Metatube 中的 `DOMAIN,ec.sod.co.jp/prime` 修正为主机名 `ec.sod.co.jp`。
- 根目录与上游 GoogleVoice 目前都误指向 Google Lens，现限域并固定官方 voice.google.com 入口，排除 Lens；原内容已归档。
- 原 Oracle 中的自定义宽关键词保留在 [OracleLegacy.list](rules/custom/OracleLegacy.list)，旧根地址继续兼容；新模板只用标准 Oracle 服务集，未默认启用这些宽关键词。
- Talkatone 的本地 `tktn.be` 补充保留在 [TalkatoneExtras.list](rules/custom/TalkatoneExtras.list)。
- 旧 ChatGPT / OpenAI / Claude 根地址指向新的对应 AI 内容。旧 AIGC 地址为经过审查的 AI 列表兼容并集，排除 Muse 进程和 DeepSeek；新配置优先逐服务引用。
- 原 [hot.yaml](hot.yaml) 是 Clash `payload` 规则文件，不是 Surge 热加载配置；保留原地址与历史副本，不作为本次 Surge 模板的输入。
- PT 中的 `announce` / `torrent` / `tracker`、Special 中的进程和 Tailnet 匹配保留原意。模板中的 Tailnet / LAN 优先直连；不要把这些定制规则当作通用纯域名列表使用。

上游选型见 [来源记录](docs/upstreams.md)，整理与分流变化见 [迁移说明](docs/rules-migration.md)，署名和许可见 [第三方声明](THIRD_PARTY_NOTICES.md)。离线检查及模板冒烟不代表已在真实 Surge 客户端测试所有服务。
