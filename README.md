# Surge 代理规则库

自动维护 42 份服务规则，原仓库的 12 份手工规则按用途分类；另提供 4 份合并入口。根目录及旧平铺目录共 29 个地址保留为自动生成的兼容入口。

## 目录

| 位置 | 用途 |
| --- | --- |
| [rules/ai](rules/ai/) | 19 类独立 AI 服务 |
| [rules/services](rules/services/) | 21 类平台、通信、游戏、媒体与通用分流 |
| [rules/security](rules/security/) | 2 类广告、隐私与恶意域名拦截 |
| [rules/custom](rules/custom/) 的分类子目录 | 12 份人工维护源 |
| [rules/collections](rules/collections/) | 4 份实体规则合并入口 |
| 根目录及 rules/custom 下的平铺列表 | 29 个兼容入口，由脚本重建，不直接编辑 |
| [examples/Rule.template.conf](examples/Rule.template.conf) | 完整 `[Rule]` 通用模板 |
| [archive/legacy-2026-11-02](archive/legacy-2026-11-02/) | 历史原文，仅供回溯 |

手工源分类如下：

```text
rules/custom/
├── trackers/       PrivateTracker.list
├── media/          MtProviders.list、Plex.list、XPTV.list
├── direct/         NewAPI.list、WebNovel.list
├── network/        SynologyDDNS.list、Parsec.list
├── proxy/          WebsiteProxy.list、Special.list
├── communication/  TalkatoneExtras.list
└── cloud/          OracleLegacy.list
```

例如，PT 现在编辑 [分类后的 PrivateTracker](rules/custom/trackers/PrivateTracker.list)。原 [根目录入口](PrivateTracker.list) 和 [旧平铺入口](rules/custom/PrivateTracker.list) 继续提供相同规则，并注明新的维护位置。

## 更新时间和上游注释

活跃列表使用 `#` 注释注明名称、更新时间、上游、维护位置及内容校验。所有注释均不参与 Surge 匹配。

- **更新时间**是本文件有效内容或来源说明最后变化的时间，统一为北京时间 `+08:00`。首次增加注释使用本次真实生成时间，不编造历史日期。
- 内容和来源都没有变化时保留原时间，不会每次检查都刷新日期、制造空提交。
- 自动服务列表写真实抓取 URL；合并列表汇总各个来源；手工列表注明本仓库维护及可编辑位置。
- 该时间不是未知的上游 Git 提交时间，也不表示所有节点已经通过连通性测试。
- 手工改动后运行注释脚本更新内容校验和时间；校验可发现修改规则后遗漏更新头部的情况。
- 历史归档保留原始字节和旧注释，不为历史副本补写新的更新时间。

## 合并入口

| 合并结果 | 来源 | 使用策略 |
| --- | --- | --- |
| [DirectSites](rules/collections/direct/DirectSites.list) | NewAPI + WebNovel | DIRECT |
| [Talkatone](rules/collections/communication/Talkatone.list) | 自动 Talkatone + 本地 tktn.be 补充 | Talkatone |
| [OracleLegacy](rules/collections/cloud/OracleLegacy.list) | 自动 Oracle + 仓库历史定制 | Oracle；兼容旧范围，含宽关键词 |
| [AIGC](rules/collections/ai/AIGC.list) | 17 个经过审查的 AI 列表 | 兼容合集，新配置优先逐服务引用 |

合并文件包含实际规则，不使用软链接、HTTP 跳转或嵌套远程 RULE-SET。只做精确去重，保留不同 options。媒体刮削、PT、群晖等继续按各自用途和策略独立使用。

新模板使用合并后的直连站点和 Talkatone 入口；Oracle 仍使用标准服务列表，没有默认启用历史共享关键词。旧根目录 Oracle、Talkatone、AIGC 地址则对应各自兼容合集，原有范围保留。

## 使用

参考 [完整模板](examples/Rule.template.conf)，仅替换自己的 `[Rule]` 段，保留节点和策略组等其他配置。公开模板不包含个人服务器 IP 和真实 tailnet 后缀。

所有活跃列表均为 **Surge RULE-SET** 格式，China 和广告 Domainset 也已转换：

```ini
RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/custom/trackers/PrivateTracker.list,PrivateTracker
RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/collections/direct/DirectSites.list,DIRECT
RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/collections/communication/Talkatone.list,Talkatone
RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/ai/Grok.list,智能助理
RULE-SET,https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/rules/security/RejectDomain.list,REJECT
```

模板保留 Tailnet 优先直连、异常地址防护、LAN、QUIC、安全拦截和 Muse 的顺序；AI 位于通用服务之前，Spotify 位于 GlobalMedia 之前，Copilot 专属端点位于 GitHub 之前。Muse 应用目录匹配需 Surge Mac 6.0.0+。详情见 [AI 说明](docs/ai-rules.md)。

## 自动流程与本地维护

[同步工作流](.github/workflows/sync-ai-rules.yml) 配置为北京时间每天 **02:17、08:17、14:17、20:17**，也支持选择分支手动运行。GitHub 定时派发可能延迟；配置启用不等于已验证每次定时执行。

流程：测试 → 抓取并生成服务规则 → 更新手工源注释 → 构建分类合集 → 重建兼容入口 → 离线校验与模板冒烟 → 仅提交变化的内容。失败不提交半成品；上游内容不会覆盖手工规则正文。

Python 3.10+ 标准库即可运行，Actions 使用 3.12：

```bash
python3 scripts/sync_rules.py
python3 scripts/stamp_custom.py
python3 scripts/build_collections.py
python3 scripts/build_compat.py
python3 scripts/stamp_custom.py --validate
python3 scripts/sync_rules.py --validate
python3 scripts/build_collections.py --validate
python3 scripts/build_compat.py --validate
python3 scripts/validate_profile.py --smoke
python3 -m unittest discover -s tests
```

配置分别为 [服务来源](config/rule_sources.json)、[手工源](config/manual_rules.json)、[分类合集](config/collections.json)、[兼容映射](config/compatibility.json)。生成来源和输出摘要见 [manifest](rules/manifest.json)。生成器 `--check` 不写文件，返回 0 无变化、2 有变化、1 失败；`--validate` 只做离线校验。

来源与边界见 [上游记录](docs/upstreams.md)、[迁移说明](docs/rules-migration.md)、[第三方声明](THIRD_PARTY_NOTICES.md)。原 [hot.yaml](hot.yaml) 是 Clash payload，保留原地址，不作为 Surge 模板输入。离线验证不替代真实客户端的服务连通性测试。
