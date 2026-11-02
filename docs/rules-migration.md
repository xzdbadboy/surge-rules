# 全量规则整理与新 Rule 段

本次整理在独立功能分支完成，目标是统一来源管理和目录、保留旧地址，并按既有策略名称生成新的 `[Rule]` 段。未修改客户端的节点或策略组。

## 自动同步范围

- `rules/ai/`：19 类服务，沿用已审查的域名范围提取。
- `rules/services/`：21 类服务，保留给定上游的服务范围。
- `rules/security/`：Sukka 两份拦截规则。
- Telegram 将域名 / ASN 与 CIDR 两份同策略上游合为一个文件。
- China 和广告 Domainset 转成标准 Surge RULE-SET。新文件不能再按 DOMAIN-SET 引用。
- Spotify 改跟随 Rabbit-Spec 的有效原版源，不再停留在用户 fork 的旧快照。
- GitHub 独立列出；Copilot 专属端点优先于它，普通 GitHub API 使用节点选择。

源 URL、格式、输出和许可信息在 [同步配置](../config/rule_sources.json)；[manifest](../rules/manifest.json) 保存来源摘要、输出校验和、规则数及来源关系。镜像规则本身可以包含 IP / ASN、关键词及共享基础设施，不能误认为它们已按 AI 的严格范围收窄。

## 原根目录文件

| 原地址 | 规范来源 | 处理 |
| --- | --- | --- |
| MtProviders.list | [custom/MtProviders.list](../rules/custom/MtProviders.list) | 修正带路径 DOMAIN，删除相同条目 |
| Plex.list | [custom/Plex.list](../rules/custom/Plex.list) | 保留精确域名 |
| PrivateTracker.list | [custom/PrivateTracker.list](../rules/custom/PrivateTracker.list) | 去重；保留 PT 站、下载进程及原有宽匹配 |
| SynologyDDNS.list | [custom/SynologyDDNS.list](../rules/custom/SynologyDDNS.list) | 保留 |
| WebsiteProxy.list | [custom/WebsiteProxy.list](../rules/custom/WebsiteProxy.list) | 保留 |
| Speacial.list | [custom/Special.list](../rules/custom/Special.list) | 规范文件修正拼写，旧地址与 Speacial 策略名不变 |
| WebNovel.list | [custom/WebNovel.list](../rules/custom/WebNovel.list) | 保留 |
| NewAPI.list | [custom/NewAPI.list](../rules/custom/NewAPI.list) | 保留 |
| Parsec.list | [custom/Parsec.list](../rules/custom/Parsec.list) | 保留；模板未额外启用原配置中没有的服务 |
| xptv.list | [custom/XPTV.list](../rules/custom/XPTV.list) | 保留；模板未额外启用 |
| GoogleVoice.list | [services/GoogleVoice.list](../rules/services/GoogleVoice.list) | 原文件及上游仅含 Google Lens 域名；固定官方 Voice 入口并限域，旧内容归档 |
| oracle.list | [services/Oracle.list](../rules/services/Oracle.list) + [custom/OracleLegacy.list](../rules/custom/OracleLegacy.list) | 原定制项保留在兼容并集；新模板只启用标准服务集 |
| talkatone.list | [services/Talkatone.list](../rules/services/Talkatone.list) + [custom/TalkatoneExtras.list](../rules/custom/TalkatoneExtras.list) | 保留本地额外的 tktn.be |
| ChatGPT.list / OpenAI.list | [ai/ChatGPT.list](../rules/ai/ChatGPT.list) | 旧的宽泛集合归档，兼容入口变为经筛选的 ChatGPT 内容 |
| claude.list | [ai/Claude.list](../rules/ai/Claude.list) | 归档旧副本，按新规则生成 |
| AIGC.list | 17 个经审查的 AI 集合并集 | 不包含 Muse 进程与 DeepSeek；建议改用逐服务规则 |

兼容入口由 [build_compat.py](../scripts/build_compat.py) 生成，内容是实际规则，不使用软链接或跳转；完整映射见 [compatibility.json](../config/compatibility.json)。

[历史目录](../archive/legacy-2026-11-02/) 保留旧 AI、GoogleVoice、Oracle、Talkatone、hot.yaml 原文。归档文件不是推荐加载的最新规则。原 [hot.yaml](../hot.yaml) 是 Clash payload，保留原地址和内容，不误称为 Surge 热加载配置。

## 内容修正与刻意保留

- `ec.sod.co.jp/prime` 不能用 DOMAIN 匹配，修正为主机名 `ec.sod.co.jp`。
- 精确相同的 `theporndb.net`、`madsrevolution.net` 等条目去重，未批量删除自定义站点。
- Surge 支持 IP-ASN、行尾空格后的 `//` 注释，以及 `.oracle` / `.java` 等单标签后缀；没有把这些合法语法误删。
- Oracle 历史关键词 hcaptcha / mpulse / metrix、PT 的 tracker / torrent / announce、Special 的进程 / Tailnet 匹配仍保留在手工源。前者不在新模板中默认启用，后两者沿用用户配置中的策略。
- 没有把显示界面中的脱敏 IP 标记当作原文件非法 CIDR。真正的 CIDR 校验使用实际源字节。

## 新 Rule 段的顺序

1. 顶部 Tailnet / 独立 Tailscale App 例外保留。公开模板使用示例 tailnet 后缀，个人完整版本另行交付。
2. 先拒绝 0.0.0.0 与 Telegram 异常地址，再让固定服务器和已知内网直连。前置 LAN 使用 no-resolve，底部仍保留普通 LAN 检查。
3. UDP 443 与 YouTube 其他 UDP 拦截位于 Muse 之前；Muse 不再绕过这两条及广告拦截。支持 TCP 的客户端通常会回落，但不把它描述为对所有软件的稳定性保证。
4. 广告拦截沿用原本实际启用的状态，修正与“默认禁用”注释的矛盾。
5. AI 专用规则在苹果、微软、Google、GlobalMedia、Proxy 等通用规则之前。
6. Spotify 在 GlobalMedia 之前；GitHub 在通用代理前，Copilot 专属端点更早。
7. China、LAN、ChinaCIDR 和 FINAL 保持兜底作用，保留 dns-failed。

模板保留原策略组名称，并使用已有的智能助理处理各独立 AI；DeepSeek 和 pool.ntp.org 明确直连。若要按服务选择不同节点，可只改对应规则的策略列。

## 验证边界

[validate_profile.py](../scripts/validate_profile.py) 离线检查段结构、规则语法子集、全部引用存在性，并以 14 个无 DNS 场景检查 Tailnet / LAN / QUIC / Muse / AI / GitHub / Spotify 等顺序。它不查询 DNS / ASN、不模拟全部 Surge 行为，也不检查另一个段中未提供的策略组定义。真实 macOS Surge、推送、流媒体解锁等仍取决于客户端设置、DNS 与出口。

提交前运行：

```bash
python3 scripts/sync_rules.py
python3 scripts/build_compat.py
python3 scripts/sync_rules.py --validate
python3 scripts/build_compat.py --validate
python3 scripts/validate_profile.py --smoke
python3 -m unittest discover -s tests
```
