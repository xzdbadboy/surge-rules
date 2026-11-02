# AI 规则上游选型记录

核查日期：2026-11-02。更新时间针对相关文件的提交历史，不以仓库 `pushed_at` 代替文件维护状态。固定日期仅用于记录本次选型；实际同步使用配置中指定的滚动分支。

| 上游 | 相关文件最近提交（UTC） | 用途 |
| --- | --- | --- |
| [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) | [2026-11-02 01:43:19，xai.list 发布提交](https://github.com/MetaCubeX/meta-rules-dat/commit/dc60743738b8c81d45b61773d585b97d5c3f428d) | 主源。`meta/geo/geosite/` 下有按服务拆分的域名列表。格式为裸域名和 `+.` 后缀，严格转换为 Surge DOMAIN / DOMAIN-SUFFIX。 |
| [SukkaW/Surge](https://github.com/SukkaW/Surge) | [2026-10-12 11:45:24，Source/non_ip/ai.conf](https://github.com/SukkaW/Surge/commit/7c67f6c8f0eb0e990097f3f94b39992151644d88) | 补充源。聚合 AI 规则，经逐服务范围过滤后导入。其 URL 正则、关键词等不自动进入服务产物。 |
| [Rabbit-Spec/Surge](https://github.com/Rabbit-Spec/Surge) | [2026-11-02 06:14:58，Rules/AIGC.list](https://github.com/Rabbit-Spec/Surge/commit/818b8b46d98ab8915511bb40e148d574c78c4472) | 补充源。原生 Surge 格式，包含的共享平台与 IP / ASN 规则均不自动导入服务产物。 |
| [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) | [2025-06-17 07:19:38，OpenAI.list](https://github.com/blackmatrix7/ios_rule_script/commit/0fa60782abfe70f58da510e90d9086136cf0d855) | 本次不选作 AI 主源。这里只评价该文件，不据此推断整个仓库停止维护。 |

## 自动抓取的文件

MetaCubeX：

- [openai.list](https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/openai.list)
- [anthropic.list](https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/anthropic.list)
- [xai.list](https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/xai.list)
- [google-gemini.list](https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/google-gemini.list)
- [github-copilot.list](https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/github-copilot.list)
- [cursor.list](https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cursor.list)
- [windsurf.list](https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/windsurf.list)
- [perplexity.list](https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/perplexity.list)
- [deepseek.list](https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/deepseek.list)

补充：

- [Sukka AI 源文件](https://raw.githubusercontent.com/SukkaW/Surge/master/Source/non_ip/ai.conf)
- [Rabbit-Spec AIGC](https://raw.githubusercontent.com/Rabbit-Spec/Surge/Master/Rules/AIGC.list)

完整机器可读映射在 [配置](../config/rule_sources.json)。自动下载的上游内容只作为数据，不能改变配置、执行命令或扩大服务允许范围。

## 人工维护与不确定项

- Claude 的六个核心后缀保留原仓库人工核对结果，参考 [官方网络要求](https://code.claude.com/docs/en/network-config) 和 [桌面端说明](https://code.claude.com/docs/en/desktop)。这部分不会因某个社区源删除域名而自动消失。
- Muse 的事实依据来自用户现有 `/Applications/Muse.app/Contents/MacOS/Muse` 进程规则。原 `kkykkky/metamuse-rules/main/MetaMuse.domainset` 本次核查返回 404；没有把其他同名产品域名归入 Muse。
- 不把 `grokipedia.com` 自动归入 Grok，也不把 `api.github.com` 自动归入 Copilot；存在于同一上游集合不代表属于同一客户端的专属后端。
- Google 的多个 AI 产品存在共用后端，拆分列表不能保证每个 Agent 全部请求独占一个域名集合；共用开发接口放在独立的 GoogleAIShared 列表。
