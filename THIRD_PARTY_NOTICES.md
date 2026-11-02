# 第三方来源与许可证

自动生成的规则包含从以下上游提取、筛选、镜像或转换的规则条目。每个输出保留源 URL，原始内容 SHA-256、AI 的逐条来源和大规模镜像的紧凑来源关系记录在 [manifest](rules/manifest.json)，转换配置和脚本均在本仓库公开。

本声明只涉及新增的自动同步内容，不为仓库历史文件重新指定许可证，也不代表上游作者为本项目背书。

## MetaCubeX/meta-rules-dat

- 项目：https://github.com/MetaCubeX/meta-rules-dat
- 使用范围：`meta` 分支 `geo/geosite/` 下配置所列的 AI 服务列表。
- 处理方式：将裸域名及 `+.` 后缀转换成 Surge 规则，按服务允许范围筛选、去重，并保留条目来源。
- 上游声明的许可证：[GNU GPL v3](https://github.com/MetaCubeX/meta-rules-dat/blob/master/LICENSE)。
- 本仓库保留的原文副本：[MetaCubeX-GPL-3.0.txt](licenses/MetaCubeX-GPL-3.0.txt)。
- 该项目亦构建、汇集其他社区数据；其来源归属以 [上游 README](https://github.com/MetaCubeX/meta-rules-dat/blob/master/README.md) 的说明为准，不能将所有原始条目归为本项目原创。

## SukkaW/Surge

- 项目：https://github.com/SukkaW/Surge
- 使用范围：`Source/non_ip/ai.conf` 中已审查的 AI 域名，以及 `ruleset.skk.moe/List/domainset/reject.conf` 和 `List/non_ip/reject.conf` 两份拦截规则。
- 处理方式：AI 按服务筛选并收窄精确主机；拦截规则按原有范围镜像并规范化为 Surge RULE-SET。两种模式的导入范围不同。
- 上游声明的许可证：[GNU AGPL v3](https://github.com/SukkaW/Surge/blob/master/LICENSE)。
- 本仓库保留的原文副本：[Sukka-AGPL-3.0.txt](licenses/Sukka-AGPL-3.0.txt)。

## Rabbit-Spec/Surge

- 项目：https://github.com/Rabbit-Spec/Surge
- 使用范围：`Rules/AIGC.list` 中已审查的 AI 域名，以及配置中列出的 Apple、Microsoft、Google、Telegram、游戏、流媒体、国内域名和 CIDR、通用代理等服务文件。
- 署名：深巷有喵 / Rabbit-Spec。该集合标注为上游同步规则，原始贡献归属还应参考其上游说明。
- 处理方式：AI 仅提取服务专属域名和经配置确认的主机；其他服务采用镜像模式，保留其现有 IP / ASN、关键词和共享基础设施匹配范围。China 从 Domainset 转换为 Surge RULE-SET，Telegram 两份同策略源合并。
- 本次核查未发现仓库根目录许可证；不将该部分标为 MIT / GPL，也不把保留链接等同于授予其他权利。

## blackmatrix7/ios_rule_script

- 项目：https://github.com/blackmatrix7/ios_rule_script
- 使用范围：Surge WeChat、Oracle、GoogleVoice、GitHub 服务列表。
- WeChat、Oracle、GitHub 按上游原范围镜像；GoogleVoice 上游当前包含 Lens 主机，单独限域并补充官方 voice.google.com 入口。
- 上游许可证：[GNU GPL v2](https://github.com/blackmatrix7/ios_rule_script/blob/master/LICENSE)，保留副本：[blackmatrix7-GPL-2.0.txt](licenses/blackmatrix7-GPL-2.0.txt)。

## APNs 与 Talkatone

- [mrbruce516/apns-fix](https://github.com/mrbruce516/apns-fix)：使用 Apple_APNs.list，保留域名及指定 IP 子网的 APNs 分流范围。
- [mottzz87/crules](https://github.com/mottzz87/crules)：使用 rule/talkatone.list；本仓库既有 tktn.be 补充由手工列表单独保留。
- 本次未确认这两个仓库的明确许可文本，不为其声明 MIT / GPL；保留原项目链接、来源和原始内容摘要，不声称取得其他权利。

## 本地规则

Muse 的进程路径来自用户现有配置；Claude 核心后缀沿用仓库既有人工核对结果。来源标记为 `local`，对应的官方文档证据写入配置、输出头部和 manifest。服务运行所需的第三方共享基础设施不因此全部纳入。

若继续分发或修改这些生成内容，应保留本声明、来源、适用的上游许可文本以及可获取的转换源码。仓库发布内容仅提供路由规则；来源许可、实际服务所有权和客户端连通性是不同事项。
