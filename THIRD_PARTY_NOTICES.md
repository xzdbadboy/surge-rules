# 第三方来源与许可证

自动生成的 AI 规则包含从以下上游提取、筛选或转换的域名事实及规则条目。每个输出文件保留源 URL，逐条来源及原始内容 SHA-256 记录在 [manifest](rules/manifest.json)，转换配置和脚本均在本仓库公开。

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
- 使用范围：`Source/non_ip/ai.conf` 中位于已审查服务域名范围内的 DOMAIN / DOMAIN-SUFFIX 条目。
- 处理方式：按服务筛选、收窄精确主机、规范化和去重；不导入其中的宽关键词、URL 正则或共享平台兜底。
- 上游声明的许可证：[GNU AGPL v3](https://github.com/SukkaW/Surge/blob/master/LICENSE)。
- 本仓库保留的原文副本：[Sukka-AGPL-3.0.txt](licenses/Sukka-AGPL-3.0.txt)。

## Rabbit-Spec/Surge

- 项目：https://github.com/Rabbit-Spec/Surge
- 使用范围：`Rules/AIGC.list` 中位于已审查服务域名范围内的 DOMAIN / DOMAIN-SUFFIX 条目。
- 署名：深巷有喵 / Rabbit-Spec。该集合标注为上游同步规则，原始贡献归属还应参考其上游说明。
- 处理方式：仅提取服务专属域名和经配置确认的专属主机，不复制聚合集合中的 IP / ASN、共享登录、支付、校时或遥测匹配。
- 本次核查未发现仓库根目录许可证；不将该部分标为 MIT / GPL，也不把保留链接等同于授予其他权利。

## 本地规则

Muse 的进程路径来自用户现有配置；Claude 核心后缀沿用仓库既有人工核对结果。来源标记为 `local`，对应的官方文档证据写入配置、输出头部和 manifest。服务运行所需的第三方共享基础设施不因此全部纳入。

若继续分发或修改这些生成内容，应保留本声明、来源、适用的上游许可文本以及可获取的转换源码。仓库发布内容仅提供路由规则；来源许可、实际服务所有权和客户端连通性是不同事项。
