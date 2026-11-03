# 旧列表迁移路径

旧根目录及 custom 平铺 URL 已停用。规则内容已核对并保留在下列分类文件中；请使用新版 Rule 段，或将旧 URL 的路径替换为新路径。

| 旧路径（已移除） | 分类后的文件 |
| --- | --- |
| `MtProviders.list` | [media/MtProviders.list](../rules/custom/media/MtProviders.list) |
| `Plex.list` | [media/Plex.list](../rules/custom/media/Plex.list) |
| `PrivateTracker.list` | [trackers/PrivateTracker.list](../rules/custom/trackers/PrivateTracker.list) |
| `SynologyDDNS.list` | [network/SynologyDDNS.list](../rules/custom/network/SynologyDDNS.list) |
| `WebsiteProxy.list` | [proxy/WebsiteProxy.list](../rules/custom/proxy/WebsiteProxy.list) |
| `Speacial.list` | [proxy/Special.list](../rules/custom/proxy/Special.list) |
| `WebNovel.list` | [direct/WebNovel.list](../rules/custom/direct/WebNovel.list) |
| `NewAPI.list` | [direct/NewAPI.list](../rules/custom/direct/NewAPI.list) |
| `Parsec.list` | [network/Parsec.list](../rules/custom/network/Parsec.list) |
| `xptv.list` | [media/XPTV.list](../rules/custom/media/XPTV.list) |
| `GoogleVoice.list` | [services/GoogleVoice.list](../rules/services/GoogleVoice.list) |
| `oracle.list` | [cloud/OracleLegacy.list](../rules/collections/cloud/OracleLegacy.list) |
| `talkatone.list` | [communication/Talkatone.list](../rules/collections/communication/Talkatone.list) |
| `ChatGPT.list` | [ai/ChatGPT.list](../rules/ai/ChatGPT.list) |
| `OpenAI.list` | [ai/ChatGPT.list](../rules/ai/ChatGPT.list) |
| `claude.list` | [ai/Claude.list](../rules/ai/Claude.list) |
| `AIGC.list` | [ai/AIGC.list](../rules/collections/ai/AIGC.list) |
| `rules/custom/MtProviders.list` | [media/MtProviders.list](../rules/custom/media/MtProviders.list) |
| `rules/custom/Plex.list` | [media/Plex.list](../rules/custom/media/Plex.list) |
| `rules/custom/XPTV.list` | [media/XPTV.list](../rules/custom/media/XPTV.list) |
| `rules/custom/PrivateTracker.list` | [trackers/PrivateTracker.list](../rules/custom/trackers/PrivateTracker.list) |
| `rules/custom/NewAPI.list` | [direct/NewAPI.list](../rules/custom/direct/NewAPI.list) |
| `rules/custom/WebNovel.list` | [direct/WebNovel.list](../rules/custom/direct/WebNovel.list) |
| `rules/custom/SynologyDDNS.list` | [network/SynologyDDNS.list](../rules/custom/network/SynologyDDNS.list) |
| `rules/custom/Parsec.list` | [network/Parsec.list](../rules/custom/network/Parsec.list) |
| `rules/custom/WebsiteProxy.list` | [proxy/WebsiteProxy.list](../rules/custom/proxy/WebsiteProxy.list) |
| `rules/custom/Special.list` | [proxy/Special.list](../rules/custom/proxy/Special.list) |
| `rules/custom/OracleLegacy.list` | [cloud/OracleLegacy.list](../rules/custom/cloud/OracleLegacy.list) |
| `rules/custom/TalkatoneExtras.list` | [communication/TalkatoneExtras.list](../rules/custom/communication/TalkatoneExtras.list) |

ChatGPT 与旧 OpenAI 内容同源，统一引用 AI 目录的 ChatGPT；旧 claude 使用规范的 Claude 文件。Oracle 历史定制和 AIGC 聚合仍为按需入口，新模板保持独立服务分流。

迁移前已逐项验证 29 个旧入口等于其分类来源的实体规则并集，保留不同 options，没有因清理副本删减站点。
