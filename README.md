# Surge 代理规则库

Surge 代理客户端的自定义规则和配置文件集合。

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