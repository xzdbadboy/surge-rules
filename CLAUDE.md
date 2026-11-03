# CLAUDE.md

此文件为 Claude Code（claude.ai/code）在此仓库中工作时提供指导。

## 项目概述

Surge 代理规则集合库。通过 `.list` 和 `.yaml` 文件管理网络流量路由。请参考 README.md 了解文件用途和格式。

规范目录：`rules/custom/<category>/` 是人工维护源；`rules/ai/`、`rules/services/`、`rules/security/` 是同步产物；`rules/collections/<category>/` 是实体合并产物。根目录及 `rules/custom/` 直下禁止放置平铺 `.list` 副本，所有活跃规则按分类路径维护和引用。

配置：服务来源在 `config/rule_sources.json`，手工源在 `config/manual_rules.json`，分类合集在 `config/collections.json`。修改人工源后依次运行 `stamp_custom.py`、`build_collections.py`，最后校验。受管头的内容校验和更新时间由脚本维护，不能每次检查都刷新日期。`archive/` 保留历史原文，不作为新规则源。

## 快速维护命令

### 检测重复

```bash
# 查找某个文件中的重复条目
grep "^DOMAIN-SUFFIX," rules/custom/trackers/PrivateTracker.list | sort | uniq -d

# 修改人工源后校验并重建分类合集
python3 scripts/stamp_custom.py
python3 scripts/build_collections.py
python3 scripts/validate_profile.py --smoke
```

### 查找条目

```bash
# 跨所有规则文件搜索
grep -r "domain.com" .

# 在特定文件中查找
grep "DOMAIN" rules/custom/trackers/PrivateTracker.list | grep "example"
```

### 添加新域名

1. 确定正确的规则文件（按服务分类）
2. 添加格式：`DOMAIN-SUFFIX,example.com` 或对应类型
3. 使用 `//` 添加行内注释说明提供商（参考 MtProviders.list）
4. 提交时说明：`Add example.com to PrivateTracker list`

### 删除重复或过期项

1. `git log --oneline -n 20` 查看最近改动
2. 移除条目后验证：`grep -r "被删除的域名" .` 确保无其他引用
3. 提交：`Remove duplicate DOMAIN entry for domain.com`

## 格式规范

- 域名全部小写
- 逗号后无空格：`DOMAIN-SUFFIX,example.com` ✓
- 无尾部空格
- 按字母顺序排列（如文件已排序）

## 提交约定

遵循现有风格：
- `Add ... to ... list`
- `Remove duplicate DOMAIN entry for ...`
- `Update ... with new provider domains`
- `docs: 更新 README 说明`

## 需要验证的场景

- **添加前**：检查是否已存在（`grep -r`）
- **删除后**：验证无其他文件引用
- **大文件变更**：运行 `sort | uniq` 检查重复
