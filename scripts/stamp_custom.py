#!/usr/bin/env python3
"""手工维护规则文件的统一 metadata 头打点工具（``rules/custom`` 分类源）。

背景
----
``rules/custom/<category>/<file>.list`` 是人工维护源，不经过自动同步引擎。
为了和自动产物一样可追溯「名称 / 更新时间 / 上游 / 维护位置 / 内容校验」，
本脚本按固定配置 :file:`config/manual_rules.json` 统一给这些文件加受管头。

设计要点
--------
- 只允许 ``rules/custom/<category>/<file>.list`` 这一种安全规范路径；拒绝扁平
  ``rules/custom/foo.list``、任意嵌套、``..``、绝对路径与符号链接逃逸。
- 保持规则行和原注释**一字不改**，只增删统一 metadata 头。
- 先统一在内存中校验（文件存在、``parse_surge`` 合法且非空），全部通过后才
  ``write_outputs``（fail closed，不产生半更新）。
- 内容哈希能发现「手工改了规则但没重打时间」：``--check`` / ``--validate`` 会因
  旧头哈希与当前正文不符而报告不一致。
- 时间只在正文/来源描述实际变化时更新；``--check`` / ``--validate`` 跨次稳定。

配置 schema（``config/manual_rules.json``）::

    {
      "version": 1,
      "rules": [
        {
          "path": "rules/custom/trackers/PrivateTracker.list",
          "name": "PrivateTracker",
          "upstreams": ["本仓库手工维护，无外部同步源"],
          "canonical_sources": [
            "https://github.com/xzdbadboy/surge-rules/blob/main/rules/custom/trackers/PrivateTracker.list"
          ]
        }
      ]
    }

用法::

    python3 scripts/stamp_custom.py [--config PATH] [--root PATH] [--check] [--validate]

退出码：
    0  默认成功 / --check 无需更新 / --validate 通过
    1  失败（配置 / 路径 / 解析失败，或 --validate 检测到不一致）
    2  --check 检测到需要更新
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

try:  # 作为包的一部分导入（测试：from scripts import stamp_custom）
    from . import sync_rules as sync
    from . import list_metadata as meta
except ImportError:  # 直接以脚本方式运行（python3 scripts/stamp_custom.py）
    import sync_rules as sync  # type: ignore[no-redef]
    import list_metadata as meta  # type: ignore[no-redef]

CONFIG_VERSION = 1
DEFAULT_CONFIG_REL = "config/manual_rules.json"

# custom 分类源固定四段：rules/custom/<category>/<file>.list。
CUSTOM_SOURCE_PARTS = 4


class StampError(sync.ConfigError):
    """手工源配置/打点过程中的错误（属于 sync.SyncError 子类）。"""


# ---------------------------------------------------------------------------
# 配置加载
# ---------------------------------------------------------------------------


def default_project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def load_stamp_config(config_path: Path) -> dict:
    path = Path(config_path)
    if not path.is_file():
        raise StampError(f"手工源配置文件不存在: {path}")
    try:
        with path.open("r", encoding="utf-8") as fh:
            config = json.load(fh)
    except json.JSONDecodeError as exc:
        raise StampError(f"手工源配置文件不是合法 JSON: {exc}") from exc
    if not isinstance(config, dict):
        raise StampError("手工源配置根必须是 JSON 对象")
    return config


# ---------------------------------------------------------------------------
# 路径 / 配置校验
# ---------------------------------------------------------------------------


def _validate_path(rel: str, project_root: Path) -> Path:
    """校验 ``rules/custom/<category>/<file>.list`` 安全规范路径，返回解析绝对路径。"""
    if not isinstance(rel, str) or not rel.strip():
        raise StampError(f"path 必须是非空字符串: {rel!r}")
    if "\\" in rel:
        raise StampError(f"path 不允许反斜杠: {rel!r}")
    if rel.startswith("/") or (len(rel) >= 2 and rel[1] == ":"):
        raise StampError(f"path 不允许绝对路径: {rel!r}")
    parts = rel.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise StampError(f"path 包含非法片段: {rel!r}")
    if len(parts) != CUSTOM_SOURCE_PARTS:
        raise StampError(
            f"path 必须正好是 rules/custom/<category>/<file>.list（四段）: {rel!r}"
        )
    if parts[0] != "rules" or parts[1] != "custom":
        raise StampError(f"path 必须位于 rules/custom/<category>/ 下: {rel!r}")
    if not rel.endswith(".list"):
        raise StampError(f"path 必须以 .list 结尾: {rel!r}")

    root = project_root.resolve()
    candidate = root / rel
    if not candidate.exists():
        raise StampError(f"手工源文件不存在: {rel!r}")
    if not candidate.is_file():
        raise StampError(f"手工源不是文件: {rel!r}")
    resolved = candidate.resolve()
    if resolved != root and root not in resolved.parents:
        raise StampError(f"手工源符号链接逃逸出项目根: {rel!r}")
    custom_root = (root / "rules" / "custom").resolve()
    if custom_root not in resolved.parents:
        raise StampError(f"手工源解析后逃逸出 rules/custom/（可能是符号链接）: {rel!r}")
    return resolved


def validate_stamp_config(config: Mapping, project_root: Path) -> None:
    if not isinstance(config, dict):
        raise StampError("手工源配置根必须是 JSON 对象")
    if config.get("version") != CONFIG_VERSION:
        raise StampError(
            f"不支持的手工源配置 version: {config.get('version')!r} (期望 {CONFIG_VERSION})"
        )
    rules = config.get("rules")
    if not isinstance(rules, list) or not rules:
        raise StampError("manual_rules.rules 必须是非空数组")

    seen: Dict[str, str] = {}
    seen_resolved: Dict[str, str] = {}
    for entry in rules:
        if not isinstance(entry, dict):
            raise StampError(f"rules 项必须是对象: {entry!r}")
        path = entry.get("path")
        resolved = _validate_path(path, project_root)
        low = str(path).lower()
        if low in seen:
            raise StampError(f"重复的手工源路径（大小写不敏感）: {path!r} 与 {seen[low]!r}")
        if resolved in seen_resolved:
            raise StampError(f"手工源 resolve 后重复: {path!r} 与 {seen_resolved[resolved]!r}")
        seen[low] = path
        seen_resolved[resolved] = path

        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            raise StampError(f"{path!r} 缺少 name")
        upstreams = entry.get("upstreams")
        if not isinstance(upstreams, list) or any(not isinstance(u, str) or not u.strip() for u in upstreams):
            raise StampError(f"{path!r} 的 upstreams 必须是非空字符串数组")
        canonical_sources = entry.get("canonical_sources", [])
        if not isinstance(canonical_sources, list) or any(
            not isinstance(c, str) or not c.strip() for c in canonical_sources
        ):
            raise StampError(f"{path!r} 的 canonical_sources 必须是字符串数组")


# ---------------------------------------------------------------------------
# 构建输出
# ---------------------------------------------------------------------------


def build_stamp_outputs(
    config: Mapping,
    project_root: Path,
    now=None,
) -> Dict[str, str]:
    """为全部手工源生成受管 metadata 头后的文件内容（不写盘，fail closed）。"""
    validate_stamp_config(config, project_root)
    root = project_root.resolve()
    shared_now = meta.now_beijing(now)

    files: Dict[str, str] = {}
    for entry in config["rules"]:
        rel = entry["path"]
        path = root / rel
        try:
            original = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise StampError(f"读取手工源失败: {rel!r}: {exc}") from exc
        # parse_surge 会校验每条规则合法且非空（空/纯注释会抛 ParseError）。
        try:
            sync.parse_surge(original, source_id=rel)
        except sync.ParseError as exc:
            raise StampError(f"手工源规则非法: {rel!r}: {exc}") from exc

        files[rel] = meta.annotate_list(
            original,
            name=entry["name"],
            upstreams=list(entry["upstreams"]),
            canonical_sources=list(entry.get("canonical_sources", [])),
            previous_text=original,
            now=shared_now,
        )
    return files


# ---------------------------------------------------------------------------
# 比较
# ---------------------------------------------------------------------------


def _changed_files(files: Mapping[str, str], project_root: Path) -> List[str]:
    root = project_root.resolve()
    changed: List[str] = []
    for rel, content in files.items():
        target = sync._resolve_target(root, rel)
        if not target.is_file():
            changed.append(rel)
            continue
        try:
            if target.read_bytes() != content.encode("utf-8"):
                changed.append(rel)
        except OSError:
            changed.append(rel)
    return changed


# ---------------------------------------------------------------------------
# 顶层命令
# ---------------------------------------------------------------------------


def run_default(config_path: Path, project_root: Path) -> int:
    try:
        config = load_stamp_config(config_path)
        files = build_stamp_outputs(config, project_root)
        written = sync.write_outputs(files, project_root)
    except sync.SyncError as exc:
        print(f"[stamp] 失败: {exc}")
        return 1
    if written:
        print(f"已更新 {len(written)} 个文件：")
        for rel in written:
            print(f"  - {rel}")
    else:
        print("无内容变更，未写入任何文件。")
    return 0


def run_check(config_path: Path, project_root: Path) -> int:
    try:
        config = load_stamp_config(config_path)
        files = build_stamp_outputs(config, project_root)
        changed = _changed_files(files, project_root)
    except sync.SyncError as exc:
        print(f"[check] 失败: {exc}")
        return 1
    if changed:
        print(f"[check] 有 {len(changed)} 个文件需要更新：")
        for rel in changed:
            print(f"  - {rel}")
        return 2
    print("[check] 无内容变更。")
    return 0


def run_validate(config_path: Path, project_root: Path) -> int:
    try:
        config = load_stamp_config(config_path)
        files = build_stamp_outputs(config, project_root)
        changed = _changed_files(files, project_root)
    except sync.SyncError as exc:
        print(f"[validate] 失败: {exc}")
        return 1
    if changed:
        print(f"[validate] 不一致，{len(changed)} 个文件与预期不同：")
        for rel in changed:
            print(f"  - {rel}")
        return 1
    print("[validate] 通过。")
    return 0


def build_arg_parser():
    import argparse

    parser = argparse.ArgumentParser(
        description="按 config/manual_rules.json 为手工规则文件统一打点 metadata 头（不联网）。",
    )
    parser.add_argument(
        "--config",
        default=None,
        help=f"手工源配置文件路径（默认 <项目根>/{DEFAULT_CONFIG_REL}）",
    )
    parser.add_argument(
        "--root",
        default=None,
        help="项目根目录（默认：脚本所在项目根），主要用于测试覆盖",
    )
    parser.add_argument("--check", action="store_true", help="比较是否需要更新，不写文件（0 无变更 / 2 有变更）")
    parser.add_argument("--validate", action="store_true", help="同 --check，但不一致返回 1")
    return parser


def main(argv=None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    if args.check and args.validate:
        parser.error("--check 与 --validate 不能同时使用")

    root = Path(args.root) if args.root else default_project_root()
    config_path = Path(args.config) if args.config else root / DEFAULT_CONFIG_REL

    if args.validate:
        return run_validate(config_path, root)
    if args.check:
        return run_check(config_path, root)
    return run_default(config_path, root)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
