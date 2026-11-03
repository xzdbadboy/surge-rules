#!/usr/bin/env python3
"""按分类合并旧 list，生成 ``rules/collections/<category>/<filename>.list``。

背景
----
仓库把规则整理进 ``rules/{custom,ai,services,security}/`` 下的 canonical 文件后，
仍需要把若干同策略、同用途的旧 list 归类合并成新的集合文件（例如 ``AIGC`` 兼容合集、
Oracle/Talkatone 的历史兼容并集）。本脚本读取 ``config/collections.json``，把每个
collection 的 ``sources`` 逐源严格解析成实体 Surge 规则，合并去重后渲染到
``rules/collections/<category>/<filename>.list``。

设计要点
--------
- 纯标准库、不联网；解析 / 渲染 / 写入全部复用 ``sync_rules`` 的公用接口
  （``parse_surge``、``Rule.render``、``write_outputs``），并复用共享的
  ``scripts/list_metadata.py``（``annotate_list`` / ``extract_upstreams``）生成
  文件头，绝不在此重复实现另一套 metadata。
- 逐源严格解析：任何一行非法规则都会让整轮失败（fail closed），不忽略坏行。
- 去重只做 **exact（type + value + options 全等）** 去重，绝不按 suffix 跨源裁剪，
  从而保留带不同 options 或更具体域名的合法规则。
- 确定性排序：按 ``VALID_RULE_TYPES`` 顺序、再按 value / options 排序。
- 不生成网络嵌套 ``RULE-SET`` 引用，不抓取任何远端内容。
- fail closed（整轮原子）：配置 schema 错误、任意来源缺失 / 非法 / 为空 / 出现异常时，
  **所有** collection 输出都不写盘；只有全部在内存中渲染成功后，才统一调用
  ``sync_rules.write_outputs``。
- 时间幂等：读取现有目标文件作为 ``previous_text`` 交给 ``annotate_list``；只有内容 /
  来源发生变化时才更新时间（时间逻辑由共享 metadata 模块负责）。
- 安全：输出只允许安全的相对路径 ``rules/collections/<category>/<filename>.list``；
  输入只允许 ``rules/{custom,ai,services,security}/...``；禁止 ``rules/collections`` 作为
  输入（防循环）；禁止绝对路径、``..``、反斜杠、大小写冲突、重复输出；禁止目标与来源
  解析到同一位置；禁止符号链接逃逸仓库或非普通文件。

配置 schema（``config/collections.json``）::

    {
      "version": 1,
      "collections": {
        "rules/collections/direct/DirectSites.list": {
          "name": "自建直连站点",
          "sources": ["rules/custom/direct/NewAPI.list", "rules/custom/direct/WebNovel.list"],
          "policy_hint": "DIRECT"
        }
      }
    }

- 未知字段一律报错（不猜测）。
- ``custom`` 来源必须位于分类子目录下（``rules/custom/<category>/<file>.list``），
  不把根目录 / 扁平兼容层当作来源。

用法::

    python3 scripts/build_collections.py [--config PATH] [--root PATH] [--check] [--validate]

退出码：
    0  默认模式成功 / --check 无变更 / --validate 通过
    1  失败（配置 / 路径 / 解析 / 校验失败，或 --validate 检测到不一致）
    2  --check 检测到需要更新
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

try:  # 作为包的一部分导入（测试：from scripts import build_collections）
    from . import sync_rules as sync
except ImportError:  # 直接以脚本方式运行（python3 scripts/build_collections.py）
    import sync_rules as sync  # type: ignore[no-redef]


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

CONFIG_VERSION = 1

# 允许作为输入来源的 rules 子目录（不得包含 collections 自身，防循环）。
ALLOWED_SOURCE_DIRS: Tuple[str, ...] = ("custom", "ai", "services", "security")

COLLECTIONS_PREFIX_PARTS: Tuple[str, str] = ("rules", "collections")

# 纯手工来源补全 canonical 地址时使用的仓库位置。
REPO_SLUG = "https://github.com/xzdbadboy/surge-rules"

# collection spec 允许的字段（未知字段一律报错）。
_COLLECTION_KEYS = frozenset({"name", "sources", "policy_hint"})
# 顶层允许的字段。
_TOP_LEVEL_KEYS = frozenset({"version", "collections"})

_CATEGORY_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_DRIVE_RE = re.compile(r"^[A-Za-z]:")


class CollectionsError(sync.ConfigError):
    """collection 配置 / 构建过程中的错误（属于 sync.SyncError 子类）。"""


# ---------------------------------------------------------------------------
# 配置加载
# ---------------------------------------------------------------------------


def default_project_root() -> Path:
    """脚本所在项目的根目录（scripts/ 的上一级）。"""
    return Path(__file__).resolve().parent.parent


def load_collections_config(config_path: Path) -> dict:
    path = Path(config_path)
    if not path.is_file():
        raise CollectionsError(f"collections 配置文件不存在: {path}")
    try:
        with path.open("r", encoding="utf-8") as fh:
            config = json.load(fh)
    except json.JSONDecodeError as exc:
        raise CollectionsError(f"collections 配置文件不是合法 JSON: {exc}") from exc
    except OSError as exc:
        raise CollectionsError(f"读取 collections 配置文件失败: {exc}") from exc
    if not isinstance(config, dict):
        raise CollectionsError("collections 配置根必须是 JSON 对象")
    return config


# ---------------------------------------------------------------------------
# 共享 metadata 模块（按需导入）
# ---------------------------------------------------------------------------


def _load_metadata():
    """导入共享的 list_metadata 模块；不可用时返回 None（构建时再报错）。"""
    try:
        from . import list_metadata as meta  # type: ignore
        return meta
    except Exception:
        pass
    try:
        import list_metadata as meta  # type: ignore
        return meta
    except Exception:
        return None


def _require_metadata():
    meta = _load_metadata()
    if meta is None:
        raise CollectionsError(
            "缺少共享模块 scripts/list_metadata.py（需要 annotate_list / extract_upstreams）"
        )
    for fn_name in ("annotate_list", "extract_upstreams"):
        if not hasattr(meta, fn_name):
            raise CollectionsError(f"scripts/list_metadata.py 缺少必需函数: {fn_name}")
    return meta


# ---------------------------------------------------------------------------
# 路径校验
# ---------------------------------------------------------------------------


def _validate_output_rel(rel: object, project_root: Path) -> str:
    """校验 collection 输出路径：只允许 rules/collections/<category>/<file>.list。"""
    if not isinstance(rel, str) or not rel.strip():
        raise CollectionsError(f"输出路径必须是非空字符串: {rel!r}")
    # 复用 sync_rules 的基础安全校验（反斜杠/绝对路径/../受保护目录/逃逸/.list）。
    try:
        sync._validate_output_path(rel, project_root)
    except sync.ConfigError as exc:
        raise CollectionsError(str(exc)) from exc
    parts = rel.split("/")
    if len(parts) < 2 or parts[0] != COLLECTIONS_PREFIX_PARTS[0] or parts[1] != COLLECTIONS_PREFIX_PARTS[1]:
        raise CollectionsError(
            f"输出路径必须位于 rules/collections/ 下: {rel!r}"
        )
    if len(parts) != 4:
        raise CollectionsError(
            f"输出路径必须形如 rules/collections/<category>/<filename>.list: {rel!r}"
        )
    category, filename = parts[2], parts[3]
    if not _CATEGORY_RE.match(category):
        raise CollectionsError(f"输出分类目录名非法（仅小写字母数字 _ -）: {rel!r}")
    if not filename.endswith(".list"):
        raise CollectionsError(f"输出文件名必须以 .list 结尾: {rel!r}")
    return rel


def _validate_source_rel(rel: object, project_root: Path) -> Path:
    """校验输入来源路径，返回其解析后的绝对路径。"""
    if not isinstance(rel, str) or not rel.strip():
        raise CollectionsError(f"来源必须是非空字符串: {rel!r}")
    if "\\" in rel:
        raise CollectionsError(f"来源不允许反斜杠: {rel!r}")
    if rel.startswith("/") or _DRIVE_RE.match(rel):
        raise CollectionsError(f"来源不允许绝对路径: {rel!r}")
    parts = rel.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise CollectionsError(f"来源包含非法路径片段: {rel!r}")
    if not rel.endswith(".list"):
        raise CollectionsError(f"来源必须以 .list 结尾: {rel!r}")
    if parts[0] != "rules" or len(parts) < 2:
        raise CollectionsError(f"来源必须位于 rules/ 下: {rel!r}")
    sub = parts[1]
    if sub == "collections":
        raise CollectionsError(f"不允许以 rules/collections/ 作为输入来源（防止循环引用）: {rel!r}")
    if sub not in ALLOWED_SOURCE_DIRS:
        raise CollectionsError(
            f"来源必须位于 rules/{{{','.join(ALLOWED_SOURCE_DIRS)}}}/ 下: {rel!r}"
        )
    if sub == "custom" and len(parts) < 4:
        # custom 只能以分类子目录下的 canonical 文件为来源，不接受扁平兼容层。
        raise CollectionsError(
            f"custom 来源必须位于分类子目录下（rules/custom/<category>/<file>.list）: {rel!r}"
        )
    if sub != "custom" and len(parts) < 3:
        raise CollectionsError(f"来源路径层级不足: {rel!r}")

    root = project_root.resolve()
    candidate = root / rel
    if not candidate.exists():
        raise CollectionsError(f"来源不存在: {rel!r}")
    if not candidate.is_file():
        raise CollectionsError(f"来源不是普通文件: {rel!r}")
    resolved = candidate.resolve()
    if resolved != root and root not in resolved.parents:
        raise CollectionsError(f"来源符号链接逃逸出项目根: {rel!r}")
    rules_root = (root / "rules").resolve()
    if resolved != rules_root and rules_root not in resolved.parents:
        raise CollectionsError(f"来源解析后逃逸出 rules/（可能是符号链接）: {rel!r}")
    return resolved


# ---------------------------------------------------------------------------
# 配置校验
# ---------------------------------------------------------------------------


def validate_collections_config(config: Mapping, project_root: Path) -> None:
    """校验 schema、字段、路径、大小写冲突、目标覆盖来源等；不解析规则内容。"""
    if not isinstance(config, dict):
        raise CollectionsError("collections 配置根必须是 JSON 对象")

    unknown_top = set(config.keys()) - _TOP_LEVEL_KEYS
    if unknown_top:
        raise CollectionsError(f"collections 配置包含未知顶层字段: {sorted(unknown_top)}")
    if config.get("version") != CONFIG_VERSION:
        raise CollectionsError(
            f"不支持的 collections 配置 version: {config.get('version')!r} (期望 {CONFIG_VERSION})"
        )
    collections = config.get("collections")
    if not isinstance(collections, dict) or not collections:
        raise CollectionsError("collections 必须是非空对象")

    root = project_root.resolve()

    # 1) 逐 collection 校验字段并收集来源解析路径。
    source_resolved: set = set()
    for out_rel, spec in collections.items():
        if not isinstance(spec, dict):
            raise CollectionsError(f"collection {out_rel!r} 的配置必须是对象")
        extra = set(spec.keys()) - _COLLECTION_KEYS
        if extra:
            raise CollectionsError(
                f"collection {out_rel!r} 包含未知字段: {sorted(extra)}"
            )
        name = spec.get("name")
        if not isinstance(name, str) or not name.strip():
            raise CollectionsError(f"collection {out_rel!r} 的 name 必须是非空字符串")
        policy_hint = spec.get("policy_hint")
        if not isinstance(policy_hint, str) or not policy_hint.strip():
            raise CollectionsError(f"collection {out_rel!r} 的 policy_hint 必须是非空字符串")
        sources = spec.get("sources")
        if not isinstance(sources, list) or not sources:
            raise CollectionsError(f"collection {out_rel!r} 的 sources 必须是非空数组")
        for rel in sources:
            source_resolved.add(_validate_source_rel(rel, root))

    # 2) 校验输出路径、大小写冲突、目标不得覆盖来源。
    lowered: Dict[str, str] = {}
    target_resolved: Dict[str, Path] = {}
    for out_rel in collections:
        _validate_output_rel(out_rel, root)
        low = out_rel.lower()
        if low in lowered:
            raise CollectionsError(
                f"输出路径大小写冲突: {out_rel!r} 与 {lowered[low]!r} 仅大小写不同"
            )
        lowered[low] = out_rel
        resolved_target = (root / out_rel).resolve()
        if resolved_target in source_resolved:
            raise CollectionsError(f"输出 {out_rel!r} 会覆盖其来源文件（含符号链接解析后同址）")
        if resolved_target in target_resolved.values():
            raise CollectionsError(f"输出路径解析到重复目标: {out_rel!r}")
        target_resolved[out_rel] = resolved_target


# ---------------------------------------------------------------------------
# 构建输出
# ---------------------------------------------------------------------------


def _sort_key(rule: sync.Rule):
    type_index = sync._TYPE_ORDER.get(rule.type, len(sync.VALID_RULE_TYPES))
    return (type_index, rule.value, rule.options)


def _parse_source(rel: str, project_root: Path) -> Tuple[List[sync.Rule], str]:
    """严格解析单个来源，返回 (rules, raw_text)。"""
    path = project_root.resolve() / rel
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise CollectionsError(f"读取来源失败: {rel!r}: {exc}") from exc
    text = sync._decode_bytes(data, rel)
    rules = sync.parse_surge(text, source_id=rel)
    return rules, text


def canonical_source_url(rel: str) -> str:
    """纯手工来源的 canonical 维护地址。"""
    return f"{REPO_SLUG}/blob/main/{rel.lstrip('/')}"


def render_body(policy_hint: str, rules: Sequence[sync.Rule]) -> str:
    """渲染规则正文（含稳定的策略 / 来源类型注释），供共享 metadata 注释。

    维护位置（``sources``）与上游由 ``annotate_list`` 的受管头统一渲染；
    这里只保留不属于受管头的额外说明行。注意：``# 维护位置：`` 是受管前缀，
    会被 ``list_metadata.strip_metadata`` 剥离，故不在此重复生成。
    """
    lines: List[str] = [
        f"# 策略：{policy_hint}",
        "# 来源类型：生成合并（同一策略使用）",
        "",
    ]
    lines.extend(rule.render() for rule in rules)
    return "\n".join(lines) + "\n"


def _read_previous(target: Path) -> Optional[str]:
    try:
        if target.is_file():
            return target.read_text(encoding="utf-8")
    except OSError:
        return None
    return None


def _dedup(seq: Sequence[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in seq:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def build_collections_outputs(
    config: Mapping, project_root: Path, *, now=None
) -> Dict[str, str]:
    """在内存中构建全部 collection 文件；任何错误都不产生部分结果，不写盘。"""
    validate_collections_config(config, project_root)
    root = project_root.resolve()
    meta = _require_metadata()

    files: Dict[str, str] = {}
    for out_rel, spec in config["collections"].items():
        name = spec["name"]
        policy_hint = spec["policy_hint"]
        ordered_sources = _dedup(spec["sources"])

        # exact（type + value + options 全等）去重，绝不跨源 suffix 裁剪。
        merged: Dict[str, sync.Rule] = {}
        upstreams: List[str] = []
        seen_upstreams = set()

        for rel in ordered_sources:
            rules, text = _parse_source(rel, root)
            for rule in rules:
                merged.setdefault(rule.key(), rule)
            try:
                found = meta.extract_upstreams(text)
            except Exception as exc:  # metadata 异常同样 fail closed
                raise CollectionsError(f"解析来源上游失败: {rel!r}: {exc}") from exc
            if not isinstance(found, list):
                raise CollectionsError(f"extract_upstreams 返回值必须是列表: {rel!r}")
            local_upstreams: List[str] = []
            for url in found:
                if not isinstance(url, str) or not url:
                    raise CollectionsError(f"extract_upstreams 返回了非字符串 URL: {rel!r}")
                if url not in seen_upstreams:
                    seen_upstreams.add(url)
                    upstreams.append(url)
                local_upstreams.append(url)
            # 纯手工来源（自身没有 HTTP 上游）补充 canonical 维护地址作为来源。
            if not local_upstreams:
                canon = canonical_source_url(rel)
                if canon not in seen_upstreams:
                    seen_upstreams.add(canon)
                    upstreams.append(canon)

        if not merged:
            raise CollectionsError(f"collection {out_rel!r} 未产生任何有效规则")

        # 维护位置 = sources 列表（由共享 metadata 渲染为 ``# 维护位置：``）。
        canonical_sources = list(ordered_sources)

        rules = sorted(merged.values(), key=_sort_key)
        body = render_body(policy_hint, rules)
        previous_text = _read_previous((root / out_rel))

        try:
            content = meta.annotate_list(
                body,
                name=name,
                upstreams=upstreams,
                canonical_sources=canonical_sources,
                previous_text=previous_text,
                now=now,
            )
        except TypeError:
            # 兼容共享模块尚未支持某些可选参数的情况：至少保证核心字段可用。
            raise
        if not isinstance(content, str):
            raise CollectionsError(f"annotate_list 未返回字符串: {out_rel!r}")
        files[out_rel] = content
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


def run_default(config_path: Path, project_root: Path, *, now=None) -> int:
    try:
        config = load_collections_config(config_path)
        files = build_collections_outputs(config, project_root, now=now)
        written = sync.write_outputs(files, project_root)
    except Exception as exc:  # 任何异常都不得落盘（构建全部在内存中完成）
        print(f"[collections] 失败: {exc}")
        return 1
    if written:
        print(f"已更新 {len(written)} 个文件：")
        for rel in written:
            print(f"  - {rel}")
    else:
        print("无内容变更，未写入任何文件。")
    return 0


def run_check(config_path: Path, project_root: Path, *, now=None) -> int:
    try:
        config = load_collections_config(config_path)
        files = build_collections_outputs(config, project_root, now=now)
        changed = _changed_files(files, project_root)
    except Exception as exc:
        print(f"[check] 失败: {exc}")
        return 1
    if changed:
        print(f"[check] 有 {len(changed)} 个文件需要更新：")
        for rel in changed:
            print(f"  - {rel}")
        return 2
    print("[check] 无内容变更。")
    return 0


def run_validate(config_path: Path, project_root: Path, *, now=None) -> int:
    try:
        config = load_collections_config(config_path)
        files = build_collections_outputs(config, project_root, now=now)
        changed = _changed_files(files, project_root)
    except Exception as exc:
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
        description="按 config/collections.json 合并旧 list 生成分类集合 .list（不联网）。",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="collections 配置文件路径（默认 <项目根>/config/collections.json）",
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
    config_path = Path(args.config) if args.config else root / "config" / "collections.json"

    if args.validate:
        return run_validate(config_path, root)
    if args.check:
        return run_check(config_path, root)
    return run_default(config_path, root)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
