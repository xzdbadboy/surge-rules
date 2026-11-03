#!/usr/bin/env python3
"""生成根目录兼容别名 `.list`（rebuild compatibility aliases）。

背景
----
仓库把规则整理进 ``rules/{custom,ai,services,security,collections}/`` 下的 canonical
文件后，仍需保留根目录的旧文件名（例如 ``AIGC.list``、``ChatGPT.list``、
``MtProviders.list``）以及少数 ``rules/custom/`` 直下别名作为兼容地址。本脚本读取
``config/compatibility.json`` 的映射，把多个 canonical 文件的规则**合并去重**后渲染
成兼容别名 ``.list``，并写入统一的中文 metadata 头。

设计要点
--------
- 纯标准库，不联网；解析/校验/渲染复用 ``sync_rules`` 的公用接口与
  ``list_metadata`` 的统一 metadata 头。
- fail closed：任一 canonical 源缺失 / 非法 / 路径问题 / 无规则时，**所有**别名都
  不写盘；只有全部别名先在内存中渲染成功后才统一写入。
- 去重仅做 **exact（type+value+options 全等）** 去重，绝不按 suffix 粗略裁剪。
- 输出稳定：metadata 头的时间只在「输出有效内容 / 来源描述」变化时更新；内容无
  变化时 ``--check`` / ``--validate`` 跨次稳定，不按运行时刻刷新。
- 不生成 ``RULE-SET`` 网络嵌套引用。

目标与来源约束
--------------
- 目标（target）只允许：
    * 根目录单文件名 ``foo.list``；或
    * 正好三层 ``rules/custom/foo.list``。
  其它任意嵌套目标一律拒绝。
- 来源（source）只允许位于 ``rules/{custom,ai,services,security,collections}/`` 下；
  其中 ``custom`` 规范源必须再分类到 ``rules/custom/<category>/<file>.list``（不能是
  ``rules/custom`` 直下的扁平层，避免与兼容目标互相依赖）。
- 全局禁止：任一 target 出现在任一 source（字符串相同或 resolve 后相同）、target
  之间大小写冲突 / resolve 后重复，防止循环、覆盖与大小写冲突、路径逃逸。

用法::

    python3 scripts/build_compat.py [--config PATH] [--root PATH] [--check] [--validate]

退出码：
    0  默认模式成功 / --check 无变更 / --validate 通过
    1  失败（配置 / 路径 / 解析 / 校验失败，或 --validate 检测到不一致）
    2  --check 检测到需要更新
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

try:  # 作为包的一部分导入（测试：from scripts import build_compat）
    from . import sync_rules as sync
    from . import list_metadata as meta
except ImportError:  # 直接以脚本方式运行（python3 scripts/build_compat.py）
    import sync_rules as sync  # type: ignore[no-redef]
    import list_metadata as meta  # type: ignore[no-redef]

# 允许作为 canonical 来源的 rules 子目录（含新增 collections 实体集合）。
ALLOWED_SOURCE_DIRS: Tuple[str, ...] = ("custom", "ai", "services", "security", "collections")

# 本仓库 canonical RULE-SET 固定 URL 前缀（用于手工源的注释来源说明）。
CANONICAL_BASE_URL = "https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/"

# 兼容正文里的历史标记（保留以兼容既有消费者，非受管头）。
GENERATED_MARKER = "# generated; edit canonical paths"

CONFIG_VERSION = 1

# target 允许的嵌套层数（rules/custom/<file>.list）。
NESTED_TARGET_PARTS = ("rules", "custom")


class CompatError(sync.ConfigError):
    """兼容别名配置/构建过程中的错误（属于 sync.SyncError 子类）。"""


# ---------------------------------------------------------------------------
# 配置加载
# ---------------------------------------------------------------------------


def default_project_root() -> Path:
    """脚本所在项目的根目录（scripts/ 的上一级）。"""
    return Path(__file__).resolve().parent.parent


def load_compat_config(config_path: Path) -> dict:
    path = Path(config_path)
    if not path.is_file():
        raise CompatError(f"兼容配置文件不存在: {path}")
    try:
        with path.open("r", encoding="utf-8") as fh:
            config = json.load(fh)
    except json.JSONDecodeError as exc:
        raise CompatError(f"兼容配置文件不是合法 JSON: {exc}") from exc
    if not isinstance(config, dict):
        raise CompatError("兼容配置根必须是 JSON 对象")
    return config


# ---------------------------------------------------------------------------
# 路径校验
# ---------------------------------------------------------------------------


def _validate_target(target: str, project_root: Path) -> str:
    """校验兼容目标路径。

    允许：根目录 ``foo.list``，或正好三层 ``rules/custom/foo.list``。
    """
    if not isinstance(target, str) or not target.strip():
        raise CompatError(f"别名目标必须是非空字符串: {target!r}")
    if "\\" in target:
        raise CompatError(f"别名目标不允许反斜杠: {target!r}")
    if target.startswith("/") or (len(target) >= 2 and target[1] == ":"):
        raise CompatError(f"别名目标必须是相对路径: {target!r}")
    if target in (".", ".."):
        raise CompatError(f"别名目标非法: {target!r}")
    parts = target.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise CompatError(f"别名目标包含非法路径片段: {target!r}")
    if not target.endswith(".list"):
        raise CompatError(f"别名目标必须以 .list 结尾: {target!r}")
    if len(parts) == 1:
        pass  # 根目录单文件名
    elif len(parts) == 3 and parts[0] == NESTED_TARGET_PARTS[0] and parts[1] == NESTED_TARGET_PARTS[1]:
        pass  # rules/custom/foo.list
    else:
        raise CompatError(
            f"别名目标只允许根目录 foo.list 或 rules/custom/foo.list（正好三层）: {target!r}"
        )
    # 复用 sync_rules 的路径安全校验（受保护目录、逃逸等）。
    sync._validate_output_path(target, project_root)
    return target


def _validate_source_rel(rel: str, project_root: Path) -> Path:
    """校验 canonical 来源路径，返回其解析后的绝对路径。"""
    if not isinstance(rel, str) or not rel.strip():
        raise CompatError(f"canonical 来源必须是非空字符串: {rel!r}")
    if "\\" in rel:
        raise CompatError(f"canonical 来源不允许反斜杠: {rel!r}")
    if rel.startswith("/") or (len(rel) >= 2 and rel[1] == ":"):
        raise CompatError(f"canonical 来源不允许绝对路径: {rel!r}")
    parts = rel.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise CompatError(f"canonical 来源包含非法路径片段: {rel!r}")
    if not rel.endswith(".list"):
        raise CompatError(f"canonical 来源必须以 .list 结尾: {rel!r}")
    if parts[0] != "rules":
        raise CompatError(f"canonical 来源必须位于 rules/ 下（不允许根别名自引用）: {rel!r}")
    if len(parts) < 3 or parts[1] not in ALLOWED_SOURCE_DIRS:
        raise CompatError(
            f"canonical 来源必须位于 rules/{{{','.join(ALLOWED_SOURCE_DIRS)}}}/ 下: {rel!r}"
        )
    if parts[1] == "custom" and len(parts) < 4:
        raise CompatError(
            f"custom 规范源必须分类到 rules/custom/<category>/<file>.list（不能是扁平层）: {rel!r}"
        )

    root = project_root.resolve()
    candidate = root / rel
    if not candidate.exists():
        raise CompatError(f"canonical 来源不存在: {rel!r}")
    if not candidate.is_file():
        raise CompatError(f"canonical 来源不是文件: {rel!r}")
    resolved = candidate.resolve()
    if resolved != root and root not in resolved.parents:
        raise CompatError(f"canonical 来源符号链接逃逸出项目根: {rel!r}")
    rules_root = (root / "rules").resolve()
    if resolved != rules_root and rules_root not in resolved.parents:
        raise CompatError(f"canonical 来源解析后逃逸出 rules/（可能是符号链接）: {rel!r}")
    return resolved


# ---------------------------------------------------------------------------
# 配置校验
# ---------------------------------------------------------------------------


def validate_compat_config(config: Mapping, project_root: Path) -> None:
    """校验 schema、路径、大小写冲突、别名覆盖、循环与逃逸；不解析规则内容。"""
    if not isinstance(config, dict):
        raise CompatError("兼容配置根必须是 JSON 对象")
    if config.get("version") != CONFIG_VERSION:
        raise CompatError(
            f"不支持的兼容配置 version: {config.get('version')!r} (期望 {CONFIG_VERSION})"
        )
    aliases = config.get("aliases")
    if not isinstance(aliases, dict):
        raise CompatError("compatibility.aliases 必须是对象")
    if not aliases:
        raise CompatError("compatibility.aliases 不能为空")

    root = project_root.resolve()

    # 1) 校验所有来源，收集字符串与解析后 canonical 路径集合。
    source_strings: Dict[str, str] = {}
    source_resolved: set = set()
    for target, sources in aliases.items():
        if not isinstance(sources, list) or not sources:
            raise CompatError(f"别名 {target!r} 的来源必须是非空数组")
        for rel in sources:
            if not isinstance(rel, str):
                raise CompatError(f"别名 {target!r} 的来源必须都是字符串: {rel!r}")
            low = rel.lower()
            if low in source_strings and source_strings[low] != rel:
                raise CompatError(
                    f"来源路径大小写冲突: {rel!r} 与 {source_strings[low]!r} 仅大小写不同"
                )
            source_strings[low] = rel
            source_resolved.add(_validate_source_rel(rel, root))

    # 2) 校验目标：路径、大小写冲突、resolve 后重复、不得覆盖 canonical 来源。
    lowered_targets: Dict[str, str] = {}
    target_resolved: Dict[str, Path] = {}
    for target in aliases:
        _validate_target(target, root)
        low = target.lower()
        if low in lowered_targets:
            raise CompatError(
                f"别名目标大小写冲突: {target!r} 与 {lowered_targets[low]!r} 仅大小写不同"
            )
        if low in source_strings:
            raise CompatError(
                f"别名目标与 canonical 来源同名（大小写不敏感）: {target!r} vs {source_strings[low]!r}"
            )
        lowered_targets[low] = target
        resolved_target = (root / target).resolve()
        if resolved_target in source_resolved:
            raise CompatError(f"别名 {target!r} 会覆盖 canonical 文件")
        if resolved_target in target_resolved.values():
            raise CompatError(f"别名目标 resolve 后重复: {target!r}")
        target_resolved[target] = resolved_target


# ---------------------------------------------------------------------------
# 构建输出
# ---------------------------------------------------------------------------


def _sort_key(rule: sync.Rule):
    type_index = sync._TYPE_ORDER.get(rule.type, len(sync.VALID_RULE_TYPES))
    return (type_index, rule.value, rule.options)


def _parse_source(rel: str, project_root: Path) -> List[sync.Rule]:
    path = (project_root.resolve() / rel)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise CompatError(f"读取 canonical 来源失败: {rel!r}: {exc}") from exc
    text = sync._decode_bytes(data, rel)
    # parse_surge 逐条严格校验：任何非法行都会抛 ParseError，绝不忽略坏行。
    return sync.parse_surge(text, source_id=rel)


def _source_text(rel: str, project_root: Path) -> str:
    path = (project_root.resolve() / rel)
    try:
        return sync._decode_bytes(path.read_bytes(), rel)
    except OSError as exc:
        raise CompatError(f"读取 canonical 来源失败: {rel!r}: {exc}") from exc


def _collect_upstreams(sources: Sequence[str], project_root: Path) -> List[str]:
    """汇总各来源的真实上游；纯手工源指向本仓库 canonical URL 并注明手工类型。"""
    upstreams: List[str] = []
    for rel in sources:
        text = _source_text(rel, project_root)
        found = meta.extract_upstreams(text)
        if found:
            candidates = found
        else:
            candidates = [f"{CANONICAL_BASE_URL}{rel}（手工维护，无外部同步源）"]
        for item in candidates:
            if item not in upstreams:
                upstreams.append(item)
    return upstreams


def render_compat(
    target: str,
    sources: Sequence[str],
    rules: Sequence[sync.Rule],
    upstreams: Sequence[str],
    previous_text: Optional[str] = None,
    now=None,
) -> str:
    """渲染兼容别名文件内容（统一中文 metadata 头 + 稳定规则正文）。"""
    body_lines: List[str] = [GENERATED_MARKER, "# sources: " + ", ".join(sources), ""]
    body_lines.extend(rule.render() for rule in rules)
    body = "\n".join(body_lines) + "\n"
    name = Path(target).stem
    return meta.annotate_list(
        body,
        name=name,
        upstreams=list(upstreams),
        canonical_sources=list(sources),
        previous_text=previous_text,
        now=now,
    )


def build_compat_outputs(
    config: Mapping,
    project_root: Path,
    previous_outputs: Optional[Mapping[str, str]] = None,
    now=None,
) -> Dict[str, str]:
    """在内存中构建所有兼容别名文件，不写盘；任何错误都不产生部分结果。"""
    validate_compat_config(config, project_root)
    root = project_root.resolve()
    shared_now = meta.now_beijing(now)

    files: Dict[str, str] = {}
    for target, sources in config["aliases"].items():
        # 按配置顺序去重来源（完全相同字符串出现多次无意义）。
        ordered_sources: List[str] = []
        seen_sources = set()
        for rel in sources:
            if rel not in seen_sources:
                seen_sources.add(rel)
                ordered_sources.append(rel)

        # exact 去重：以 Rule.key()（type+value+options 全等）为唯一键。
        merged: Dict[str, sync.Rule] = {}
        for rel in ordered_sources:
            for rule in _parse_source(rel, root):
                merged.setdefault(rule.key(), rule)

        if not merged:
            raise CompatError(f"别名 {target!r} 未产生任何有效规则（无规则则 fail）")

        rules = sorted(merged.values(), key=_sort_key)
        upstreams = _collect_upstreams(ordered_sources, root)
        previous_text = previous_outputs.get(target) if previous_outputs else None
        files[target] = render_compat(
            target, ordered_sources, rules, upstreams, previous_text=previous_text, now=shared_now
        )
    return files


# ---------------------------------------------------------------------------
# 比较与读取
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


def _read_previous_outputs(config: Mapping, project_root: Path) -> Dict[str, str]:
    """读取现有兼容别名文件（target -> 文本），用于沿用旧更新时间。"""
    root = project_root.resolve()
    aliases = config.get("aliases") if isinstance(config, dict) else None
    if not isinstance(aliases, dict):
        return {}
    previous: Dict[str, str] = {}
    for target in aliases:
        try:
            path = sync._resolve_target(root, target)
        except sync.SyncError:
            continue
        if not path.is_file():
            continue
        try:
            previous[target] = path.read_text(encoding="utf-8")
        except OSError:
            continue
    return previous


# ---------------------------------------------------------------------------
# 顶层命令
# ---------------------------------------------------------------------------


def run_default(config_path: Path, project_root: Path) -> int:
    try:
        config = load_compat_config(config_path)
        previous = _read_previous_outputs(config, project_root)
        files = build_compat_outputs(config, project_root, previous_outputs=previous)
        written = sync.write_outputs(files, project_root)
    except sync.SyncError as exc:
        print(f"[compat] 失败: {exc}")
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
        config = load_compat_config(config_path)
        previous = _read_previous_outputs(config, project_root)
        files = build_compat_outputs(config, project_root, previous_outputs=previous)
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
        config = load_compat_config(config_path)
        previous = _read_previous_outputs(config, project_root)
        files = build_compat_outputs(config, project_root, previous_outputs=previous)
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
        description="根据 config/compatibility.json 生成根目录兼容别名 .list（不联网）。",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="兼容配置文件路径（默认 <项目根>/config/compatibility.json）",
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
    config_path = Path(args.config) if args.config else root / "config" / "compatibility.json"

    if args.validate:
        return run_validate(config_path, root)
    if args.check:
        return run_check(config_path, root)
    return run_default(config_path, root)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
