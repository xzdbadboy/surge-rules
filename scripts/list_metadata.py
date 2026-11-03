#!/usr/bin/env python3
"""统一的中文受管 metadata 头工具（仅标准库）。

本模块为 ``.list`` 规则文件提供**唯一**的 metadata 头生成/解析实现，供
:mod:`scripts.sync_rules`、:mod:`scripts.build_compat` 与
:mod:`scripts.stamp_custom` 共用，避免三处各写一套导致时间/哈希语义漂移。

受管头（位于文件最前部，均为整行注释）::

    # 名称：ChatGPT / OpenAI
    # 更新时间：2026-11-03 10:00:00 +08:00
    # 上游：https://raw.githubusercontent.com/.../openai.list
    # 上游：https://raw.githubusercontent.com/.../ai.conf
    # 维护位置：rules/ai/ChatGPT.list
    # 内容校验：sha256:<64 位小写十六进制>

设计要点
--------
- **北京时间**：所有时间统一为 ``Asia/Shanghai``（UTC+8），格式固定
  ``YYYY-MM-DD HH:MM:SS +08:00``。
- **稳定哈希**：内容哈希只取决于「剥离受管头后的规范正文 + 名称 + 上游 + 维护位置」，
  与文件 mtime、运行时刻无关。定时检查内容不变时哈希不变。
- **时间只在有效内容/来源描述变化时更新**：重新注释时，仅当旧头的哈希与本次预期
  哈希相同、且旧文件正文实际哈希与旧头自洽、旧时间格式合法，才沿用旧时间；
  否则使用本次真实时间。绝不按 mtime 或“每次运行”刷新，也绝不编造历史时间。
- **保留原始正文**：只增删受管头行，规则行与其它有用注释（``# FORMAT`` /
  ``# 说明`` / ``# 证据`` 等）原样保留。

公共接口（另一代理的 collections 生成器按此名称导入，勿改名）::

    annotate_list(content, *, name, upstreams, canonical_sources=(),
                  previous_text=None, now=None) -> str
    extract_upstreams(text) -> list[str]
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Sequence

# 北京时区（UTC+8），避免依赖第三方 tzdata。
BEIJING_TZ = timezone(timedelta(hours=8))

# 固定时间格式（含字面量 ``+08:00``）。
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S +08:00"

# 受管头各字段的行前缀。
NAME_PREFIX = "# 名称："
UPDATED_PREFIX = "# 更新时间："
UPSTREAM_PREFIX = "# 上游："
MAINTENANCE_PREFIX = "# 维护位置："
HASH_PREFIX = "# 内容校验："

# 受管头行前缀集合（用于剥离）。
MANAGED_PREFIXES = (
    NAME_PREFIX,
    UPDATED_PREFIX,
    UPSTREAM_PREFIX,
    MAINTENANCE_PREFIX,
    HASH_PREFIX,
)

# 旧格式（自动引擎历史输出）里表示上游的行前缀，extract_upstreams 也识别。
LEGACY_SOURCE_PREFIX = "# 来源："

_HASH_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_URL_RE = re.compile(r"https?://[^\s,;，；（()\[\]<>\"']+")


# ---------------------------------------------------------------------------
# 时间
# ---------------------------------------------------------------------------


def now_beijing(now: Optional[datetime] = None) -> datetime:
    """返回北京时间；``now`` 为 None 时用当前时间，naive 时间按北京时间解释。"""
    if now is None:
        return datetime.now(BEIJING_TZ)
    if now.tzinfo is None:
        return now.replace(tzinfo=BEIJING_TZ)
    return now.astimezone(BEIJING_TZ)


def format_timestamp(now: Optional[datetime] = None) -> str:
    """把时间格式化为 ``YYYY-MM-DD HH:MM:SS +08:00``（北京时区）。"""
    dt = now_beijing(now)
    return dt.strftime("%Y-%m-%d %H:%M:%S") + " +08:00"


def parse_timestamp(text: Optional[str]) -> Optional[datetime]:
    """严格解析受管头时间；非法（格式/数值不合法）返回 None。"""
    if not isinstance(text, str):
        return None
    text = text.strip()
    try:
        dt = datetime.strptime(text, TIMESTAMP_FORMAT)
    except (TypeError, ValueError):
        return None
    dt = dt.replace(tzinfo=BEIJING_TZ)
    # 回写一致性校验，拒绝如 2026-02-30 等被 strptime 宽松接受的边界值。
    if format_timestamp(dt) != text:
        return None
    return dt


# ---------------------------------------------------------------------------
# 受管头识别 / 剥离
# ---------------------------------------------------------------------------


def is_managed_line(line: str) -> bool:
    """判断整行是否为受管头字段行。"""
    stripped = line.strip()
    return any(stripped.startswith(prefix) for prefix in MANAGED_PREFIXES)


def strip_metadata(text: str) -> str:
    """去掉受管头行，返回规范正文（去首尾空行，内部原样保留）。

    只删除受管字段（名称/更新时间/上游/维护位置/内容校验），其它注释与规则
    行保持不变。
    """
    if not isinstance(text, str):
        raise TypeError("text 必须是字符串")
    lines = [ln for ln in text.splitlines() if not is_managed_line(ln)]
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 稳定哈希
# ---------------------------------------------------------------------------


def compute_content_hash(
    canonical_body: str,
    name: str,
    upstreams: Sequence[str],
    canonical_sources: Sequence[str] = (),
) -> str:
    """计算稳定内容哈希（与顺序、位置无关的时间无关指纹）。

    输入为「剥离受管头后的规范正文 + 名称 + 上游列表 + 维护位置列表」，
    以 canonical JSON（sort_keys + 紧凑分隔符）序列化后取 sha256。
    """
    payload = {
        "name": name,
        "upstreams": list(upstreams),
        "canonical_sources": list(canonical_sources),
        "body": canonical_body,
    }
    canon = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# 头解析
# ---------------------------------------------------------------------------


def parse_header(text: str) -> dict:
    """解析受管头，返回字段与合法性标记。

    返回 dict：
        name, updated_at, upstreams, canonical_sources, hash,
        valid_time, valid_hash
    ``canonical_sources`` 来源于 ``# 维护位置：`` 行（按逗号拆分）。
    """
    name: Optional[str] = None
    updated_at: Optional[str] = None
    upstreams: List[str] = []
    canonical_sources: Optional[List[str]] = None
    hash_hex: Optional[str] = None

    for line in text.splitlines():
        s = line.strip()
        if s.startswith(NAME_PREFIX):
            if name is None:
                name = s[len(NAME_PREFIX):].strip()
        elif s.startswith(UPDATED_PREFIX):
            if updated_at is None:
                updated_at = s[len(UPDATED_PREFIX):].strip()
        elif s.startswith(UPSTREAM_PREFIX):
            value = s[len(UPSTREAM_PREFIX):].strip()
            if value:
                upstreams.append(value)
        elif s.startswith(MAINTENANCE_PREFIX):
            if canonical_sources is None:
                value = s[len(MAINTENANCE_PREFIX):].strip()
                canonical_sources = [p.strip() for p in value.split(",") if p.strip()]
        elif s.startswith(HASH_PREFIX):
            if hash_hex is None:
                value = s[len(HASH_PREFIX):].strip()
                if value.startswith("sha256:"):
                    value = value[len("sha256:"):]
                hash_hex = value if _HASH_HEX_RE.match(value) else ""

    valid_hash = bool(hash_hex) and bool(_HASH_HEX_RE.match(hash_hex or ""))
    return {
        "name": name,
        "updated_at": updated_at,
        "upstreams": upstreams,
        "canonical_sources": canonical_sources if canonical_sources is not None else [],
        "hash": hash_hex if valid_hash else None,
        "valid_time": parse_timestamp(updated_at) is not None,
        "valid_hash": valid_hash,
    }


# ---------------------------------------------------------------------------
# 上游解析
# ---------------------------------------------------------------------------


def extract_upstreams(text: str) -> List[str]:
    """从文本的 ``# 上游：`` / 旧 ``# 来源：`` 行解析 HTTP(S) URL。

    - 只识别上述两种前缀；``# 证据`` / ``# 维护位置`` 等不计入上游。
    - 保持出现顺序并去重。
    - 纯手工说明（无 URL）不会产生上游项。
    """
    if not isinstance(text, str):
        return []
    result: List[str] = []
    for line in text.splitlines():
        s = line.strip()
        value = None
        if s.startswith(UPSTREAM_PREFIX):
            value = s[len(UPSTREAM_PREFIX):]
        elif s.startswith(LEGACY_SOURCE_PREFIX):
            value = s[len(LEGACY_SOURCE_PREFIX):]
        if value is None:
            continue
        for match in _URL_RE.findall(value):
            if match not in result:
                result.append(match)
    return result


# ---------------------------------------------------------------------------
# 渲染与注释
# ---------------------------------------------------------------------------


def _render_header(
    name: str,
    timestamp: str,
    upstreams: Sequence[str],
    canonical_sources: Sequence[str],
    content_hash: str,
) -> str:
    lines: List[str] = [f"{NAME_PREFIX}{name}", f"{UPDATED_PREFIX}{timestamp}"]
    if upstreams:
        for upstream in upstreams:
            lines.append(f"{UPSTREAM_PREFIX}{upstream}")
    else:
        lines.append(f"{UPSTREAM_PREFIX}无外部上游（本仓库维护）")
    if canonical_sources:
        lines.append(f"{MAINTENANCE_PREFIX}" + ", ".join(canonical_sources))
    lines.append(f"{HASH_PREFIX}sha256:{content_hash}")
    return "\n".join(lines)


def _resolve_timestamp(
    body: str,
    name: str,
    upstreams: Sequence[str],
    canonical_sources: Sequence[str],
    expected_hash: str,
    previous_text: Optional[str],
    now: Optional[datetime],
) -> str:
    """决定本次应写入的更新时间。"""
    if previous_text is not None:
        info = parse_header(previous_text)
        if info["valid_time"] and info["valid_hash"]:
            old_body = strip_metadata(previous_text)
            old_actual = compute_content_hash(
                old_body,
                info["name"] if info["name"] is not None else "",
                info["upstreams"],
                info["canonical_sources"],
            )
            # 旧文件必须自洽（正文真实哈希 == 旧头哈希），且旧头哈希与本次预期一致。
            if old_actual == info["hash"] and info["hash"] == expected_hash:
                return info["updated_at"]  # type: ignore[return-value]
    return format_timestamp(now)


def annotate_list(
    content: str,
    *,
    name: str,
    upstreams: Sequence[str],
    canonical_sources: Sequence[str] = (),
    previous_text: Optional[str] = None,
    now: Optional[datetime] = None,
) -> str:
    """为规则正文生成/更新统一受管头，返回完整文件文本。

    参数
    ----
    content:
        规则正文（可包含旧受管头，会被自动剥离；也可是纯正文）。
    name:
        列表名称。
    upstreams:
        真实上游来源（URL 或明确的手工说明），渲染为多行 ``# 上游：``。
    canonical_sources:
        规范维护位置（路径或 URL），渲染为 ``# 维护位置：`` 并纳入稳定哈希。
    previous_text:
        旧文件全文（含旧受管头），用于在内容未变化时沿用旧更新时间。
    now:
        注入的当前时间（测试用）；None 表示使用真实当前北京时间。
    """
    body = strip_metadata(content)
    upstream_list = list(upstreams) or ["无外部上游（本仓库维护）"]
    source_list = list(canonical_sources)
    expected_hash = compute_content_hash(body, name, upstream_list, source_list)
    timestamp = _resolve_timestamp(
        body, name, upstream_list, source_list, expected_hash, previous_text, now
    )
    header = _render_header(name, timestamp, upstream_list, source_list, expected_hash)
    if body:
        return header + "\n\n" + body + "\n"
    return header + "\n"


__all__ = [
    "BEIJING_TZ",
    "TIMESTAMP_FORMAT",
    "now_beijing",
    "format_timestamp",
    "parse_timestamp",
    "is_managed_line",
    "strip_metadata",
    "compute_content_hash",
    "parse_header",
    "extract_upstreams",
    "annotate_list",
]
