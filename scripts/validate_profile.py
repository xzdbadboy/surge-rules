#!/usr/bin/env python3
"""Surge ``[Rule]`` 段配置的纯离线静态校验与顺序冒烟（仅标准库）。

本脚本只做**静态**检查与有限的确定性匹配模拟，明确不替代真实的 Surge
DNS/ASN/网络行为：

- 静态校验：确认 profile 只有一个 ``[Rule]`` 段、``FINAL`` 唯一且位于最后；
  规则语法（含 ``AND``/``OR`` 逻辑子规则）合法；``RULE-SET`` 只引用本仓库
  canonical 路径且引用文件真实存在，并按 Surge RULE-SET 格式读取。
- 顺序冒烟：提供一个极简的 ``evaluate(profile, context)`` 匹配器，仅支持
  无 DNS 的静态匹配，用于验证模板中若干关键规则的先后顺序。它**不是**完整的
  Surge 解释器：``IP-ASN`` / ``USER-AGENT`` / ``URL-REGEX`` 等在缺少对应上下文
  时一律不匹配，也不会进行任何网络或 ASN 查询。

解析/校验尽量复用 ``scripts/sync_rules.py`` 的公用接口（``parse_surge``、
``Rule``、``_parse_rule``、``_strip_inline_comment``），不重复实现规则语法。

用法::

    python3 scripts/validate_profile.py [PROFILE] [--root PATH] [--smoke] [--no-smoke]

``PROFILE`` 默认 ``<root>/examples/Rule.template.conf``。默认在 profile 就是
默认模板时，校验通过后自动跑顺序冒烟；也可用 ``--smoke`` / ``--no-smoke`` 显式控制。

退出码：
    0  校验通过（且冒烟场景全部符合预期，若执行）
    1  校验失败或冒烟场景不符预期 / 文件无法读取
"""

from __future__ import annotations

import argparse
import fnmatch
import ipaddress
import os
import re
import sys
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

try:  # 作为包的一部分导入（测试：from scripts import validate_profile）
    from . import sync_rules as sync
except ImportError:  # 直接以脚本方式运行（python3 scripts/validate_profile.py）
    import sync_rules as sync  # type: ignore[no-redef]


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

# 本仓库 canonical RULE-SET 的固定 URL 前缀；除此以外只允许内置 LAN。
CANONICAL_BASE_URL = "https://raw.githubusercontent.com/xzdbadboy/surge-rules/main/"

# 内置（无需仓库文件）的 RULE-SET 名称。
BUILTIN_RULE_SETS = frozenset({"LAN"})

# 顶层逻辑类型。
LOGIC_TYPES = frozenset({"AND", "OR", "NOT"})

# 可由 sync_rules._parse_rule 直接校验的普通类型。
SIMPLE_TYPES = frozenset(sync.VALID_RULE_TYPES)

# 只允许出现在 AND/OR 子规则里的类型（无策略列）。
SUB_ONLY_TYPES = frozenset({"PROTOCOL", "DEST-PORT", "SRC-PORT", "IN-PORT"})

# RULE-SET 允许的选项。
RULESET_OPTIONS = frozenset({"extended-matching", "no-resolve"})

# FINAL 允许的选项。
FINAL_OPTIONS = frozenset({"dns-failed"})

# 内置 LAN 私网段（仅用于静态冒烟；不涉及 DNS 解析）。
# 参考 RFC1918 / CGNAT / 回环 / 链路本地 / IPv6 ULA 与链路本地。
LAN_NETWORKS: Tuple[ipaddress._BaseNetwork, ...] = tuple(
    ipaddress.ip_network(text)
    for text in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "192.0.0.0/24",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)

# 需要双引号的 emoji 区间（区域性指示符 + 常见 emoji 块）。
_EMOJI_RANGES = (
    (0x1F000, 0x1FAFF),
    (0x1F1E6, 0x1F1FF),
    (0x2600, 0x27BF),
    (0x2B00, 0x2BFF),
    (0xFE00, 0xFE0F),
)


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------


@dataclass
class RuleSpec:
    """一条已解析的 [Rule] 规则。

    - 普通规则：``value`` 为规则值，``policy`` 为策略，``options`` 为选项。
    - ``RULE-SET``：``value`` 为目标（``LAN`` 或完整 URL）。
    - 逻辑规则：``sub_rules`` 为子规则元组，``value`` 保留原始表达式文本。
    - ``FINAL``：``policy`` 为兜底策略。
    """

    type: str
    value: str = ""
    policy: Optional[str] = None
    options: Tuple[str, ...] = ()
    sub_rules: Tuple["RuleSpec", ...] = ()
    raw: str = ""
    line_no: int = 0


@dataclass
class ValidationResult:
    rules: List[RuleSpec] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


# ---------------------------------------------------------------------------
# 顶层逗号切分（正确处理括号与引号）
# ---------------------------------------------------------------------------


def split_top_level(text: str) -> List[str]:
    """按顶层逗号切分，忽略圆括号与引号内部的逗号。

    同时校验括号配对与引号闭合，遇到错误抛出 ``ValueError``。
    """
    parts: List[str] = []
    buf: List[str] = []
    depth = 0
    quote: Optional[str] = None
    i = 0
    while i < len(text):
        ch = text[i]
        if quote is not None:
            buf.append(ch)
            if ch == "\\" and i + 1 < len(text):
                buf.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ('"', "'"):
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch == "(":
            depth += 1
            buf.append(ch)
            i += 1
            continue
        if ch == ")":
            depth -= 1
            if depth < 0:
                raise ValueError("括号不匹配：出现多余的 ')'")
            buf.append(ch)
            i += 1
            continue
        if ch == "," and depth == 0:
            parts.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    if quote is not None:
        raise ValueError("引号未闭合")
    if depth != 0:
        raise ValueError("括号不匹配：缺少 ')'")
    parts.append("".join(buf))
    return parts


# ---------------------------------------------------------------------------
# 策略名（emoji / 含空格必须双引号）
# ---------------------------------------------------------------------------


def _is_emoji_char(ch: str) -> bool:
    code = ord(ch)
    for lo, hi in _EMOJI_RANGES:
        if lo <= code <= hi:
            return True
    return False


def _has_emoji(text: str) -> bool:
    return any(_is_emoji_char(ch) for ch in text)


def normalize_policy(raw: str) -> str:
    """校验并还原策略名列（不做 Proxy Group 存在性检查）。"""
    text = raw.strip()
    if not text:
        raise ValueError("策略列为空")
    if text[0] in ('"', "'"):
        quote = text[0]
        if len(text) < 2 or text[-1] != quote:
            raise ValueError(f"策略名引号未闭合: {raw!r}")
        inner = text[1:-1]
        if quote in inner:
            raise ValueError(f"策略名包含未转义引号: {raw!r}")
        if not inner.strip():
            raise ValueError(f"策略名为空: {raw!r}")
        return inner
    # 未加引号：emoji / 空格等必须显式双引号。
    if any(ch.isspace() for ch in text):
        raise ValueError(f"含空格的策略名必须使用双引号: {raw!r}")
    if _has_emoji(text):
        raise ValueError(f"含 emoji 的策略名必须使用双引号: {raw!r}")
    if '"' in text or "'" in text:
        raise ValueError(f"策略名引号位置非法: {raw!r}")
    return text


# ---------------------------------------------------------------------------
# 子规则 / 逻辑表达式解析
# ---------------------------------------------------------------------------


def _parse_port_spec(value: str) -> str:
    v = value.strip()
    if not v:
        raise ValueError("DEST-PORT 为空")
    m = re.fullmatch(r"(\d+)(?:\s*-\s*(\d+))?", v)
    if not m:
        raise ValueError(f"非法端口/端口段: {value!r}")
    lo = int(m.group(1))
    hi = int(m.group(2)) if m.group(2) else lo
    if not (0 <= lo <= 65535 and 0 <= hi <= 65535) or lo > hi:
        raise ValueError(f"端口越界或区间倒置: {value!r}")
    return v


def _parse_sub_rule(rtype: str, fields: Sequence[str], line_no: int) -> RuleSpec:
    """解析 AND/OR 内部的单个子规则（无策略列）。"""
    if rtype in LOGIC_TYPES:
        raise ValueError(f"逻辑子项嵌套错误: {rtype}")
    if len(fields) < 2:
        raise ValueError(f"子规则缺少值: {rtype}")
    value = fields[1].strip()
    if not value:
        raise ValueError(f"子规则值为空: {rtype}")
    opts = tuple(o.strip().lower() for o in fields[2:] if o.strip())
    if rtype in SUB_ONLY_TYPES:
        if opts:
            raise ValueError(f"{rtype} 子规则不允许选项: {opts!r}")
        if rtype == "PROTOCOL":
            proto = value.upper()
            if proto not in ("TCP", "UDP", "TCP,UDP", "UDP,TCP", "HTTP", "HTTPS"):
                raise ValueError(f"非法 PROTOCOL: {value!r}")
            return RuleSpec(rtype, proto, None, (), line_no=line_no)
        # 端口类
        _parse_port_spec(value)
        return RuleSpec(rtype, value, None, (), line_no=line_no)
    if rtype not in SIMPLE_TYPES:
        raise ValueError(f"逻辑子规则不允许的类型: {rtype}")
    rule_part = f"{rtype},{value}"
    if opts:
        rule_part += "," + ",".join(opts)
    sync._parse_rule(rule_part, source_id="<logic>")  # 抛 sync.ParseError
    return RuleSpec(rtype, value, None, opts, line_no=line_no)


def _parse_logic_expr(text: str, rtype: str, line_no: int) -> RuleSpec:
    expr = text.strip()
    if not (expr.startswith("(") and expr.endswith(")")):
        raise ValueError(f"{rtype} 表达式必须整体用括号包裹: {text!r}")
    inner = expr[1:-1]
    if not inner.strip():
        raise ValueError(f"{rtype} 表达式为空")
    try:
        parts = split_top_level(inner)
    except ValueError as exc:
        raise ValueError(f"{rtype} 表达式括号/引号错误: {exc}") from exc
    terms: List[RuleSpec] = []
    for part in parts:
        p = part.strip()
        if not p:
            raise ValueError(f"{rtype} 表达式含空子项")
        if not (p.startswith("(") and p.endswith(")")):
            raise ValueError(f"{rtype} 每个子项必须用括号包裹: {p!r}")
        term_inner = p[1:-1]
        try:
            fields = split_top_level(term_inner)
        except ValueError as exc:
            raise ValueError(f"{rtype} 子项括号/引号错误: {exc}") from exc
        tr = fields[0].strip().upper()
        if not tr:
            raise ValueError(f"{rtype} 子项类型为空: {p!r}")
        if tr in LOGIC_TYPES:
            if len(fields) != 2:
                raise ValueError(f"{tr} 子项必须恰好是 (类型,表达式): {p!r}")
            terms.append(_parse_logic_expr(fields[1], tr, line_no))
        else:
            terms.append(_parse_sub_rule(tr, fields, line_no))
    if rtype == "NOT" and len(terms) != 1:
        raise ValueError("NOT 必须恰好包含一个子项")
    if rtype in ("AND", "OR") and not terms:
        raise ValueError(f"{rtype} 至少需要一个子项")
    return RuleSpec(type=rtype, value=expr, sub_rules=tuple(terms), line_no=line_no)


# ---------------------------------------------------------------------------
# 单行规则解析
# ---------------------------------------------------------------------------


def parse_rule_line(content: str, line_no: int = 0) -> RuleSpec:
    """解析一行非注释的 [Rule] 内容。失败抛 ``ValueError``。"""
    try:
        fields = split_top_level(content)
    except ValueError as exc:
        raise ValueError(f"第 {line_no} 行切分失败: {exc}") from exc
    rtype = fields[0].strip().upper()
    if not rtype:
        raise ValueError(f"第 {line_no} 行规则类型为空")

    if rtype in LOGIC_TYPES:
        if len(fields) != 3:
            raise ValueError(f"第 {line_no} 行 {rtype} 需要 3 列 (类型,表达式,策略): {content!r}")
        expr = _parse_logic_expr(fields[1], rtype, line_no)
        policy = normalize_policy(fields[2])
        expr.policy = policy
        expr.raw = content
        return expr

    if rtype == "RULE-SET":
        if len(fields) < 3:
            raise ValueError(f"第 {line_no} 行 RULE-SET 需要 (类型,目标,策略[,选项]): {content!r}")
        target = fields[1].strip()
        if not target:
            raise ValueError(f"第 {line_no} 行 RULE-SET 目标为空")
        policy = normalize_policy(fields[2])
        opts = tuple(o.strip().lower() for o in fields[3:] if o.strip())
        for opt in opts:
            if opt not in RULESET_OPTIONS:
                raise ValueError(f"第 {line_no} 行 RULE-SET 不允许的选项 {opt!r}")
        return RuleSpec("RULE-SET", target, policy, opts, raw=content, line_no=line_no)

    if rtype == "FINAL":
        if len(fields) < 2:
            raise ValueError(f"第 {line_no} 行 FINAL 缺少策略: {content!r}")
        policy = normalize_policy(fields[1])
        opts = tuple(o.strip().lower() for o in fields[2:] if o.strip())
        for opt in opts:
            if opt not in FINAL_OPTIONS:
                raise ValueError(f"第 {line_no} 行 FINAL 不允许的选项 {opt!r}")
        return RuleSpec("FINAL", "", policy, opts, raw=content, line_no=line_no)

    if rtype in SIMPLE_TYPES:
        if len(fields) < 3:
            raise ValueError(f"第 {line_no} 行 {rtype} 需要 (类型,值,策略[,选项]): {content!r}")
        value = fields[1].strip()
        if not value:
            raise ValueError(f"第 {line_no} 行 {rtype} 值为空")
        policy = normalize_policy(fields[2])
        opts = tuple(o.strip().lower() for o in fields[3:] if o.strip())
        if any(not o.strip() for o in fields[3:]) and fields[3:]:
            raise ValueError(f"第 {line_no} 行 {rtype} 出现空选项列")
        rule_part = f"{rtype},{value}"
        if opts:
            rule_part += "," + ",".join(opts)
        sync._parse_rule(rule_part, source_id="<profile>")  # 校验值/选项
        return RuleSpec(rtype, value, policy, opts, raw=content, line_no=line_no)

    raise ValueError(f"第 {line_no} 行不允许的规则类型 {rtype!r}: {content!r}")


# ---------------------------------------------------------------------------
# profile 解析（单 [Rule] 段 + FINAL 唯一最后）
# ---------------------------------------------------------------------------

_SECTION_RE = re.compile(r"^\[([^\]]+)\]\s*(?:(?://|#|;).*)?$")


def parse_profile(text: str) -> Tuple[List[RuleSpec], List[str]]:
    """解析 profile 文本，返回 (规则列表, 错误列表)。"""
    errors: List[str] = []
    specs: List[RuleSpec] = []
    lines = text.splitlines()

    section: Optional[str] = None
    rule_section_seen = 0
    in_rule = False

    for idx, raw in enumerate(lines, 1):
        stripped = raw.strip()
        m = _SECTION_RE.match(stripped)
        if m:
            section = m.group(1).strip()
            in_rule = section.lower() == "rule"
            if in_rule:
                rule_section_seen += 1
                if rule_section_seen > 1:
                    errors.append(f"第 {idx} 行: 出现多个 [Rule] 段（只允许一个）")
            continue

        if not in_rule:
            continue
        if not stripped:
            continue
        # 整行注释（# ; //）
        if sync._is_whole_line_comment(raw.lstrip()):
            continue
        content = sync._strip_inline_comment(raw).strip()
        if not content:
            continue
        try:
            specs.append(parse_rule_line(content, idx))
        except sync.ParseError as exc:
            errors.append(f"第 {idx} 行: 非法规则: {exc}")
        except ValueError as exc:
            errors.append(str(exc) if str(exc).startswith("第 ") else f"第 {idx} 行: {exc}")

    if rule_section_seen == 0:
        errors.append("缺少 [Rule] 段")
        return specs, errors

    # FINAL：必须存在、唯一、且位于规则最后。
    finals = [s for s in specs if s.type == "FINAL"]
    if not finals:
        errors.append("缺少 FINAL 规则（[Rule] 段必须以 FINAL 结尾）")
    elif len(finals) > 1:
        errors.append(f"FINAL 出现 {len(finals)} 次（必须唯一）")
    else:
        if specs[-1] is not finals[0]:
            errors.append("FINAL 必须是 [Rule] 段的最后一条规则")
        # 即便前面已判定，再次检查 FINAL 之后是否还有规则（可读性更好的报错）。
        idx_of_final = specs.index(finals[0])
        if idx_of_final != len(specs) - 1:
            errors.append("FINAL 之后不应再有规则")
    return specs, errors


# ---------------------------------------------------------------------------
# RULE-SET 目标解析 + 文件加载（带缓存）
# ---------------------------------------------------------------------------


def resolve_ruleset_target(target: str, root: Path) -> Tuple[str, Path]:
    """把 RULE-SET URL 解析为 (相对路径, 绝对路径)，并做安全校验。

    - 必须位于 ``CANONICAL_BASE_URL`` 下；
    - 拒绝 ``..`` / ``.`` / 空段等非法路径片段；
    - 解析后的绝对路径不得逃逸出项目根。
    """
    if not target.startswith(CANONICAL_BASE_URL):
        raise ValueError(
            f"RULE-SET URL 必须位于 {CANONICAL_BASE_URL} 之下: {target!r}"
        )
    rel = target[len(CANONICAL_BASE_URL):]
    if not rel:
        raise ValueError(f"RULE-SET URL 缺少文件路径: {target!r}")
    if "?" in rel or "#" in rel:
        raise ValueError(f"RULE-SET URL 不允许查询串或锚点: {target!r}")
    parts = rel.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise ValueError(f"RULE-SET URL 含非法路径片段（含 '..' 等）: {target!r}")
    root_resolved = root.resolve()
    resolved = (root_resolved / rel).resolve()
    if resolved != root_resolved and root_resolved not in resolved.parents:
        raise ValueError(f"RULE-SET URL 逃逸出项目根: {target!r}")
    return rel, resolved


_DECLARED_FORMAT_RE = re.compile(r"^#\s*FORMAT\s*:\s*(.+)$", re.IGNORECASE)

# 缓存：(绝对路径, mtime_ns, size) -> 已解析规则列表。
_LIST_CACHE: Dict[Tuple[str, int, int], List[sync.Rule]] = {}


def _declared_format(text: str) -> Optional[str]:
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        m = _DECLARED_FORMAT_RE.match(stripped)
        if m:
            return m.group(1).strip()
        if stripped.startswith(("#", ";", "//")):
            continue
        break
    return None


def load_rule_set_file(rel: str, resolved: Path) -> List[sync.Rule]:
    """按 Surge RULE-SET 格式读取并解析引用文件（进程内缓存）。

    明确不把文件当作 domainset/纯域名列表：整行必须能被 ``sync.parse_surge``
    解析为合法规则，否则报错（防止把 RULESET 误当 DOMAINSET，反之亦然）。
    """
    try:
        stat = resolved.stat()
    except OSError as exc:
        raise ValueError(f"RULE-SET 引用文件不可读 {rel}: {exc}") from exc
    key = (str(resolved), stat.st_mtime_ns, stat.st_size)
    cached = _LIST_CACHE.get(key)
    if cached is not None:
        return cached

    try:
        text = resolved.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise ValueError(f"RULE-SET 引用文件读取失败 {rel}: {exc}") from exc

    declared = _declared_format(text)
    if declared is not None:
        low = declared.lower().replace("_", " ").replace("-", " ")
        if "surge" not in low:
            raise ValueError(
                f"RULE-SET 引用文件 {rel} 声明的格式为 {declared!r}，"
                f"但 RULE-SET 需要 Surge RULE-SET 格式"
            )
    try:
        rules = sync.parse_surge(text, source_id=rel)
    except sync.ParseError as exc:
        raise ValueError(
            f"RULE-SET 引用文件 {rel} 不是合法的 Surge RULE-SET"
            f"（疑似 DOMAINSET/纯域名格式）: {exc}"
        ) from exc
    _LIST_CACHE[key] = rules
    return rules


# ---------------------------------------------------------------------------
# 校验入口
# ---------------------------------------------------------------------------


def validate(
    profile_text: str, root: Union[str, os.PathLike], *, check_files: bool = True
) -> ValidationResult:
    """静态校验 profile 文本。``root`` 为项目根（用于定位 RULE-SET 文件）。"""
    result = ValidationResult()
    specs, errors = parse_profile(profile_text)
    result.rules = specs
    result.errors.extend(errors)
    if not check_files:
        return result

    root_path = Path(root)
    # 逐条 RULE-SET 引用检查（同一 URL 只解析一次，缓存于 load_rule_set_file）。
    seen: set = set()
    for spec in specs:
        if spec.type != "RULE-SET":
            continue
        target = spec.value
        if target.upper() in BUILTIN_RULE_SETS:
            continue
        try:
            rel, resolved = resolve_ruleset_target(target, root_path)
        except ValueError as exc:
            result.errors.append(f"第 {spec.line_no} 行 RULE-SET: {exc}")
            continue
        if not resolved.is_file():
            result.errors.append(
                f"第 {spec.line_no} 行 RULE-SET 引用文件不存在: {rel}"
            )
            continue
        if rel in seen:
            continue
        seen.add(rel)
        try:
            load_rule_set_file(rel, resolved)
        except ValueError as exc:
            result.errors.append(f"第 {spec.line_no} 行 RULE-SET: {exc}")
    return result


# ---------------------------------------------------------------------------
# 静态匹配器（明确不完整，仅用于顺序冒烟）
# ---------------------------------------------------------------------------


def _context_value(context: Mapping, key: str) -> Optional[str]:
    value = context.get(key)
    if value is None:
        return None
    return str(value)


def _ctx_ip(context: Mapping) -> Optional[ipaddress._BaseAddress]:
    raw = _context_value(context, "ip")
    if raw is None:
        return None
    try:
        return ipaddress.ip_address(raw.strip())
    except ValueError:
        return None


def _is_builtin_lan(context: Mapping) -> bool:
    ip = _ctx_ip(context)
    if ip is None:
        return False
    return any(ip in net for net in LAN_NETWORKS)


def _match_domain(value: str, hostname: str) -> bool:
    return hostname.lower() == value.lower()


def _match_domain_suffix(value: str, hostname: str) -> bool:
    h = hostname.lower().rstrip(".")
    v = value.lower()
    return h == v or h.endswith("." + v)


def _match_keyword(value: str, hostname: str) -> bool:
    return value.lower() in hostname.lower()


def _wildcard_to_regex(pattern: str) -> "re.Pattern[str]":
    out: List[str] = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        elif ch == "[":
            j = i + 1
            while j < len(pattern) and pattern[j] != "]":
                j += 1
            cls = pattern[i + 1:j]
            out.append("[" + cls + "]")
            i = j
        else:
            out.append(re.escape(ch))
        i += 1
    return re.compile("^" + "".join(out) + "$", re.IGNORECASE)


def _match_process(value: str, process: str) -> bool:
    """Surge process matching is case-sensitive; bundle mode needs a real path."""
    val = value.strip()
    proc = process.strip()
    if not val or not proc:
        return False
    if val.startswith("/"):
        if not proc.startswith("/"):
            return False
        if val.endswith("/"):
            return proc.startswith(val)
        return fnmatch.fnmatchcase(proc, val)
    return fnmatch.fnmatchcase(os.path.basename(proc), val)


def _match_simple_rule(
    rtype: str, value: str, options: Sequence[str], context: Mapping
) -> bool:
    hostname = _context_value(context, "hostname")
    if rtype == "DOMAIN":
        return bool(hostname) and _match_domain(value, hostname)
    if rtype == "DOMAIN-SUFFIX":
        return bool(hostname) and _match_domain_suffix(value, hostname)
    if rtype == "DOMAIN-KEYWORD":
        return bool(hostname) and _match_keyword(value, hostname)
    if rtype == "DOMAIN-WILDCARD":
        return bool(hostname) and bool(_wildcard_to_regex(value).match(hostname))
    if rtype == "PROCESS-NAME":
        proc = _context_value(context, "process")
        return bool(proc) and _match_process(value, proc)
    if rtype in ("IP-CIDR", "IP-CIDR6"):
        ip = _ctx_ip(context)
        if ip is None:
            return False
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return False
        return ip.version == net.version and ip in net
    if rtype == "PROTOCOL":
        proto = _context_value(context, "protocol")
        return bool(proto) and proto.upper() == value.upper()
    if rtype == "DEST-PORT":
        port = context.get("port")
        if port is None:
            return False
        try:
            port_i = int(port)
        except (TypeError, ValueError):
            return False
        v = value.strip()
        if "-" in v:
            a, b = v.split("-", 1)
            try:
                return int(a) <= port_i <= int(b)
            except ValueError:
                return False
        try:
            return port_i == int(v)
        except ValueError:
            return False
    # IP-ASN / USER-AGENT / URL-REGEX 等：无对应上下文，明确不匹配。
    return False


def _eval_logic(spec: RuleSpec, context: Mapping, root: Path) -> bool:
    if spec.type == "AND":
        return bool(spec.sub_rules) and all(_match_spec(t, context, root) for t in spec.sub_rules)
    if spec.type == "OR":
        return any(_match_spec(t, context, root) for t in spec.sub_rules)
    if spec.type == "NOT":
        return bool(spec.sub_rules) and not _match_spec(spec.sub_rules[0], context, root)
    return False


def _match_spec(spec: RuleSpec, context: Mapping, root: Path) -> bool:
    if spec.type in LOGIC_TYPES:
        return _eval_logic(spec, context, root)
    return _match_simple_rule(spec.type, spec.value, spec.options, context)


def _match_rule_set(spec: RuleSpec, context: Mapping, root: Path) -> bool:
    target = spec.value
    if target.upper() in BUILTIN_RULE_SETS:
        if target.upper() == "LAN":
            return _is_builtin_lan(context)
        return False
    rel, resolved = resolve_ruleset_target(target, root)
    rules = load_rule_set_file(rel, resolved)
    for rule in rules:
        if _match_simple_rule(rule.type, rule.value, rule.options, context):
            return True
    return False


def _as_rules(profile: Union[str, os.PathLike, Sequence[RuleSpec]]) -> List[RuleSpec]:
    if isinstance(profile, Sequence) and not isinstance(profile, (str, bytes, os.PathLike)):
        return list(profile)
    if isinstance(profile, os.PathLike):
        return parse_profile(Path(profile).read_text(encoding="utf-8-sig"))[0]
    text = str(profile)
    path = Path(text)
    if "\n" not in text and path.is_file():
        return parse_profile(path.read_text(encoding="utf-8-sig"))[0]
    return parse_profile(text)[0]


def evaluate(
    profile: Union[str, os.PathLike, Sequence[RuleSpec]],
    context: Mapping,
    root: Union[str, os.PathLike],
) -> Optional[str]:
    """按规则顺序做静态匹配，返回命中的策略名；无匹配返回 ``None``。

    仅支持无 DNS 的静态匹配（DOMAIN/*、PROCESS-NAME、IP 网段、AND/OR、
    内置 LAN、RULE-SET、FINAL）。``IP-ASN`` / ``USER-AGENT`` / ``URL-REGEX``
    在没有相应上下文时一律不匹配，不做网络或 ASN 查询。
    """
    rules = _as_rules(profile)
    root_path = Path(root)
    for spec in rules:
        if spec.type == "FINAL":
            return spec.policy
        if spec.type == "RULE-SET":
            if _match_rule_set(spec, context, root_path):
                return spec.policy
            continue
        if _match_spec(spec, context, root_path):
            return spec.policy
    return None


# ---------------------------------------------------------------------------
# CLI 冒烟场景（针对实际模板）
# ---------------------------------------------------------------------------


# (说明, context, 期望策略)
SMOKE_SCENARIOS: Tuple[Tuple[str, Dict[str, object], str], ...] = (
    ("100.96.0.1+Muse => DIRECT", {"ip": "100.96.0.1", "process": "/Applications/Muse.app/Contents/MacOS/Muse"}, "DIRECT"),
    (
        "192.168.1.20 UDP443+Muse => DIRECT",
        {"ip": "192.168.1.20", "protocol": "UDP", "port": 443, "process": "/Applications/Muse.app/Contents/MacOS/Muse"},
        "DIRECT",
    ),
    ("0.0.0.0 => REJECT", {"ip": "0.0.0.0"}, "REJECT"),
    ("Telegram到224.0.0.1 => REJECT", {"process": "Telegram", "ip": "224.0.0.1"}, "REJECT"),
    (
        "普通公网UDP443+Muse => REJECT-NO-DROP",
        {"ip": "8.8.8.8", "protocol": "UDP", "port": 443, "process": "/Applications/Muse.app/Contents/MacOS/Muse"},
        "REJECT-NO-DROP",
    ),
    (
        "Muse访问api.openai.com TCP443 => 美国节点",
        {"hostname": "api.openai.com", "protocol": "TCP", "port": 443, "process": "/Applications/Muse.app/Contents/MacOS/Muse"},
        "🇺🇲 美国节点",
    ),
    (
        "非Muse api.openai.com => ChatGPT",
        {"hostname": "api.openai.com", "protocol": "TCP", "port": 443},
        "ChatGPT",
    ),
    ("api.github.com => 节点选择", {"hostname": "api.github.com", "protocol": "TCP", "port": 443}, "节点选择"),
    (
        "api.githubcopilot.com => 智能助理",
        {"hostname": "api.githubcopilot.com", "protocol": "TCP", "port": 443},
        "智能助理",
    ),
    ("grok.com => 智能助理", {"hostname": "grok.com", "protocol": "TCP", "port": 443}, "智能助理"),
    ("api.deepseek.com => DIRECT", {"hostname": "api.deepseek.com", "protocol": "TCP", "port": 443}, "DIRECT"),
    ("open.spotify.com => Spotify", {"hostname": "open.spotify.com", "protocol": "TCP", "port": 443}, "Spotify"),
    (
        "voice.google.com => GoogleVoice",
        {"hostname": "voice.google.com", "protocol": "TCP", "port": 443},
        "GoogleVoice",
    ),
    ("www.baidu.com（给定国内 IP） => DIRECT", {"hostname": "www.baidu.com", "ip": "180.101.49.12", "protocol": "TCP", "port": 443}, "DIRECT"),
)


def run_smoke(rules: Sequence[RuleSpec], root: Path) -> int:
    """执行固定冒烟场景并打印报告；返回 0 表示全部符合，1 表示有不符。"""
    failures = 0
    print("[smoke] 顺序冒烟（静态匹配，非真实 Surge）：")
    for desc, context, expected in SMOKE_SCENARIOS:
        actual = evaluate(rules, context, root)
        ok = actual == expected
        if not ok:
            failures += 1
        mark = "PASS" if ok else "FAIL"
        detail = f"期望 {expected!r} / 实际 {actual!r}"
        print(f"  [{mark}] {desc}  ->  {detail}")
    if failures:
        print(f"[smoke] {failures} 个场景不符合预期。")
        return 1
    print("[smoke] 全部场景符合预期。")
    return 0


def _default_root() -> Path:
    return Path(__file__).resolve().parent.parent


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="离线校验 Surge [Rule] 段配置，并可跑关键规则顺序冒烟。",
    )
    parser.add_argument(
        "profile",
        nargs="?",
        default=None,
        help="待校验的 profile 文件（默认 <root>/examples/Rule.template.conf）",
    )
    parser.add_argument(
        "--root",
        default=None,
        help="项目根目录（默认脚本所在仓库根）",
    )
    smoke_group = parser.add_mutually_exclusive_group()
    smoke_group.add_argument("--smoke", action="store_true", help="校验通过后执行顺序冒烟")
    smoke_group.add_argument(
        "--no-smoke", action="store_true", help="即使校验默认模板也不执行顺序冒烟"
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    root = Path(args.root).resolve() if args.root else _default_root()
    if args.profile:
        profile_path = Path(args.profile)
    else:
        profile_path = root / "examples" / "Rule.template.conf"

    if not profile_path.is_file():
        print(f"[validate] 失败: profile 文件不存在: {profile_path}", file=sys.stderr)
        return 1
    try:
        text = profile_path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        print(f"[validate] 失败: 无法读取 profile: {exc}", file=sys.stderr)
        return 1

    result = validate(text, root)
    if result.errors:
        print(f"[validate] 失败（{len(result.errors)} 个错误）：", file=sys.stderr)
        for err in result.errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print(f"[validate] 通过：{profile_path}（{len(result.rules)} 条规则）")

    is_default = profile_path.resolve() == (root / "examples" / "Rule.template.conf").resolve()
    do_smoke = args.smoke or (is_default and not args.no_smoke)
    if do_smoke:
        return run_smoke(result.rules, root)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
