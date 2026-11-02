#!/usr/bin/env python3
"""安全、确定性的 Surge 规则同步引擎（仅使用 Python 标准库）。

从多个活跃 GitHub 上游获取规则，按服务专属域名白名单筛选，生成独立的
Surge RULE-SET `.list` 文件与稳定的 `rules/manifest.json`。

设计要点：
- 抓取或解析失败时不写入任何文件（fail closed）：网络错误、HTML/空内容、解析失败
  都会在写盘之前中止本轮同步。
- 写入失败不保证跨多个文件的事务性：单个文件使用临时文件 + 原子替换，不做复杂
  回滚；若多文件中途出现 OS 写盘错误，可能已替换前面的文件。仓库侧依赖 CI job
  失败即不提交来规避半更新，脚本本身不承诺多文件回滚。
- 输出稳定：不写入当前时间，write-if-changed，原子替换。
- 纯标准库实现，无第三方依赖。

用法::

    python3 scripts/sync_rules.py [--config PATH] [--check] [--validate] [--output-root PATH]

退出码：
    0  成功 / --check 无变更 / --validate 通过
    1  失败（配置错误、网络错误、校验失败等）
    2  --check 检测到需要更新
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

SCHEMA_VERSION = 1
CONFIG_VERSION = 1
MANIFEST_REL_PATH = "rules/manifest.json"

# 允许出现在规则文件中的全部类型。
VALID_RULE_TYPES: Tuple[str, ...] = (
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-WILDCARD",
    "IP-CIDR",
    "IP-CIDR6",
    "IP-ASN",
    "USER-AGENT",
    "PROCESS-NAME",
    "URL-REGEX",
)
_TYPE_ORDER = {t: i for i, t in enumerate(VALID_RULE_TYPES)}

# 关键词域名类型（无选项）。
_DOMAIN_TYPES = ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD")
# DOMAIN / DOMAIN-SUFFIX 允许的扩展选项白名单（不含策略列）。
_DOMAIN_OPTIONS = ("extended-matching",)
# filtered 模式下允许自动导入的上游类型。
_FILTERED_SOURCE_TYPES = ("DOMAIN", "DOMAIN-SUFFIX")
# local_rules 允许的类型（人工维护证据）。
_LOCAL_ALLOWED_TYPES = ("DOMAIN", "DOMAIN-SUFFIX", "PROCESS-NAME")
# IP 规则（IP-CIDR / IP-CIDR6 / IP-ASN）允许的选项白名单（不含策略列）。
_IP_OPTIONS = ("no-resolve", "extended-matching")
# 支持的 source 文本格式。
_SOURCE_FORMATS = ("surge", "domainset", "geosite")

# local_rules 中拒绝的泛进程名（无路径的裸进程名）。
_GENERIC_PROCESS_NAMES = frozenset(
    {
        "node",
        "nodejs",
        "python",
        "python2",
        "python3",
        "ruby",
        "java",
        "bash",
        "sh",
        "zsh",
        "perl",
        "php",
        "curl",
        "wget",
    }
)

# 输出路径禁止落在这些受保护目录中。
_RESERVED_TOP_DIRS = frozenset({"scripts", "config", "tests", ".git"})

# 下载相关。
DEFAULT_TIMEOUT = 20.0
FETCH_ATTEMPTS = 3
FETCH_BACKOFF = 0.5  # 秒，指数退避基数
MAX_CONCURRENCY = 6

_LABEL_RE = re.compile(r"^[a-z0-9_-]+$")
_ASN_RE = re.compile(r"^(?:AS)?\d+$")
_HTML_HINTS = ("<!doctype", "<html", "<head", "<body", "<?xml")


# ---------------------------------------------------------------------------
# 异常
# ---------------------------------------------------------------------------


class SyncError(Exception):
    """同步流程中的通用错误（配置、抓取、解析、写入等）。"""


class ConfigError(SyncError):
    """配置非法。"""


class ParseError(SyncError):
    """上游内容解析失败。"""


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    type: str
    value: str
    options: Tuple[str, ...] = ()

    def key(self) -> str:
        """规范化规则字符串（也是去重 key）。"""
        base = f"{self.type},{self.value}"
        if self.options:
            base += "," + ",".join(self.options)
        return base

    def render(self) -> str:
        return self.key()


# ---------------------------------------------------------------------------
# 通用辅助
# ---------------------------------------------------------------------------


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _decode_bytes(data: bytes, source_id: str) -> str:
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:  # pragma: no cover - 明确报错
        raise ParseError(f"source '{source_id}' 不是合法的 UTF-8 文本: {exc}") from exc


def _looks_like_html(text: str) -> bool:
    head = text.lstrip("\ufeff \t\r\n").lower()
    if head.startswith(_HTML_HINTS):
        return True
    window = text[:1024].lower()
    return "<html" in window or "<!doctype" in window


def _validate_domain(value: str, *, allow_wildcard: bool = False) -> str:
    """校验并规范化一个域名，返回小写形式。

    支持合法单标签 TLD（如 ``cn`` / ``msleep`` / 品牌 gTLD ``apple``），这与
    Surge 把 ``DOMAIN-SUFFIX,cn`` 视作对整个 ``.cn`` 后缀的匹配一致。
    """
    if not isinstance(value, str):
        raise ParseError(f"域名必须是字符串: {value!r}")
    v = value.strip().lower()
    if not v:
        raise ParseError("空域名")
    if "/" in v:
        raise ParseError(f"非法域名（含路径 '/'）: {value!r}")
    if any(c in v for c in (":", "#", ";", "\\", " ", "\t", ",")):
        raise ParseError(f"非法域名（含非法字符）: {value!r}")
    if "*" in v and not allow_wildcard:
        raise ParseError(f"非法域名（含通配符）: {value!r}")
    if v.startswith(".") or v.endswith(".") or ".." in v:
        raise ParseError(f"非法域名（点位置错误）: {value!r}")
    if len(v) > 253:
        raise ParseError(f"域名过长: {value!r}")
    labels = v.split(".")
    if len(labels) == 1:
        # 单标签 TLD：合法，但至少两个字符，且不以连字符开头/结尾
        # （TLD 不会只有 1 个字符；xn-- 形式的 IDN TLD 仍是合法 ASCII 标签）。
        label = labels[0]
        if (
            len(label) < 2
            or len(label) > 63
            or not _LABEL_RE.match(label)
            or label.startswith("-")
            or label.endswith("-")
        ):
            raise ParseError(f"非法单标签域名 {value!r}")
        return v
    for label in labels:
        if not label or len(label) > 63 or not _LABEL_RE.match(label):
            if allow_wildcard and label and set(label) <= {"*"}:
                continue
            raise ParseError(f"非法域名标签 {label!r}: {value!r}")
    return v


# DOMAIN-WILDCARD 标签允许 * / ? / [] 与常规域名标签字符混合（如 ads-*.foo.com）。
_WILDCARD_LABEL_RE = re.compile(r"^[a-z0-9_*?\[\]-]+$")


def _validate_wildcard_domain(value: str) -> str:
    """校验 Surge ``DOMAIN-WILDCARD`` 值，支持 *、? 与字符类 [] 混合。

    真实上游形如 ``ads-*.tiktok.com``、``beacons*.gvt?.com``、``*.ad.*.host``，
    不能因含通配符就把合法规则判为非法。只拒绝会破坏规则行语法的字符。
    """
    if not isinstance(value, str):
        raise ParseError(f"DOMAIN-WILDCARD 必须是字符串: {value!r}")
    v = value.strip().lower()
    if not v:
        raise ParseError("空 DOMAIN-WILDCARD")
    if "/" in v:
        raise ParseError(f"非法 DOMAIN-WILDCARD（含路径 '/'）: {value!r}")
    if any(c in v for c in (":", "#", ";", "\\", " ", "\t", ",")):
        raise ParseError(f"非法 DOMAIN-WILDCARD（含非法字符）: {value!r}")
    if v.startswith(".") or v.endswith(".") or ".." in v:
        raise ParseError(f"非法 DOMAIN-WILDCARD（点位置错误）: {value!r}")
    if len(v) > 253:
        raise ParseError(f"DOMAIN-WILDCARD 过长: {value!r}")
    labels = v.split(".")
    if len(labels) < 2:
        raise ParseError(f"DOMAIN-WILDCARD 域名缺少顶级域: {value!r}")
    for label in labels:
        if not label or len(label) > 63 or not _WILDCARD_LABEL_RE.match(label):
            raise ParseError(f"非法通配标签 {label!r}: {value!r}")
        if label.count("[") != label.count("]"):
            raise ParseError(f"DOMAIN-WILDCARD 字符类括号不匹配: {value!r}")
    return v


def _validate_keyword(value: str) -> str:
    """校验 DOMAIN-KEYWORD。Surge 允许任意非空关键词（含短词如 ad/ads、带点如 .foo.）。"""
    v = value.strip()
    if not v:
        raise ParseError("空 DOMAIN-KEYWORD")
    # 不再用长度 heuristic 把合法的短广告关键词（ad/ads/xn 等）一律拒绝；
    # 只拒绝会破坏规则行语法的字符。
    if any(c in v for c in ("/", "\\", "#", ";", ",")) or any(c.isspace() for c in v):
        raise ParseError(f"非法 DOMAIN-KEYWORD: {value!r}")
    return v.lower()


def _validate_ip(value: str, rule_type: str) -> str:
    v = value.strip()
    try:
        net = ipaddress.ip_network(v, strict=False)
    except ValueError as exc:
        raise ParseError(f"非法 {rule_type} 网段 {value!r}: {exc}") from exc
    if rule_type == "IP-CIDR" and net.version != 4:
        raise ParseError(f"IP-CIDR 只允许 IPv4: {value!r}")
    if rule_type == "IP-CIDR6" and net.version != 6:
        raise ParseError(f"IP-CIDR6 只允许 IPv6: {value!r}")
    return str(net)


# ---------------------------------------------------------------------------
# 注释剥离与规则解析
# ---------------------------------------------------------------------------


def _strip_inline_comment(line: str) -> str:
    """去掉行尾注释。仅当 # ; // 前有空白时才视为注释。

    这样 `https://host/path` 中的 `//` 不会被误当作注释。
    """
    best: Optional[int] = None
    for marker in ("#", ";", "//"):
        idx = 0
        while True:
            i = line.find(marker, idx)
            if i == -1:
                break
            if i > 0 and line[i - 1] in " \t":
                if best is None or i < best:
                    best = i
                break
            idx = i + 1
    if best is not None:
        return line[:best].rstrip()
    return line.rstrip()


def _is_whole_line_comment(stripped: str) -> bool:
    return stripped.startswith("#") or stripped.startswith(";") or stripped.startswith("//")


def _parse_rule(content: str, *, source_id: str = "<inline>") -> Rule:
    fields = [f.strip() for f in content.split(",")]
    raw_type = fields[0].strip()
    rtype = raw_type.upper()
    if not raw_type:
        raise ParseError(f"[{source_id}] 空规则类型: {content!r}")
    if rtype not in VALID_RULE_TYPES:
        raise ParseError(f"[{source_id}] 未知规则类型 {raw_type!r}: {content!r}")

    def need_two() -> str:
        if len(fields) != 2:
            raise ParseError(f"[{source_id}] 规则字段数量错误: {content!r}")
        return fields[1]

    if rtype in ("DOMAIN", "DOMAIN-SUFFIX"):
        if len(fields) < 2:
            raise ParseError(f"[{source_id}] {rtype} 缺少域名: {content!r}")
        value = _validate_domain(fields[1])
        raw_opts = fields[2:]
        if any(not o.strip() for o in raw_opts):
            raise ParseError(f"[{source_id}] {rtype} 出现空选项列: {content!r}")
        opts = tuple(o.strip().lower() for o in raw_opts)
        for opt in opts:
            if opt not in _DOMAIN_OPTIONS:
                raise ParseError(f"[{source_id}] {rtype} 不允许的选项/策略列 {opt!r}: {content!r}")
        return Rule(rtype, value, opts)
    if rtype == "DOMAIN-WILDCARD":
        value = _validate_wildcard_domain(need_two())
        return Rule(rtype, value)
    if rtype == "DOMAIN-KEYWORD":
        return Rule(rtype, _validate_keyword(need_two()))
    if rtype in ("IP-CIDR", "IP-CIDR6"):
        if len(fields) < 2:
            raise ParseError(f"[{source_id}] {rtype} 缺少网段: {content!r}")
        value = _validate_ip(fields[1], rtype)
        opts = tuple(o.strip().lower() for o in fields[2:] if o.strip())
        for opt in opts:
            if opt not in _IP_OPTIONS:
                raise ParseError(f"[{source_id}] {rtype} 不允许的选项/策略列 {opt!r}: {content!r}")
        return Rule(rtype, value, opts)
    if rtype == "IP-ASN":
        if len(fields) < 2:
            raise ParseError(f"[{source_id}] IP-ASN 缺少 ASN: {content!r}")
        value = fields[1].strip().upper()
        if not _ASN_RE.match(value):
            raise ParseError(f"[{source_id}] 非法 IP-ASN {fields[1]!r}: {content!r}")
        opts = tuple(o.strip().lower() for o in fields[2:] if o.strip())
        for opt in opts:
            if opt not in _IP_OPTIONS:
                raise ParseError(f"[{source_id}] IP-ASN 不允许的选项/策略列 {opt!r}: {content!r}")
        return Rule(rtype, value, opts)
    if rtype == "PROCESS-NAME":
        value = need_two()
        if not value:
            raise ParseError(f"[{source_id}] 空 PROCESS-NAME: {content!r}")
        return Rule(rtype, value)
    if rtype == "USER-AGENT":
        value = ",".join(fields[1:]).strip()
        if not value:
            raise ParseError(f"[{source_id}] 空 USER-AGENT: {content!r}")
        return Rule(rtype, value)
    if rtype == "URL-REGEX":
        value = ",".join(fields[1:]).strip()
        if not value:
            raise ParseError(f"[{source_id}] 空 URL-REGEX: {content!r}")
        try:
            re.compile(value)
        except re.error as exc:
            raise ParseError(f"[{source_id}] 非法 URL-REGEX {value!r}: {exc}") from exc
        return Rule(rtype, value)
    raise ParseError(f"[{source_id}] 未处理的规则类型 {rtype!r}: {content!r}")  # pragma: no cover


def parse_surge(text: str, *, source_id: str) -> List[Rule]:
    text = text.lstrip("\ufeff")
    if _looks_like_html(text):
        raise ParseError(f"source '{source_id}' 返回 HTML 而非规则文本")
    rules: List[Rule] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if _is_whole_line_comment(line.lstrip()):
            continue
        content = _strip_inline_comment(line).strip()
        if not content:
            continue
        rules.append(_parse_rule(content, source_id=source_id))
    if not rules:
        raise ParseError(f"source '{source_id}' 无有效规则（空或仅注释）")
    return rules


def parse_domainset(text: str, *, source_id: str) -> List[Rule]:
    text = text.lstrip("\ufeff")
    if _looks_like_html(text):
        raise ParseError(f"source '{source_id}' 返回 HTML 而非 domainset")
    rules: List[Rule] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if _is_whole_line_comment(line.lstrip()):
            continue
        content = _strip_inline_comment(line).strip()
        if not content:
            continue
        if content.startswith("."):
            value = _validate_domain(content[1:])
            rules.append(Rule("DOMAIN-SUFFIX", value))
        else:
            value = _validate_domain(content)
            rules.append(Rule("DOMAIN", value))
    if not rules:
        raise ParseError(f"source '{source_id}' domainset 无有效规则（空或仅注释）")
    return rules


def parse_geosite(text: str, *, source_id: str) -> List[Rule]:
    """解析 MetaCubeX / geosite 文本（与 Surge domainset 严格区分）。

    只接受两种形态：
    - 普通域名 ``foo.com``            -> ``DOMAIN,foo.com``
    - 后缀标记 ``+.foo.com``          -> ``DOMAIN-SUFFIX,foo.com``

    明确不接受 Surge domainset 的前导点 ``.foo.com``（那是 domainset 语义，不能与
    ``+.foo.com`` 混用），也不接受 ``full:`` / ``keyword:`` / ``regexp:`` 等带前缀或
    正则格式：这些都会 fail closed，避免把未知语义静默当成域名。
    """
    text = text.lstrip("\ufeff")
    if _looks_like_html(text):
        raise ParseError(f"source '{source_id}' 返回 HTML 而非 geosite")
    rules: List[Rule] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if _is_whole_line_comment(line.lstrip()):
            continue
        content = _strip_inline_comment(line).strip()
        if not content:
            continue
        if content.startswith("+."):
            value = _validate_domain(content[2:])
            rules.append(Rule("DOMAIN-SUFFIX", value))
        elif content.startswith((".", "+")):
            # 前导点属于 domainset 语义，或 + 后缺点的非法写法 —— 一律拒绝。
            raise ParseError(
                f"[{source_id}] 非法 geosite 行 {content!r}（仅支持 'domain' 或 '+.domain'）"
            )
        elif ":" in content:
            # regexp:/full:/keyword:/include: 等未知前缀或正则格式。
            raise ParseError(f"[{source_id}] 不支持的 geosite 前缀/正则格式: {content!r}")
        else:
            value = _validate_domain(content)
            rules.append(Rule("DOMAIN", value))
    if not rules:
        raise ParseError(f"source '{source_id}' geosite 无有效规则（空或仅注释）")
    return rules


def parse_local_rule(text: str) -> Rule:
    rule = _parse_rule(text, source_id="local_rules")
    if rule.type not in _LOCAL_ALLOWED_TYPES:
        raise ConfigError(f"local_rules 不允许类型 {rule.type}: {text!r}")
    if rule.type == "PROCESS-NAME":
        name = rule.value.strip()
        if "/" not in name and name.lower() in _GENERIC_PROCESS_NAMES:
            raise ConfigError(
                f"local_rules 拒绝泛进程 {name!r}（如 node/python），请使用具体可执行文件或 .app 包路径: {text!r}"
            )
    return rule


# ---------------------------------------------------------------------------
# 配置加载与校验
# ---------------------------------------------------------------------------


def _default_project_root(config_path: Path) -> Path:
    cfg = config_path.resolve()
    if cfg.parent.name == "config":
        return cfg.parent.parent
    return cfg.parent


def _validate_output_path(path: str, project_root: Path) -> str:
    if not isinstance(path, str) or not path.strip():
        raise ConfigError(f"输出路径必须是非空字符串: {path!r}")
    if "\\" in path:
        raise ConfigError(f"输出路径不允许反斜杠: {path!r}")
    if path.startswith("/") or re.match(r"^[A-Za-z]:", path):
        raise ConfigError(f"输出路径必须是相对路径: {path!r}")
    parts = path.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise ConfigError(f"输出路径包含非法片段: {path!r}")
    if not path.endswith(".list"):
        raise ConfigError(f"输出文件必须以 .list 结尾: {path!r}")
    if parts[0] in _RESERVED_TOP_DIRS:
        raise ConfigError(f"输出路径不得位于受保护目录 {parts[0]!r}: {path!r}")
    root = project_root.resolve()
    target = (root / path).resolve()
    if target != root and root not in target.parents:
        raise ConfigError(f"输出路径逃逸出项目根: {path!r}")
    return path


def validate_config(config: Mapping, project_root: Path) -> None:
    if not isinstance(config, dict):
        raise ConfigError("配置根必须是 JSON 对象")
    if config.get("version") != CONFIG_VERSION:
        raise ConfigError(f"不支持的配置 version: {config.get('version')!r} (期望 {CONFIG_VERSION})")

    sources = config.get("sources")
    services = config.get("services")
    if not isinstance(sources, dict):
        raise ConfigError("config.sources 必须是对象（可为空，仅供 local_rules 的服务）")
    if not isinstance(services, dict) or not services:
        raise ConfigError("config.services 必须是非空对象")

    # 校验 sources
    for sid, src in sources.items():
        if not isinstance(sid, str) or not sid:
            raise ConfigError(f"source id 非法: {sid!r}")
        if not isinstance(src, dict):
            raise ConfigError(f"source '{sid}' 必须是对象")
        url = src.get("url")
        if not isinstance(url, str) or not re.match(r"^https?://", url):
            raise ConfigError(f"source '{sid}' 的 url 必须是 http(s) URL: {url!r}")
        fmt = src.get("format")
        if fmt not in _SOURCE_FORMATS:
            raise ConfigError(
                f"source '{sid}' 的 format 必须是 {', '.join(repr(f) for f in _SOURCE_FORMATS)} 之一: {fmt!r}"
            )
        for opt_key in ("license_url", "repository", "path"):
            if opt_key in src and src[opt_key] is not None and not isinstance(src[opt_key], str):
                raise ConfigError(f"source '{sid}' 的 {opt_key} 必须是字符串")

    # 校验 services
    outputs_seen: Dict[str, str] = {}
    for svc_id, svc in services.items():
        if not isinstance(svc_id, str) or not svc_id:
            raise ConfigError(f"service id 非法: {svc_id!r}")
        if not isinstance(svc, dict):
            raise ConfigError(f"service '{svc_id}' 必须是对象")
        name = svc.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ConfigError(f"service '{svc_id}' 缺少 name")
        mode = svc.get("mode")
        if mode not in ("filtered", "mirror"):
            raise ConfigError(f"service '{svc_id}' 的 mode 必须是 'filtered' 或 'mirror': {mode!r}")

        output = svc.get("output")
        _validate_output_path(output, project_root)
        if output == MANIFEST_REL_PATH:
            raise ConfigError(f"service '{svc_id}' 输出不得覆盖 manifest: {output!r}")
        low = output.lower()
        if low in outputs_seen:
            raise ConfigError(
                f"输出路径重复或大小写冲突: {output!r} 与 {outputs_seen[low]!r}"
            )
        outputs_seen[low] = output

        list_sources = svc.get("listSources", [])
        if not isinstance(list_sources, list) or any(not isinstance(s, str) for s in list_sources):
            raise ConfigError(f"service '{svc_id}' 的 listSources 必须是字符串数组")
        for s in list_sources:
            if s not in sources:
                raise ConfigError(f"service '{svc_id}' 引用了未知 source: {s!r}")
        if len(set(list_sources)) != len(list_sources):
            raise ConfigError(f"service '{svc_id}' 的 listSources 有重复项")

        local_rules = svc.get("local_rules", [])
        if not isinstance(local_rules, list) or any(not isinstance(r, str) for r in local_rules):
            raise ConfigError(f"service '{svc_id}' 的 local_rules 必须是字符串数组")
        for r in local_rules:
            parse_local_rule(r)  # 会抛出 ConfigError

        if not list_sources and not local_rules:
            raise ConfigError(
                f"service '{svc_id}' 既无 listSources 也无 local_rules，无法产生规则"
            )

        suffix_key_present = "allowed_suffixes" in svc and bool(svc.get("allowed_suffixes"))
        domain_key_present = "allowed_domains" in svc and bool(svc.get("allowed_domains"))
        if mode == "mirror":
            if suffix_key_present or domain_key_present:
                raise ConfigError(
                    f"service '{svc_id}' 为 mirror 模式，不允许 allowed_suffixes/allowed_domains"
                )
        else:  # filtered
            suffixes = svc.get("allowed_suffixes", [])
            domains = svc.get("allowed_domains", [])
            if not isinstance(suffixes, list) or any(not isinstance(x, str) for x in suffixes):
                raise ConfigError(f"service '{svc_id}' 的 allowed_suffixes 必须是字符串数组")
            if not isinstance(domains, list) or any(not isinstance(x, str) for x in domains):
                raise ConfigError(f"service '{svc_id}' 的 allowed_domains 必须是字符串数组")
            if not suffixes and not domains and not local_rules:
                raise ConfigError(
                    f"filtered service '{svc_id}' 需要 allowed_suffixes/allowed_domains 或 local_rules"
                )
            normalized_suffixes = set()
            for s in suffixes:
                ns = _validate_domain(s.lstrip("."))
                if ns in normalized_suffixes:
                    raise ConfigError(f"service '{svc_id}' 的 allowed_suffixes 有重复: {s!r}")
                normalized_suffixes.add(ns)
            normalized_domains = set()
            for d in domains:
                nd = _validate_domain(d)
                if nd in normalized_domains:
                    raise ConfigError(f"service '{svc_id}' 的 allowed_domains 有重复: {d!r}")
                normalized_domains.add(nd)

        description = svc.get("description")
        if description is not None and not isinstance(description, str):
            raise ConfigError(f"service '{svc_id}' 的 description 必须是字符串")
        evidence = svc.get("evidence", [])
        if not isinstance(evidence, list) or any(not isinstance(e, str) for e in evidence):
            raise ConfigError(f"service '{svc_id}' 的 evidence 必须是字符串数组")


def load_config(config_path: Path) -> dict:
    path = Path(config_path)
    if not path.is_file():
        raise ConfigError(f"配置文件不存在: {path}")
    try:
        with path.open("r", encoding="utf-8") as fh:
            config = json.load(fh)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"配置文件不是合法 JSON: {exc}") from exc
    return config


def load_and_validate(config_path: Path, project_root: Path) -> dict:
    config = load_config(config_path)
    validate_config(config, project_root)
    return config


# ---------------------------------------------------------------------------
# 抓取
# ---------------------------------------------------------------------------


def _http_get(url: str, timeout: float = DEFAULT_TIMEOUT) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "surge-rules-sync/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        status = getattr(resp, "status", 200)
        if status != 200:
            raise SyncError(f"HTTP {status} for {url}")
        return resp.read()


def fetch_source_bytes(source_id: str, source: Mapping, timeout: float = DEFAULT_TIMEOUT) -> bytes:
    url = source["url"]
    last: Optional[Exception] = None
    for attempt in range(FETCH_ATTEMPTS):
        try:
            data = _http_get(url, timeout=timeout)
            if not isinstance(data, (bytes, bytearray)):
                raise SyncError(f"source '{source_id}' 返回非字节数据")
            return bytes(data)
        except Exception as exc:  # noqa: BLE001 - 统一重试
            last = exc
            if attempt < FETCH_ATTEMPTS - 1:
                time.sleep(FETCH_BACKOFF * (2 ** attempt))
    raise SyncError(f"source '{source_id}' 抓取失败（{FETCH_ATTEMPTS} 次）: {last!r}")


def fetch_all_sources(
    config: Mapping, timeout: float = DEFAULT_TIMEOUT
) -> Dict[str, bytes]:
    sources = config["sources"]
    used = sorted({sid for svc in config["services"].values() for sid in svc.get("listSources", [])})
    if not used:
        return {}
    results: Dict[str, bytes] = {}
    workers = min(MAX_CONCURRENCY, len(used))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(fetch_source_bytes, sid, sources[sid], timeout): sid for sid in used
        }
        for future in as_completed(future_map):
            sid = future_map[future]
            results[sid] = future.result()
    return results


def parse_sources(config: Mapping, raw: Mapping[str, bytes]) -> Dict[str, List[Rule]]:
    parsed: Dict[str, List[Rule]] = {}
    for sid, data in raw.items():
        source = config["sources"][sid]
        fmt = source["format"]
        text = _decode_bytes(data, sid)
        if fmt == "surge":
            parsed[sid] = parse_surge(text, source_id=sid)
        elif fmt == "domainset":
            parsed[sid] = parse_domainset(text, source_id=sid)
        elif fmt == "geosite":
            parsed[sid] = parse_geosite(text, source_id=sid)
        else:  # pragma: no cover - validate_config 已拦截
            raise ConfigError(f"source '{sid}' 未知 format {fmt!r}")
    return parsed


# ---------------------------------------------------------------------------
# 规则选择、排序、去重
# ---------------------------------------------------------------------------


def _suffix_in_scope(domain: str, suffixes: Iterable[str]) -> bool:
    d = domain.lower()
    for suffix in suffixes:
        if d == suffix or d.endswith("." + suffix):
            return True
    return False


def _in_scope(domain: str, suffixes: Iterable[str], exact_domains: Iterable[str]) -> bool:
    if _suffix_in_scope(domain, suffixes):
        return True
    return domain.lower() in set(exact_domains)


def _iter_parent_suffixes(value: str, include_self: bool):
    """按标签逐级产出候选后缀（O(标签数)），供 set 命中查询使用。

    ``api.example.com, include_self=True`` -> ``api.example.com``, ``example.com``, ``com``；
    ``include_self=False`` 时跳过自身，仅产出严格父后缀。
    """
    labels = value.split(".")
    start = 0 if include_self else 1
    for i in range(start, len(labels)):
        yield ".".join(labels[i:])


def _prune_covered(rules: Mapping[str, Tuple[Rule, set]]) -> Dict[str, Tuple[Rule, set]]:
    """同服务内裁剪被更宽后缀覆盖的规则，复杂度 O(规则数 × 标签数)。

    旧实现对每条规则遍历全部 suffix 集合，遇 146k 级列表会退化为 O(N^2) 卡死；
    这里按“选项组合”各建一次 suffix set，然后每条规则只沿自身标签逐级生成候选
    后缀做 O(1) 查询。

    只有选项完全相同才允许裁剪：``extended-matching`` 等选项会改变匹配语义，
    不同选项的规则必须同时保留，避免错误扩大/缩小覆盖范围。
    """
    suffix_by_opts: Dict[Tuple[str, ...], set] = {}
    for rule, _ in rules.values():
        if rule.type == "DOMAIN-SUFFIX":
            suffix_by_opts.setdefault(rule.options, set()).add(rule.value)

    kept: Dict[str, Tuple[Rule, set]] = {}
    for key, (rule, origins) in rules.items():
        if rule.type == "DOMAIN":
            suffixes = suffix_by_opts.get(rule.options)
            if suffixes and any(s in suffixes for s in _iter_parent_suffixes(rule.value, True)):
                continue
        elif rule.type == "DOMAIN-SUFFIX":
            suffixes = suffix_by_opts.get(rule.options)
            if suffixes and any(s in suffixes for s in _iter_parent_suffixes(rule.value, False)):
                continue
        kept[key] = (rule, origins)
    return kept


def _add_rule(store: Dict[str, Tuple[Rule, set]], rule: Rule, origin: str) -> None:
    key = rule.key()
    if key in store:
        store[key][1].add(origin)
    else:
        store[key] = (rule, {origin})


def select_rules(
    config: Mapping, svc_id: str, svc: Mapping, parsed: Mapping[str, List[Rule]]
) -> Tuple[List[Rule], Optional[Dict[str, List[str]]]]:
    mode = svc["mode"]
    store: Dict[str, Tuple[Rule, set]] = {}

    if mode == "filtered":
        suffixes = [s.lstrip(".").lower() for s in svc.get("allowed_suffixes", [])]
        domains = [d.lower() for d in svc.get("allowed_domains", [])]
        domain_set = set(domains)
        for sid in svc.get("listSources", []):
            for rule in parsed.get(sid, []):
                if rule.type == "DOMAIN":
                    if _in_scope(rule.value, suffixes, domains):
                        _add_rule(store, rule, sid)
                elif rule.type == "DOMAIN-SUFFIX":
                    if _suffix_in_scope(rule.value, suffixes):
                        _add_rule(store, rule, sid)
                    elif rule.value in domain_set:
                        # allowed_domains 是精确主机白名单：上游 DOMAIN-SUFFIX 的值
                        # 恰好命中的必须是收窄后的 DOMAIN，绝不扩成整个子域树。
                        _add_rule(store, Rule("DOMAIN", rule.value, rule.options), sid)
                    # 其它情况（父域或越界域）一律不导入。
                # 其余类型 filtered 模式不自动导入。
    else:  # mirror
        for sid in svc.get("listSources", []):
            for rule in parsed.get(sid, []):
                _add_rule(store, rule, sid)

    for local_rule_text in svc.get("local_rules", []):
        rule = parse_local_rule(local_rule_text)
        _add_rule(store, rule, "local")

    store = _prune_covered(store)
    ordered = sorted(
        store.values(), key=lambda item: (_TYPE_ORDER[item[0].type], item[0].value, item[0].options)
    )
    rules = [rule for rule, _ in ordered]
    # mirror 单源/多源镜像关系明确，不需要逐条来源映射（146k 条会撑爆 manifest）；
    # filtered 仍保留逐条 rule_sources 以记录白名单命中的上游来源。
    if mode == "filtered":
        provenance: Optional[Dict[str, List[str]]] = {
            rule.key(): sorted(origins) for rule, origins in ordered
        }
    else:
        provenance = None
    return rules, provenance


# ---------------------------------------------------------------------------
# 输出渲染与 manifest
# ---------------------------------------------------------------------------


def _source_urls(config: Mapping, svc: Mapping) -> List[str]:
    urls: List[str] = []
    for sid in svc.get("listSources", []):
        url = config["sources"][sid]["url"]
        if url not in urls:
            urls.append(url)
    return urls


def render_list(config: Mapping, svc: Mapping, rules: Sequence[Rule]) -> str:
    lines: List[str] = []
    lines.append(f"# 名称：{svc['name']}")
    urls = _source_urls(config, svc)
    if urls:
        for url in urls:
            lines.append(f"# 来源：{url}")
    else:
        lines.append("# 来源：本地维护（人工规则，无更新时间）")
    lines.append("# FORMAT: Surge RULE-SET")
    description = svc.get("description")
    if description:
        lines.append(f"# 说明：{description}")
    for evidence in svc.get("evidence", []) or []:
        lines.append(f"# 证据：{evidence}")
    lines.append("")
    for rule in rules:
        lines.append(rule.render())
    return "\n".join(lines) + "\n"


def _rule_types(rules: Sequence[Rule]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for rule in rules:
        counts[rule.type] = counts.get(rule.type, 0) + 1
    return {k: counts[k] for k in sorted(counts)}


def canonical_config_sha256(config: Mapping) -> str:
    """配置的 canonical JSON（sort_keys + 紧凑分隔符）sha256，可用于跨机校验。"""
    canon = json.dumps(config, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return sha256_hex(canon.encode("utf-8"))


# source 中会透传到 manifest（若有）的元数据键。
_SOURCE_META_KEYS = ("repository", "path", "license_url")


def build_outputs(
    config: Mapping, raw: Mapping[str, bytes]
) -> Dict[str, str]:
    """在内存中构建所有输出文件（含 manifest），不写盘。"""
    parsed = parse_sources(config, raw)

    files: Dict[str, str] = {}
    manifest: Dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "config_sha256": canonical_config_sha256(config),
        "sources": {},
        "outputs": {},
    }
    manifest_sources = manifest["sources"]  # type: ignore[assignment]
    for sid in sorted(raw):
        src = config["sources"][sid]
        entry: Dict[str, object] = {
            "url": src["url"],
            "format": src["format"],
            "raw_sha256": sha256_hex(raw[sid]),
        }
        for meta_key in _SOURCE_META_KEYS:
            if src.get(meta_key) is not None:
                entry[meta_key] = src[meta_key]
        manifest_sources[sid] = entry

    manifest_outputs = manifest["outputs"]  # type: ignore[assignment]
    for svc_id in sorted(config["services"]):
        svc = config["services"][svc_id]
        rules, provenance = select_rules(config, svc_id, svc, parsed)
        if not rules:
            raise SyncError(
                f"service '{svc_id}' 没有产生任何有效规则（检查白名单/上游/local_rules）"
            )
        content = render_list(config, svc, rules)
        path = svc["output"]
        files[path] = content
        data = content.encode("utf-8")
        out_entry: Dict[str, object] = {
            "service": svc_id,
            "mode": svc["mode"],
            "sha256": sha256_hex(data),
            "rule_count": len(rules),
            "rule_types": _rule_types(rules),
            "source_urls": _source_urls(config, svc),
            "evidence": list(svc.get("evidence", []) or []),
        }
        if svc["mode"] == "filtered":
            out_entry["rule_sources"] = provenance
        else:
            # 紧凑 provenance：镜像单源关系明确，记录来源集合与本地规则数，
            # 不逐条存 source 映射（避免 146k 条 key 撑大 manifest）。
            out_entry["source_ids"] = sorted(svc.get("listSources", []))
            out_entry["local_rule_count"] = len(svc.get("local_rules", []))
        manifest_outputs[path] = out_entry

    manifest_text = json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    files[MANIFEST_REL_PATH] = manifest_text
    return files


# ---------------------------------------------------------------------------
# 写入（write-if-changed + 原子替换）
# ---------------------------------------------------------------------------


def _resolve_target(root: Path, rel: str) -> Path:
    root = root.resolve()
    target = (root / rel).resolve()
    if target != root and root not in target.parents:
        raise SyncError(f"写入目标逃逸出项目根: {rel!r}")
    return target


def write_outputs(files: Mapping[str, str], project_root: Path) -> List[str]:
    root = project_root.resolve()
    # 先统一校验全部目标路径（写盘前 fail closed：路径逃逸等直接拒绝）。
    # 注意：本函数逐文件做“临时文件 + os.replace”原子替换，单文件原子；
    # 但不保证跨多个文件的事务性，中途 OS 写盘失败可能已替换前面的文件。
    targets: Dict[str, Path] = {rel: _resolve_target(root, rel) for rel in files}

    written: List[str] = []
    for rel, content in files.items():
        target = targets[rel]
        data = content.encode("utf-8")
        if target.is_file():
            try:
                if target.read_bytes() == data:
                    continue  # 内容无变化，不重写
            except OSError:
                pass
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(target.parent), prefix=".tmp-", suffix=".swp")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            # 替换前再次确认临时文件与目标均在项目根内。
            _resolve_target(root, os.path.relpath(tmp, str(root)))
            os.replace(tmp, target)
        except BaseException:
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
            raise
        written.append(rel)
    return written


# ---------------------------------------------------------------------------
# 顶层命令
# ---------------------------------------------------------------------------


def run_sync(config_path: Path, project_root: Path, timeout: float = DEFAULT_TIMEOUT) -> int:
    config = load_and_validate(config_path, project_root)
    raw = fetch_all_sources(config, timeout=timeout)
    files = build_outputs(config, raw)
    written = write_outputs(files, project_root)
    if written:
        print(f"已更新 {len(written)} 个文件：")
        for rel in written:
            print(f"  - {rel}")
    else:
        print("无内容变更，未写入任何文件。")
    return 0


def run_check(config_path: Path, project_root: Path, timeout: float = DEFAULT_TIMEOUT) -> int:
    try:
        config = load_and_validate(config_path, project_root)
        raw = fetch_all_sources(config, timeout=timeout)
        files = build_outputs(config, raw)
    except SyncError as exc:
        print(f"[check] 失败: {exc}", file=sys.stderr)
        return 1

    root = project_root.resolve()
    changed: List[str] = []
    for rel, content in files.items():
        target = _resolve_target(root, rel)
        data = content.encode("utf-8")
        if not target.is_file():
            changed.append(f"缺失 {rel}")
            continue
        try:
            existing = target.read_bytes()
        except OSError:
            changed.append(f"无法读取 {rel}")
            continue
        if existing != data:
            changed.append(f"变更 {rel}")

    if changed:
        print("[check] 需要更新：")
        for item in changed:
            print(f"  - {item}")
        return 2
    print("[check] 无变更。")
    return 0


def _count_rule_lines(text: str) -> int:
    count = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        count += 1
    return count


def _used_source_ids(config: Mapping) -> set:
    used = set()
    for svc in config["services"].values():
        used.update(svc.get("listSources", []))
    return used


def _validate_filtered_output(
    config: Mapping, svc_id: str, svc: Mapping, rules: Sequence[Rule]
) -> None:
    """校验 filtered 输出只含 scope 内域名规则，或与 local_rules 完全相等的规则。"""
    suffixes = [s.lstrip(".").lower() for s in svc.get("allowed_suffixes", [])]
    domains = [d.lower() for d in svc.get("allowed_domains", [])]
    domain_set = set(domains)
    local_keys = {parse_local_rule(t).key() for t in svc.get("local_rules", [])}
    for rule in rules:
        if rule.key() in local_keys:
            continue  # 仅当与 local 规则完全相等才允许越界（如 PROCESS-NAME）
        if rule.type in ("DOMAIN", "DOMAIN-SUFFIX") and _in_scope(rule.value, suffixes, domains):
            if (
                rule.type == "DOMAIN-SUFFIX"
                and rule.value in domain_set
                and not _suffix_in_scope(rule.value, suffixes)
            ):
                raise SyncError(
                    f"{svc_id}: {rule.render()} 命中 allowed_domains 精确主机，应窄化为 DOMAIN 而非子域"
                )
            continue
        raise SyncError(f"{svc_id}: filtered 输出包含越界或不允许的规则 {rule.render()}")

    # 用已生成的 rules 作为 parsed 输入重新选择，确认与 scope/local 规则一致。
    parsed_like = {sid: list(rules) for sid in svc.get("listSources", [])}
    selected, _ = select_rules(config, svc_id, svc, parsed_like)
    if {r.key() for r in selected} != {r.key() for r in rules}:
        raise SyncError(f"{svc_id}: filtered 输出与按 scope/local 重新选择的结果不一致")


def run_validate(config_path: Path, project_root: Path) -> int:
    """纯本地校验：配置 + manifest（config 哈希/元数据/输出）+ 输出逐条规则。不联网、不写盘。"""
    try:
        config = load_and_validate(config_path, project_root)
        root = project_root.resolve()
        manifest_path = root / MANIFEST_REL_PATH
        if not manifest_path.is_file():
            raise SyncError(f"manifest 不存在: {MANIFEST_REL_PATH}")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise SyncError(f"manifest 不是合法 JSON: {exc}") from exc
        if manifest.get("schema_version") != SCHEMA_VERSION:
            raise SyncError(f"manifest schema_version 非法: {manifest.get('schema_version')!r}")

        # 1) config canonical hash：配置一旦改动必须重新同步。
        if manifest.get("config_sha256") != canonical_config_sha256(config):
            raise SyncError("manifest.config_sha256 与当前配置不一致（配置已变更，请重新同步）")

        # 2) source 集合与 URL/format/元数据。
        manifest_sources = manifest.get("sources")
        if not isinstance(manifest_sources, dict):
            raise SyncError("manifest.sources 缺失或类型错误")
        used = _used_source_ids(config)
        if set(manifest_sources) != used:
            raise SyncError(
                f"manifest.sources 与配置使用集合不一致 (缺少={sorted(used - set(manifest_sources))}, "
                f"多余={sorted(set(manifest_sources) - used)})"
            )
        for sid, entry in manifest_sources.items():
            if not isinstance(entry, dict):
                raise SyncError(f"manifest.sources['{sid}'] 类型错误")
            src = config["sources"][sid]
            if entry.get("url") != src["url"] or entry.get("format") != src["format"]:
                raise SyncError(f"manifest.sources['{sid}'] 的 url/format 与配置不一致")
            if "raw_sha256" not in entry:
                raise SyncError(f"manifest.sources['{sid}'] 缺少 raw_sha256")
            for meta_key in _SOURCE_META_KEYS:
                cfg_val = src.get(meta_key)
                if cfg_val is not None and entry.get(meta_key) != cfg_val:
                    raise SyncError(f"manifest.sources['{sid}'] 的 {meta_key} 与配置不一致")

        # 3) 输出集合与 manifest 对应。
        outputs = manifest.get("outputs")
        if not isinstance(outputs, dict):
            raise SyncError("manifest.outputs 缺失或类型错误")
        expected = {svc["output"]: sid for sid, svc in config["services"].items()}
        if set(outputs) != set(expected):
            raise SyncError(
                f"manifest.outputs 与配置不一致 (缺少={sorted(set(expected) - set(outputs))}, "
                f"多余={sorted(set(outputs) - set(expected))})"
            )

        # 4) 逐输出：sha/规则逐条解析/count/rule_types/provenance keys/service/source_urls/scope。
        for rel, info in sorted(outputs.items()):
            if not isinstance(info, dict):
                raise SyncError(f"manifest.outputs['{rel}'] 类型错误")
            svc_id = expected[rel]
            svc = config["services"][svc_id]
            if info.get("service") != svc_id:
                raise SyncError(f"{rel} 的 service 字段 {info.get('service')!r} 与配置 {svc_id!r} 不一致")
            target = _resolve_target(root, rel)
            if not target.is_file():
                raise SyncError(f"声明的输出文件不存在: {rel}")
            data = target.read_bytes()
            if sha256_hex(data) != info.get("sha256"):
                raise SyncError(f"{rel} 的 sha256 与 manifest 不一致")
            text = data.decode("utf-8")
            # parse_surge 逐条严格校验：任何非法行都会抛 ParseError。
            rules = parse_surge(text, source_id=rel)
            if len(rules) != info.get("rule_count"):
                raise SyncError(
                    f"{rel} 的规则数 {len(rules)} 与 manifest 的 {info.get('rule_count')} 不一致"
                )
            if _rule_types(rules) != info.get("rule_types"):
                raise SyncError(f"{rel} 的 rule_types 与 manifest 不一致")
            if "mode" in info and info.get("mode") != svc["mode"]:
                raise SyncError(f"{rel} 的 mode {info.get('mode')!r} 与配置 {svc['mode']!r} 不一致")
            if info.get("source_urls") != _source_urls(config, svc):
                raise SyncError(f"{rel} 的 source_urls 与配置不一致")
            if svc["mode"] == "filtered":
                provenance = info.get("rule_sources")
                if not isinstance(provenance, dict):
                    raise SyncError(f"{rel} 的 rule_sources 缺失或类型错误")
                if set(provenance) != {r.key() for r in rules}:
                    raise SyncError(f"{rel} 的 provenance keys 与实际规则不一致")
                _validate_filtered_output(config, svc_id, svc, rules)
            else:
                # mirror：紧凑 provenance，校验来源集合/本地规则数，禁止逐条 rule_sources。
                # 规则本身已由上面的 parse_surge 严格逐条校验，不能跳过合法性检查。
                if "rule_sources" in info:
                    raise SyncError(f"{rel} 为 mirror 输出，不应包含逐条 rule_sources")
                if info.get("source_ids") != sorted(svc.get("listSources", [])):
                    raise SyncError(f"{rel} 的 source_ids 与配置不一致")
                if info.get("local_rule_count") != len(svc.get("local_rules", [])):
                    raise SyncError(f"{rel} 的 local_rule_count 与配置不一致")
        print("[validate] 通过。")
        return 0
    except (SyncError, ConfigError) as exc:
        print(f"[validate] 失败: {exc}", file=sys.stderr)
        return 1


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="从多个 GitHub 上游同步并生成 Surge RULE-SET 规则文件。",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="配置文件路径（默认 <项目根>/config/rule_sources.json）",
    )
    parser.add_argument(
        "--output-root",
        default=None,
        help="项目输出根目录（默认：配置文件所在项目的根目录）",
    )
    parser.add_argument("--check", action="store_true", help="联网比较是否需要更新，不写文件")
    parser.add_argument("--validate", action="store_true", help="纯本地校验配置与输出，不联网不写")
    parser.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT, help=f"单次下载超时秒数（默认 {DEFAULT_TIMEOUT}）"
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    if args.check and args.validate:
        parser.error("--check 与 --validate 不能同时使用")

    if args.config:
        config_path = Path(args.config)
        project_root = Path(args.output_root) if args.output_root else _default_project_root(config_path)
    else:
        project_root = Path(args.output_root) if args.output_root else Path.cwd()
        config_path = project_root / "config" / "rule_sources.json"

    if args.validate:
        return run_validate(config_path, project_root)
    if args.check:
        return run_check(config_path, project_root, timeout=args.timeout)
    try:
        return run_sync(config_path, project_root, timeout=args.timeout)
    except SyncError as exc:
        print(f"[sync] 失败: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
