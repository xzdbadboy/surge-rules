#!/usr/bin/env python3
"""tests/test_sync_rules.py — 针对 scripts/sync_rules.py 的单元测试（标准库 unittest）。

运行：
    python3 -m unittest discover -s tests -v

测试通过 unittest.mock 模拟网络，不访问真实外网，不写仓库文件（全部使用临时目录）。
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from scripts import sync_rules as sync  # noqa: E402


SURGE_A = "https://up.example/a.list"
SURGE_B = "https://up.example/b.list"
DS_C = "https://up.example/c.domainset"


def make_config(sources, services):
    return {"version": 1, "sources": sources, "services": services}


def src(url, fmt="surge", **extra):
    d = {"url": url, "format": fmt}
    d.update(extra)
    return d


class BaseCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.config_path = self.root / "config" / "rule_sources.json"

    def tearDown(self):
        self._tmp.cleanup()

    # -- helpers ---------------------------------------------------------
    def write_config(self, cfg):
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")

    @contextmanager
    def fetch_patch(self, url_map, fail_urls=()):
        urls = dict(url_map)
        fails = set(fail_urls)
        calls = []

        def fake_get(url, timeout=sync.DEFAULT_TIMEOUT):
            calls.append(url)
            if url in fails:
                raise OSError("network down: " + url)
            if url in urls:
                data = urls[url]
                return data if isinstance(data, bytes) else data.encode("utf-8")
            raise OSError("unexpected url: " + url)

        with patch.object(sync, "_http_get", side_effect=fake_get), patch.object(
            sync, "FETCH_BACKOFF", 0.0
        ), patch.object(sync, "FETCH_ATTEMPTS", 3):
            self.fetch_calls = calls
            yield

    def cli(self, *args):
        return sync.main(["--config", str(self.config_path), "--output-root", str(self.root), *args])

    def read(self, rel):
        return (self.root / rel).read_bytes()

    def manifest(self):
        return json.loads((self.root / "rules" / "manifest.json").read_text(encoding="utf-8"))

    def output_lines(self, rel):
        return [
            ln for ln in self.read(rel).decode("utf-8").splitlines() if ln and not ln.startswith("#")
        ]


# ---------------------------------------------------------------------------
# 解析 / 规范化
# ---------------------------------------------------------------------------


class ParsingTests(unittest.TestCase):
    def test_mixed_surge_normalization_and_comments(self):
        text = (
            "\ufeff# 整行注释\n"
            "; 分号注释\n"
            "// 双斜线注释\n"
            "\n"
            "DOMAIN-SUFFIX,Example.COM   // 见 https://example.com/docs\n"
            "DOMAIN, api.openai.com\t# 行尾 tab 注释\n"
            "DOMAIN-KEYWORD,openai\n"
            "IP-CIDR,1.2.3.0/24,no-resolve\n"
            "IP-CIDR6,2001:db8::/32\n"
            "IP-ASN,13335\n"
            "USER-AGENT,Telegram*\n"
            "PROCESS-NAME,/Applications/Muse.app/Contents/MacOS/Muse\n"
            "URL-REGEX,^https://api\\.example\\.com/\n"
        )
        rules = sync.parse_surge(text, source_id="t")
        rendered = [r.render() for r in rules]
        self.assertIn("DOMAIN-SUFFIX,example.com", rendered)
        self.assertIn("DOMAIN,api.openai.com", rendered)
        self.assertIn("IP-CIDR,1.2.3.0/24,no-resolve", rendered)
        self.assertIn("IP-CIDR6,2001:db8::/32", rendered)
        self.assertIn("IP-ASN,13335", rendered)
        self.assertIn("DOMAIN-KEYWORD,openai", rendered)
        # 行尾注释中的 https URL 不会破坏解析：整行注释仍正确剥离
        self.assertEqual(len(rules), 9)

    def test_domainset_conversion(self):
        text = "# 注释\n.example.com\nother.org\n  .Sub.Example.NET  \n"
        rules = sync.parse_domainset(text, source_id="ds")
        self.assertEqual(
            [r.render() for r in rules],
            ["DOMAIN-SUFFIX,example.com", "DOMAIN,other.org", "DOMAIN-SUFFIX,sub.example.net"],
        )

    def test_bad_domain_with_path_rejected(self):
        with self.assertRaises(sync.ParseError):
            sync.parse_surge("DOMAIN-SUFFIX,example.com/path", source_id="t")

    def test_scheme_domain_rejected(self):
        with self.assertRaises(sync.ParseError):
            sync.parse_surge("DOMAIN,https://evil.com/x", source_id="t")

    def test_html_rejected(self):
        with self.assertRaises(sync.ParseError):
            sync.parse_surge("<!DOCTYPE html><html><body>nope</body></html>", source_id="t")

    def test_empty_rejected(self):
        with self.assertRaises(sync.ParseError):
            sync.parse_surge("# only comments\n\n", source_id="t")

    def test_unknown_rule_type_rejected(self):
        with self.assertRaises(sync.ParseError):
            sync.parse_surge("FINAL,Proxy", source_id="t")

    def test_domain_extra_field_rejected(self):
        with self.assertRaises(sync.ParseError):
            sync.parse_surge("DOMAIN,example.com,force-remote-dns", source_id="t")

    def test_ip_validation_and_policy_column(self):
        ok = sync.parse_surge("IP-CIDR,10.0.0.0/8,no-resolve,extended-matching", source_id="t")
        self.assertEqual(ok[0].options, ("no-resolve", "extended-matching"))
        with self.assertRaises(sync.ParseError):
            sync.parse_surge("IP-CIDR,10.0.0.0/8,DIRECT", source_id="t")
        self.assertEqual(
            sync.parse_surge("IP-CIDR6,2001:db8::/32,no-resolve", source_id="t")[0].type,
            "IP-CIDR6",
        )
        with self.assertRaises(sync.ParseError):
            sync.parse_surge("IP-CIDR,::1/128,no-resolve", source_id="t")  # v6 不能塞进 IP-CIDR
        with self.assertRaises(sync.ParseError):
            sync.parse_surge("IP-CIDR,not-a-cidr", source_id="t")

    def test_short_and_dotted_keyword_allowed(self):
        # Surge 支持短关键词（ad/ads）与带点关键词（.estream.），不能一概判为非法；
        # filtered 模式不导入关键词，mirror 模式则原样保留。
        for kw in ("com", "ads", "ad", ".estream.", "anybest."):
            with self.subTest(kw=kw):
                r = sync.parse_surge(f"DOMAIN-KEYWORD,{kw}", source_id="t")
                self.assertEqual(r[0].render(), f"DOMAIN-KEYWORD,{kw.lower()}")
        with self.assertRaises(sync.ParseError):
            sync.parse_surge("DOMAIN-KEYWORD,", source_id="t")
        self.assertEqual(sync.parse_surge("DOMAIN-KEYWORD,openai", source_id="t")[0].value, "openai")

    def test_url_regex_compile_checked(self):
        with self.assertRaises(sync.ParseError):
            sync.parse_surge("URL-REGEX,[invalid(", source_id="t")

    def test_single_label_tld_domains(self):
        # 真实上游含 DOMAIN-SUFFIX,cn / DOMAIN-SUFFIX,apple 等单标签 TLD。
        rules = sync.parse_surge(
            "DOMAIN-SUFFIX,cn\nDOMAIN,msleep\nDOMAIN-SUFFIX,apple\n", source_id="t"
        )
        self.assertEqual(
            [r.render() for r in rules],
            ["DOMAIN-SUFFIX,cn", "DOMAIN,msleep", "DOMAIN-SUFFIX,apple"],
        )
        # domainset 的 .cn / .ms 单标签同样合法。
        ds = sync.parse_domainset(".cn\n.ms\n", source_id="ds")
        self.assertEqual([r.render() for r in ds], ["DOMAIN-SUFFIX,cn", "DOMAIN-SUFFIX,ms"])
        # 单字符「TLD」与非法标签仍拒绝。
        with self.assertRaises(sync.ParseError):
            sync.parse_surge("DOMAIN-SUFFIX,x", source_id="t")
        with self.assertRaises(sync.ParseError):
            sync.parse_surge("DOMAIN-SUFFIX,-bad", source_id="t")

    def test_domain_wildcard_embedded_patterns(self):
        # 真实上游形如 ads-*.tiktok.com / beacons*.gvt?.com / *.ad.*.host，不能误拒。
        for val in (
            "ads-*.tiktok.com",
            "*.ad.*.prod.hosts.ooklaserver.net",
            "beacons*.gvt?.com",
            "[ab]oo.example.com",
            "v*.thenewstack.io",
        ):
            with self.subTest(val=val):
                r = sync.parse_surge(f"DOMAIN-WILDCARD,{val}", source_id="t")[0]
                self.assertEqual(r.type, "DOMAIN-WILDCARD")
                self.assertEqual(r.value, val.lower())
        for bad in ("bad path.com", "foo..com", "foo.com/x", "a[bc.example.com"):
            with self.subTest(bad=bad):
                with self.assertRaises(sync.ParseError):
                    sync.parse_surge(f"DOMAIN-WILDCARD,{bad}", source_id="t")

    def test_url_not_treated_as_comment(self):
        # URL-REGEX / 行尾注释里的 // 不得被当注释，只有前置空白的 // 才是注释。
        rules = sync.parse_surge(
            "URL-REGEX,^https://api\\.example\\.com/x // 尾注释\n"
            "DOMAIN-SUFFIX,foo.com // 见 https://foo.com/doc\n",
            source_id="t",
        )
        self.assertEqual(
            [r.render() for r in rules],
            ["URL-REGEX,^https://api\\.example\\.com/x", "DOMAIN-SUFFIX,foo.com"],
        )


# ---------------------------------------------------------------------------
# 配置校验 / 路径安全
# ---------------------------------------------------------------------------


class ConfigTests(BaseCase):
    def _cfg(self, **svc_overrides):
        svc = {
            "name": "Demo",
            "output": "rules/Demo.list",
            "mode": "filtered",
            "listSources": ["a"],
            "allowed_suffixes": ["demo.com"],
        }
        svc.update(svc_overrides)
        return make_config({"a": src(SURGE_A)}, {"demo": svc})

    def test_valid_config_passes(self):
        sync.validate_config(self._cfg(), self.root)

    def test_illegal_output_paths(self):
        for bad in ("../evil.list", "/abs/x.list", "scripts/x.list", "rules/foo.txt", "a//b.list"):
            with self.subTest(bad=bad):
                with self.assertRaises(sync.ConfigError):
                    sync.validate_config(self._cfg(output=bad), self.root)

    def test_duplicate_and_case_conflicting_outputs(self):
        cfg = make_config(
            {"a": src(SURGE_A)},
            {
                "s1": {"name": "A", "output": "rules/X.list", "mode": "filtered",
                       "listSources": ["a"], "allowed_suffixes": ["a.com"]},
                "s2": {"name": "B", "output": "rules/x.list", "mode": "filtered",
                       "listSources": ["a"], "allowed_suffixes": ["b.com"]},
            },
        )
        with self.assertRaises(sync.ConfigError):
            sync.validate_config(cfg, self.root)

    def test_unknown_source_reference(self):
        cfg = self._cfg(listSources=["missing"])
        with self.assertRaises(sync.ConfigError):
            sync.validate_config(cfg, self.root)

    def test_mirror_rejects_whitelist(self):
        cfg = self._cfg(mode="mirror", allowed_suffixes=["demo.com"])
        with self.assertRaises(sync.ConfigError):
            sync.validate_config(cfg, self.root)
        # 去掉白名单即通过
        cfg2 = self._cfg(mode="mirror")
        cfg2["services"]["demo"].pop("allowed_suffixes")
        sync.validate_config(cfg2, self.root)

    def test_local_rule_type_restricted(self):
        cfg = self._cfg(local_rules=["USER-AGENT,foo"])
        with self.assertRaises(sync.ConfigError):
            sync.validate_config(cfg, self.root)

    def test_local_generic_process_rejected(self):
        for bad in ("PROCESS-NAME,node", "PROCESS-NAME,python3"):
            with self.subTest(bad=bad):
                cfg = self._cfg(local_rules=[bad])
                with self.assertRaises(sync.ConfigError):
                    sync.validate_config(cfg, self.root)
        # .app bundle 路径允许
        sync.validate_config(
            self._cfg(local_rules=["PROCESS-NAME,/Applications/Muse.app/Contents/MacOS/Muse"]),
            self.root,
        )

    def test_empty_sources_without_local_rejected(self):
        cfg = self._cfg(listSources=[])
        with self.assertRaises(sync.ConfigError):
            sync.validate_config(cfg, self.root)

    def test_bad_version(self):
        cfg = self._cfg()
        cfg["version"] = 2
        with self.assertRaises(sync.ConfigError):
            sync.validate_config(cfg, self.root)


# ---------------------------------------------------------------------------
# 过滤 / 选择 / provenance
# ---------------------------------------------------------------------------


class SelectionTests(BaseCase):
    def test_filtered_selects_scope_and_drops_other_types(self):
        source = (
            "DOMAIN-SUFFIX,openai.com\n"
            "DOMAIN-SUFFIX,sub.openai.com\n"  # 被 openai.com 覆盖 -> 裁剪
            "DOMAIN,api.openai.com\n"        # 被 openai.com 覆盖 -> 裁剪
            "DOMAIN,shared.example.net\n"    # allowed_domains 精确命中
            "DOMAIN-SUFFIX,evil.com\n"       # 越界
            "DOMAIN-KEYWORD,openai\n"        # filtered 不导入
            "IP-CIDR,1.2.3.0/24\n"           # filtered 不导入
            "IP-ASN,13335\n"                 # filtered 不导入
            "PROCESS-NAME,node\n"            # filtered 不导入
        )
        cfg = make_config(
            {"a": src(SURGE_A)},
            {"demo": {
                "name": "Demo", "output": "rules/Demo.list", "mode": "filtered",
                "listSources": ["a"],
                "allowed_suffixes": ["openai.com"],
                "allowed_domains": ["shared.example.net"],
            }},
        )
        self.write_config(cfg)
        with self.fetch_patch({SURGE_A: source}):
            self.assertEqual(self.cli(), 0)
        lines = self.output_lines("rules/Demo.list")
        self.assertEqual(lines, ["DOMAIN,shared.example.net", "DOMAIN-SUFFIX,openai.com"])
        # provenance
        m = self.manifest()
        prov = m["outputs"]["rules/Demo.list"]["rule_sources"]
        self.assertEqual(prov["DOMAIN-SUFFIX,openai.com"], ["a"])
        self.assertEqual(prov["DOMAIN,shared.example.net"], ["a"])
        self.assertEqual(m["outputs"]["rules/Demo.list"]["rule_count"], 2)

    def test_parent_domain_override_rejected(self):
        source = "DOMAIN-SUFFIX,openai.com\nDOMAIN-SUFFIX,api.openai.com\n"
        cfg = make_config(
            {"a": src(SURGE_A)},
            {"demo": {
                "name": "Demo", "output": "rules/Demo.list", "mode": "filtered",
                "listSources": ["a"], "allowed_suffixes": ["api.openai.com"],
            }},
        )
        self.write_config(cfg)
        with self.fetch_patch({SURGE_A: source}):
            self.assertEqual(self.cli(), 0)
        # 父域 openai.com 不得因覆盖 api.openai.com 被纳入
        self.assertEqual(self.output_lines("rules/Demo.list"), ["DOMAIN-SUFFIX,api.openai.com"])

    def test_api_github_not_auto_included_in_copilot(self):
        source = (
            "DOMAIN-SUFFIX,githubcopilot.com\n"
            "DOMAIN,api.github.com\n"
            "DOMAIN-SUFFIX,github.com\n"
        )
        cfg = make_config(
            {"a": src(SURGE_A)},
            {"copilot": {
                "name": "Copilot", "output": "rules/Copilot.list", "mode": "filtered",
                "listSources": ["a"], "allowed_suffixes": ["githubcopilot.com"],
            }},
        )
        self.write_config(cfg)
        with self.fetch_patch({SURGE_A: source}):
            self.assertEqual(self.cli(), 0)
        lines = self.output_lines("rules/Copilot.list")
        self.assertEqual(lines, ["DOMAIN-SUFFIX,githubcopilot.com"])

    def test_local_only_muse(self):
        cfg = make_config(
            {},
            {"muse": {
                "name": "Muse", "output": "rules/Muse.list", "mode": "filtered",
                "listSources": [],
                "local_rules": [
                    "PROCESS-NAME,/Applications/Muse.app/Contents/MacOS/Muse",
                    "DOMAIN-SUFFIX,museapp.com",
                ],
                "description": "Muse 待确认域名，暂用进程兜底",
            }},
        )
        self.write_config(cfg)
        with self.fetch_patch({}):
            self.assertEqual(self.cli(), 0)
        lines = self.output_lines("rules/Muse.list")
        self.assertEqual(
            lines, ["DOMAIN-SUFFIX,museapp.com", "PROCESS-NAME,/Applications/Muse.app/Contents/MacOS/Muse"]
        )
        prov = self.manifest()["outputs"]["rules/Muse.list"]["rule_sources"]
        self.assertEqual(prov["DOMAIN-SUFFIX,museapp.com"], ["local"])

    def test_duplicate_sorting_and_multi_source_provenance(self):
        a = "DOMAIN-SUFFIX,b.com\nDOMAIN-SUFFIX,a.com\nDOMAIN-SUFFIX,a.com\n"
        b = "DOMAIN-SUFFIX,a.com\nDOMAIN-SUFFIX,c.com\n"
        cfg = make_config(
            {"a": src(SURGE_A), "b": src(SURGE_B)},
            {"demo": {
                "name": "Demo", "output": "rules/Demo.list", "mode": "filtered",
                "listSources": ["a", "b"], "allowed_suffixes": ["a.com", "b.com", "c.com"],
            }},
        )
        self.write_config(cfg)
        with self.fetch_patch({SURGE_A: a, SURGE_B: b}):
            self.assertEqual(self.cli(), 0)
        self.assertEqual(
            self.output_lines("rules/Demo.list"),
            ["DOMAIN-SUFFIX,a.com", "DOMAIN-SUFFIX,b.com", "DOMAIN-SUFFIX,c.com"],
        )
        prov = self.manifest()["outputs"]["rules/Demo.list"]["rule_sources"]
        self.assertEqual(prov["DOMAIN-SUFFIX,a.com"], ["a", "b"])  # 多源 provenance 合并排序
        self.assertEqual(prov["DOMAIN-SUFFIX,b.com"], ["a"])
        self.assertEqual(prov["DOMAIN-SUFFIX,c.com"], ["b"])

    def test_no_cross_service_dedup(self):
        source = "DOMAIN-SUFFIX,shared.com\n"
        cfg = make_config(
            {"a": src(SURGE_A)},
            {
                "s1": {"name": "S1", "output": "rules/S1.list", "mode": "filtered",
                       "listSources": ["a"], "allowed_suffixes": ["shared.com"]},
                "s2": {"name": "S2", "output": "rules/S2.list", "mode": "mirror",
                       "listSources": ["a"]},
            },
        )
        self.write_config(cfg)
        with self.fetch_patch({SURGE_A: source}):
            self.assertEqual(self.cli(), 0)
        self.assertIn("DOMAIN-SUFFIX,shared.com", self.output_lines("rules/S1.list"))
        self.assertIn("DOMAIN-SUFFIX,shared.com", self.output_lines("rules/S2.list"))

    def test_mirror_keeps_all_types(self):
        source = (
            "DOMAIN-SUFFIX,mirror.com\nDOMAIN-KEYWORD,specialword\nIP-CIDR,9.9.9.0/24\n"
            "IP-ASN,65000\nPROCESS-NAME,SomeApp\nURL-REGEX,^https://mirror\\.com/\n"
        )
        cfg = make_config(
            {"a": src(SURGE_A)},
            {"m": {"name": "Mirror", "output": "rules/M.list", "mode": "mirror", "listSources": ["a"]}},
        )
        self.write_config(cfg)
        with self.fetch_patch({SURGE_A: source}):
            self.assertEqual(self.cli(), 0)
        lines = self.output_lines("rules/M.list")
        for expected in (
            "DOMAIN-SUFFIX,mirror.com",
            "DOMAIN-KEYWORD,specialword",
            "IP-CIDR,9.9.9.0/24",
            "IP-ASN,65000",
            "PROCESS-NAME,SomeApp",
        ):
            self.assertIn(expected, lines)


    def test_mirror_keeps_short_keyword_wildcard_and_single_label(self):
        source = (
            "DOMAIN-KEYWORD,ads\n"
            "DOMAIN-KEYWORD,ad\n"
            "DOMAIN-WILDCARD,ads-*.foo.com\n"
            "DOMAIN-SUFFIX,cn\n"
        )
        cfg = make_config(
            {"a": src(SURGE_A)},
            {"m": {"name": "Mirror", "output": "rules/M2.list", "mode": "mirror", "listSources": ["a"]}},
        )
        self.write_config(cfg)
        with self.fetch_patch({SURGE_A: source}):
            self.assertEqual(self.cli(), 0)
        self.assertEqual(
            self.output_lines("rules/M2.list"),
            [
                "DOMAIN-SUFFIX,cn",
                "DOMAIN-KEYWORD,ad",
                "DOMAIN-KEYWORD,ads",
                "DOMAIN-WILDCARD,ads-*.foo.com",
            ],
        )

    def test_filtered_never_imports_keywords(self):
        source = "DOMAIN-KEYWORD,com\nDOMAIN-KEYWORD,ads\nDOMAIN-SUFFIX,demo.com\n"
        cfg = make_config(
            {"a": src(SURGE_A)},
            {"demo": {"name": "Demo", "output": "rules/Demo.list", "mode": "filtered",
                      "listSources": ["a"], "allowed_suffixes": ["demo.com"]}},
        )
        self.write_config(cfg)
        with self.fetch_patch({SURGE_A: source}):
            self.assertEqual(self.cli(), 0)
        # filtered 不导入任何 DOMAIN-KEYWORD（含短关键词 com/ads），只保留白名单后缀。
        self.assertEqual(self.output_lines("rules/Demo.list"), ["DOMAIN-SUFFIX,demo.com"])


# ---------------------------------------------------------------------------
# 失败封闭 / 原子性 / 无部分更新
# ---------------------------------------------------------------------------


class FailClosedTests(BaseCase):
    def _basic(self):
        return make_config(
            {"a": src(SURGE_A), "b": src(SURGE_B)},
            {
                "s1": {"name": "S1", "output": "rules/S1.list", "mode": "filtered",
                       "listSources": ["a"], "allowed_suffixes": ["a.com"]},
                "s2": {"name": "S2", "output": "rules/S2.list", "mode": "filtered",
                       "listSources": ["b"], "allowed_suffixes": ["b.com"]},
            },
        )

    def test_single_source_failure_leaves_outputs_unchanged(self):
        cfg = self._basic()
        self.write_config(cfg)
        with self.fetch_patch({SURGE_A: "DOMAIN-SUFFIX,a.com\n", SURGE_B: "DOMAIN-SUFFIX,b.com\n"}):
            self.assertEqual(self.cli(), 0)
        before_a = self.read("rules/S1.list")
        before_b = self.read("rules/S2.list")
        before_m = self.read("rules/manifest.json")
        # 改动 source a 内容，但 source b 失败：整轮必须 fail closed，无任何写入
        with self.fetch_patch(
            {SURGE_A: "DOMAIN-SUFFIX,a.com\nDOMAIN-SUFFIX,a2.com\n"}, fail_urls=[SURGE_B]
        ):
            self.assertEqual(self.cli(), 1)
        self.assertEqual(self.read("rules/S1.list"), before_a)
        self.assertEqual(self.read("rules/S2.list"), before_b)
        self.assertEqual(self.read("rules/manifest.json"), before_m)

    def test_no_write_before_all_fetched(self):
        cfg = self._basic()
        self.write_config(cfg)
        with self.fetch_patch({SURGE_A: "DOMAIN-SUFFIX,a.com\n"}, fail_urls=[SURGE_B]):
            self.assertEqual(self.cli(), 1)
        self.assertFalse((self.root / "rules").exists())
        # 所有 source 都被尝试过（并发抓取）
        self.assertIn(SURGE_A, self.fetch_calls)
        self.assertIn(SURGE_B, self.fetch_calls)

    def test_invalid_source_content_fails_closed(self):
        cfg = self._basic()
        self.write_config(cfg)
        with self.fetch_patch({SURGE_A: "<html>err</html>", SURGE_B: "DOMAIN-SUFFIX,b.com\n"}):
            self.assertEqual(self.cli(), 1)
        self.assertFalse((self.root / "rules").exists())


# ---------------------------------------------------------------------------
# --check / --validate
# ---------------------------------------------------------------------------


class CheckValidateTests(BaseCase):
    def _cfg(self):
        return make_config(
            {"a": src(SURGE_A)},
            {"demo": {"name": "Demo", "output": "rules/Demo.list", "mode": "filtered",
                      "listSources": ["a"], "allowed_suffixes": ["demo.com"]}},
        )

    def test_check_no_change_then_change_without_write(self):
        self.write_config(self._cfg())
        with self.fetch_patch({SURGE_A: "DOMAIN-SUFFIX,demo.com\n"}):
            self.assertEqual(self.cli(), 0)              # 生成
            self.assertEqual(self.cli("--check"), 0)     # 无变更
            before = self.read("rules/Demo.list")
            # 上游新增范围内的域名 -> check 报告需要更新，但不写文件
            with self.fetch_patch({SURGE_A: "DOMAIN-SUFFIX,demo.com\nDOMAIN-SUFFIX,api.demo.com\n"}):
                self.assertEqual(self.cli("--check"), 2)
            self.assertEqual(self.read("rules/Demo.list"), before)
            # 上游字节未变 -> 无变更（manifest 记录 raw_sha256，故只需上游一致）
            with self.fetch_patch({SURGE_A: "DOMAIN-SUFFIX,demo.com\n"}):
                self.assertEqual(self.cli("--check"), 0)

    def test_check_failure_returns_1(self):
        self.write_config(self._cfg())
        with self.fetch_patch({}, fail_urls=[SURGE_A]):
            self.assertEqual(self.cli("--check"), 1)

    def test_validate_offline_pass_and_bad_hash(self):
        self.write_config(self._cfg())
        with self.fetch_patch({SURGE_A: "DOMAIN-SUFFIX,demo.com\n"}):
            self.assertEqual(self.cli(), 0)
        # validate 不联网：若调用 _http_get 会抛错
        with patch.object(sync, "_http_get", side_effect=AssertionError("network used in validate")):
            self.assertEqual(self.cli("--validate"), 0)
        # 篡改输出 -> sha 不匹配 -> 失败
        target = self.root / "rules" / "Demo.list"
        target.write_text(target.read_text(encoding="utf-8") + "DOMAIN-SUFFIX,extra.com\n", encoding="utf-8")
        with patch.object(sync, "_http_get", side_effect=AssertionError("network used in validate")):
            self.assertEqual(self.cli("--validate"), 1)

    def test_validate_missing_output_fails(self):
        self.write_config(self._cfg())
        with self.fetch_patch({SURGE_A: "DOMAIN-SUFFIX,demo.com\n"}):
            self.assertEqual(self.cli(), 0)
        (self.root / "rules" / "Demo.list").unlink()
        self.assertEqual(self.cli("--validate"), 1)

    def test_validate_missing_manifest_fails(self):
        self.write_config(self._cfg())
        self.assertEqual(self.cli("--validate"), 1)


# ---------------------------------------------------------------------------
# 稳定性 / 幂等 / 头部
# ---------------------------------------------------------------------------


class StabilityTests(BaseCase):
    def _cfg(self):
        return make_config(
            {"a": src(SURGE_A)},
            {"demo": {"name": "Demo", "output": "rules/Demo.list", "mode": "filtered",
                      "listSources": ["a"], "allowed_suffixes": ["demo.com"],
                      "description": "Demo 服务说明"}},
        )

    def test_idempotent_no_rewrite(self):
        self.write_config(self._cfg())
        with self.fetch_patch({SURGE_A: "DOMAIN-SUFFIX,demo.com\n"}):
            self.assertEqual(self.cli(), 0)
            stat_before = os.stat(self.root / "rules" / "Demo.list").st_mtime_ns
            time.sleep(0.01)
            self.assertEqual(self.cli(), 0)  # 再次同步
            stat_after = os.stat(self.root / "rules" / "Demo.list").st_mtime_ns
        self.assertEqual(stat_before, stat_after, "内容无变化时不应重写文件")

    def test_header_has_no_timestamp_and_stable(self):
        self.write_config(self._cfg())
        with self.fetch_patch({SURGE_A: "DOMAIN-SUFFIX,demo.com\n"}):
            self.assertEqual(self.cli(), 0)
            first = self.read("rules/Demo.list")
            self.assertEqual(self.cli(), 0)
            second = self.read("rules/Demo.list")
        self.assertEqual(first, second)
        text = first.decode("utf-8")
        self.assertIn("# 名称：Demo", text)
        self.assertIn("# FORMAT: Surge RULE-SET", text)
        self.assertIn("# 来源：https://up.example/a.list", text)
        self.assertIn("# 说明：Demo 服务说明", text)
        # 不写入当前时间（无 4 位年份）
        import re
        self.assertIsNone(re.search(r"\b20\d{2}\b", text))

    def test_manifest_relative_paths_and_reproducible(self):
        self.write_config(self._cfg())
        with self.fetch_patch({SURGE_A: "DOMAIN-SUFFIX,demo.com\n"}):
            self.assertEqual(self.cli(), 0)
            m1 = self.read("rules/manifest.json")
            self.assertEqual(self.cli(), 0)
            m2 = self.read("rules/manifest.json")
        self.assertEqual(m1, m2)
        manifest = json.loads(m1)
        self.assertEqual(manifest["schema_version"], 1)
        for key in manifest["outputs"]:
            self.assertFalse(key.startswith("/"))
            self.assertNotIn("..", key)
        # sources 记录 raw_sha256
        self.assertIn("raw_sha256", manifest["sources"]["a"])
        self.assertEqual(manifest["outputs"]["rules/Demo.list"]["rule_types"], {"DOMAIN-SUFFIX": 1})


# ---------------------------------------------------------------------------
# geosite 格式（MetaCubeX）：普通域名 / +. 前缀，严格拒绝其它格式
# ---------------------------------------------------------------------------


class GeositeTests(unittest.TestCase):
    def test_plain_and_plus_prefix(self):
        text = "plain.example.com\n+.openai.com\n# 注释\n  +.Sub.Example.NET  \n"
        rules = sync.parse_geosite(text, source_id="geo")
        self.assertEqual(
            [r.render() for r in rules],
            [
                "DOMAIN,plain.example.com",
                "DOMAIN-SUFFIX,openai.com",
                "DOMAIN-SUFFIX,sub.example.net",
            ],
        )

    def test_leading_dot_is_domainset_not_geosite(self):
        # Surge domainset 的 .foo 与 MetaCubeX 的 +.foo 严格区分
        with self.assertRaises(sync.ParseError):
            sync.parse_geosite(".example.com\n", source_id="geo")
        with self.assertRaises(sync.ParseError):
            sync.parse_geosite("+example.com\n", source_id="geo")
        # 反向：domainset 不接受 +.foo
        with self.assertRaises(sync.ParseError):
            sync.parse_domainset("+.example.com\n", source_id="ds")

    def test_unknown_prefix_and_regex_rejected(self):
        for bad in ("regexp:^https?://", "keyword:google", "full:example.com", "include:xx"):
            with self.subTest(bad=bad):
                with self.assertRaises(sync.ParseError):
                    sync.parse_geosite(bad + "\n", source_id="geo")

    def test_empty_and_html_rejected(self):
        with self.assertRaises(sync.ParseError):
            sync.parse_geosite("# only comments\n\n", source_id="geo")
        with self.assertRaises(sync.ParseError):
            sync.parse_geosite("<!DOCTYPE html><html><body>x</body></html>", source_id="geo")

    def test_config_accepts_geosite_format(self):
        cfg = make_config(
            {"g": src("https://up.example/g.list", fmt="geosite")},
            {"demo": {"name": "Demo", "output": "rules/Demo.list", "mode": "filtered",
                      "listSources": ["g"], "allowed_suffixes": ["example.com"]}},
        )
        sync.validate_config(cfg, Path(tempfile.mkdtemp()))
        # parse_sources 路由到 geosite
        parsed = sync.parse_sources(cfg, {"g": b"+.example.com\nplain.example.com\n"})
        self.assertEqual(
            [r.render() for r in parsed["g"]],
            ["DOMAIN-SUFFIX,example.com", "DOMAIN,plain.example.com"],
        )


# ---------------------------------------------------------------------------
# 选项：IP-ASN / DOMAIN / DOMAIN-SUFFIX 的合法选项与非法策略列
# ---------------------------------------------------------------------------


class OptionTests(unittest.TestCase):
    def test_ip_asn_no_resolve_allowed(self):
        # Rabbit AIGC 含 IP-ASN,20473,no-resolve —— 之前 need_two 会误判
        rules = sync.parse_surge("IP-ASN,20473,no-resolve\n", source_id="t")
        self.assertEqual(rules[0].type, "IP-ASN")
        self.assertEqual(rules[0].value, "20473")
        self.assertEqual(rules[0].options, ("no-resolve",))
        self.assertEqual(rules[0].render(), "IP-ASN,20473,no-resolve")

    def test_ip_asn_extended_matching_allowed_unknown_rejected(self):
        r = sync.parse_surge("IP-ASN,AS20473,extended-matching\n", source_id="t")[0]
        self.assertEqual(r.options, ("extended-matching",))
        self.assertEqual(r.value, "AS20473")
        with self.assertRaises(sync.ParseError):
            sync.parse_surge("IP-ASN,20473,DIRECT\n", source_id="t")

    def test_domain_and_suffix_extended_matching(self):
        d = sync.parse_surge("DOMAIN,example.com,extended-matching\n", source_id="t")[0]
        self.assertEqual(d.render(), "DOMAIN,example.com,extended-matching")
        s = sync.parse_surge("DOMAIN-SUFFIX,example.com,extended-matching\n", source_id="t")[0]
        self.assertEqual(s.render(), "DOMAIN-SUFFIX,example.com,extended-matching")

    def test_domain_unknown_policy_column_rejected(self):
        for bad in ("DOMAIN,example.com,DIRECT", "DOMAIN-SUFFIX,example.com,REJECT"):
            with self.subTest(bad=bad):
                with self.assertRaises(sync.ParseError):
                    sync.parse_surge(bad, source_id="t")

    def test_no_extension_to_other_types(self):
        # 通用功能不扩展到新类型：DOMAIN-KEYWORD 仍只允许两列
        with self.assertRaises(sync.ParseError):
            sync.parse_surge("DOMAIN-KEYWORD,openai,extended-matching", source_id="t")


# ---------------------------------------------------------------------------
# allowed_domains 精确主机：DOMAIN-SUFFIX 需收窄为 DOMAIN
# ---------------------------------------------------------------------------


class AllowedDomainsNarrowingTests(BaseCase):
    def test_suffix_narrowed_to_exact_domain(self):
        source = (
            "DOMAIN-SUFFIX,demo.com\n"           # 父域：拒绝
            "DOMAIN-SUFFIX,api.demo.com\n"       # 精确命中 allowed_domains：收窄为 DOMAIN
            "DOMAIN-SUFFIX,sub.api.demo.com\n"   # 子域：不得被扩大导入
            "DOMAIN,api.demo.com\n"              # 等价 DOMAIN，合并
        )
        cfg = make_config(
            {"a": src(SURGE_A)},
            {"demo": {"name": "Demo", "output": "rules/Demo.list", "mode": "filtered",
                      "listSources": ["a"], "allowed_suffixes": [],
                      "allowed_domains": ["api.demo.com"]}},
        )
        self.write_config(cfg)
        with self.fetch_patch({SURGE_A: source}):
            self.assertEqual(self.cli(), 0)
        # 只有收窄后的精确主机，绝无 DOMAIN-SUFFIX，也不扩成子域
        self.assertEqual(self.output_lines("rules/Demo.list"), ["DOMAIN,api.demo.com"])

    def test_suffix_within_allowed_suffix_stays_suffix(self):
        source = "DOMAIN-SUFFIX,api.demo.com\n"
        cfg = make_config(
            {"a": src(SURGE_A)},
            {"demo": {"name": "Demo", "output": "rules/Demo.list", "mode": "filtered",
                      "listSources": ["a"], "allowed_suffixes": ["demo.com"],
                      "allowed_domains": ["api.demo.com"]}},
        )
        self.write_config(cfg)
        with self.fetch_patch({SURGE_A: source}):
            self.assertEqual(self.cli(), 0)
        # 已被 allowed_suffixes 覆盖，保持 DOMAIN-SUFFIX（子域仍属白名单）
        self.assertEqual(self.output_lines("rules/Demo.list"), ["DOMAIN-SUFFIX,api.demo.com"])


# ---------------------------------------------------------------------------
# manifest 元数据：config_sha256 / source 元数据 / evidence / 头部证据
# ---------------------------------------------------------------------------


class ManifestMetadataTests(BaseCase):
    def _cfg(self):
        return make_config(
            {"a": src(SURGE_A, repository="Owner/Repo", path="rules/a.list",
                      license_url="https://lic.example/l")},
            {"demo": {"name": "Demo", "output": "rules/Demo.list", "mode": "filtered",
                      "listSources": ["a"], "allowed_suffixes": ["demo.com"],
                      "evidence": ["https://evidence.example/doc"]}},
        )

    def test_config_sha256_reproducible(self):
        cfg = self._cfg()
        self.write_config(cfg)
        with self.fetch_patch({SURGE_A: "DOMAIN-SUFFIX,demo.com\n"}):
            self.assertEqual(self.cli(), 0)
        m = self.manifest()
        self.assertEqual(m["config_sha256"], sync.canonical_config_sha256(cfg))
        self.assertRegex(m["config_sha256"], r"^[0-9a-f]{64}$")

    def test_source_metadata_propagated(self):
        self.write_config(self._cfg())
        with self.fetch_patch({SURGE_A: "DOMAIN-SUFFIX,demo.com\n"}):
            self.assertEqual(self.cli(), 0)
        s = self.manifest()["sources"]["a"]
        self.assertEqual(s["repository"], "Owner/Repo")
        self.assertEqual(s["path"], "rules/a.list")
        self.assertEqual(s["license_url"], "https://lic.example/l")

    def test_output_evidence_and_header(self):
        self.write_config(self._cfg())
        with self.fetch_patch({SURGE_A: "DOMAIN-SUFFIX,demo.com\n"}):
            self.assertEqual(self.cli(), 0)
        out = self.manifest()["outputs"]["rules/Demo.list"]
        self.assertEqual(out["evidence"], ["https://evidence.example/doc"])
        self.assertEqual(out["service"], "demo")
        text = self.read("rules/Demo.list").decode("utf-8")
        self.assertIn("# 证据：https://evidence.example/doc", text)

    def test_local_only_header_declares_no_update_time(self):
        cfg = make_config(
            {},
            {"muse": {"name": "Muse", "output": "rules/Muse.list", "mode": "filtered",
                      "listSources": [],
                      "local_rules": ["PROCESS-NAME,/Applications/Muse.app/Contents/MacOS/Muse"]}},
        )
        self.write_config(cfg)
        with self.fetch_patch({}):
            self.assertEqual(self.cli(), 0)
        text = self.read("rules/Muse.list").decode("utf-8")
        self.assertIn("本地维护", text)
        self.assertIn("无更新时间", text)


# ---------------------------------------------------------------------------
# --validate 强化：config 哈希 / 输出逐条 / scope / provenance / source
# ---------------------------------------------------------------------------


class ValidateHardeningTests(BaseCase):
    def _cfg(self):
        return make_config(
            {"a": src(SURGE_A)},
            {"demo": {"name": "Demo", "output": "rules/Demo.list", "mode": "filtered",
                      "listSources": ["a"], "allowed_suffixes": ["demo.com"]}},
        )

    def _sync(self):
        self.write_config(self._cfg())
        with self.fetch_patch({SURGE_A: "DOMAIN-SUFFIX,demo.com\n"}):
            self.assertEqual(self.cli(), 0)

    def test_validate_rejects_config_change(self):
        self._sync()
        cfg = self._cfg()
        cfg["services"]["demo"]["allowed_suffixes"] = ["demo.com", "other.com"]
        self.write_config(cfg)  # 配置变更但未重新同步
        with patch.object(sync, "_http_get", side_effect=AssertionError("no network")):
            self.assertEqual(self.cli("--validate"), 1)

    def test_validate_rejects_invalid_output_line(self):
        self._sync()
        target = self.root / "rules" / "Demo.list"
        target.write_text(target.read_text(encoding="utf-8") + "FINAL,Proxy\n", encoding="utf-8")
        with patch.object(sync, "_http_get", side_effect=AssertionError("no network")):
            self.assertEqual(self.cli("--validate"), 1)

    def test_validate_rejects_provenance_mismatch(self):
        self._sync()
        mp = self.root / "rules" / "manifest.json"
        m = json.loads(mp.read_text(encoding="utf-8"))
        m["outputs"]["rules/Demo.list"]["rule_sources"] = {}
        mp.write_text(json.dumps(m), encoding="utf-8")
        with patch.object(sync, "_http_get", side_effect=AssertionError("no network")):
            self.assertEqual(self.cli("--validate"), 1)

    def test_validate_rejects_rule_types_mismatch(self):
        self._sync()
        mp = self.root / "rules" / "manifest.json"
        m = json.loads(mp.read_text(encoding="utf-8"))
        m["outputs"]["rules/Demo.list"]["rule_types"] = {"DOMAIN": 99}
        mp.write_text(json.dumps(m), encoding="utf-8")
        with patch.object(sync, "_http_get", side_effect=AssertionError("no network")):
            self.assertEqual(self.cli("--validate"), 1)

    def test_validate_rejects_source_url_mismatch(self):
        self._sync()
        mp = self.root / "rules" / "manifest.json"
        m = json.loads(mp.read_text(encoding="utf-8"))
        m["sources"]["a"]["url"] = "https://other.example/x.list"
        mp.write_text(json.dumps(m), encoding="utf-8")
        with patch.object(sync, "_http_get", side_effect=AssertionError("no network")):
            self.assertEqual(self.cli("--validate"), 1)

    def test_filtered_output_scope_rules(self):
        svc = {"name": "D", "output": "rules/D.list", "mode": "filtered",
               "listSources": ["a"], "allowed_suffixes": ["demo-suffix.com"],
               "allowed_domains": ["api.demo.com"],
               "local_rules": ["PROCESS-NAME,/Applications/Demo.app/Contents/MacOS/Demo"]}
        cfg = make_config({"a": src(SURGE_A)}, {"d": svc})
        R = sync.Rule
        # 合法：scope 内的 DOMAIN/DOMAIN-SUFFIX + 与 local 完全相等的 PROCESS-NAME
        sync._validate_filtered_output(
            cfg, "d", svc,
            [R("DOMAIN-SUFFIX", "demo-suffix.com"),
             R("DOMAIN", "api.demo.com"),
             R("PROCESS-NAME", "/Applications/Demo.app/Contents/MacOS/Demo")],
        )
        for bad in (
            R("IP-ASN", "20473", ("no-resolve",)),
            R("IP-CIDR", "10.0.0.0/8"),
            R("DOMAIN-KEYWORD", "openai"),
            R("PROCESS-NAME", "other-app"),
            R("DOMAIN-SUFFIX", "evil.com"),
            R("DOMAIN-SUFFIX", "api.demo.com"),  # 应窄化却以 suffix 出现
        ):
            with self.subTest(bad=bad.render()):
                with self.assertRaises(sync.SyncError):
                    sync._validate_filtered_output(cfg, "d", svc, [bad])


# ---------------------------------------------------------------------------
# 后缀裁剪：O(N) 线性、选项语义、extended-matching 不丢失
# ---------------------------------------------------------------------------


class PruneCoverageTests(unittest.TestCase):
    def test_prune_is_linear_not_quadratic(self):
        # 通过统计逐级后缀生成 helper 的调用次数证明 O(N)：每条规则只调用一次，
        # 而非旧实现那样对每条规则遍历整个 suffix 集合（O(N^2)，146k 会卡死）。
        store = {}
        sync._add_rule(store, sync.Rule("DOMAIN-SUFFIX", "example.com"), "s")
        n = 20000
        for i in range(n):
            sync._add_rule(store, sync.Rule("DOMAIN", f"h{i}.example.com"), "s")
        calls = {"n": 0}
        orig = sync._iter_parent_suffixes

        def counting(value, include_self):
            calls["n"] += 1
            yield from orig(value, include_self)

        with patch.object(sync, "_iter_parent_suffixes", counting):
            kept = sync._prune_covered(store)
        self.assertEqual(set(kept), {"DOMAIN-SUFFIX,example.com"})  # 子域全被覆盖
        self.assertEqual(calls["n"], n + 1)  # 每条规则一次 helper 调用 -> 线性

    def test_prune_20k_is_fast_enough(self):
        store = {}
        sync._add_rule(store, sync.Rule("DOMAIN-SUFFIX", "example.com"), "s")
        for i in range(20000):
            sync._add_rule(store, sync.Rule("DOMAIN", f"h{i}.example.com"), "s")
        t0 = time.perf_counter()
        kept = sync._prune_covered(store)
        elapsed = time.perf_counter() - t0
        self.assertEqual(len(kept), 1)
        # 线性实现远低于此；二次实现（2e4^2 ≈ 4e8 次比较）会明显超过。阈值取宽松值防抖动。
        self.assertLess(elapsed, 5.0)

    def test_prune_respects_options_and_keeps_extended_matching(self):
        store = {}
        sync._add_rule(store, sync.Rule("DOMAIN-SUFFIX", "example.com", ("extended-matching",)), "s")
        sync._add_rule(store, sync.Rule("DOMAIN", "api.example.com"), "s")  # 选项不同：保留
        sync._add_rule(store, sync.Rule("DOMAIN", "www.example.com", ("extended-matching",)), "s")
        sync._add_rule(store, sync.Rule("DOMAIN-SUFFIX", "plain.com"), "s")
        sync._add_rule(store, sync.Rule("DOMAIN", "a.plain.com"), "s")
        kept = set(sync._prune_covered(store))
        self.assertIn("DOMAIN-SUFFIX,example.com,extended-matching", kept)
        # 选项不同：不能因「后缀更宽」而裁掉 extended-matching 的窄域，避免错误改变覆盖语义。
        self.assertIn("DOMAIN,api.example.com", kept)
        # 选项相同：同语义下被宽后缀覆盖，可安全裁剪。
        self.assertNotIn("DOMAIN,www.example.com,extended-matching", kept)
        self.assertIn("DOMAIN-SUFFIX,plain.com", kept)
        self.assertNotIn("DOMAIN,a.plain.com", kept)


# ---------------------------------------------------------------------------
# mirror 紧凑 manifest：无逐条 rule_sources，离线校验/篡改失败
# ---------------------------------------------------------------------------


class MirrorManifestTests(BaseCase):
    def _cfg(self, **over):
        svc = {"name": "Mirror", "output": "rules/M.list", "mode": "mirror", "listSources": ["a"]}
        svc.update(over)
        return make_config({"a": src(SURGE_A)}, {"m": svc})

    def test_compact_manifest_and_offline_validate(self):
        self.write_config(self._cfg())
        source = (
            "DOMAIN-SUFFIX,a.com\n"
            "DOMAIN,b.a.com\n"  # 被 a.com 覆盖 -> 裁剪
            "DOMAIN-KEYWORD,ads\n"
            "DOMAIN-WILDCARD,ads-*.a.com\n"
            "IP-ASN,65000,no-resolve\n"
        )
        with self.fetch_patch({SURGE_A: source}):
            self.assertEqual(self.cli(), 0)
        out = self.manifest()["outputs"]["rules/M.list"]
        self.assertEqual(out["mode"], "mirror")
        self.assertEqual(out["source_ids"], ["a"])
        self.assertEqual(out["local_rule_count"], 0)
        self.assertNotIn("rule_sources", out)  # 镜像不逐条存来源映射
        # 146k 场景下 manifest 不会膨胀：其中不含任何逐条 rule key。
        raw = self.read("rules/manifest.json").decode("utf-8")
        self.assertNotIn("DOMAIN-SUFFIX,a.com", raw)
        # 离线 validate（禁止联网）
        with patch.object(sync, "_http_get", side_effect=AssertionError("no network")):
            self.assertEqual(self.cli("--validate"), 0)

    def test_mirror_local_rule_count(self):
        cfg = self._cfg(local_rules=["DOMAIN-SUFFIX,local.example"])
        self.write_config(cfg)
        with self.fetch_patch({SURGE_A: "DOMAIN-SUFFIX,a.com\n"}):
            self.assertEqual(self.cli(), 0)
        out = self.manifest()["outputs"]["rules/M.list"]
        self.assertEqual(out["local_rule_count"], 1)
        self.assertIn("DOMAIN-SUFFIX,local.example", self.output_lines("rules/M.list"))

    def test_validate_rejects_tampered_compact_provenance(self):
        self.write_config(self._cfg())
        with self.fetch_patch({SURGE_A: "DOMAIN-SUFFIX,a.com\n"}):
            self.assertEqual(self.cli(), 0)
        mp = self.root / "rules" / "manifest.json"
        m = json.loads(mp.read_text(encoding="utf-8"))
        m["outputs"]["rules/M.list"]["source_ids"] = ["bogus"]
        mp.write_text(json.dumps(m), encoding="utf-8")
        with patch.object(sync, "_http_get", side_effect=AssertionError("no network")):
            self.assertEqual(self.cli("--validate"), 1)

    def test_validate_rejects_forbidden_rule_sources_on_mirror(self):
        self.write_config(self._cfg())
        with self.fetch_patch({SURGE_A: "DOMAIN-SUFFIX,a.com\n"}):
            self.assertEqual(self.cli(), 0)
        mp = self.root / "rules" / "manifest.json"
        m = json.loads(mp.read_text(encoding="utf-8"))
        m["outputs"]["rules/M.list"]["rule_sources"] = {"DOMAIN-SUFFIX,a.com": ["a"]}
        mp.write_text(json.dumps(m), encoding="utf-8")
        with patch.object(sync, "_http_get", side_effect=AssertionError("no network")):
            self.assertEqual(self.cli("--validate"), 1)

    def test_validate_still_checks_rule_legality(self):
        # 即便篡改者重算了 sha，非法规则行仍必须被解析拒绝（镜像不跳过规则校验）。
        self.write_config(self._cfg())
        with self.fetch_patch({SURGE_A: "DOMAIN-SUFFIX,a.com\n"}):
            self.assertEqual(self.cli(), 0)
        target = self.root / "rules" / "M.list"
        data = (target.read_text(encoding="utf-8") + "FINAL,Proxy\n").encode("utf-8")
        target.write_bytes(data)
        mp = self.root / "rules" / "manifest.json"
        m = json.loads(mp.read_text(encoding="utf-8"))
        m["outputs"]["rules/M.list"]["sha256"] = sync.sha256_hex(data)
        mp.write_text(json.dumps(m), encoding="utf-8")
        with patch.object(sync, "_http_get", side_effect=AssertionError("no network")):
            self.assertEqual(self.cli("--validate"), 1)


class DocstringHonestyTests(unittest.TestCase):
    def test_no_all_or_nothing_overpromise(self):
        doc = sync.__doc__ or ""
        self.assertNotIn("绝不部分更新", doc)
        self.assertIn("不保证", doc)


if __name__ == "__main__":
    unittest.main()
