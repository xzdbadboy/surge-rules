#!/usr/bin/env python3
"""tests/test_profile.py — 针对 scripts/validate_profile.py 的离线单元测试。

全部使用标准库 unittest；不访问网络；不依赖仓库当前尚未生成的 canonical
services/security 数据。所有 fixtures 都建在临时目录中。

运行：
    python3 -m unittest tests.test_profile -v
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from scripts import validate_profile as vp  # noqa: E402


class BaseCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, rel: str, content: str) -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def url(self, rel: str) -> str:
        return vp.CANONICAL_BASE_URL + rel

    def validate(self, text: str):
        return vp.validate(text, self.root)

    def assertErrorContains(self, result, needle: str):
        joined = "\n".join(result.errors)
        self.assertFalse(result.ok, msg=f"期望校验失败，但通过了。错误：{joined}")
        self.assertIn(needle, joined, msg=f"错误信息未包含 {needle!r}，实际：\n{joined}")


# ---------------------------------------------------------------------------
# 基础解析 / 结构
# ---------------------------------------------------------------------------


class ParseStructureTests(BaseCase):
    def test_minimal_valid_profile(self):
        text = "[Rule]\nDOMAIN-SUFFIX,example.com,PROXY\nFINAL,DIRECT\n"
        result = self.validate(text)
        self.assertTrue(result.ok, msg=result.errors)
        self.assertEqual([r.type for r in result.rules], ["DOMAIN-SUFFIX", "FINAL"])

    def test_comment_and_inline_comment_handling(self):
        text = (
            "[Rule]\n"
            "# 整行注释\n"
            "// 双斜线注释\n"
            "; 分号注释\n"
            "DOMAIN-SUFFIX,example.com,DIRECT // 行尾注释 https://x/y\n"
            "PROCESS-NAME,Telegram,PROXY # 行尾\n"
            "FINAL,DIRECT\n"
        )
        result = self.validate(text)
        self.assertTrue(result.ok, msg=result.errors)
        self.assertEqual(result.rules[0].value, "example.com")
        self.assertEqual(result.rules[0].policy, "DIRECT")
        self.assertEqual(result.rules[1].value, "Telegram")

    def test_missing_rule_section(self):
        result = self.validate("[General]\nfoo=bar\n")
        self.assertErrorContains(result, "[Rule]")

    def test_multiple_rule_sections(self):
        text = "[Rule]\nFINAL,DIRECT\n[Rule]\nFINAL,DIRECT\n"
        result = self.validate(text)
        self.assertErrorContains(result, "多个 [Rule]")

    def test_missing_final(self):
        result = self.validate("[Rule]\nDOMAIN-SUFFIX,a.com,DIRECT\n")
        self.assertErrorContains(result, "缺少 FINAL")

    def test_final_not_last(self):
        text = "[Rule]\nFINAL,DIRECT\nDOMAIN-SUFFIX,a.com,DIRECT\n"
        result = self.validate(text)
        self.assertErrorContains(result, "FINAL 必须")

    def test_final_duplicate(self):
        text = "[Rule]\nFINAL,DIRECT\nFINAL,PROXY\n"
        result = self.validate(text)
        self.assertErrorContains(result, "FINAL 出现")

    def test_final_with_dns_failed_option(self):
        text = "[Rule]\nDOMAIN-SUFFIX,a.com,DIRECT\nFINAL,节点选择,dns-failed\n"
        result = self.validate(text)
        self.assertTrue(result.ok, msg=result.errors)


# ---------------------------------------------------------------------------
# RULE-SET URL / 文件格式
# ---------------------------------------------------------------------------


class RuleSetTests(BaseCase):
    def test_missing_rule_set_file(self):
        text = (
            "[Rule]\n"
            f'RULE-SET,{self.url("rules/security/Reject.list")},REJECT\n'
            "FINAL,DIRECT\n"
        )
        result = self.validate(text)
        self.assertErrorContains(result, "引用文件不存在")

    def test_rule_set_wrong_base_url(self):
        text = (
            "[Rule]\n"
            "RULE-SET,https://raw.githubusercontent.com/other/repo/main/x.list,REJECT\n"
            "FINAL,DIRECT\n"
        )
        result = self.validate(text)
        self.assertErrorContains(result, "必须位于")

    def test_rule_set_dotdot_escape(self):
        text = (
            "[Rule]\n"
            f'RULE-SET,{self.url("rules/../config/evil.list")},REJECT\n'
            "FINAL,DIRECT\n"
        )
        result = self.validate(text)
        self.assertErrorContains(result, "..")

    def test_domainset_content_is_rejected(self):
        # RULE-SET 指向一个实际是 domainset（纯域名、无 FORMAT 头）的文件 -> 必须拒绝。
        self.write("rules/security/Reject.list", "ads.example.com\nfoo.example.org\n")
        text = (
            "[Rule]\n"
            f'RULE-SET,{self.url("rules/security/Reject.list")},REJECT\n'
            "FINAL,DIRECT\n"
        )
        result = self.validate(text)
        self.assertErrorContains(result, "不是合法的 Surge RULE-SET")

    def test_domainset_declared_format_is_rejected(self):
        self.write("rules/security/Reject.list", "# FORMAT: domainset\nDOMAIN-SUFFIX,ads.example\n")
        text = (
            "[Rule]\n"
            f'RULE-SET,{self.url("rules/security/Reject.list")},REJECT\n'
            "FINAL,DIRECT\n"
        )
        result = self.validate(text)
        self.assertErrorContains(result, "声明的格式")

    def test_valid_surge_rule_set_file(self):
        self.write(
            "rules/security/Reject.list",
            "# FORMAT: Surge RULE-SET\nDOMAIN-SUFFIX,ads.example\nDOMAIN,exact.example\n",
        )
        text = (
            "[Rule]\n"
            f'RULE-SET,{self.url("rules/security/Reject.list")},REJECT,extended-matching\n'
            "FINAL,DIRECT\n"
        )
        result = self.validate(text)
        self.assertTrue(result.ok, msg=result.errors)

    def test_builtin_lan_skips_file_check(self):
        text = "[Rule]\nRULE-SET,LAN,DIRECT,no-resolve\nFINAL,DIRECT\n"
        result = self.validate(text)
        self.assertTrue(result.ok, msg=result.errors)


# ---------------------------------------------------------------------------
# 逻辑表达式 / 策略引号
# ---------------------------------------------------------------------------


class LogicAndPolicyTests(BaseCase):
    def test_logic_bracket_missing(self):
        text = (
            "[Rule]\n"
            "AND,((PROTOCOL,UDP),(DEST-PORT,443),REJECT-NO-DROP\n"
            "FINAL,DIRECT\n"
        )
        result = self.validate(text)
        self.assertErrorContains(result, "括号")

    def test_logic_extra_close_bracket(self):
        text = (
            "[Rule]\n"
            "AND,((PROTOCOL,UDP),(DEST-PORT,443))),REJECT-NO-DROP\n"
            "FINAL,DIRECT\n"
        )
        result = self.validate(text)
        self.assertErrorContains(result, "括号")

    def test_logic_valid_nested(self):
        text = (
            "[Rule]\n"
            "AND,((PROCESS-NAME,Telegram),(OR,((IP-CIDR,0.0.0.0/8,no-resolve),"
            "(IP-CIDR,224.0.0.0/4,no-resolve)))),REJECT\n"
            "FINAL,DIRECT\n"
        )
        result = self.validate(text)
        self.assertTrue(result.ok, msg=result.errors)
        self.assertEqual(result.rules[0].type, "AND")

    def test_unquoted_emoji_policy_rejected(self):
        self.write("rules/ai/Muse.list", "PROCESS-NAME,/Applications/Muse.app/\n")
        text = (
            "[Rule]\n"
            f"RULE-SET,{self.url('rules/ai/Muse.list')},🇺🇲 美国节点\n"
            "FINAL,DIRECT\n"
        )
        result = self.validate(text)
        self.assertErrorContains(result, "双引号")

    def test_emoji_only_policy_rejected(self):
        result = self.validate("[Rule]\nDOMAIN-SUFFIX,x.com,🇺🇸\nFINAL,DIRECT\n")
        self.assertErrorContains(result, "双引号")

    def test_quoted_emoji_policy_accepted(self):
        self.write("rules/ai/Muse.list", "PROCESS-NAME,/Applications/Muse.app/\n")
        text = (
            "[Rule]\n"
            f'RULE-SET,{self.url("rules/ai/Muse.list")},"🇺🇲 美国节点"\n'
            "FINAL,DIRECT\n"
        )
        result = self.validate(text)
        self.assertTrue(result.ok, msg=result.errors)
        self.assertEqual(result.rules[0].policy, "🇺🇲 美国节点")

    def test_unknown_type_rejected(self):
        result = self.validate("[Rule]\nBOGUS-TYPE,x,DIRECT\nFINAL,DIRECT\n")
        self.assertErrorContains(result, "不允许的规则类型")


# ---------------------------------------------------------------------------
# 顺序冒烟（fixtures 完全可控）
# ---------------------------------------------------------------------------


class OrderSmokeTests(BaseCase):
    def _make_common_lists(self):
        self.write("rules/ai/Muse.list", "PROCESS-NAME,/Applications/Muse.app/\n")
        self.write("rules/ai/ChatGPT.list", "DOMAIN-SUFFIX,openai.com\n")
        self.write("rules/services/Spotify.list", "DOMAIN-SUFFIX,spotify.com\n")
        self.write("rules/services/GlobalMedia.list", "DOMAIN-SUFFIX,spotify.com\n")
        self.write("rules/services/Proxy.list", "DOMAIN-SUFFIX,openai.com\n")

    def _eval(self, text, context):
        result = self.validate(text)
        self.assertTrue(result.ok, msg=result.errors)
        return vp.evaluate(result.rules, context, self.root)

    def test_lan_before_muse(self):
        self._make_common_lists()
        good = (
            "[Rule]\n"
            "RULE-SET,LAN,DIRECT,no-resolve\n"
            f'RULE-SET,{self.url("rules/ai/Muse.list")},"🇺🇲 美国节点"\n'
            "FINAL,节点选择\n"
        )
        ctx = {"ip": "192.168.1.20", "protocol": "UDP", "port": 443, "process": "/Applications/Muse.app/Contents/MacOS/Muse"}
        self.assertEqual(self._eval(good, ctx), "DIRECT")
        bad = (
            "[Rule]\n"
            f'RULE-SET,{self.url("rules/ai/Muse.list")},"🇺🇲 美国节点"\n'
            "RULE-SET,LAN,DIRECT,no-resolve\n"
            "FINAL,节点选择\n"
        )
        # Muse 若排在 LAN 之前，LAN 私网请求会被误判到美国节点（顺序错误）。
        self.assertEqual(self._eval(bad, ctx), "🇺🇲 美国节点")

    def test_quic_before_muse(self):
        self._make_common_lists()
        good = (
            "[Rule]\n"
            "AND,((PROTOCOL,UDP),(DEST-PORT,443)),REJECT-NO-DROP\n"
            f'RULE-SET,{self.url("rules/ai/Muse.list")},"🇺🇲 美国节点"\n'
            "FINAL,节点选择\n"
        )
        ctx = {"ip": "8.8.8.8", "protocol": "UDP", "port": 443, "process": "/Applications/Muse.app/Contents/MacOS/Muse"}
        self.assertEqual(self._eval(good, ctx), "REJECT-NO-DROP")
        bad = (
            "[Rule]\n"
            f'RULE-SET,{self.url("rules/ai/Muse.list")},"🇺🇲 美国节点"\n'
            "AND,((PROTOCOL,UDP),(DEST-PORT,443)),REJECT-NO-DROP\n"
            "FINAL,节点选择\n"
        )
        self.assertEqual(self._eval(bad, ctx), "🇺🇲 美国节点")

    def test_spotify_before_global_media(self):
        self._make_common_lists()
        good = (
            "[Rule]\n"
            f'RULE-SET,{self.url("rules/services/Spotify.list")},Spotify\n'
            f'RULE-SET,{self.url("rules/services/GlobalMedia.list")},国外媒体\n'
            "FINAL,节点选择\n"
        )
        ctx = {"hostname": "open.spotify.com", "protocol": "TCP", "port": 443}
        self.assertEqual(self._eval(good, ctx), "Spotify")
        bad = (
            "[Rule]\n"
            f'RULE-SET,{self.url("rules/services/GlobalMedia.list")},国外媒体\n'
            f'RULE-SET,{self.url("rules/services/Spotify.list")},Spotify\n'
            "FINAL,节点选择\n"
        )
        self.assertEqual(self._eval(bad, ctx), "国外媒体")

    def test_ai_before_general(self):
        self._make_common_lists()
        good = (
            "[Rule]\n"
            f'RULE-SET,{self.url("rules/ai/ChatGPT.list")},ChatGPT\n'
            f'RULE-SET,{self.url("rules/services/Proxy.list")},节点选择\n'
            "FINAL,节点选择\n"
        )
        ctx = {"hostname": "api.openai.com", "protocol": "TCP", "port": 443}
        self.assertEqual(self._eval(good, ctx), "ChatGPT")
        bad = (
            "[Rule]\n"
            f'RULE-SET,{self.url("rules/services/Proxy.list")},节点选择\n'
            f'RULE-SET,{self.url("rules/ai/ChatGPT.list")},ChatGPT\n'
            "FINAL,节点选择\n"
        )
        self.assertEqual(self._eval(bad, ctx), "节点选择")


# ---------------------------------------------------------------------------
# 完整模板顺序 fixture：覆盖全部 14 个冒烟场景
# ---------------------------------------------------------------------------


class FullScenarioTests(BaseCase):
    def _build_fixture(self):
        lists = {
            "rules/ai/Muse.list": "PROCESS-NAME,/Applications/Muse.app/\n",
            "rules/ai/ChatGPT.list": "DOMAIN-SUFFIX,openai.com\n",
            "rules/ai/Copilot.list": "DOMAIN-SUFFIX,githubcopilot.com\n",
            "rules/ai/Grok.list": "DOMAIN-SUFFIX,grok.com\n",
            "rules/ai/DeepSeek.list": "DOMAIN-SUFFIX,deepseek.com\n",
            "rules/services/GitHub.list": "DOMAIN-SUFFIX,github.com\n",
            "rules/services/Spotify.list": "DOMAIN-SUFFIX,spotify.com\n",
            "rules/services/GlobalMedia.list": "DOMAIN-SUFFIX,spotify.com\n",
            "rules/services/GoogleVoice.list": "DOMAIN-SUFFIX,voice.google.com\n",
            "rules/services/Google.list": "DOMAIN-SUFFIX,google.com\n",
            "rules/services/China.list": "DOMAIN-SUFFIX,example.cn\n",
            "rules/services/ChinaCIDR.list": "IP-CIDR,180" ".101" ".0.0/16,no-resolve\n",
            "rules/security/RejectDomain.list": "DOMAIN-SUFFIX,ads.example\n",
            "rules/security/Reject.list": "DOMAIN-SUFFIX,malware.example\n",
        }
        for rel, content in lists.items():
            self.write(rel, content)

        urls = {rel: self.url(rel) for rel in lists}
        text = f"""[Rule]
DOMAIN-SUFFIX,tailscale.com,DIRECT
IP-CIDR,100.64.0.0/10,DIRECT,no-resolve
IP-CIDR6,fd7a:115c:a1e0::/48,DIRECT,no-resolve
DOMAIN-SUFFIX,ts.net,DIRECT

IP-CIDR,0.0.0.0/32,REJECT,no-resolve
AND,((PROCESS-NAME,Telegram),(OR,((IP-CIDR,0.0.0.0/8,no-resolve),(IP-CIDR,224.0.0.0/4,no-resolve)))),REJECT

RULE-SET,LAN,DIRECT,no-resolve

AND,((PROTOCOL,UDP),(DEST-PORT,443)),REJECT-NO-DROP
AND,((PROTOCOL,UDP),(DOMAIN-SUFFIX,googlevideo.com)),REJECT-NO-DROP

RULE-SET,{urls["rules/security/RejectDomain.list"]},REJECT
RULE-SET,{urls["rules/security/Reject.list"]},REJECT,extended-matching
RULE-SET,{urls["rules/ai/Muse.list"]},"🇺🇲 美国节点"
RULE-SET,{urls["rules/services/GitHub.list"]},节点选择
RULE-SET,{urls["rules/ai/ChatGPT.list"]},ChatGPT
RULE-SET,{urls["rules/ai/Copilot.list"]},智能助理
RULE-SET,{urls["rules/ai/Grok.list"]},智能助理
RULE-SET,{urls["rules/ai/DeepSeek.list"]},DIRECT
RULE-SET,{urls["rules/services/Spotify.list"]},Spotify
RULE-SET,{urls["rules/services/GlobalMedia.list"]},国外媒体
RULE-SET,{urls["rules/services/GoogleVoice.list"]},GoogleVoice
RULE-SET,{urls["rules/services/Google.list"]},谷歌服务
RULE-SET,{urls["rules/services/China.list"]},DIRECT
RULE-SET,LAN,DIRECT
RULE-SET,{urls["rules/services/ChinaCIDR.list"]},DIRECT
FINAL,节点选择,dns-failed
"""
        return text

    def test_unknown_domain_does_not_invent_dns_results(self):
        result = self.validate(self._build_fixture())
        self.assertTrue(result.ok)
        context = {"hostname": "www.baidu.com", "protocol": "TCP", "port": 443}
        self.assertEqual(vp.evaluate(result.rules, context, self.root), "节点选择")

    def test_all_fourteen_scenarios(self):
        text = self._build_fixture()
        result = self.validate(text)
        self.assertTrue(result.ok, msg="\n".join(result.errors))
        for desc, ctx, expected in vp.SMOKE_SCENARIOS:
            actual = vp.evaluate(result.rules, ctx, self.root)
            self.assertEqual(actual, expected, msg=f"{desc}: 期望 {expected!r} 实际 {actual!r}")

    def test_run_smoke_passes(self):
        text = self._build_fixture()
        result = self.validate(text)
        self.assertTrue(result.ok, msg="\n".join(result.errors))
        self.assertEqual(vp.run_smoke(result.rules, self.root), 0)


# ---------------------------------------------------------------------------
# 匹配器细节
# ---------------------------------------------------------------------------


class MatcherUnitTests(unittest.TestCase):
    def test_split_top_level(self):
        self.assertEqual(
            vp.split_top_level('AND,((A,B),(C,D)),POLICY'),
            ["AND", "((A,B),(C,D))", "POLICY"],
        )
        self.assertEqual(vp.split_top_level('X,"a,b",Y'), ["X", '"a,b"', "Y"])

    def test_wildcard(self):
        self.assertTrue(vp._match_simple_rule("DOMAIN-WILDCARD", "ads-*.example.com", (), {"hostname": "ads-1.example.com"}))
        self.assertFalse(vp._match_simple_rule("DOMAIN-WILDCARD", "ads-*.example.com", (), {"hostname": "x.example.com"}))

    def test_process_app_bundle_prefix(self):
        self.assertFalse(vp._match_simple_rule("PROCESS-NAME", "/Applications/Muse.app/", (), {"process": "Muse"}))
        self.assertTrue(
            vp._match_simple_rule(
                "PROCESS-NAME",
                "/Applications/Muse.app/",
                (),
                {"process": "/Applications/Muse.app/Contents/MacOS/Muse"},
            )
        )
        self.assertFalse(vp._match_simple_rule("PROCESS-NAME", "Telegram", (), {"process": "Muse"}))

    def test_process_case_and_full_path_boundaries(self):
        self.assertFalse(vp._match_process("Telegram", "telegram"))
        self.assertFalse(vp._match_process("/Applications/Muse.app/Contents/MacOS/Muse", "/Applications/Muse.app/Contents/MacOS/MuseOther"))
        self.assertFalse(vp._match_process("/Applications/Muse.app/", "/Applications/muse.app/Contents/MacOS/Muse"))
        self.assertTrue(vp._match_process("Muse*", "/Applications/Muse.app/Contents/MacOS/Muse Helper"))

    def test_unsupported_types_never_match(self):
        for rtype, value in (("IP-ASN", "13335"), ("USER-AGENT", "Telegram*"), ("URL-REGEX", "^https://x/")):
            self.assertFalse(
                vp._match_simple_rule(rtype, value, (), {"hostname": "x", "ip": "1.1.1.1"}),
                msg=f"{rtype} 不应在无对应上下文时匹配",
            )


if __name__ == "__main__":
    unittest.main()
