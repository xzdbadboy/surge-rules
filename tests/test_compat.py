#!/usr/bin/env python3
"""tests/test_compat.py — 针对 scripts/build_compat.py 的单元测试（标准库 unittest）。

全部使用临时目录，不依赖仓库主配置、不联网、不写仓库文件。

运行：
    python3 -m unittest tests.test_compat -v
    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from scripts import build_compat as bc  # noqa: E402
from scripts import sync_rules as sync  # noqa: E402


class CompatTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        for d in bc.ALLOWED_SOURCE_DIRS:
            (self.root / "rules" / d).mkdir(parents=True, exist_ok=True)
        (self.root / "config").mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    # --- helpers -------------------------------------------------------
    def write_source(self, rel: str, content: str) -> str:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return rel

    def write_config(self, aliases: dict, version: int = 1) -> Path:
        p = self.root / "config" / "compatibility.json"
        p.write_text(
            json.dumps({"version": version, "aliases": aliases}, ensure_ascii=False),
            encoding="utf-8",
        )
        return p

    def out_text(self, name: str) -> str:
        return (self.root / name).read_text(encoding="utf-8")

    def out_rules(self, name: str):
        return [
            line
            for line in self.out_text(name).splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]

    def build(self, aliases: dict, **kwargs):
        cfg = {"version": 1, "aliases": aliases}
        return bc.build_compat_outputs(cfg, self.root, **kwargs)


class TestMergeAndDedup(CompatTestBase):
    def test_manual_rules_preserved_and_exact_dedup(self):
        self.write_source("rules/custom/misc/A.list", "DOMAIN-SUFFIX,foo.com\nDOMAIN,bar.com\n")
        self.write_source("rules/custom/misc/B.list", "DOMAIN,bar.com\nDOMAIN-SUFFIX,baz.com\n")
        files = self.build({"Mix.list": ["rules/custom/misc/A.list", "rules/custom/misc/B.list"]})
        rules = [
            l for l in files["Mix.list"].splitlines() if l and not l.startswith("#")
        ]
        # 去重后按 type 顺序 + value 排序；bar.com 只出现一次。
        self.assertEqual(
            rules,
            ["DOMAIN,bar.com", "DOMAIN-SUFFIX,baz.com", "DOMAIN-SUFFIX,foo.com"],
        )

    def test_aggregate_excludes_never_present_shared_and_ip(self):
        self.write_source(
            "rules/ai/ChatGPT.list",
            "DOMAIN,openai.com\nDOMAIN-SUFFIX,chatgpt.com\n",
        )
        self.write_source("rules/ai/Claude.list", "DOMAIN-SUFFIX,anthropic.com\n")
        files = self.build(
            {"AIGC.list": ["rules/ai/ChatGPT.list", "rules/ai/Claude.list"]}
        )
        rules = [
            l for l in files["AIGC.list"].splitlines() if l and not l.startswith("#")
        ]
        self.assertEqual(len(rules), 3)
        self.assertEqual(
            set(rules),
            {"DOMAIN,openai.com", "DOMAIN-SUFFIX,chatgpt.com", "DOMAIN-SUFFIX,anthropic.com"},
        )
        joined = "\n".join(rules)
        for forbidden in ("cdn.auth0.com", "IP-CIDR", "IP-CIDR6", "PROCESS-NAME", "node"):
            self.assertNotIn(forbidden, joined)

    def test_options_preserved_and_not_suffix_pruned(self):
        self.write_source(
            "rules/custom/misc/Opt.list",
            "\n".join(
                [
                    "DOMAIN-SUFFIX,example.com",
                    "DOMAIN-SUFFIX,example.com,extended-matching",
                    "DOMAIN,sub.example.com",
                    "IP-CIDR,203.0.113.0/24,no-resolve",
                    "",
                ]
            ),
        )
        files = self.build({"Opt.list": ["rules/custom/misc/Opt.list"]})
        rules = [
            l for l in files["Opt.list"].splitlines() if l and not l.startswith("#")
        ]
        self.assertIn("DOMAIN-SUFFIX,example.com", rules)
        self.assertIn("DOMAIN-SUFFIX,example.com,extended-matching", rules)
        self.assertIn("DOMAIN,sub.example.com", rules)
        self.assertIn("IP-CIDR,203.0.113.0/24,no-resolve", rules)
        self.assertEqual(len(rules), 4)

    def test_header_has_metadata_and_is_stable(self):
        self.write_source(
            "rules/ai/H.list",
            "# 名称：H\n# 上游：https://up.example/h.list\n\nDOMAIN,a.com\n",
        )
        files = self.build({"H.list": ["rules/ai/H.list"]})
        text = files["H.list"]
        self.assertIn("# 名称：H", text)
        self.assertRegex(text, r"# 更新时间：\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \+08:00")
        self.assertIn("# 上游：https://up.example/h.list", text)
        self.assertIn("# 维护位置：rules/ai/H.list", text)
        self.assertRegex(text, r"# 内容校验：sha256:[0-9a-f]{64}")


class TestLocalProcessAndMuse(CompatTestBase):
    def test_local_muse_process_generated_when_mapped(self):
        self.write_source(
            "rules/ai/Muse.list", "PROCESS-NAME,/Applications/Muse.app/\n"
        )
        cfg = self.write_config({"Muse.list": ["rules/ai/Muse.list"]})
        rc = bc.run_default(cfg, self.root)
        self.assertEqual(rc, 0)
        self.assertTrue((self.root / "Muse.list").is_file())
        self.assertIn("PROCESS-NAME,/Applications/Muse.app/", self.out_rules("Muse.list"))


class TestAllOrNothingAndErrors(CompatTestBase):
    def test_missing_canonical_writes_no_alias_at_all(self):
        self.write_source("rules/custom/misc/Good.list", "DOMAIN,good.com\n")
        cfg = self.write_config(
            {
                "Good.list": ["rules/custom/misc/Good.list"],
                "Bad.list": ["rules/custom/misc/DoesNotExist.list"],
            }
        )
        rc = bc.run_default(cfg, self.root)
        self.assertEqual(rc, 1)
        self.assertFalse((self.root / "Good.list").exists())
        self.assertFalse((self.root / "Bad.list").exists())

    def test_invalid_canonical_line_writes_no_alias(self):
        self.write_source("rules/custom/misc/Good.list", "DOMAIN,good.com\n")
        self.write_source("rules/custom/misc/Broken.list", "DOMAIN-SUFFIX, bad domain \n")
        cfg = self.write_config(
            {
                "Good.list": ["rules/custom/misc/Good.list"],
                "Broken.list": ["rules/custom/misc/Broken.list"],
            }
        )
        rc = bc.run_default(cfg, self.root)
        self.assertEqual(rc, 1)
        self.assertFalse((self.root / "Good.list").exists())
        self.assertFalse((self.root / "Broken.list").exists())

    def test_source_with_only_comments_fails(self):
        self.write_source("rules/custom/misc/Empty.list", "# only a comment\n# another\n")
        cfg = self.write_config({"Empty.list": ["rules/custom/misc/Empty.list"]})
        self.assertEqual(bc.run_default(cfg, self.root), 1)
        self.assertFalse((self.root / "Empty.list").exists())


class TestPathValidation(CompatTestBase):
    def _expect_invalid(self, aliases: dict):
        with self.assertRaises(bc.CompatError):
            self.build(aliases)

    def test_absolute_source_rejected(self):
        self._expect_invalid({"X.list": ["/etc/passwd.list"]})

    def test_dotdot_source_rejected(self):
        self.write_source("rules/custom/misc/ok.list", "DOMAIN,a.com\n")
        self._expect_invalid({"X.list": ["rules/custom/../scripts/x.list"]})

    def test_root_alias_self_reference_rejected(self):
        self._expect_invalid({"AIGC.list": ["ChatGPT.list"]})

    def test_source_must_be_in_allowed_dirs(self):
        self.write_source("rules/other/X.list", "DOMAIN,a.com\n")
        self._expect_invalid({"X.list": ["rules/other/X.list"]})

    def test_flat_custom_source_rejected(self):
        # custom 规范源必须分类，扁平 rules/custom/foo.list 不可作来源。
        self.write_source("rules/custom/Flat.list", "DOMAIN,a.com\n")
        self._expect_invalid({"X.list": ["rules/custom/Flat.list"]})

    def test_missing_source_rejected(self):
        self._expect_invalid({"X.list": ["rules/ai/missing.list"]})

    @unittest.skipUnless(hasattr(os, "symlink"), "需要 symlink 支持")
    def test_symlink_escaping_root_rejected(self):
        outside = Path(self._tmp.name).parent / "outside-target.list"
        outside.write_text("DOMAIN,evil.com\n", encoding="utf-8")
        link = self.root / "rules" / "ai" / "evil.list"
        try:
            os.symlink(outside, link)
        except OSError as exc:  # pragma: no cover
            self.skipTest(f"无法创建符号链接: {exc}")
        self._expect_invalid({"X.list": ["rules/ai/evil.list"]})

    def test_duplicate_target_case_conflict_rejected(self):
        self.write_source("rules/custom/misc/a.list", "DOMAIN,a.com\n")
        self._expect_invalid(
            {
                "Widget.list": ["rules/custom/misc/a.list"],
                "widget.list": ["rules/custom/misc/a.list"],
            }
        )

    def test_target_with_path_separator_rejected(self):
        self.write_source("rules/custom/misc/a.list", "DOMAIN,a.com\n")
        # rules/ai/a.list 不是允许的目标层（仅根或 rules/custom/foo.list）。
        self._expect_invalid({"rules/ai/a.list": ["rules/custom/misc/a.list"]})

    def test_target_too_deep_rejected(self):
        self.write_source("rules/custom/misc/a.list", "DOMAIN,a.com\n")
        self._expect_invalid({"rules/custom/sub/a.list": ["rules/custom/misc/a.list"]})

    def test_target_dotdot_rejected(self):
        self.write_source("rules/custom/misc/a.list", "DOMAIN,a.com\n")
        self._expect_invalid({"../escape.list": ["rules/custom/misc/a.list"]})

    def test_target_must_end_with_list(self):
        self.write_source("rules/custom/misc/a.list", "DOMAIN,a.com\n")
        self._expect_invalid({"Widget.txt": ["rules/custom/misc/a.list"]})

    def test_bad_version_rejected(self):
        self.write_source("rules/custom/misc/a.list", "DOMAIN,a.com\n")
        cfg = {"version": 99, "aliases": {"A.list": ["rules/custom/misc/a.list"]}}
        with self.assertRaises(bc.CompatError):
            bc.build_compat_outputs(cfg, self.root)

    @unittest.skipUnless(hasattr(os, "symlink"), "需要 symlink 支持")
    def test_source_resolving_onto_target_rejected(self):
        # 来源符号链接解析到目标路径 -> 覆盖/循环风险 -> 拒绝。
        self.write_source("rules/custom/misc/real.list", "DOMAIN,a.com\n")
        link = self.root / "rules" / "ai" / "alias-target.list"
        try:
            os.symlink(self.root / "rules" / "custom" / "Alias.list", link)
        except OSError as exc:  # pragma: no cover
            self.skipTest(f"无法创建符号链接: {exc}")
        # 目标 rules/custom/Alias.list；来源解析后指向同一路径。
        self._expect_invalid({"rules/custom/Alias.list": ["rules/ai/alias-target.list"]})


class TestNestedTarget(CompatTestBase):
    def test_nested_custom_target_allowed(self):
        self.write_source("rules/custom/misc/A.list", "DOMAIN,a.com\n")
        cfg = self.write_config({"rules/custom/Alias.list": ["rules/custom/misc/A.list"]})
        self.assertEqual(bc.run_default(cfg, self.root), 0)
        target = self.root / "rules" / "custom" / "Alias.list"
        self.assertTrue(target.is_file())
        self.assertIn("DOMAIN,a.com", self.out_rules("rules/custom/Alias.list"))


class TestCheckAndValidate(CompatTestBase):
    def setUp(self):
        super().setUp()
        self.write_source("rules/custom/misc/A.list", "DOMAIN,a.com\nDOMAIN-SUFFIX,b.com\n")
        self.cfg = self.write_config({"Alias.list": ["rules/custom/misc/A.list"]})

    def test_check_no_write_when_missing_then_clean(self):
        self.assertEqual(bc.run_check(self.cfg, self.root), 2)
        self.assertFalse((self.root / "Alias.list").exists())
        self.assertEqual(bc.run_default(self.cfg, self.root), 0)
        self.assertEqual(bc.run_check(self.cfg, self.root), 0)

    def test_default_idempotent_same_content_and_mtime(self):
        self.assertEqual(bc.run_default(self.cfg, self.root), 0)
        target = self.root / "Alias.list"
        before = target.read_bytes()
        before_mtime = target.stat().st_mtime_ns
        self.assertEqual(bc.run_default(self.cfg, self.root), 0)
        self.assertEqual(target.read_bytes(), before)
        self.assertEqual(target.stat().st_mtime_ns, before_mtime)

    def test_check_detects_change_without_writing(self):
        self.assertEqual(bc.run_default(self.cfg, self.root), 0)
        target = self.root / "Alias.list"
        tampered = target.read_text(encoding="utf-8") + "DOMAIN,tampered.com\n"
        target.write_text(tampered, encoding="utf-8")
        self.assertEqual(bc.run_check(self.cfg, self.root), 2)
        self.assertEqual(target.read_text(encoding="utf-8"), tampered)

    def test_validate_passes_when_consistent(self):
        self.assertEqual(bc.run_default(self.cfg, self.root), 0)
        self.assertEqual(bc.run_validate(self.cfg, self.root), 0)

    def test_validate_fails_when_inconsistent(self):
        self.assertEqual(bc.run_default(self.cfg, self.root), 0)
        target = self.root / "Alias.list"
        target.write_text(target.read_text(encoding="utf-8") + "DOMAIN,x.com\n", encoding="utf-8")
        self.assertEqual(bc.run_validate(self.cfg, self.root), 1)
        self.assertIn("DOMAIN,x.com", target.read_text(encoding="utf-8"))

    def test_check_returns_1_on_config_error_not_2(self):
        bad = self.write_config({"Alias.list": ["rules/custom/misc/missing.list"]})
        self.assertEqual(bc.run_check(bad, self.root), 1)
        self.assertEqual(bc.run_validate(bad, self.root), 1)

    def test_missing_config_file_error(self):
        self.assertEqual(bc.run_default(self.root / "config" / "nope.json", self.root), 1)


class TestMetadataTimestamps(CompatTestBase):
    def setUp(self):
        super().setUp()
        self.write_source("rules/ai/A.list", "# 上游：https://up/a\n\nDOMAIN-SUFFIX,demo.com\n")

    def test_fixed_clock_cross_day_no_change_stable(self):
        from datetime import datetime

        cfg = {"version": 1, "aliases": {"Alias.list": ["rules/ai/A.list"]}}
        day1 = bc.build_compat_outputs(cfg, self.root, now=datetime(2026, 11, 3, 9, 0, 0))
        day2 = bc.build_compat_outputs(
            cfg, self.root, previous_outputs=day1, now=datetime(2026, 11, 4, 18, 0, 0)
        )
        self.assertEqual(day1["Alias.list"], day2["Alias.list"])
        self.assertIn("2026-11-03 09:00:00 +08:00", day1["Alias.list"])

    def test_source_change_updates_time(self):
        from datetime import datetime

        cfg = {"version": 1, "aliases": {"Alias.list": ["rules/ai/A.list"]}}
        day1 = bc.build_compat_outputs(cfg, self.root, now=datetime(2026, 11, 3, 9, 0, 0))
        self.write_source("rules/ai/A.list", "# 上游：https://up/a\n\nDOMAIN-SUFFIX,demo.com\nDOMAIN,demo.org\n")
        day2 = bc.build_compat_outputs(
            cfg, self.root, previous_outputs=day1, now=datetime(2026, 11, 4, 18, 0, 0)
        )
        self.assertIn("2026-11-04 18:00:00 +08:00", day2["Alias.list"])

    def test_manual_source_upstream_is_canonical_url_with_note(self):
        self.write_source("rules/custom/misc/Manual.list", "# 手工\nDOMAIN,m.com\n")
        files = self.build({"Manual.list": ["rules/custom/misc/Manual.list"]})
        text = files["Manual.list"]
        self.assertIn(bc.CANONICAL_BASE_URL + "rules/custom/misc/Manual.list", text)
        self.assertIn("手工维护", text)

    def test_corrupt_header_detected_by_check_and_validate(self):
        import re

        cfg = self.write_config({"Alias.list": ["rules/ai/A.list"]})
        self.assertEqual(bc.run_default(cfg, self.root), 0)
        target = self.root / "Alias.list"
        target.write_text(
            re.sub(r"# 更新时间：.*", "# 更新时间：坏时间", target.read_text(encoding="utf-8")),
            encoding="utf-8",
        )
        self.assertEqual(bc.run_check(cfg, self.root), 2)
        self.assertEqual(bc.run_validate(cfg, self.root), 1)


if __name__ == "__main__":
    unittest.main()
