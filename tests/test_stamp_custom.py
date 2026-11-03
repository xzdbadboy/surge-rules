#!/usr/bin/env python3
"""tests/test_stamp_custom.py — 针对 scripts/stamp_custom.py 的单元测试。"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from scripts import stamp_custom as sc  # noqa: E402
from scripts import sync_rules as sync  # noqa: E402


CANON = "https://github.com/xzdbadboy/surge-rules/blob/main/"


class StampTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "config").mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def write_source(self, rel: str, content: str) -> str:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return rel

    def rule_entry(self, rel: str, name: str = "X", upstreams=None, canonical=None):
        return {
            "path": rel,
            "name": name,
            "upstreams": upstreams or ["本仓库手工维护，无外部同步源"],
            "canonical_sources": canonical or [CANON + rel],
        }

    def write_config(self, rules, version: int = 1) -> Path:
        p = self.root / "config" / "manual_rules.json"
        p.write_text(
            json.dumps({"version": version, "rules": rules}, ensure_ascii=False),
            encoding="utf-8",
        )
        return p

    def build(self, rules, **kwargs):
        return sc.build_stamp_outputs({"version": 1, "rules": rules}, self.root, **kwargs)

    def out_text(self, rel):
        return (self.root / rel).read_text(encoding="utf-8")

    def out_rules(self, rel):
        return [l for l in self.out_text(rel).splitlines() if l and not l.startswith("#")]


class TestGenerate(StampTestBase):
    def test_default_generates_header_and_preserves_rules_and_comments(self):
        rel = self.write_source(
            "rules/custom/trackers/P.list",
            "# > Private Tracker\nDOMAIN-KEYWORD,announce\nDOMAIN-SUFFIX,1ptba.com\n",
        )
        cfg = self.write_config([self.rule_entry(rel, name="PrivateTracker")])
        self.assertEqual(sc.run_default(cfg, self.root), 0)
        text = self.out_text(rel)
        self.assertIn("# 名称：PrivateTracker", text)
        self.assertRegex(text, r"# 更新时间：\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \+08:00")
        self.assertIn("# 上游：本仓库手工维护，无外部同步源", text)
        self.assertIn("# 维护位置：" + CANON + rel, text)
        self.assertRegex(text, r"# 内容校验：sha256:[0-9a-f]{64}")
        # 规则行与原注释保持。
        self.assertIn("# > Private Tracker", text)
        self.assertEqual(
            self.out_rules(rel), ["DOMAIN-KEYWORD,announce", "DOMAIN-SUFFIX,1ptba.com"]
        )

    def test_idempotent_no_rewrite(self):
        rel = self.write_source("rules/custom/trackers/P.list", "DOMAIN-SUFFIX,a.com\n")
        cfg = self.write_config([self.rule_entry(rel)])
        self.assertEqual(sc.run_default(cfg, self.root), 0)
        target = self.root / rel
        before = target.read_bytes()
        before_mtime = target.stat().st_mtime_ns
        self.assertEqual(sc.run_default(cfg, self.root), 0)
        self.assertEqual(target.read_bytes(), before)
        self.assertEqual(target.stat().st_mtime_ns, before_mtime)

    def test_fixed_clock_cross_day_no_change_stable(self):
        rel = self.write_source("rules/custom/trackers/P.list", "DOMAIN-SUFFIX,a.com\n")
        rules = [self.rule_entry(rel)]
        day1 = self.build(rules, now=datetime(2026, 11, 3, 10, 0, 0))
        sync.write_outputs(day1, self.root)  # 落盘，day2 从磁盘读取旧头以沿用时间
        day2 = self.build(rules, now=datetime(2026, 11, 4, 12, 0, 0))
        self.assertEqual(day1[rel], day2[rel])
        self.assertIn("2026-11-03 10:00:00 +08:00", day1[rel])


class TestCheckValidate(StampTestBase):
    def setUp(self):
        super().setUp()
        self.rel = self.write_source(
            "rules/custom/trackers/P.list", "DOMAIN-KEYWORD,announce\nDOMAIN-SUFFIX,1ptba.com\n"
        )
        self.cfg = self.write_config([self.rule_entry(self.rel, name="P")])

    def test_check_missing_then_clean(self):
        self.assertEqual(sc.run_check(self.cfg, self.root), 2)
        self.assertEqual(sc.run_default(self.cfg, self.root), 0)
        self.assertEqual(sc.run_check(self.cfg, self.root), 0)

    def test_validate_passes_then_detects_manual_edit(self):
        self.assertEqual(sc.run_default(self.cfg, self.root), 0)
        self.assertEqual(sc.run_validate(self.cfg, self.root), 0)
        # 手工加规则但没重打时间 -> 旧头哈希与正文不符 -> 不一致。
        target = self.root / self.rel
        target.write_text(target.read_text(encoding="utf-8") + "DOMAIN-SUFFIX,new.com\n", encoding="utf-8")
        self.assertEqual(sc.run_check(self.cfg, self.root), 2)
        self.assertEqual(sc.run_validate(self.cfg, self.root), 1)
        # 校验不写盘。
        self.assertIn("DOMAIN-SUFFIX,new.com", target.read_text(encoding="utf-8"))

    def test_validate_detects_corrupted_header_hash(self):
        self.assertEqual(sc.run_default(self.cfg, self.root), 0)
        target = self.root / self.rel
        import re
        corrupted = re.sub(r"# 内容校验：sha256:[0-9a-f]+", "# 内容校验：sha256:bad", target.read_text(encoding="utf-8"))
        target.write_text(corrupted, encoding="utf-8")
        self.assertEqual(sc.run_validate(self.cfg, self.root), 1)

    def test_config_error_returns_1_not_2(self):
        bad = self.write_config([self.rule_entry("rules/custom/trackers/missing.list")])
        self.assertEqual(sc.run_check(bad, self.root), 1)
        self.assertEqual(sc.run_validate(bad, self.root), 1)


class TestPathValidation(StampTestBase):
    def _expect_invalid(self, rules):
        with self.assertRaises(sc.StampError):
            self.build(rules)

    def test_flat_path_rejected(self):
        self.write_source("rules/custom/Flat.list", "DOMAIN,a.com\n")
        self._expect_invalid([self.rule_entry("rules/custom/Flat.list")])

    def test_too_deep_rejected(self):
        self.write_source("rules/custom/a/b/c.list", "DOMAIN,a.com\n")
        self._expect_invalid([self.rule_entry("rules/custom/a/b/c.list")])

    def test_wrong_top_dir_rejected(self):
        self.write_source("rules/ai/X.list", "DOMAIN,a.com\n")
        self._expect_invalid([self.rule_entry("rules/ai/X.list")])

    def test_absolute_rejected(self):
        self._expect_invalid([self.rule_entry("/etc/x.list")])

    def test_missing_file_rejected(self):
        self._expect_invalid([self.rule_entry("rules/custom/trackers/nope.list")])

    def test_duplicate_rejected(self):
        rel = self.write_source("rules/custom/trackers/P.list", "DOMAIN,a.com\n")
        self._expect_invalid([self.rule_entry(rel), self.rule_entry(rel)])

    @unittest.skipUnless(hasattr(os, "symlink"), "需要 symlink 支持")
    def test_symlink_escape_rejected(self):
        outside = Path(self._tmp.name).parent / "outside.list"
        outside.write_text("DOMAIN,a.com\n", encoding="utf-8")
        link = self.root / "rules" / "custom" / "trackers" / "evil.list"
        link.parent.mkdir(parents=True)
        try:
            os.symlink(outside, link)
        except OSError as exc:  # pragma: no cover
            self.skipTest(f"无法创建符号链接: {exc}")
        self._expect_invalid([self.rule_entry("rules/custom/trackers/evil.list")])

    def test_empty_source_rejected(self):
        self.write_source("rules/custom/trackers/E.list", "# only comment\n")
        with self.assertRaises(sc.StampError):
            self.build([self.rule_entry("rules/custom/trackers/E.list")])

    def test_bad_version_rejected(self):
        rel = self.write_source("rules/custom/trackers/P.list", "DOMAIN,a.com\n")
        cfg = {"version": 99, "rules": [self.rule_entry(rel)]}
        with self.assertRaises(sc.StampError):
            sc.build_stamp_outputs(cfg, self.root)


if __name__ == "__main__":
    unittest.main()
