#!/usr/bin/env python3
"""tests/test_collections.py — 针对 scripts/build_collections.py 的单元测试。

全部使用临时目录，不依赖仓库主配置、不联网、不写仓库文件。
metadata 头由共享的 scripts/list_metadata.py 负责（集成测试）。

运行：
    python3 -m unittest tests.test_collections -v
    python3 -m unittest discover -s tests -v
"""

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

from scripts import build_collections as bc  # noqa: E402
from scripts import sync_rules as sync  # noqa: E402


def rule_lines(text: str):
    """取输出中的规则行（所有注释行以 '#' 开头，规则行不含 '#'）。"""
    return [ln for ln in text.splitlines() if ln and not ln.startswith("#")]


def updated_line(text: str):
    for ln in text.splitlines():
        if ln.startswith("# 更新时间："):
            return ln
    return None


class CollectionsTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        for d in bc.ALLOWED_SOURCE_DIRS:
            (self.root / "rules" / d).mkdir(parents=True, exist_ok=True)
        (self.root / "config").mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self._tmp.cleanup()

    # --- helpers -------------------------------------------------------
    def write_source(self, rel: str, content: str) -> str:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return rel

    def write_config(self, collections: dict, version: int = 1) -> Path:
        p = self.root / "config" / "collections.json"
        p.write_text(
            json.dumps({"version": version, "collections": collections}, ensure_ascii=False),
            encoding="utf-8",
        )
        return p

    def one_collection(self, out_rel, sources, *, name="测试合集", policy_hint="DIRECT"):
        return {out_rel: {"name": name, "sources": list(sources), "policy_hint": policy_hint}}

    def build(self, config_or_path, *, now=None):
        cfg = config_or_path
        if isinstance(cfg, (Path, str)):
            cfg = bc.load_collections_config(cfg)
        elif isinstance(cfg, dict) and "collections" not in cfg:
            # 允许直接传 {out_rel: spec} 形式的 collections 映射。
            cfg = {"version": 1, "collections": cfg}
        return bc.build_collections_outputs(cfg, self.root, now=now)


class BuildLogicTest(CollectionsTestBase):
    def test_exact_union_dedup_and_deterministic_order(self):
        self.write_source(
            "rules/custom/direct/A.list",
            "DOMAIN-SUFFIX,b.com\nDOMAIN-SUFFIX,a.com\n",
        )
        self.write_source(
            "rules/custom/direct/B.list",
            "DOMAIN-SUFFIX,b.com\nDOMAIN,exact.com\n",
        )
        out = "rules/collections/direct/Union.list"
        files = self.build(self.one_collection(out, [
            "rules/custom/direct/A.list",
            "rules/custom/direct/B.list",
        ]))
        lines = rule_lines(files[out])
        # exact 并集去重：a/b/exact 各一次；按类型顺序 DOMAIN 先于 DOMAIN-SUFFIX。
        self.assertEqual(
            lines,
            ["DOMAIN,exact.com", "DOMAIN-SUFFIX,a.com", "DOMAIN-SUFFIX,b.com"],
        )

    def test_different_options_are_not_collapsed(self):
        self.write_source(
            "rules/custom/direct/A.list", "DOMAIN-SUFFIX,x.com,extended-matching\n"
        )
        self.write_source("rules/custom/direct/B.list", "DOMAIN-SUFFIX,x.com\n")
        out = "rules/collections/direct/Opts.list"
        files = self.build(self.one_collection(out, [
            "rules/custom/direct/A.list",
            "rules/custom/direct/B.list",
        ]))
        lines = sorted(rule_lines(files[out]))
        self.assertIn("DOMAIN-SUFFIX,x.com", lines)
        self.assertIn("DOMAIN-SUFFIX,x.com,extended-matching", lines)
        self.assertEqual(len(lines), 2)

    def test_no_cross_source_suffix_pruning(self):
        self.write_source("rules/custom/direct/A.list", "DOMAIN-SUFFIX,example.com\n")
        self.write_source("rules/custom/direct/B.list", "DOMAIN,www.example.com\n")
        out = "rules/collections/direct/Keep.list"
        files = self.build(self.one_collection(out, [
            "rules/custom/direct/A.list",
            "rules/custom/direct/B.list",
        ]))
        lines = rule_lines(files[out])
        # 更具体的 DOMAIN 不得因被 DOMAIN-SUFFIX 覆盖而被裁剪。
        self.assertIn("DOMAIN-SUFFIX,example.com", lines)
        self.assertIn("DOMAIN,www.example.com", lines)

    def test_upstreams_aggregated_and_hand_source_canonical(self):
        self.write_source(
            "rules/services/Svc.list",
            "# 名称：Svc\n# 来源：https://up.example/a.list\nDOMAIN-SUFFIX,svc.com\n",
        )
        self.write_source(
            "rules/custom/direct/Hand.list",
            "# 手工维护，无外部上游\nDOMAIN-SUFFIX,hand.com\n",
        )
        out = "rules/collections/direct/Up.streams.list"
        files = self.build(self.one_collection(out, [
            "rules/services/Svc.list",
            "rules/custom/direct/Hand.list",
        ]))
        text = files[out]
        # 真实上游聚合。
        self.assertIn("# 上游：https://up.example/a.list", text)
        # 纯手工源补充 canonical github 维护地址作为来源。
        self.assertIn(
            "https://github.com/xzdbadboy/surge-rules/blob/main/rules/custom/direct/Hand.list",
            text,
        )
        # 维护位置 = sources 列表。
        self.assertIn(
            "# 维护位置：rules/services/Svc.list, rules/custom/direct/Hand.list",
            text,
        )
        # policy_hint 与来源类型进入 metadata / 说明。
        self.assertIn("# 策略：DIRECT", text)
        self.assertIn("# 来源类型：生成合并", text)

    def test_fixed_clock_same_content_is_stable(self):
        self.write_source("rules/custom/direct/A.list", "DOMAIN-SUFFIX,a.com\n")
        out = "rules/collections/direct/Stable.list"
        cfg = self.one_collection(out, ["rules/custom/direct/A.list"])
        t1 = datetime(2026, 1, 1, 10, 0, 0)
        t2 = datetime(2026, 1, 2, 10, 0, 0)

        files1 = self.build(cfg, now=t1)
        sync.write_outputs(files1, self.root)
        # 内容未变，即使注入更晚的时钟也应沿用旧时间（不漂移）。
        files2 = self.build(cfg, now=t2)
        self.assertEqual(files1[out], files2[out])
        self.assertEqual(updated_line(files1[out]), updated_line(files2[out]))
        self.assertIn("2026-01-01", updated_line(files1[out]))

    def test_content_change_updates_timestamp(self):
        rel = self.write_source("rules/custom/direct/A.list", "DOMAIN-SUFFIX,a.com\n")
        out = "rules/collections/direct/Changed.list"
        cfg = self.one_collection(out, [rel])
        t1 = datetime(2026, 1, 1, 10, 0, 0)
        t2 = datetime(2026, 1, 2, 10, 0, 0)

        files1 = self.build(cfg, now=t1)
        sync.write_outputs(files1, self.root)
        self.write_source(rel, "DOMAIN-SUFFIX,a.com\nDOMAIN-SUFFIX,b.com\n")
        files2 = self.build(cfg, now=t2)

        self.assertNotEqual(files1[out], files2[out])
        self.assertIn("DOMAIN-SUFFIX,b.com", rule_lines(files2[out]))
        self.assertNotEqual(updated_line(files1[out]), updated_line(files2[out]))
        self.assertIn("2026-01-02", updated_line(files2[out]))

    def test_sources_change_updates_timestamp(self):
        self.write_source("rules/custom/direct/A.list", "DOMAIN-SUFFIX,a.com\n")
        self.write_source("rules/custom/direct/B.list", "DOMAIN-SUFFIX,b.com\n")
        out = "rules/collections/direct/SrcChanged.list"
        t1 = datetime(2026, 1, 1, 10, 0, 0)
        t2 = datetime(2026, 1, 2, 10, 0, 0)

        cfg1 = self.one_collection(out, ["rules/custom/direct/A.list"])
        files1 = self.build(cfg1, now=t1)
        sync.write_outputs(files1, self.root)
        cfg2 = self.one_collection(
            out, ["rules/custom/direct/A.list", "rules/custom/direct/B.list"]
        )
        files2 = self.build(cfg2, now=t2)
        self.assertNotEqual(updated_line(files1[out]), updated_line(files2[out]))


class CommandTest(CollectionsTestBase):
    def _setup_good(self):
        self.write_source("rules/custom/direct/A.list", "DOMAIN-SUFFIX,a.com\n")
        out = "rules/collections/direct/A.list"
        cfg = self.write_config(self.one_collection(out, ["rules/custom/direct/A.list"]))
        return cfg, out

    def test_default_writes_then_idempotent(self):
        cfg, out = self._setup_good()
        self.assertEqual(bc.run_default(cfg, self.root), 0)
        target = self.root / out
        self.assertTrue(target.is_file())
        before = target.read_bytes()
        before_mtime = target.stat().st_mtime_ns
        self.assertEqual(bc.run_default(cfg, self.root), 0)
        self.assertEqual(target.read_bytes(), before)
        self.assertEqual(target.stat().st_mtime_ns, before_mtime)

    def test_check_no_change_returns_0(self):
        cfg, _ = self._setup_good()
        self.assertEqual(bc.run_default(cfg, self.root), 0)
        self.assertEqual(bc.run_check(cfg, self.root), 0)

    def test_check_detects_change_returns_2_without_writing(self):
        cfg, out = self._setup_good()
        self.assertEqual(bc.run_default(cfg, self.root), 0)
        target = self.root / out
        tampered = target.read_text(encoding="utf-8") + "DOMAIN,tampered.com\n"
        target.write_text(tampered, encoding="utf-8")
        self.assertEqual(bc.run_check(cfg, self.root), 2)
        self.assertEqual(target.read_text(encoding="utf-8"), tampered)

    def test_validate_passes_when_consistent(self):
        cfg, _ = self._setup_good()
        self.assertEqual(bc.run_default(cfg, self.root), 0)
        self.assertEqual(bc.run_validate(cfg, self.root), 0)

    def test_validate_fails_on_inconsistency_without_writing(self):
        cfg, out = self._setup_good()
        self.assertEqual(bc.run_default(cfg, self.root), 0)
        target = self.root / out
        tampered = target.read_text(encoding="utf-8") + "DOMAIN,x.com\n"
        target.write_text(tampered, encoding="utf-8")
        self.assertEqual(bc.run_validate(cfg, self.root), 1)
        self.assertEqual(target.read_text(encoding="utf-8"), tampered)

    def test_check_config_error_returns_1_not_2(self):
        cfg = self.write_config(
            self.one_collection(
                "rules/collections/direct/A.list", ["rules/custom/direct/missing.list"]
            )
        )
        self.assertEqual(bc.run_check(cfg, self.root), 1)
        self.assertEqual(bc.run_validate(cfg, self.root), 1)

    def test_missing_config_returns_1(self):
        missing = self.root / "config" / "nope.json"
        self.assertEqual(bc.run_default(missing, self.root), 1)
        self.assertEqual(bc.run_check(missing, self.root), 1)
        self.assertEqual(bc.run_validate(missing, self.root), 1)


class FailClosedTest(CollectionsTestBase):
    def test_one_bad_source_aborts_all_writes(self):
        self.write_source("rules/custom/direct/A.list", "DOMAIN-SUFFIX,a.com\n")
        self.write_source("rules/custom/direct/Bad.list", "BOGUS-TYPE,x.com\n")
        out_good = "rules/collections/direct/Good.list"
        out_bad = "rules/collections/direct/Bad.list"
        cfg = self.write_config({
            out_good: {
                "name": "好合集", "sources": ["rules/custom/direct/A.list"], "policy_hint": "DIRECT"
            },
            out_bad: {
                "name": "坏合集", "sources": ["rules/custom/direct/Bad.list"], "policy_hint": "PROXY"
            },
        })
        self.assertEqual(bc.run_default(cfg, self.root), 1)
        # 整轮 fail closed：好合集也不得写盘。
        self.assertFalse((self.root / out_good).exists())
        self.assertFalse((self.root / out_bad).exists())

    def test_empty_source_aborts_all_writes(self):
        self.write_source("rules/custom/direct/A.list", "DOMAIN-SUFFIX,a.com\n")
        self.write_source("rules/custom/direct/Empty.list", "# 只有注释\n\n")
        out = "rules/collections/direct/Out.list"
        cfg = self.write_config(self.one_collection(out, [
            "rules/custom/direct/A.list", "rules/custom/direct/Empty.list",
        ]))
        self.assertEqual(bc.run_default(cfg, self.root), 1)
        self.assertFalse((self.root / out).exists())

    def test_missing_source_aborts(self):
        self.write_source("rules/custom/direct/A.list", "DOMAIN-SUFFIX,a.com\n")
        out = "rules/collections/direct/Out.list"
        cfg = self.write_config(self.one_collection(out, [
            "rules/custom/direct/A.list", "rules/custom/direct/not-there.list",
        ]))
        self.assertEqual(bc.run_default(cfg, self.root), 1)
        self.assertFalse((self.root / out).exists())


class ValidationTest(CollectionsTestBase):
    def _cfg(self, out_rel, source_rel="rules/custom/direct/A.list"):
        self.write_source("rules/custom/direct/A.list", "DOMAIN-SUFFIX,a.com\n")
        return self.write_config(self.one_collection(out_rel, [source_rel]))

    def test_unknown_top_level_field_rejected(self):
        self.write_source("rules/custom/direct/A.list", "DOMAIN-SUFFIX,a.com\n")
        cfg = {
            "version": 1,
            "collections": self.one_collection(
                "rules/collections/direct/A.list", ["rules/custom/direct/A.list"]
            ),
            "surprise": True,
        }
        with self.assertRaises(bc.CollectionsError):
            bc.validate_collections_config(cfg, self.root)

    def test_unknown_collection_field_rejected(self):
        self.write_source("rules/custom/direct/A.list", "DOMAIN-SUFFIX,a.com\n")
        cfg = {"version": 1, "collections": {
            "rules/collections/direct/A.list": {
                "name": "n", "sources": ["rules/custom/direct/A.list"],
                "policy_hint": "DIRECT", "extra": "x",
            }
        }}
        with self.assertRaises(bc.CollectionsError):
            bc.validate_collections_config(cfg, self.root)

    def test_bad_output_paths_rejected(self):
        self.write_source("rules/custom/direct/A.list", "DOMAIN-SUFFIX,a.com\n")
        bad_paths = [
            "/tmp/abs.list",
            "rules/collections/direct/../x.list",
            "rules/custom/direct/X.list",          # 前缀不是 collections
            "rules/collections/a/b/X.list",         # 层级过深
            "rules/collections/direct/X.txt",       # 非 .list
            "rules/collections/Direct/X.list",      # 分类目录非小写
        ]
        for bad in bad_paths:
            with self.subTest(path=bad):
                cfg = {"version": 1, "collections": self.one_collection(
                    bad, ["rules/custom/direct/A.list"])}
                with self.assertRaises(bc.CollectionsError):
                    bc.validate_collections_config(cfg, self.root)

    def test_output_case_collision_rejected(self):
        self.write_source("rules/custom/direct/A.list", "DOMAIN-SUFFIX,a.com\n")
        cfg = {"version": 1, "collections": {
            "rules/collections/direct/a.list": {
                "name": "n", "sources": ["rules/custom/direct/A.list"], "policy_hint": "DIRECT"},
            "rules/collections/direct/A.list": {
                "name": "n", "sources": ["rules/custom/direct/A.list"], "policy_hint": "DIRECT"},
        }}
        with self.assertRaises(bc.CollectionsError):
            bc.validate_collections_config(cfg, self.root)

    def test_source_under_collections_rejected(self):
        self.write_source("rules/custom/direct/A.list", "DOMAIN-SUFFIX,a.com\n")
        self.write_source("rules/collections/direct/Existing.list", "DOMAIN-SUFFIX,b.com\n")
        cfg = {"version": 1, "collections": self.one_collection(
            "rules/collections/direct/Out.list",
            ["rules/collections/direct/Existing.list"],
        )}
        with self.assertRaises(bc.CollectionsError):
            bc.validate_collections_config(cfg, self.root)

    def test_flat_custom_source_rejected(self):
        self.write_source("rules/custom/Flat.list", "DOMAIN-SUFFIX,a.com\n")
        cfg = {"version": 1, "collections": self.one_collection(
            "rules/collections/direct/Out.list", ["rules/custom/Flat.list"]
        )}
        with self.assertRaises(bc.CollectionsError):
            bc.validate_collections_config(cfg, self.root)

    def test_directory_source_rejected(self):
        (self.root / "rules" / "services" / "Dir.list").mkdir(parents=True)
        cfg = {"version": 1, "collections": self.one_collection(
            "rules/collections/direct/Out.list", ["rules/services/Dir.list"]
        )}
        with self.assertRaises(bc.CollectionsError):
            bc.validate_collections_config(cfg, self.root)

    def test_symlink_source_escape_rejected(self):
        outside_dir = tempfile.TemporaryDirectory()
        self.addCleanup(outside_dir.cleanup)
        outside = Path(outside_dir.name) / "evil.list"
        outside.write_text("DOMAIN-SUFFIX,evil.com\n", encoding="utf-8")
        link = self.root / "rules" / "custom" / "direct" / "Evil.list"
        link.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(outside, link)
        cfg = {"version": 1, "collections": self.one_collection(
            "rules/collections/direct/Out.list", ["rules/custom/direct/Evil.list"]
        )}
        with self.assertRaises(bc.CollectionsError):
            bc.validate_collections_config(cfg, self.root)

    def test_target_that_resolves_to_source_rejected(self):
        src = self.write_source("rules/custom/direct/A.list", "DOMAIN-SUFFIX,a.com\n")
        target = self.root / "rules" / "collections" / "direct" / "X.list"
        target.parent.mkdir(parents=True, exist_ok=True)
        os.symlink((self.root / src).resolve(), target)
        cfg = {"version": 1, "collections": self.one_collection(
            "rules/collections/direct/X.list", [src]
        )}
        with self.assertRaises(bc.CollectionsError):
            bc.validate_collections_config(cfg, self.root)


if __name__ == "__main__":
    unittest.main()
