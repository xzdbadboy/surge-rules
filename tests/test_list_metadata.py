#!/usr/bin/env python3
"""tests/test_list_metadata.py — 针对 scripts/list_metadata.py 的单元测试。"""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timezone, timedelta

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from scripts import list_metadata as lm  # noqa: E402


BODY = "# FORMAT: Surge RULE-SET\n# 说明：demo\n\nDOMAIN,a.com\n"


class TimestampTests(unittest.TestCase):
    def test_format_is_beijing_fixed(self):
        dt = datetime(2026, 11, 3, 10, 0, 0, tzinfo=timezone(timedelta(hours=8)))
        self.assertEqual(lm.format_timestamp(dt), "2026-11-03 10:00:00 +08:00")

    def test_naive_treated_as_beijing(self):
        self.assertEqual(lm.format_timestamp(datetime(2026, 1, 2, 3, 4, 5)), "2026-01-02 03:04:05 +08:00")

    def test_utc_converted(self):
        dt = datetime(2026, 1, 2, 2, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(lm.format_timestamp(dt), "2026-01-02 10:00:00 +08:00")

    def test_parse_valid_roundtrip(self):
        dt = lm.parse_timestamp("2026-11-03 10:00:00 +08:00")
        self.assertIsNotNone(dt)
        self.assertEqual(lm.format_timestamp(dt), "2026-11-03 10:00:00 +08:00")

    def test_parse_invalid(self):
        for bad in ("", None, "2026-11-03", "2026-02-30 10:00:00 +08:00", "2026-13-01 00:00:00 +08:00"):
            self.assertIsNone(lm.parse_timestamp(bad))


class HeaderTests(unittest.TestCase):
    def test_annotate_renders_all_fields(self):
        out = lm.annotate_list(
            BODY,
            name="Demo",
            upstreams=["https://u/a", "https://u/b"],
            canonical_sources=["rules/ai/Demo.list"],
            now=datetime(2026, 11, 3, 10, 0, 0),
        )
        lines = out.splitlines()
        self.assertEqual(lines[0], "# 名称：Demo")
        self.assertEqual(lines[1], "# 更新时间：2026-11-03 10:00:00 +08:00")
        self.assertIn("# 上游：https://u/a", lines)
        self.assertIn("# 上游：https://u/b", lines)
        self.assertIn("# 维护位置：rules/ai/Demo.list", lines)
        self.assertTrue(any(l.startswith("# 内容校验：sha256:") for l in lines))
        # 原始正文/注释保留
        self.assertIn("# FORMAT: Surge RULE-SET", out)
        self.assertIn("# 说明：demo", out)
        self.assertIn("DOMAIN,a.com", out)

    def test_parse_header_roundtrip(self):
        out = lm.annotate_list(
            BODY, name="Demo", upstreams=["https://u/a"],
            canonical_sources=["rules/ai/Demo.list"], now=datetime(2026, 11, 3, 10, 0, 0),
        )
        info = lm.parse_header(out)
        self.assertEqual(info["name"], "Demo")
        self.assertEqual(info["updated_at"], "2026-11-03 10:00:00 +08:00")
        self.assertEqual(info["upstreams"], ["https://u/a"])
        self.assertEqual(info["canonical_sources"], ["rules/ai/Demo.list"])
        self.assertTrue(info["valid_time"])
        self.assertTrue(info["valid_hash"])

    def test_strip_metadata_removes_only_managed_lines(self):
        out = lm.annotate_list(BODY, name="Demo", upstreams=["https://u/a"], now=datetime(2026, 1, 1))
        self.assertEqual(lm.strip_metadata(out), BODY.strip("\n"))

    def test_empty_upstreams_gets_placeholder(self):
        out = lm.annotate_list("DOMAIN,a.com\n", name="X", upstreams=[], now=datetime(2026, 1, 1))
        self.assertIn("# 上游：", out)
        self.assertIn("无外部上游", out)

    def test_empty_upstreams_are_self_consistent_and_stable(self):
        first = lm.annotate_list(BODY, name="Local", upstreams=[], now=datetime(2026, 1, 1))
        info = lm.parse_header(first)
        actual = lm.compute_content_hash(lm.strip_metadata(first), info["name"], info["upstreams"], info["canonical_sources"])
        self.assertEqual(actual, info["hash"])
        second = lm.annotate_list(BODY, name="Local", upstreams=[], previous_text=first, now=datetime(2026, 1, 2))
        self.assertEqual(second, first)


class HashTests(unittest.TestCase):
    def test_hash_transparent_to_header_time(self):
        now1 = datetime(2026, 11, 3, 10, 0, 0)
        out1 = lm.annotate_list(BODY, name="Demo", upstreams=["https://u/a"], now=now1)
        info = lm.parse_header(out1)
        recomputed = lm.compute_content_hash(lm.strip_metadata(out1), info["name"], info["upstreams"], info["canonical_sources"])
        self.assertEqual(recomputed, info["hash"])

    def test_hash_changes_with_body_and_sources(self):
        base = lm.compute_content_hash(BODY, "Demo", ["https://u/a"], ["rules/ai/Demo.list"])
        self.assertNotEqual(base, lm.compute_content_hash(BODY + "DOMAIN,b\n", "Demo", ["https://u/a"], ["rules/ai/Demo.list"]))
        self.assertNotEqual(base, lm.compute_content_hash(BODY, "Demo", ["https://u/b"], ["rules/ai/Demo.list"]))
        self.assertNotEqual(base, lm.compute_content_hash(BODY, "Demo", ["https://u/a"], ["rules/ai/Other.list"]))


class UpstreamExtractionTests(unittest.TestCase):
    def test_parses_new_and_legacy_but_not_evidence(self):
        text = (
            "# 上游：https://a/x\n"
            "# 来源：https://b/y\n"
            "# 证据：https://c/z\n"
            "# 维护位置：https://d/w\n"
            "DOMAIN,a.com\n"
        )
        self.assertEqual(lm.extract_upstreams(text), ["https://a/x", "https://b/y"])

    def test_dedup_and_manual_note(self):
        text = "# 上游：https://a/x\n# 上游：https://a/x\n# 上游：本仓库手工维护\n"
        self.assertEqual(lm.extract_upstreams(text), ["https://a/x"])


class TimestampPreservationTests(unittest.TestCase):
    def _first(self):
        return lm.annotate_list(
            BODY, name="Demo", upstreams=["https://u/a"],
            canonical_sources=["rules/ai/Demo.list"], now=datetime(2026, 11, 3, 10, 0, 0),
        )

    def test_unchanged_preserves_old_time(self):
        first = self._first()
        second = lm.annotate_list(
            first, name="Demo", upstreams=["https://u/a"],
            canonical_sources=["rules/ai/Demo.list"], previous_text=first,
            now=datetime(2026, 11, 4, 12, 0, 0),
        )
        self.assertEqual(first, second)

    def test_body_change_updates_time(self):
        first = self._first()
        second = lm.annotate_list(
            first + "DOMAIN,b.com\n", name="Demo", upstreams=["https://u/a"],
            canonical_sources=["rules/ai/Demo.list"], previous_text=first,
            now=datetime(2026, 11, 4, 12, 0, 0),
        )
        self.assertIn("2026-11-04 12:00:00 +08:00", second)

    def test_source_change_updates_time(self):
        first = self._first()
        second = lm.annotate_list(
            first, name="Demo", upstreams=["https://u/a", "https://u/new"],
            canonical_sources=["rules/ai/Demo.list"], previous_text=first,
            now=datetime(2026, 11, 4, 12, 0, 0),
        )
        self.assertIn("2026-11-04 12:00:00 +08:00", second)

    def test_body_corruption_not_preserved(self):
        first = self._first()
        # 篡改正文但保留旧头（哈希不自洽）-> 不沿用旧时间。
        corrupted = first.replace("DOMAIN,a.com", "DOMAIN,evil.com")
        second = lm.annotate_list(
            corrupted, name="Demo", upstreams=["https://u/a"],
            canonical_sources=["rules/ai/Demo.list"], previous_text=corrupted,
            now=datetime(2026, 11, 4, 12, 0, 0),
        )
        self.assertIn("2026-11-04 12:00:00 +08:00", second)

    def test_invalid_old_time_not_preserved(self):
        first = self._first()
        broken = first.replace("2026-11-03 10:00:00 +08:00", "not-a-time")
        second = lm.annotate_list(
            broken, name="Demo", upstreams=["https://u/a"],
            canonical_sources=["rules/ai/Demo.list"], previous_text=broken,
            now=datetime(2026, 11, 4, 12, 0, 0),
        )
        self.assertIn("2026-11-04 12:00:00 +08:00", second)

    def test_first_annotation_uses_injected_now(self):
        out = lm.annotate_list(BODY, name="Demo", upstreams=["https://u/a"], now=datetime(2020, 5, 6, 7, 8, 9))
        self.assertIn("2020-05-06 07:08:09 +08:00", out)


if __name__ == "__main__":
    unittest.main()
