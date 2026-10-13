#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PentDB 面板 server 参数校验单测（stdlib unittest，不起面板）。
运行：python -m unittest test_server_param -v

背景（QA P2）：/api/evidence/view 与 /api/evidence/packet 对非数字 id 抛裸
ValueError，do_GET 无兜底 → 客户端收到连接断开而非 JSON 错误。
修法：模块级 int_param() 安全转换，路由层 None → 400 {"error":"bad id"}。

取舍说明：不起面板（QA 负责实跑），直接单测 int_param 纯函数——路由分支里
`eid = int_param(q,"id"); if eid is None: return 400` 是两行直线代码，
覆盖 int_param 全部边界即等价覆盖该分支行为。
"""
import os
import unittest

import pdb_core
import server


class TestResolvePath(unittest.TestCase):
    """resolve_path（2026-10-13 实证修复）：evidence.path 既有绝对也有相对套件根的，
    读侧统一解析——绝对原样、相对按套件根拼、空串原样。防 CWD 依赖假阳性
    （CLI 在仓库根跑得过、面板进程 CWD 不同就误报 E-101 堵死报告门禁）。"""

    def test_absolute_unchanged(self):
        self.assertEqual(server.resolve_path("C:/x/y.log"), "C:/x/y.log")

    def test_relative_joins_suite_root(self):
        self.assertEqual(server.resolve_path("pentdb/data/x.log"),
                         os.path.join(os.path.dirname(pdb_core.BASE), "pentdb/data/x.log"))

    def test_empty_and_backslash(self):
        self.assertEqual(server.resolve_path(""), "")
        self.assertEqual(server.resolve_path(None), None)
        self.assertEqual(server.resolve_path("pentdb\\data\\x.log"),
                         os.path.join(os.path.dirname(pdb_core.BASE), "pentdb\\data\\x.log"))


class TestIntParam(unittest.TestCase):
    def test_numeric(self):
        self.assertEqual(server.int_param({"id": ["123"]}, "id"), 123)

    def test_negative_numeric(self):
        self.assertEqual(server.int_param({"id": ["-5"]}, "id"), -5)

    def test_non_numeric_returns_none(self):
        self.assertIsNone(server.int_param({"id": ["abc"]}, "id"))

    def test_float_string_returns_none(self):
        self.assertIsNone(server.int_param({"id": ["1.5"]}, "id"))

    def test_none_value_returns_none(self):
        self.assertIsNone(server.int_param({"id": [None]}, "id"))

    def test_missing_uses_default(self):
        self.assertEqual(server.int_param({}, "id"), 0)

    def test_empty_list_returns_none(self):
        # 键存在但值为空列表：属坏输入（parse_qs 实际不会产生，防御性归 None→400）
        self.assertIsNone(server.int_param({"id": []}, "id"))

    def test_custom_default(self):
        self.assertEqual(server.int_param({}, "page", default="1"), 1)

    def test_other_param_name_ignored(self):
        self.assertEqual(server.int_param({"event_id": ["7"]}, "id"), 0)


if __name__ == "__main__":
    unittest.main()
