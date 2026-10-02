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
import unittest

import server


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
