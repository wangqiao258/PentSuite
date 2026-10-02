#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PentDB 资产下钻明细单测（stdlib unittest，零依赖）。运行：python -m unittest test_asset_detail -v

覆盖 findings_for_asset 的归属解析（finding/osint 不参与 rebuild_assets 归并，
归属全靠 parent_ext 经 _resolve_host 解析后按资产类型匹配）：
  1. host 精确匹配（含 parent_ext 数字 id 语义解析）
  2. service 按冒号前 host 匹配
  3. endpoint 按 host 匹配（路径段退化语义：parent_ext 无路径/不匹配仍归 host）
  4. domain 后缀匹配（子域漏洞归主域资产，精确值归自身）
  5. 无 parent_ext 的 finding 不归属任何资产
  6. parent_ext 为 path 文本语义的两跳解析（/path -> path 观测 -> host）
"""
import argparse
import os
import tempfile
import unittest

# 必须在 import pentdb 前设置；setdefault 保证多模块同跑时与 import 顺序无关
os.environ.setdefault("PENTDB_DB", os.path.join(tempfile.mkdtemp(prefix="pentdb-detail-test-"), "test.db"))
import pentdb  # noqa: E402

PROJ = "detail-ut"


def ns(**kw):
    base = dict(project=PROJ, ext_id="", kind="note", value="v", title="", detail="",
                note="", source="unittest", parent_ext="", merge_key="", status="new",
                confidence="", severity="", code="", tech="", service="", scope="in",
                auto=False, update=False, origin="agent", stage="",
                req="", resp="", waive_capture="")
    base.update(kw)
    return argparse.Namespace(**base)


def add(**kw):
    if kw.get("kind") in ("finding", "osint") and not kw.get("req") and not kw.get("resp"):
        kw.setdefault("waive_capture", "unittest 无报文建档")  # 归属用例不关心报文/取证，走豁免起草通道
    pentdb.cmd_add(ns(**kw))


def ev_id(kind, value):
    """取某观测的 record id（数字 id 语义 parent_ext 用）。"""
    c = pentdb.connect()
    try:
        return c.execute(
            "SELECT id FROM raw_events WHERE project=? AND kind=? AND value=? "
            "ORDER BY id LIMIT 1", (PROJ, kind, value)).fetchone()[0]
    finally:
        c.close()


def matched(atype, akey):
    """跑 findings_for_asset，返回命中 title 排序列表（断言用）。"""
    c = pentdb.connect()
    try:
        rows = pentdb.findings_for_asset(c, PROJ, atype, akey)
    finally:
        c.close()
    return sorted(r["title"] for r in rows)


class FindingsForAsset(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        c = pentdb.connect()
        c.execute("INSERT OR IGNORE INTO projects(name, created_at) VALUES(?,?)", (PROJ, pentdb.now()))
        c.commit()
        c.close()
        add(kind="port", value="10.0.0.5:80", service="http", origin="human", status="confirmed")
        add(kind="domain", value="example.com", origin="human", status="confirmed")
        add(kind="domain", value="app.example.com", origin="human", status="confirmed")
        add(kind="path", value="/login", parent_ext="10.0.0.5", origin="human", status="confirmed")
        port_id = ev_id("port", "10.0.0.5:80")
        dom_id = ev_id("domain", "app.example.com")
        # 数字 id 语义：parent_ext 引用 port 观测 -> 解析为 host 10.0.0.5
        add(kind="finding", value="10.0.0.5", title="numid-host", severity="high",
            parent_ext=str(port_id), origin="human")
        # 直接值语义：parent_ext 为 host/path 混合写法
        add(kind="finding", value="10.0.0.5/login", title="hostpath-endpoint", severity="crit",
            parent_ext="10.0.0.5/login", origin="human")
        # 直接值语义：parent_ext 为子域名
        add(kind="finding", value="sub.example.com", title="subdomain-of-base", severity="med",
            parent_ext="sub.example.com", origin="human")
        # 数字 id 语义：parent_ext 引用 domain 观测（osint 同样参与归属）
        add(kind="osint", value="app.example.com", title="numid-domain", severity="low",
            parent_ext=str(dom_id), origin="human")
        # path 文本语义：parent_ext 为 path 观测的 value，两跳解析回 host
        add(kind="finding", value="10.0.0.5/other", title="pathtext-endpoint", severity="med",
            parent_ext="/login", origin="human")
        # —— QA 回归补充（P0-1）：数字 id 两跳 + 逗号多 id 任一命中 ——
        # 真实库同形态：path 事件的 parent_ext 是另一个数字 id（port 观测）
        add(kind="port", value="10.0.0.6:80", service="http", origin="human", status="confirmed")
        add(kind="port", value="10.0.0.7:80", service="http", origin="human", status="confirmed")
        port6_id = ev_id("port", "10.0.0.6:80")
        port7_id = ev_id("port", "10.0.0.7:80")
        add(kind="path", value="/dc/api", parent_ext=str(port6_id),
            origin="human", status="confirmed")
        path6_id = ev_id("path", "/dc/api")
        # ①数字 id -> path -> host 两跳（单 id，host 10.0.0.6）
        add(kind="finding", value="10.0.0.6", title="twohop-path-id", severity="high",
            parent_ext=str(path6_id), origin="human")
        # ②逗号多 id 任一命中：首个 id 解析 10.0.0.6，第二个 id 解析 app.example.com
        add(kind="finding", value="multi", title="multi-id-any-hit", severity="crit",
            parent_ext=f"{path6_id},{dom_id}", origin="human")
        # ③多 id 指向不同 host：两台 host 各自资产都命中
        add(kind="finding", value="cross", title="cross-host-two-id", severity="med",
            parent_ext=f"{path6_id},{port7_id}", origin="human")
        # 无 parent_ext：不归属任何资产
        add(kind="finding", value="orphan", title="no-parent", severity="info", origin="human")

    def test_host_match(self):
        # 数字 id（port）与 host/path 混合写法均解析为同一 host
        self.assertEqual(matched("host", "10.0.0.5"),
                         ["hostpath-endpoint", "numid-host", "pathtext-endpoint"])
        # 无关 host 零命中
        self.assertEqual(matched("host", "10.0.0.9"), [])

    def test_service_match(self):
        # service 资产按 akey 冒号前 host 匹配
        self.assertEqual(matched("service", "10.0.0.5:80"),
                         ["hostpath-endpoint", "numid-host", "pathtext-endpoint"])
        self.assertEqual(matched("service", "10.0.0.5:443"),
                         ["hostpath-endpoint", "numid-host", "pathtext-endpoint"])

    def test_endpoint_host_and_path_match(self):
        # host/path 混合写法强归因；数字 id 与 path 文本（无路径段）退化按 host 匹配——
        # 同主机漏洞在它名下各端点均可见（拍板规则的退化语义）
        self.assertEqual(matched("endpoint", "10.0.0.5/login"),
                         ["hostpath-endpoint", "numid-host", "pathtext-endpoint"])
        self.assertEqual(matched("endpoint", "10.0.0.5/other"),
                         ["hostpath-endpoint", "numid-host", "pathtext-endpoint"])

    def test_domain_suffix_match(self):
        # 子域漏洞归主域资产（'.'+akey 结尾）；精确值归自身；同主域的兄弟子域不互归
        # multi-id-any-hit 的第二个 id 解析出 app.example.com，按后缀规则同归主域
        self.assertEqual(matched("domain", "example.com"),
                         ["multi-id-any-hit", "numid-domain", "subdomain-of-base"])
        self.assertEqual(matched("domain", "app.example.com"), ["multi-id-any-hit", "numid-domain"])
        self.assertEqual(matched("domain", "other.com"), [])

    def test_no_parent_ext_matches_nothing(self):
        for atype, akey in (("host", "10.0.0.5"), ("service", "10.0.0.5:80"),
                            ("endpoint", "10.0.0.5/login"), ("domain", "example.com")):
            self.assertNotIn("no-parent", matched(atype, akey),
                             f"无 parent_ext 的 finding 不应归属 {atype}/{akey}")

    def test_unknown_atype_no_match(self):
        # 防御：非资产类型不匹配任何 finding
        self.assertEqual(matched("note", "10.0.0.5"), [])

    def test_two_hop_numeric_path_id(self):
        """①真实库同形态（QA 回归）：finding -> path 事件 id -> path 的 parent_ext(数字 id) -> host。"""
        self.assertIn("twohop-path-id", matched("host", "10.0.0.6"))
        self.assertIn("twohop-path-id", matched("endpoint", "10.0.0.6/any/subpath"))
        self.assertIn("twohop-path-id", matched("service", "10.0.0.6:80"))

    def test_comma_multi_id_any_hit(self):
        """②逗号多 id 任一解析出的 host 命中即归属：不能只看首个 id。"""
        self.assertIn("multi-id-any-hit", matched("host", "10.0.0.6"))
        self.assertIn("multi-id-any-hit", matched("domain", "app.example.com"))

    def test_multi_id_different_hosts_each_match(self):
        """③finding 横跨两台 host（逗号多 id）：两台各自资产都命中。"""
        self.assertIn("cross-host-two-id", matched("host", "10.0.0.6"))
        self.assertIn("cross-host-two-id", matched("host", "10.0.0.7"))

    def test_resolve_host_untouched(self):
        """约束锁：_resolve_host 本体语义冻结（数字 id->path 只回路径文本；直值不剥端口——
        findings 链路的 svc_keys 上溯只存在于 _finding_hosts 侧）。"""
        self.assertEqual(pentdb._resolve_host("999", {}, {}), "")  # 未知 id
        self.assertEqual(pentdb._resolve_host("1.2.3.4:80", {}, {}), "1.2.3.4:80")

    def test_findings_sorted_desc(self):
        c = pentdb.connect()
        try:
            rows = pentdb.findings_for_asset(c, PROJ, "host", "10.0.0.5")
        finally:
            c.close()
        ids = [r["id"] for r in rows]
        self.assertEqual(ids, sorted(ids, reverse=True), "结果应按 id 倒序（最新在前）")

    def test_empty_project_no_findings(self):
        c = pentdb.connect()
        try:
            self.assertEqual(pentdb.findings_for_asset(c, "detail-ut-empty", "host", "x"), [])
        finally:
            c.close()


if __name__ == "__main__":
    unittest.main()
