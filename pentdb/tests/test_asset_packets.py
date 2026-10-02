#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PentDB 资产探测报文下钻单测（stdlib unittest，零依赖）。
运行：python -m unittest test_asset_packets -v

覆盖（拍板：资产明细页「探测报文」区，exec 报文按资产归属展示）：
  tests_for_asset（归属复用 findings_for_asset 同一套 _finding_hosts 规则）：
    1. host 精确归属（jbl.com 场景：parent_ext 直写 host 值）
    2. 逗号多 host（'cn.jbl.com,py.jbl.com' 两资产各自命中）
    3. 数字 id 语义（parent_ext 引 port 观测 -> 解析 host）
    4. 非 test 事件不混入（finding 同 parent_ext 不出现在 test 下钻）
    5. 空 parent_ext 跳过
  exec_packets_for_asset（exec .log -> 报文只读投影）：
    6. 解析成功收集（curl 日志 -> request/response/flags 字段齐）
    7. python 脚本静默跳过（parse 返回 None 不收集不抛）
    8. limit 截断（只取最近 N 条 test 事件所挂证据）
    9. 文件缺失跳过不抛（降级原则）
   10. façade re-export 与排序契约
"""
import argparse
import os
import tempfile
import unittest

# 必须在 import pentdb 前设置；setdefault 保证多模块同跑时与 import 顺序无关
os.environ.setdefault("PENTDB_DB", os.path.join(tempfile.mkdtemp(prefix="pentdb-pkts-test-"), "test.db"))
import pentdb  # noqa: E402
import pdb_assets  # noqa: E402
import pdb_findings  # noqa: E402

PROJ = "pkts-ut"


def ns(**kw):
    base = dict(project=PROJ, ext_id="", kind="note", value="v", title="", detail="",
                note="", source="unittest", parent_ext="", merge_key="", status="new",
                confidence="", severity="", code="", tech="", service="", scope="in",
                auto=False, update=False, origin="agent", stage="",
                req="", resp="", waive_capture="")
    base.update(kw)
    return argparse.Namespace(**base)


def add(**kw):
    if kw.get("kind") == "finding" and not kw.get("req"):
        kw.setdefault("waive_capture", "unittest 无报文建档")  # 归属用例不关心报文，走豁免起草通道
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


def attach_log(event_id, text, note="output curl-probe"):
    """按 exec 证据特征挂一条 .log 全文证据（etype='file'，note 'output ' 开头）。"""
    c = pentdb.connect()
    try:
        eid = pentdb.attach_evidence(c, PROJ, event_id, text=text, note=note)
        c.commit()  # 独立连接：不 commit 关闭即回滚
        return eid
    finally:
        c.close()


def log(cmd, out="", code=0):
    """按 cmd_exec 落盘格式拼 .log 全文（同 test_exec_packet 样本方式）。"""
    return "$ %s\nexit=%s\n\n%s" % (cmd, code, out)


CURL_LOG = log('curl.exe -sk https://h.example.com/p -d "a=1"', '{"ok":true}')
PY_LOG = log(r"C:\AI项目\PentSuite\.venv\Scripts\python.exe C:\tmp\probe_hosts.py",
             "[probe] 25/165")


def tests_of(atype, akey):
    c = pentdb.connect()
    try:
        rows = pentdb.tests_for_asset(c, PROJ, atype, akey)
    finally:
        c.close()
    return rows


def packets_of(atype, akey, limit=10):
    c = pentdb.connect()
    try:
        return pentdb.exec_packets_for_asset(c, PROJ, atype, akey, limit=limit)
    finally:
        c.close()


class AssetTestPackets(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        c = pentdb.connect()
        c.execute("INSERT OR IGNORE INTO projects(name, created_at) VALUES(?,?)", (PROJ, pentdb.now()))
        c.commit()
        c.close()
        # —— 资产底座（对齐真实 jbl 库形态）——
        add(kind="domain", value="jbl.com", origin="human", status="confirmed")
        add(kind="domain", value="cn.jbl.com", origin="human", status="confirmed")
        add(kind="domain", value="py.jbl.com", origin="human", status="confirmed")
        add(kind="port", value="jbl.com:443", service="https", origin="human", status="confirmed")
        add(kind="port", value="10.0.0.5:80", service="http", origin="human", status="confirmed")
        # —— test 事件（exec 单通道落库的典型 parent_ext 三种形态）——
        add(kind="test", value="probe-jbl", title="t-host", source="unittest exec",
            parent_ext="jbl.com", origin="human", status="confirmed")
        add(kind="test", value="probe-multi", title="t-multi", source="unittest exec",
            parent_ext="cn.jbl.com,py.jbl.com", origin="human", status="confirmed")
        add(kind="test", value="probe-numid", title="t-numid", source="unittest exec",
            parent_ext=str(ev_id("port", "10.0.0.5:80")), origin="human",
            status="confirmed")
        add(kind="test", value="probe-orphan", title="t-orphan", source="unittest exec",
            parent_ext="", origin="human", status="confirmed")
        # 非 test 事件：同 parent_ext 不应混入 test 下钻
        add(kind="finding", value="10.0.0.5", title="f-not-test", severity="high",
            parent_ext="jbl.com", origin="human")
        # —— exec 报文证据夹具：可解析 curl 日志 / python 脚本日志 / 可解析再删文件 ——
        t_host = ev_id("test", "probe-jbl")
        cls.ev_ok = attach_log(t_host, CURL_LOG, note="output curl-get")
        cls.ev_py = attach_log(t_host, PY_LOG, note="output python-probe")
        t_num = ev_id("test", "probe-numid")
        cls.ev_del = attach_log(t_num, CURL_LOG, note="output curl-to-delete")
        c = pentdb.connect()
        try:
            row = c.execute(
                "SELECT path FROM evidence WHERE id=?", (cls.ev_del,)).fetchone()
        finally:
            c.close()
        os.remove(row[0])  # 模拟证据文件丢失

    # ---------------- tests_for_asset ----------------

    def test_host_exact_jbl_scenario(self):
        """jbl.com 场景：parent_ext 直写 host 值 -> host 资产精确归属；
        domain 资产按后缀规则额外收编子域 test（cn.jbl.com 归 jbl.com 主域，与 findings 同语义）。"""
        self.assertEqual([r["title"] for r in tests_of("host", "jbl.com")], ["t-host"])
        self.assertEqual([r["title"] for r in tests_of("domain", "jbl.com")],
                         ["t-multi", "t-host"])  # id 倒序
        # 无关 host 零命中
        self.assertEqual(tests_of("host", "other.com"), [])

    def test_comma_multi_host_each_match(self):
        """'cn.jbl.com,py.jbl.com'：两个子域资产各自命中（不能只看首个 token）。"""
        self.assertEqual([r["title"] for r in tests_of("domain", "cn.jbl.com")], ["t-multi"])
        self.assertEqual([r["title"] for r in tests_of("domain", "py.jbl.com")], ["t-multi"])

    def test_numeric_id_semantics(self):
        """数字 id 语义：parent_ext 引 port 观测 -> 剥端口解析为 host。"""
        self.assertEqual([r["title"] for r in tests_of("host", "10.0.0.5")], ["t-numid"])
        self.assertEqual([r["title"] for r in tests_of("service", "10.0.0.5:80")], ["t-numid"])

    def test_non_test_events_not_mixed_in(self):
        """非 test 事件不混入：finding 同 parent_ext 也不出现在 test 下钻里。"""
        rows = tests_of("host", "jbl.com")
        self.assertTrue(rows)
        for r in rows:
            self.assertEqual(r["kind"], "test")
        self.assertNotIn("f-not-test", [r["title"] for r in rows])

    def test_empty_parent_ext_skipped(self):
        """空 parent_ext 的 test 不归属任何资产。"""
        for atype, akey in (("host", "jbl.com"), ("domain", "jbl.com"),
                            ("host", "10.0.0.5"), ("domain", "cn.jbl.com")):
            self.assertNotIn("t-orphan", [r["title"] for r in tests_of(atype, akey)],
                             f"空 parent_ext 不应归属 {atype}/{akey}")

    def test_sorted_desc(self):
        """契约：按 id 倒序（最新在前），与 findings_for_asset 对齐。"""
        ids = [r["id"] for r in tests_of("domain", "jbl.com")]
        self.assertEqual(ids, sorted(ids, reverse=True))

    # ---------------- exec_packets_for_asset ----------------

    def test_parse_ok_collected(self):
        """解析成功收集：curl 日志 -> request/response/flags 全字段齐。"""
        pkts = [p for p in packets_of("host", "jbl.com") if p["ev_id"] == self.ev_ok]
        self.assertEqual(len(pkts), 1)
        p = pkts[0]
        self.assertEqual(p["event_id"], ev_id("test", "probe-jbl"))
        self.assertTrue(p["request"].startswith("POST /p HTTP/1.1"))
        self.assertTrue(p["request"].endswith("\n\na=1"))
        self.assertEqual(p["response"], '{"ok":true}')
        self.assertTrue(p["flags"]["inferred_method"])
        self.assertTrue(p["sha256"])

    def test_python_script_silently_skipped(self):
        """python 脚本日志（非 curl）parse=None：静默跳过，不收集不抛。"""
        evs = [p["ev_id"] for p in packets_of("host", "jbl.com")]
        self.assertNotIn(self.ev_py, evs)

    def test_missing_file_skipped_no_raise(self):
        """证据文件丢失：静默跳过，exec_packets_for_asset 不抛异常。"""
        evs = [p["ev_id"] for p in packets_of("host", "10.0.0.5")]
        self.assertNotIn(self.ev_del, evs)
        self.assertEqual(evs, [])  # 该资产仅有的证据已删，报文区为空

    def test_limit_truncates_to_latest_tests(self):
        """limit 截断：只取最近 N 条 test 事件所挂证据（最旧事件报文不出现）。
        用独立 host limit.jbl.com，避免与 jbl.com 场景断言互相污染。"""
        made = []
        for i in range(12):
            val = f"probe-limit-{i:02d}"
            add(kind="test", value=val, title=f"t-limit-{i:02d}", source="unittest exec",
                parent_ext="limit.jbl.com", origin="human", status="confirmed")
            attach_log(ev_id("test", val), CURL_LOG, note=f"output limit-{i:02d}")
            made.append(val)
        pkts = packets_of("domain", "limit.jbl.com", limit=10)
        self.assertEqual(len(pkts), 10)
        got_events = {p["event_id"] for p in pkts}
        # 最旧两条（最早建的 probe-limit-00/01）不在最近 10 条 test 内
        for stale_val in made[:2]:
            self.assertNotIn(ev_id("test", stale_val), got_events)
        # 最新一条在
        self.assertIn(ev_id("test", made[-1]), got_events)

    def test_empty_when_no_tests(self):
        """归属 test 无证据输出：返回空列表（前端整区不渲染）。"""
        self.assertEqual(packets_of("domain", "py.jbl.com", limit=10), [])

    def test_facade_reexport(self):
        """façade 契约：pentdb.* 与 pdb_*. 本体同一对象。"""
        self.assertIs(pentdb.tests_for_asset, pdb_assets.tests_for_asset)
        self.assertIs(pentdb.exec_packets_for_asset, pdb_findings.exec_packets_for_asset)


if __name__ == "__main__":
    unittest.main()
