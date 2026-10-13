#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pentest 报告「复测记录」节单测（stdlib unittest，零依赖）。
运行：python -m unittest test_report_retests -v

背景（2026-10-13 待审队列改造，用户拍板"test 确认要真下游"）：
确认一条 test = 人审采信，该结论进入报告「复测记录」节——否则队列里"确认"零下游、
审了不知道有什么用。本文件锁定这个真下游的渲染规则：

  1. confirmed test 进报告，按母 finding 分组，含结论（note 全文）/归因/来源/证据指针
  2. new（未确认）test 不进报告——未采信不进证据链
  3. 无母 finding 的 confirmed test 归「未关联发现的复测记录」尾组
  4. 节号顺延：有复测记录时 复测计划=5/附录=6；无复测记录时 复测计划=4/附录=5
  5. _retest_parent 解析语义：parent_ext 只认数字 id 且 kind=finding，取首个可解析
  6. plan-review 落库即 confirmed（记录不是人审待办）由 test_review.py 锁定
"""
import argparse
import os
import tempfile
import unittest

os.environ.setdefault("PENTDB_DB", os.path.join(tempfile.mkdtemp(prefix="pentdb-report-rt-"), "test.db"))
import pentdb  # noqa: E402

pentdb.JOURNAL_DIR = os.path.join(tempfile.mkdtemp(prefix="pentdb-report-rt-"), "journal")

PROJ = "report-rt"
_TMP = tempfile.mkdtemp(prefix="pentdb-report-rt-files-")


def pkt(tag):
    """造一对最小 req/resp 报文文件（finding 写入口硬门禁要真实报文）。"""
    reqf = os.path.join(_TMP, f"{tag}.req.txt")
    respf = os.path.join(_TMP, f"{tag}.resp.txt")
    with open(reqf, "w", encoding="utf-8") as f:
        f.write("POST /rest/user/login HTTP/1.1\r\nHost: rt\r\n\r\n{}")
    with open(respf, "w", encoding="utf-8") as f:
        f.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    return reqf, respf


def ns(**kw):
    base = dict(project=PROJ, ext_id="", kind="note", value="v", title="", detail="",
                note="", source="ut-rt", parent_ext="", merge_key="", status="new",
                confidence="high", severity="", code="", tech="", service="", scope="in",
                auto=False, update=False, origin="agent",
                req="", resp="", waive_capture="", no_dedupe=False, intent_id=0)
    base.update(kw)
    return argparse.Namespace(**base)


def add(**kw):
    return pentdb.cmd_add(ns(**kw))


def confirm(eid, note="ut 采信"):
    pentdb.cmd_review(argparse.Namespace(project=PROJ, id=eid, confirm=True,
                                         reject=False, reviewer="human", note=note))


def report():
    c = pentdb.connect()
    try:
        return pentdb._pentest_report(c, PROJ)
    finally:
        c.close()


class ReportRetests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pentdb.cmd_init(argparse.Namespace(project=PROJ))

    def test_01_confirmed_test_lands_grouped_by_parent(self):
        reqf, respf = pkt("login")
        fid = add(kind="finding", value="http://rt/login", title="登录 SQL 注入",
                  detail="【描述】q 参数注入\n【请求】POST /login\n【payload】' or 1=1--",
                  severity="high", origin="human", status="confirmed",
                  req=reqf, resp=respf)
        tid = add(kind="test", value="复测登录绕过", title="登录绕过复测",
                  note="复现 ｜ 依据：POST /rest/user/login 返回 200 + admin 会话",
                  parent_ext=str(fid))
        confirm(tid, "ut 采信：报文证据充分")
        # 挂一条证据指针（直插 evidence 行，验证报告证据列渲染）
        c = pentdb.connect()
        try:
            c.execute("INSERT INTO evidence(project,event_id,etype,path,sha256,note,created_at) "
                      "VALUES(?,?,?,?,?,?,?)",
                      (PROJ, tid, "file", "evidence/rt-login.log", "a" * 64, "output",
                       pentdb.now()))
            c.commit()
        finally:
            c.close()
        text = report()
        self.assertIn("## 4 复测记录（已确认 1 条）", text)
        self.assertIn("### 4.1 登录 SQL 注入", text)          # 母 finding 分组标题
        self.assertIn(f"（#{fid} · high）", text)              # 母发现 id + 严重度
        self.assertIn("复测登录绕过", text)                    # test value
        self.assertIn("复现 ｜ 依据：POST /rest/user/login 返回 200 + admin 会话", text)
        self.assertIn("evidence/rt-login.log", text)          # 证据指针
        self.assertIn("## 5 附录", text)                      # 无 suggestion：附录=5

    def test_02_new_test_not_in_report(self):
        # 同母发现再录一条未确认 test：不进报告（未采信不进证据链）
        reqf, respf = pkt("search")
        fid = add(kind="finding", value="http://rt/search", title="搜索 UNION 拖库",
                  detail="【描述】q 参数 UNION", severity="crit",
                  origin="human", status="confirmed", req=reqf, resp=respf)
        add(kind="test", value="未确认的拖库复测", title="t-unconfirmed",
            note="复现 ｜ 依据：盲测报文", parent_ext=str(fid))
        text = report()
        self.assertNotIn("未确认的拖库复测", text)
        self.assertNotIn("### 4.2", text)  # 未确认 test 不产生分组

    def test_03_orphan_test_grouped_as_tail(self):
        add(kind="test", value="无母发现的复测", title="t-orphan",
            note="复现 ｜ 依据：脚本输出", parent_ext="rt.example.com")
        c = pentdb.connect()
        try:
            tid = c.execute("SELECT id FROM raw_events WHERE project=? AND value='无母发现的复测'",
                            (PROJ,)).fetchone()["id"]
        finally:
            c.close()
        confirm(tid)
        text = report()
        self.assertIn("未关联发现的复测记录", text)
        self.assertIn("无母发现的复测", text)

    def test_04_suggestion_section_renumbered_after_retests(self):
        add(kind="suggestion", value="plan-rt", title="批次计划",
            detail="【已做】curl 探测\n【结论】403 WAF\n【下一步】补测 orderBy 注入",
            origin="human", status="confirmed")
        text = report()
        self.assertIn("## 5 复测计划（最新批次收尾）", text)
        self.assertIn("## 6 附录", text)
        self.assertIn("补测 orderBy 注入", text)


class RetestParentResolution(unittest.TestCase):
    """_retest_parent 解析语义（与 sync_lifecycle_from_test 同轴：只认数字 id+finding）。"""

    @classmethod
    def setUpClass(cls):
        pentdb.cmd_init(argparse.Namespace(project=PROJ))

    def test_resolves_first_finding_parent(self):
        c = pentdb.connect()
        try:
            by_id = {r["id"]: r for r in c.execute(
                "SELECT * FROM raw_events WHERE project=?", (PROJ,))}
            fid = next(r["id"] for r in by_id.values()
                       if r["kind"] == "finding" and r["value"] == "http://rt/login")
            hit = pentdb._retest_parent(by_id, "999999,%d" % fid)
            self.assertEqual(hit["id"], fid)            # 首个可解析（跳过不存在的 id）
            self.assertIsNone(pentdb._retest_parent(by_id, "rt.example.com"))
            self.assertIsNone(pentdb._retest_parent(by_id, "999999"))
            # 数字 id 但指向非 finding（test 行）→ None
            tid = next(r["id"] for r in by_id.values()
                       if r["kind"] == "test" and r["value"] == "复测登录绕过")
            self.assertIsNone(pentdb._retest_parent(by_id, str(tid)))
            self.assertIsNone(pentdb._retest_parent(by_id, ""))
        finally:
            c.close()


if __name__ == "__main__":
    unittest.main()
