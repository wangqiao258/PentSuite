#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PentDB 核心逻辑单测（stdlib unittest，零依赖）。运行：python -m unittest test_sop -v

覆盖四块最易回归的纯逻辑：
  1. 术语匹配 _term_in / _match（交替词、大小写、parent_code）
  2. add 状态机守卫（AI 推断必 new、--auto 仅限事实类、重复拒绝、--update）
  3. lint_report（source 溯源 / test 归因 / scope / severity）
  4. sop_report 阶段视图（7 阶段菜单、test --stage 聚合、pending 术语反查回填）
"""
import argparse
import os
import tempfile
import unittest

# 必须在 import pentdb 前设置：测试用独立临时库，绝不触碰真实数据
_TMPDB = os.path.join(tempfile.mkdtemp(prefix="pentdb-test-"), "test.db")
os.environ["PENTDB_DB"] = _TMPDB
import pentdb  # noqa: E402

PROJ = "unittest-proj"


def ns(**kw):
    base = dict(project=PROJ, ext_id="", kind="note", value="v", title="", detail="",
                note="", source="unittest", parent_ext="", merge_key="", status="new",
                confidence="", severity="", code="", tech="", service="", scope="in",
                auto=False, update=False, origin="agent", stage="")
    base.update(kw)
    return argparse.Namespace(**base)


def add(**kw):
    pentdb.cmd_add(ns(**kw))


class TermMatch(unittest.TestCase):
    def test_alternation(self):
        self.assertTrue(pentdb._term_in("越权|IDOR", "发现 IDOR 风险"))
        self.assertTrue(pentdb._term_in("越权|IDOR", "存在水平越权"))
        self.assertFalse(pentdb._term_in("越权|IDOR", "正常业务逻辑"))

    def test_case_insensitive(self):
        self.assertTrue(pentdb._term_in("nuclei", "Nuclei scan finished"))

    def test_match_kind_and_contains(self):
        rec = {"kind": "port", "service": "mysql", "note": "", "code": "3306",
               "_parent_code": None, "value": "1.2.3.4:3306"}
        self.assertTrue(pentdb._match(rec, {"kind": "port", "service_or_note_contains": "mysql"}))
        self.assertFalse(pentdb._match(rec, {"kind": "port", "service_or_note_contains": "tomcat"}))
        self.assertTrue(pentdb._match(rec, {"code": "3306"}))
        self.assertTrue(pentdb._match(rec, {"value_contains": "1.2.3.4"}))


class AddStateMachine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        c = pentdb.connect()
        c.execute("INSERT OR IGNORE INTO projects(name, created_at) VALUES(?,?)", (PROJ, pentdb.now()))
        c.commit(); c.close()

    def test_agent_inference_forced_new(self):
        add(kind="finding", value="f1", confidence="high")
        c = pentdb.connect()
        st = c.execute("SELECT status FROM raw_events WHERE value='f1'").fetchone()["status"]
        c.close()
        self.assertEqual(st, "new")

    def test_agent_confirmed_requires_auto(self):
        with self.assertRaises(SystemExit):
            add(kind="domain", value="a.example.com", status="confirmed", confidence="high")

    def test_auto_fact_confirmed(self):
        add(kind="domain", value="b.example.com", status="confirmed", confidence="high", auto=True)
        c = pentdb.connect()
        st = c.execute("SELECT status FROM raw_events WHERE value='b.example.com'").fetchone()["status"]
        c.close()
        self.assertEqual(st, "confirmed")

    def test_auto_rejected_for_inference(self):
        with self.assertRaises(SystemExit):
            add(kind="finding", value="f-auto", confidence="high", auto=True, status="confirmed")

    def test_agent_requires_confidence(self):
        with self.assertRaises(SystemExit):
            add(kind="osint", value="o1")

    def test_duplicate_rejected_update_works(self):
        add(kind="path", value="/dup", confidence="high")
        with self.assertRaises(SystemExit):
            add(kind="path", value="/dup", confidence="high")
        add(kind="path", value="/dup", note="rescanned", update=True, origin="human", status="confirmed")
        c = pentdb.connect()
        n = c.execute("SELECT COUNT(*) n FROM raw_events WHERE kind='path' AND value='/dup'").fetchone()["n"]
        c.close()
        self.assertEqual(n, 1)

    def test_stage_validated(self):
        with self.assertRaises(SystemExit):
            add(kind="test", value="t", parent_ext="0", status="confirmed", auto=True, stage="不存在")


class Lint(unittest.TestCase):
    def test_rules(self):
        c = pentdb.connect()
        cur = c.execute("INSERT INTO raw_events(project,kind,value,status,source,origin,scope,severity,created_at) "
                        "VALUES(?,?,?,?,?,?,?,?,?)",
                        (PROJ, "note", "bad-src", "new", "", "agent", "in", "bogus", pentdb.now()))
        id1 = cur.lastrowid
        cur = c.execute("INSERT INTO raw_events(project,kind,value,status,source,origin,scope,severity,parent_ext,created_at) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (PROJ, "test", "t-no-parent", "new", "s", "human", "in", "", "", pentdb.now()))
        id2 = cur.lastrowid
        c.commit()
        rep = pentdb.lint_report(c, PROJ)
        c.close()
        joined = "\n".join(rep["errors"])
        self.assertIn(f"#{id1}", joined)
        self.assertIn("source", joined)
        self.assertIn(f"#{id2}", joined)
        self.assertIn("parent_ext", joined)
        self.assertTrue(any("bogus" in w for w in rep["warns"]))


class SopStageView(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        c = pentdb.connect()
        c.execute("INSERT OR IGNORE INTO projects(name, created_at) VALUES(?,?)", (PROJ, pentdb.now()))
        c.commit(); c.close()
        # 端口扫描阶段的测试事实：parent_ext=0（项目级归因）
        add(kind="test", value="服务识别 nmap -sV 1.2.3.4", parent_ext="0",
            status="confirmed", auto=True, confidence="high", stage="端口扫描")
        # 待审 pending（术语反查回填 stage）
        c = pentdb.connect()
        c.execute("INSERT INTO pending_tests(project,event_id,term,created_at,stage) VALUES(?,?,?,?,?)",
                  (PROJ, 0, "认证与会话", pentdb.now(), ""))
        c.commit(); c.close()

    def test_seven_stages_menu(self):
        c = pentdb.connect()
        rep = pentdb.sop_report(c, PROJ)
        c.close()
        self.assertEqual(len(rep["stage_view"]), 7)
        by = {v["stage"]: v for v in rep["stage_view"]}
        self.assertEqual(by["端口扫描"]["menu"][0]["term"], "服务识别")

    def test_test_event_aggregates_to_stage(self):
        c = pentdb.connect()
        rep = pentdb.sop_report(c, PROJ)
        c.close()
        port = {v["stage"]: v for v in rep["stage_view"]}["端口扫描"]
        self.assertTrue(any(t["value"].startswith("服务识别") for t in port["executed"]))

    def test_menu_state_done_via_text_match(self):
        c = pentdb.connect()
        rep = pentdb.sop_report(c, PROJ)
        c.close()
        port = {v["stage"]: v for v in rep["stage_view"]}["端口扫描"]
        self.assertIn(("服务识别", "done"), [(i["term"], i["state"]) for i in port["menu"]])

    def test_pending_stage_backfill(self):
        c = pentdb.connect()
        pentdb.sop_report(c, PROJ)  # 触发幂等回填
        row = c.execute("SELECT stage FROM pending_tests WHERE term='认证与会话' AND project=?",
                        (PROJ,)).fetchone()
        c.close()
        self.assertEqual(row["stage"], "漏洞探测")


if __name__ == "__main__":
    unittest.main(verbosity=2)
