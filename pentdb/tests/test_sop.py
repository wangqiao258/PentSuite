#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PentDB 核心逻辑单测（stdlib unittest，零依赖）。运行：python -m unittest test_sop -v

覆盖四块最易回归的纯逻辑：
  1. 术语匹配 _term_in / _hints_menu（交替词、大小写、扁平提示清单构造）
  2. add 状态机守卫（AI 推断必 new、--auto 仅限事实类、重复拒绝、--update）
  3. lint_report（source 溯源 / test 归因 / scope / severity）
  4. sop_report 扁平提示对账（when 语义 × 术语状态参考，无阶段、纯只读）
"""
import argparse
import os
import tempfile
import unittest

# 必须在 import pentdb 前设置：setdefault 保证多模块同跑时先加载者建临时库、
# 全套件共享隔离库，与 import 顺序无关（之前 ["PENTDB_DB"]= 覆盖写法只有
# 恰好先加载的模块生效，实测踩过重跑撞真实库）
os.environ.setdefault("PENTDB_DB", os.path.join(tempfile.mkdtemp(prefix="pentdb-test-"), "test.db"))
import pentdb  # noqa: E402

# journal 隔离：lint 对账不读真实执行流水，保证测试确定性
pentdb.JOURNAL_DIR = os.path.join(tempfile.mkdtemp(prefix="pentdb-test-"), "journal")

PROJ = "unittest-proj"


def ns(**kw):
    base = dict(project=PROJ, ext_id="", kind="note", value="v", title="", detail="",
                note="", source="unittest", parent_ext="", merge_key="", status="new",
                confidence="", severity="", code="", tech="", service="", scope="in",
                auto=False, update=False, origin="agent",
                req="", resp="", waive_capture="")
    base.update(kw)
    return argparse.Namespace(**base)


def add(**kw):
    if kw.get("kind") == "finding" and not kw.get("req"):
        kw.setdefault("waive_capture", "unittest 无报文建档")  # 状态机用例不关心报文，走豁免起草通道
    pentdb.cmd_add(ns(**kw))


class TermMatch(unittest.TestCase):
    def test_alternation(self):
        self.assertTrue(pentdb._term_in("越权|IDOR", "发现 IDOR 风险"))
        self.assertTrue(pentdb._term_in("越权|IDOR", "存在水平越权"))
        self.assertFalse(pentdb._term_in("越权|IDOR", "正常业务逻辑"))

    def test_case_insensitive(self):
        self.assertTrue(pentdb._term_in("nuclei", "Nuclei scan finished"))

    def test_flat_menu(self):
        menu = pentdb._hints_menu(pentdb.load_sop_cfg())
        terms = [it["term"] for it in menu]
        # 扁平结构：每项都带 when 触发语义，无阶段分组
        self.assertTrue(all(it["when"] for it in menu))
        # 同一术语在不同 when 下各自成项（不去重，保留触发语义）
        self.assertEqual(terms.count("弱口令"), 2)
        self.assertEqual(terms.count("越权|IDOR"), 2)
        self.assertIn("服务识别", terms)
        self.assertIn("归属确认", terms)


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
        self.assertIn("被测对象", joined)
        self.assertTrue(any("bogus" in w for w in rep["warns"]))


class SopHintsView(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        c = pentdb.connect()
        c.execute("INSERT OR IGNORE INTO projects(name, created_at) VALUES(?,?)", (PROJ, pentdb.now()))
        c.commit(); c.close()
        # 服务识别类测试事实：parent_ext=0（项目级归因）
        add(kind="test", value="服务识别 nmap -sV 1.2.3.4", parent_ext="0",
            note="nmap 服务识别结果", status="confirmed", auto=True, confidence="high")

    def _rep(self):
        c = pentdb.connect()
        rep = pentdb.sop_report(c, PROJ)
        c.close()
        return rep

    def test_flat_report_no_stage(self):
        rep = self._rep()
        self.assertEqual(set(rep), {"hints", "total", "done", "missing"})
        self.assertEqual(rep["total"], len(rep["hints"]))
        self.assertEqual(rep["done"] + rep["missing"], rep["total"])

    def test_menu_state_done_via_text_match(self):
        rep = self._rep()
        pairs = [(i["term"], i["state"]) for i in rep["hints"]]
        self.assertIn(("服务识别", "done"), pairs)
        done = [i for i in rep["hints"] if i["state"] == "done"]
        self.assertTrue(all(i["ev"].startswith("#") for i in done))

    def test_missing_default(self):
        rep = self._rep()
        pairs = [(i["term"], i["state"]) for i in rep["hints"]]
        self.assertIn(("目录爆破", "missing"), pairs)
        self.assertTrue(all(i["ev"] is None for i in rep["hints"] if i["state"] == "missing"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
