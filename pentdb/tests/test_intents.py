"""探索血缘与计划层单测（stdlib unittest，零依赖）。运行：python -m unittest test_intents -v

覆盖：
  1. Schema v9/v10 迁移：intents/plan_steps 建表、raw_events.intent_id 加列、user_version=10
  2. intent 域：add/list/show/close；关闭后拒绝新挂接；父链校验
  3. add --intent 挂血缘（含 --update 补挂、重扫更新保留原意图）
  4. plan 域：依赖置 blocked、plan next 只出前置已满足步骤、done/skip 自动解锁下游
  5. exec --intent 透传（test 事件带意图归属）
"""
import argparse
import os
import sqlite3
import sys
import tempfile
import unittest

os.environ.setdefault("PENTDB_DB", os.path.join(tempfile.mkdtemp(prefix="pentdb-intent-test-"), "test.db"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pentdb  # noqa: E402
import pdb_intents  # noqa: E402

pentdb.JOURNAL_DIR = os.path.join(tempfile.mkdtemp(prefix="pentdb-intent-test-"), "journal")

PROJ = "intent-ut"


def ns_add(**kw):
    base = dict(project=PROJ, ext_id="", kind="note", value="v", title="", detail="",
                note="", source="ut", parent_ext="1", merge_key="", status="new",
                confidence="high", severity="", code="", tech="", service="", scope="in",
                auto=False, update=False, origin="agent", stage="",
                req="", resp="", waive_capture="", no_dedupe=False, intent_id=0)
    base.update(kw)
    return argparse.Namespace(**base)


def run(fn, **kw):
    """执行 CLI 函数并捕获 SystemExit 的文本（sys.exit(msg) → 断言用）。"""
    try:
        fn(ns_add(**kw) if fn is pentdb.cmd_add else argparse.Namespace(**kw))
    except SystemExit as e:
        return str(e)
    return ""


def plan_ns(cmd, **kw):
    base = dict(plan_cmd=cmd, project=PROJ, title="", depends="", intent_id=0, note="", id=0, all_=False)
    base.update(kw)
    return argparse.Namespace(**base)


class Migration(unittest.TestCase):
    def test_schema_v10(self):
        c = pentdb.connect()
        try:
            self.assertEqual(c.execute("PRAGMA user_version").fetchone()[0], 10)
            names = {r[0] for r in c.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertIn("intents", names)
            self.assertIn("plan_steps", names)
            cols = [r[1] for r in c.execute("PRAGMA table_info(raw_events)")]
            self.assertIn("intent_id", cols)
        finally:
            c.close()


class IntentFlow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        c = pentdb.connect()
        if not c.execute("SELECT 1 FROM projects WHERE name=?", (PROJ,)).fetchone():
            pentdb.cmd_init(argparse.Namespace(project=PROJ))
        c.close()

    def test_01_intent_add_and_attach(self):
        iid = pdb_intents.intent_add(pentdb.connect.__self__ if False else _conn(), PROJ,
                                     "验证后台默认口令", hypothesis="通用弱口令指纹命中")
        self.assertTrue(iid > 0)
        # add --intent 挂血缘
        run(pentdb.cmd_add, kind="note", value="n1", note="观察", intent_id=iid)
        c = _conn()
        try:
            row = c.execute("SELECT intent_id FROM raw_events WHERE value='n1'").fetchone()
            self.assertEqual(row["intent_id"], iid)
        finally:
            c.close()
        # 挂到不存在的意图 / 已关闭的意图均拒绝
        msg = run(pentdb.cmd_add, kind="note", value="n2", note="x", intent_id=99999)
        self.assertIn("不存在", msg)
        pdb_intents.intent_close(_conn(), PROJ, iid, "done", note="验证完成")
        msg = run(pentdb.cmd_add, kind="note", value="n3", note="x", intent_id=iid)
        self.assertIn("已关闭", msg)

    def test_02_rescan_update_intent(self):
        run(pentdb.cmd_add, kind="note", value="u1", note="v1")
        iid = pdb_intents.intent_add(_conn(), PROJ, "补挂方向")
        # --update 补挂意图
        msg = run(pentdb.cmd_add, kind="note", value="u1", note="v1", update=True, intent_id=iid)
        self.assertEqual(msg, "")
        c = _conn()
        try:
            row = c.execute("SELECT intent_id FROM raw_events WHERE value='u1'").fetchone()
            self.assertEqual(row["intent_id"], iid)
        finally:
            c.close()
        # 不带 --intent 的重扫更新保留原意图
        run(pentdb.cmd_add, kind="note", value="u1", note="v2", update=True)
        c = _conn()
        try:
            row = c.execute("SELECT intent_id FROM raw_events WHERE value='u1'").fetchone()
            self.assertEqual(row["intent_id"], iid)
        finally:
            c.close()

    def test_03_intent_parent_validation(self):
        msg = ""
        c = _conn()
        try:
            try:
                pdb_intents.intent_add(c, PROJ, "坏父链", parent_id=99999)
            except SystemExit as e:
                msg = str(e)
        finally:
            c.close()
        self.assertIn("父意图不存在", msg)

    def test_04_exec_intent_passthrough(self):
        iid = pdb_intents.intent_add(_conn(), PROJ, "exec 透传方向")
        a = argparse.Namespace(project=PROJ, parent_ext="1",
                               cmd=(sys.executable + ' -c "print(1)"'),
                               action="echo-ut", title="", note="复现 ｜ 依据: 输出 1",
                               detail="", severity="", confidence="high", timeout=30,
                               probe_parse=False, probe_host="", intent_id=iid)
        pentdb.cmd_exec(a)
        c = _conn()
        try:
            row = c.execute("SELECT intent_id, kind FROM raw_events WHERE value='echo-ut'").fetchone()
            self.assertIsNotNone(row, "exec 的 test 事件应存在")
            self.assertEqual(row["kind"], "test")
            self.assertEqual(row["intent_id"], iid, "exec --intent 应透传到 test 事件")
        finally:
            c.close()


class PlanFlow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        c = pentdb.connect()
        if not c.execute("SELECT 1 FROM projects WHERE name=?", (PROJ,)).fetchone():
            pentdb.cmd_init(argparse.Namespace(project=PROJ))
        c.close()

    def test_01_dep_chain_block_and_promote(self):
        pentdb.cmd_plan(plan_ns("add", title="第一步：拿到注入点"))
        pentdb.cmd_plan(plan_ns("add", title="第二步：取凭据", depends="1"))
        pentdb.cmd_plan(plan_ns("add", title="第三步：横向", depends="1,2"))
        c = _conn()
        try:
            st = {r["title"]: r["status"] for r in
                  c.execute("SELECT title, status FROM plan_steps WHERE project=?", (PROJ,))}
            self.assertEqual(st["第一步：拿到注入点"], "ready")
            self.assertEqual(st["第二步：取凭据"], "blocked")
            self.assertEqual(st["第三步：横向"], "blocked")
        finally:
            c.close()
        # done 第一步 → 只有第二步解锁（第三步仍 blocked）
        pentdb.cmd_plan(plan_ns("done", id=1, note="sqlmap 确认注入"))
        c = _conn()
        try:
            st = {r["title"]: r["status"] for r in
                  c.execute("SELECT title, status FROM plan_steps WHERE project=?", (PROJ,))}
            self.assertEqual(st["第二步：取凭据"], "ready")
            self.assertEqual(st["第三步：横向"], "blocked", "前置 2 未完成，第三步不得提前解锁")
        finally:
            c.close()
        # skip 第二步 → 第三步解锁
        pentdb.cmd_plan(plan_ns("skip", id=2, note="凭据走别的路"))
        c = _conn()
        try:
            st = {r["title"]: r["status"] for r in
                  c.execute("SELECT title, status FROM plan_steps WHERE project=?", (PROJ,))}
            self.assertEqual(st["第三步：横向"], "ready")
        finally:
            c.close()

    def test_02_terminal_state_locked(self):
        msg = run_plan_cmd("done", id=1)
        self.assertIn("终态", msg)

    def test_03_bad_dep_rejected(self):
        msg = run_plan_cmd("add", title="坏依赖", depends="99999")
        self.assertIn("前置步骤不存在", msg)
        msg = run_plan_cmd("add", title="脏依赖", depends="abc")
        self.assertIn("只认步骤 id", msg)

    def test_04_intent_link(self):
        iid = pdb_intents.intent_add(_conn(), PROJ, "计划挂意图")
        pentdb.cmd_plan(plan_ns("add", title="带意图的步骤", intent_id=iid))
        c = _conn()
        try:
            row = c.execute("SELECT intent_id, status FROM plan_steps WHERE title='带意图的步骤'").fetchone()
            self.assertEqual(row["intent_id"], iid)
            self.assertEqual(row["status"], "ready")
        finally:
            c.close()
        # 挂已关闭意图拒绝
        pdb_intents.intent_close(_conn(), PROJ, iid, "dead")
        msg = run_plan_cmd("add", title="挂死意图", intent_id=iid)
        self.assertIn("已关闭", msg)


def _conn():
    return pentdb.connect()


def run_plan_cmd(cmd, **kw):
    try:
        pentdb.cmd_plan(plan_ns(cmd, **kw))
    except SystemExit as e:
        return str(e)
    return ""


if __name__ == "__main__":
    unittest.main()
