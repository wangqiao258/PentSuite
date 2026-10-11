"""Hint 通道单测（stdlib unittest，零依赖）。运行：python -m unittest test_hints -v

覆盖（批次1，借鉴 Cairn Hint 原语）：
  1. hint add：空 text 拒绝；绑定不存在的意图拒绝；项目级/绑定意图均可注入
  2. 挂接点：intent add / plan next 输出未吸收 hints（open）；无 hints 零输出不噪音
  3. 吸收：intent close 自动吸收绑定 hints（留痕 hint-absorb），项目级 hint 不受影响
  4. hint absorb 手动关单：幂等（重复 absorb 静默跳过）、不存在即拒绝
"""
import argparse
import contextlib
import io
import os
import tempfile
import unittest

os.environ.setdefault("PENTDB_DB", os.path.join(tempfile.mkdtemp(prefix="pentdb-hint-test-"), "test.db"))
import pentdb  # noqa: E402

pentdb.JOURNAL_DIR = os.path.join(tempfile.mkdtemp(prefix="pentdb-hint-test-"), "journal")

PROJ = "hint-ut"


def run(fn, **kw):
    """执行 CLI 函数并捕获 stdout（打印内容用于断言挂接点行为）。"""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn(argparse.Namespace(**kw))
    return buf.getvalue()


def add_hint(**kw):
    base = dict(project=PROJ, text="", intent_id=0, hint_cmd="add")
    base.update(kw)
    return run(pentdb.cmd_hint, **base)


def add_intent(goal, **kw):
    base = dict(project=PROJ, goal=goal, hypothesis="", parent=0, intent_cmd="add")
    base.update(kw)
    return run(pentdb.cmd_intent, **base)


def close_intent(iid, **kw):
    base = dict(project=PROJ, id=iid, status="done", note="", intent_cmd="close")
    base.update(kw)
    return run(pentdb.cmd_intent, **base)


def plan_next(**kw):
    base = dict(project=PROJ, plan_cmd="next")
    base.update(kw)
    return run(pentdb.cmd_plan, **base)


class HintBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        c = pentdb.connect()
        if not c.execute("SELECT 1 FROM projects WHERE name=?", (PROJ,)).fetchone():
            pentdb.cmd_init(argparse.Namespace(project=PROJ))
        c.close()


class HintAdd(HintBase):
    def test_empty_text_rejected(self):
        with self.assertRaises(SystemExit):
            add_hint(text="  ")

    def test_bind_missing_intent_rejected(self):
        with self.assertRaises(SystemExit):
            add_hint(text="孤儿线索", intent_id=9999)

    def test_add_project_level_and_list(self):
        out = add_hint(text="全项目级判断：外网只开了 443")
        self.assertIn("[ok] hint #", out)
        c = pentdb.connect()
        try:
            row = c.execute("SELECT * FROM hints WHERE project=? ORDER BY id DESC LIMIT 1",
                            (PROJ,)).fetchone()
            self.assertEqual(row["status"], "open")
            self.assertEqual(row["intent_id"], 0)
            act = c.execute("SELECT action FROM changelog WHERE project=? ORDER BY id DESC LIMIT 1",
                            (PROJ,)).fetchone()["action"]
            self.assertEqual(act, "hint-add")
        finally:
            c.close()


class HintHookpoints(HintBase):
    def test_intent_add_prints_open_hints(self):
        add_hint(text="方向判断：先摸 WAF")
        out = add_intent("验证后台是否存在默认口令")
        self.assertIn("未吸收 hints", out)
        self.assertIn("先摸 WAF", out)

    def test_plan_next_prints_open_hints(self):
        add_hint(text="计划领取时提醒：注意限速")
        out = plan_next()
        self.assertIn("注意限速", out)

    def test_no_hints_zero_noise(self):
        c = pentdb.connect()
        try:
            c.execute("UPDATE hints SET status='absorbed', absorbed_at=? WHERE project=? AND status='open'",
                      (pentdb.now(), PROJ))
            c.commit()
        finally:
            c.close()
        out = plan_next()
        self.assertNotIn("未吸收 hints", out)


class HintAbsorb(HintBase):
    def test_intent_close_auto_absorbs_bound(self):
        out = add_intent("验证弱口令方向")
        iid = int(out.split("#")[1].split(" ")[0])
        add_hint(text="绑定的判断：试 admin/admin", intent_id=iid)
        add_hint(text="项目级判断：不影响该意图")
        out = close_intent(iid)
        self.assertIn("[吸收]", out)
        c = pentdb.connect()
        try:
            bound = c.execute("SELECT status FROM hints WHERE intent_id=?", (iid,)).fetchone()
            self.assertEqual(bound["status"], "absorbed")
            free = c.execute("SELECT status FROM hints WHERE intent_id=0 AND text LIKE '项目级%'"
                             " AND status='open'").fetchone()
            self.assertIsNotNone(free, "项目级 hint 不应被意图关闭连带吸收")
            act = c.execute("SELECT action FROM changelog WHERE project=? ORDER BY id DESC LIMIT 1",
                            (PROJ,)).fetchone()["action"]
            self.assertEqual(act, "hint-absorb")
        finally:
            c.close()

    def test_manual_absorb_idempotent(self):
        add_hint(text="手动关单的判断")
        c = pentdb.connect()
        try:
            hid = c.execute("SELECT id FROM hints WHERE project=? ORDER BY id DESC LIMIT 1",
                            (PROJ,)).fetchone()["id"]
        finally:
            c.close()
        out = run(pentdb.cmd_hint, project=PROJ, ids=str(hid), note="用在 plan step",
                  hint_cmd="absorb")
        self.assertIn("[ok] 已吸收 hints", out)
        out2 = run(pentdb.cmd_hint, project=PROJ, ids=str(hid), note="重复吸收",
                   hint_cmd="absorb")
        self.assertIn("没有可吸收", out2)

    def test_absorb_missing_rejected(self):
        with self.assertRaises(SystemExit):
            run(pentdb.cmd_hint, project=PROJ, ids="424242", note="", hint_cmd="absorb")


if __name__ == "__main__":
    unittest.main()
