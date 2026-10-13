"""plan review（Reason 式图级复盘）单测（stdlib unittest，零依赖）。

覆盖（批次2，借鉴 Cairn Reason 任务）：
  1. 只读复盘：首次复盘触发判定；图变化后触发判定带增量；无变化可跳过
  2. 落库模式：--note 缺 --refs 拒绝；--refs 引用不存在观测拒绝；
     合法结论落库 kind=note value=plan-review + changelog 检查点（events/hints/open_intents）；
     落库即 confirmed（记录不是人审待办，不进 /api/pending 队列）
  3. lint R-501（健康度非阻断）：复盘结论 detail 不含观测引用 '#' → warn；带【依据】#N → 不报
    （R-501 针对 legacy/手编数据，写入口 plan review 强制带 refs，故用直插模拟——
     changelog/raw_events 的防绕过触发器只拦 update/delete，insert new 态放行）
"""
import argparse
import contextlib
import io
import os
import tempfile
import unittest

os.environ.setdefault("PENTDB_DB", os.path.join(tempfile.mkdtemp(prefix="pentdb-review-test-"), "test.db"))
import pentdb  # noqa: E402

pentdb.JOURNAL_DIR = os.path.join(tempfile.mkdtemp(prefix="pentdb-review-test-"), "journal")


def ns(**kw):
    return argparse.Namespace(**kw)


def run(fn, **kw):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn(ns(**kw))
    return buf.getvalue()


def review(proj, **kw):
    return run(pentdb.cmd_plan, project=proj, plan_cmd="review", note="", refs="", **kw)


def add_event(proj, value="观测", **kw):
    base = dict(project=proj, ext_id="", kind="note", value=value, title="", detail="",
                note="", source="ut", parent_ext="", merge_key="", status="new",
                confidence="high", severity="", code="", tech="", service="", scope="in",
                auto=False, update=False, origin="agent",
                req="", resp="", waive_capture="", no_dedupe=False, intent_id=0)
    base.update(kw)
    return run(pentdb.cmd_add, **base)


def init(proj):
    c = pentdb.connect()
    if not c.execute("SELECT 1 FROM projects WHERE name=?", (proj,)).fetchone():
        pentdb.cmd_init(argparse.Namespace(project=proj))
    c.close()


class ReviewReadonly(unittest.TestCase):
    PROJ = "review-ro"

    @classmethod
    def setUpClass(cls):
        init(cls.PROJ)

    def test_01_first_review_triggers(self):
        out = review(self.PROJ)
        self.assertIn("首次复盘", out)
        self.assertIn("探索复盘", out)

    def test_02_intent_panorama_listed(self):
        run(pentdb.cmd_intent, project=self.PROJ, goal="复盘测试方向", hypothesis="",
            parent=0, intent_cmd="add")
        out = review(self.PROJ)
        self.assertIn("意图全景", out)
        self.assertIn("复盘测试方向", out)

    def test_03_delta_trigger_after_new_events(self):
        # 自带检查点：先落一条结论建立基准，再加新观测 → 应触发"新增观测"而非"首次复盘"
        add_event(self.PROJ, value="基准观测", source="ut-review-base")
        c = pentdb.connect()
        try:
            eid = c.execute("SELECT id FROM raw_events WHERE project=? ORDER BY id DESC LIMIT 1",
                            (self.PROJ,)).fetchone()["id"]
        finally:
            c.close()
        run(pentdb.cmd_plan, project=self.PROJ, plan_cmd="review",
            note="基准复盘", refs=str(eid))
        add_event(self.PROJ, value="复盘后的新观测", source="ut-review-delta")
        out = review(self.PROJ)
        self.assertIn("新增观测", out)
        self.assertIn("需要复盘", out)


class ReviewRecord(unittest.TestCase):
    PROJ = "review-rec"

    @classmethod
    def setUpClass(cls):
        init(cls.PROJ)

    def test_01_note_without_refs_rejected(self):
        with self.assertRaises(SystemExit):
            run(pentdb.cmd_plan, project=self.PROJ, plan_cmd="review",
                note="结论：差不多了", refs="")

    def test_02_refs_nonexistent_rejected(self):
        with self.assertRaises(SystemExit):
            run(pentdb.cmd_plan, project=self.PROJ, plan_cmd="review",
                note="结论", refs="424242")

    def test_03_valid_conclusion_lands_with_checkpoint(self):
        add_event(self.PROJ, value="注入点探测", source="ut-review-ev")
        c = pentdb.connect()
        try:
            eid = c.execute("SELECT id FROM raw_events WHERE project=? ORDER BY id DESC LIMIT 1",
                            (self.PROJ,)).fetchone()["id"]
        finally:
            c.close()
        out = run(pentdb.cmd_plan, project=self.PROJ, plan_cmd="review",
                  note="结论：注入方向已有产出，转入取凭据", refs=str(eid))
        self.assertIn("[ok] 复盘结论", out)
        c = pentdb.connect()
        try:
            row = c.execute("SELECT * FROM raw_events WHERE project=? ORDER BY id DESC LIMIT 1",
                            (self.PROJ,)).fetchone()
            self.assertEqual(row["kind"], "note")
            self.assertEqual(row["value"], "plan-review")
            self.assertEqual(row["status"], "confirmed",
                             "plan-review 是记录不是人审待办：落库即自动确认（记录与待办分离）")
            self.assertIn(f"#{eid}", row["detail"])
            self.assertIn("【依据】", row["detail"])
            chk = c.execute("SELECT detail FROM changelog WHERE project=? AND action='plan-review' "
                            "ORDER BY id DESC LIMIT 1", (self.PROJ,)).fetchone()["detail"]
            self.assertIn("events=", chk)
            self.assertIn("open_intents=", chk)
        finally:
            c.close()

    def test_04_no_change_skippable(self):
        # 自带检查点：落一条结论后不再新增任何观测/hint/意图 → 复盘应判无变化
        add_event(self.PROJ, value="无变化用例观测", source="ut-review-quiet")
        c = pentdb.connect()
        try:
            eid = c.execute("SELECT id FROM raw_events WHERE project=? ORDER BY id DESC LIMIT 1",
                            (self.PROJ,)).fetchone()["id"]
        finally:
            c.close()
        run(pentdb.cmd_plan, project=self.PROJ, plan_cmd="review",
            note="安静复盘", refs=str(eid))
        out = review(self.PROJ)
        self.assertIn("无变化", out)


class ReviewLint(unittest.TestCase):
    PROJ = "review-lint"

    @classmethod
    def setUpClass(cls):
        init(cls.PROJ)

    def test_r501_unreferenced_conclusion_warns(self):
        c = pentdb.connect()
        try:
            c.execute(
                "INSERT INTO raw_events(project,kind,value,title,detail,status,confidence,"
                "source,origin,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (self.PROJ, "note", "plan-review", "探索复盘", "结论：差不多了（裸判断）",
                 "new", "high", "plan-review", "agent", pentdb.now()))
            c.commit()
            rid = c.execute("SELECT id FROM raw_events WHERE project=? ORDER BY id DESC LIMIT 1",
                            (self.PROJ,)).fetchone()["id"]
            rep = pentdb.lint_report(c, self.PROJ, journal_check=False)
        finally:
            c.close()
        r501 = [w for w in rep["items"]["warns"] if w["code"] == "R-501" and w["rid"] == rid]
        self.assertTrue(r501, "裸判断复盘结论应报 R-501 健康度提示")
        self.assertEqual([e for e in rep["items"]["errors"] if e["code"] == "R-501"], [],
                         "R-501 是健康度提示，不得阻断")

    def test_referenced_conclusion_no_r501(self):
        add_event(self.PROJ, value="有依据的复盘佐证", source="ut-review-lint")
        c = pentdb.connect()
        try:
            eid = c.execute("SELECT id FROM raw_events WHERE project=? ORDER BY id DESC LIMIT 1",
                            (self.PROJ,)).fetchone()["id"]
            c.execute(
                "INSERT INTO raw_events(project,kind,value,title,detail,status,confidence,"
                "source,origin,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (self.PROJ, "note", "plan-review", "探索复盘",
                 f"结论：方向收口\n【依据】#{eid}", "new", "high", "plan-review", "agent", pentdb.now()))
            c.commit()
            rid = c.execute("SELECT id FROM raw_events WHERE project=? ORDER BY id DESC LIMIT 1",
                            (self.PROJ,)).fetchone()["id"]
            rep = pentdb.lint_report(c, self.PROJ, journal_check=False)
        finally:
            c.close()
        self.assertEqual([w for w in rep["items"]["warns"]
                          if w["code"] == "R-501" and w["rid"] == rid], [])


if __name__ == "__main__":
    unittest.main()
