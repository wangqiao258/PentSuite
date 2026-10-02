"""P0 防绕过审计触发器单测（stdlib unittest，零依赖）。运行：python -m unittest test_guards -v

覆盖：
  1. agent INSERT confirmed：fact kind 放行 / 推断 kind 拒绝（--auto 门禁 DB 侧兜底）
  2. raw_events 核心列（kind/project/created_at）UPDATE 拒绝；普通观测列放行
  3. changelog / reviews append-only（UPDATE/DELETE 全拒）
  4. waives 仅允许 confirmed 0→1；改字段/重复确认/DELETE 拒绝
  5. cmd_drop 级联删除仍可用，且触发器自动恢复（恢复后守卫立即生效）
  6. kb.update_experience 不再暴露 status 参数（approve 门禁不可经 update 绕过）
"""
import argparse
import ast
import os
import sqlite3
import tempfile
import unittest

# 必须在 import pentdb 前设置；setdefault 保证多模块同跑时先加载者建隔离库
os.environ.setdefault("PENTDB_DB", os.path.join(tempfile.mkdtemp(prefix="pentdb-guard-test-"), "test.db"))
import pentdb  # noqa: E402
from pdb_core import AUDIT_TRIGGERS  # noqa: E402

pentdb.JOURNAL_DIR = os.path.join(tempfile.mkdtemp(prefix="pentdb-guard-test-"), "journal")

PROJ = "guard-ut"


def ns(**kw):
    base = dict(project=PROJ, ext_id="", kind="note", value="v", title="", detail="",
                note="", source="ut", parent_ext="", merge_key="", status="new",
                confidence="", severity="", code="", tech="", service="", scope="in",
                auto=False, update=False, origin="agent", stage="",
                req="", resp="", waive_capture="", no_dedupe=False)
    base.update(kw)
    return argparse.Namespace(**base)


def add(**kw):
    if kw.get("kind") == "finding" and not kw.get("req") and not kw.get("waive_capture"):
        kw["waive_capture"] = "ut 无报文建档"
    pentdb.cmd_add(ns(**kw))


def _init_proj():
    c = pentdb.connect()
    if not c.execute("SELECT 1 FROM projects WHERE name=?", (PROJ,)).fetchone():
        pentdb.cmd_init(argparse.Namespace(project=PROJ))
    c.close()


class AgentInsertGuard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _init_proj()

    def test_fact_kind_confirmed_allowed(self):
        c = pentdb.connect()
        try:
            cur = c.execute(
                "INSERT INTO raw_events(project,kind,value,source,origin,status,created_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (PROJ, "domain", "fact.example.com", "ut", "agent", "confirmed", pentdb.now()))
            self.assertTrue(cur.lastrowid)
        finally:
            c.close()  # 不 commit，回滚丢弃

    def test_inference_kind_confirmed_blocked(self):
        c = pentdb.connect()
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                c.execute(
                    "INSERT INTO raw_events(project,kind,value,source,origin,status,created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (PROJ, "finding", "x", "ut", "agent", "confirmed", pentdb.now()))
        finally:
            c.close()

    def test_inference_kind_new_allowed(self):
        c = pentdb.connect()
        try:
            cur = c.execute(
                "INSERT INTO raw_events(project,kind,value,source,origin,status,created_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (PROJ, "finding", "y", "ut", "agent", "new", pentdb.now()))
            self.assertTrue(cur.lastrowid)
        finally:
            c.close()


class CoreColumnGuard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _init_proj()
        add(project=PROJ, kind="domain", value="core.example.com", source="ut",
            auto=True, status="confirmed", confidence="high")
        c = pentdb.connect()
        try:
            cls.eid = c.execute(
                "SELECT id FROM raw_events WHERE project=? AND kind='domain' AND value='core.example.com'",
                (PROJ,)).fetchone()[0]
        finally:
            c.close()

    def test_kind_update_blocked(self):
        c = pentdb.connect()
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                c.execute("UPDATE raw_events SET kind='note' WHERE id=?", (self.eid,))
        finally:
            c.close()

    def test_project_update_blocked(self):
        c = pentdb.connect()
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                c.execute("UPDATE raw_events SET project='other' WHERE id=?", (self.eid,))
        finally:
            c.close()

    def test_created_at_update_blocked(self):
        c = pentdb.connect()
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                c.execute("UPDATE raw_events SET created_at='2000-01-01T00:00:00+08:00' WHERE id=?",
                          (self.eid,))
        finally:
            c.close()

    def test_observation_column_update_allowed(self):
        c = pentdb.connect()
        try:
            cur = c.execute("UPDATE raw_events SET note='ut 备注刷新' WHERE id=?", (self.eid,))
            self.assertEqual(cur.rowcount, 1)
        finally:
            c.close()


class ChangelogAppendOnly(unittest.TestCase):
    def test_update_blocked(self):
        c = pentdb.connect()
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                c.execute("UPDATE changelog SET detail='洗库' WHERE project=?", (PROJ,))
        finally:
            c.close()

    def test_delete_blocked(self):
        c = pentdb.connect()
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                c.execute("DELETE FROM changelog WHERE project=?", (PROJ,))
        finally:
            c.close()


class ReviewsAppendOnly(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _init_proj()
        # 必须以 new 状态入库再人工 confirm：cmd_review 对已是 confirmed 的行幂等跳过、不写 reviews
        add(project=PROJ, kind="domain", value="rev.example.com", source="ut",
            confidence="high")
        c = pentdb.connect()
        try:
            cls.eid = c.execute(
                "SELECT id FROM raw_events WHERE project=? AND kind='domain' AND value='rev.example.com'",
                (PROJ,)).fetchone()[0]
        finally:
            c.close()
        pentdb.cmd_review(argparse.Namespace(project=PROJ, id=cls.eid, confirm=True,
                                             reject=False, reviewer="ut-human", note="ut"))

    def test_update_blocked(self):
        c = pentdb.connect()
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                c.execute("UPDATE reviews SET note='改写人审记录' WHERE event_id=?", (self.eid,))
        finally:
            c.close()

    def test_delete_blocked(self):
        c = pentdb.connect()
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                c.execute("DELETE FROM reviews WHERE event_id=?", (self.eid,))
        finally:
            c.close()


class WaiveGuard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _init_proj()
        add(project=PROJ, kind="note", value="wv-ut", source="ut", confidence="high")
        pentdb.cmd_waive(argparse.Namespace(project=PROJ, wid=0, confirm=False,
                                            id=WaiveGuard._eid(), term="ut豁免", reason="ut"))

    @classmethod
    def _eid(cls):
        c = pentdb.connect()
        try:
            return c.execute(
                "SELECT id FROM raw_events WHERE project=? AND kind='note' AND value='wv-ut'",
                (PROJ,)).fetchone()[0]
        finally:
            c.close()

    @classmethod
    def _wid(cls):
        c = pentdb.connect()
        try:
            return c.execute(
                "SELECT id FROM waives WHERE project=? AND event_id=? ORDER BY id DESC LIMIT 1",
                (PROJ, cls._eid())).fetchone()[0]
        finally:
            c.close()

    def test_confirm_flip_allowed(self):
        wid = self._wid()
        c = pentdb.connect()
        try:
            cur = c.execute("UPDATE waives SET confirmed=1 WHERE id=?", (wid,))
            self.assertEqual(cur.rowcount, 1)
            c.commit()
        finally:
            c.close()

    def test_reconfirm_and_field_edit_blocked(self):
        wid = self._wid()
        c = pentdb.connect()
        try:
            with self.assertRaises(sqlite3.IntegrityError):  # 已 confirmed=1，再次翻转拒绝
                c.execute("UPDATE waives SET confirmed=1 WHERE id=?", (wid,))
            with self.assertRaises(sqlite3.IntegrityError):  # 改 reason 拒绝
                c.execute("UPDATE waives SET reason='改写豁免理由' WHERE id=?", (wid,))
            with self.assertRaises(sqlite3.IntegrityError):  # 倒退回 draft 拒绝
                c.execute("UPDATE waives SET confirmed=0 WHERE id=?", (wid,))
        finally:
            c.close()

    def test_delete_blocked(self):
        wid = self._wid()
        c = pentdb.connect()
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                c.execute("DELETE FROM waives WHERE id=?", (wid,))
        finally:
            c.close()


class DropRestore(unittest.TestCase):
    def test_drop_works_and_restores_triggers(self):
        proj = "guard-drop-ut"
        pentdb.cmd_init(argparse.Namespace(project=proj))
        add(project=proj, kind="domain", value="drop.example.com", source="ut",
            auto=True, status="confirmed", confidence="high")
        c = pentdb.connect()
        eid = c.execute("SELECT id FROM raw_events WHERE project=?", (proj,)).fetchone()[0]
        c.close()
        pentdb.cmd_review(argparse.Namespace(project=proj, id=eid, confirm=True,
                                             reject=False, reviewer="ut-human", note="ut"))
        pentdb.cmd_drop(argparse.Namespace(project=proj, confirm=True))
        # 触发器全部恢复 + 墓碑留痕 + 守卫立即生效
        c = pentdb.connect()
        try:
            ph = ",".join("?" * len(AUDIT_TRIGGERS))
            n = c.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' "
                          "AND name IN (%s)" % ph, AUDIT_TRIGGERS).fetchone()[0]
            self.assertEqual(n, len(AUDIT_TRIGGERS))
            tomb = c.execute("SELECT COUNT(*) FROM changelog WHERE project='__system__' "
                             "AND action='drop' AND detail LIKE ?", (f"%{proj}%",)).fetchone()[0]
            self.assertEqual(tomb, 1)
            with self.assertRaises(sqlite3.IntegrityError):
                c.execute("UPDATE changelog SET detail='洗库' WHERE project='__system__'")
        finally:
            c.close()


class KbSignature(unittest.TestCase):
    def test_update_experience_has_no_status_param(self):
        """approve 门禁唯一通道：update 不得再接受 status（否则 Python 直调可绕过 --confirm）。"""
        src = open(os.path.join(pentdb.BASE, "kb", "kb.py"), encoding="utf-8").read()
        tree = ast.parse(src)
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "update_experience")
        args = [a.arg for a in fn.args.args]
        self.assertNotIn("status", args)


if __name__ == "__main__":
    unittest.main()
