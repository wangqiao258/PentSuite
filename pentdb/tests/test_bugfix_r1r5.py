#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BugFix 批次 R1-R5 回归单测（stdlib unittest，零依赖）。

独立验证工程师本批修复（非橡皮图章——每条都用全新场景重证）：
  F1a 全新库 connect 后 user_version=12、projects 含 profile 列；
      /api/projects 同款 SQL 不炸（子进程+独立临时库，含 v11 历史库迁移复现场景）
  F1b _mig_v12_projects_profile 幂等：已含 profile 列再跑不报错
  F2  cmd_drop 级联清 intents/plan_steps/hints，changelog 墓碑在，审计触发器恢复
  F3a cmd_add 返回真实事件 id（新建/重扫更新/dedup 合并三出口）；test 幂等命中仍拒写
  F3b exec 通道证据挂在 cmd_add 返回的事件 id 上（后有新行也不挂错）
  F4  lint 指引文本不再引用不存在的 update --id（R-501/F-503 如实文案）
"""
import argparse
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest

os.environ.setdefault("PENTDB_DB", os.path.join(tempfile.mkdtemp(prefix="pentdb-bugfix-test-"), "test.db"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pentdb  # noqa: E402
import pdb_core  # noqa: E402

PENTDB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def ns(**kw):
    base = dict(project="", ext_id="", kind="note", value="v", title="", detail="",
                note="", source="bugfix-ut", parent_ext="", merge_key="", status="new",
                confidence="", severity="", code="", tech="", service="", scope="in",
                auto=False, update=False, origin="human", stage="",
                req="", resp="", waive_capture="", no_dedupe=False, intent_id=0)
    base.update(kw)
    return argparse.Namespace(**base)


def count(c, table, proj):
    return c.execute(f"SELECT count(*) FROM {table} WHERE project=?", (proj,)).fetchone()[0]


class F1SchemaV12FreshDb(unittest.TestCase):
    """F1a：子进程 + 全新独立临时库（与套件共享库隔离，真实复现新装/历史库场景）。"""

    CHILD = r"""
import pentdb

SQL = "SELECT name, profile, archived FROM projects ORDER BY archived, name"

# 场景1：全新库——建库即 v12 且 /api/projects 同款 SQL 不炸
c = pentdb.connect()
ver = c.execute("PRAGMA user_version").fetchone()[0]
assert ver == 12, "user_version=%r" % (ver,)
cols = [r[1] for r in c.execute("PRAGMA table_info(projects)")]
assert "profile" in cols, cols
list(c.execute(SQL))

# 场景2：模拟 v11 历史库（无 profile 列——修复前 /api/projects 必炸的库形）
# → connect() 应自动迁移补列；之后同款 SQL 不炸
c.execute("ALTER TABLE projects DROP COLUMN profile")
c.execute("PRAGMA user_version=11")
c.commit()
c.close()
c2 = pentdb.connect()
ver2 = c2.execute("PRAGMA user_version").fetchone()[0]
assert ver2 == 12, "migrated user_version=%r" % (ver2,)
cols2 = [r[1] for r in c2.execute("PRAGMA table_info(projects)")]
assert "profile" in cols2, cols2
list(c2.execute(SQL))
c2.close()
print("CHILD-OK")
"""

    def test_fresh_and_legacy_db_projects_sql(self):
        db = os.path.join(tempfile.mkdtemp(prefix="pentdb-bugfix-fresh-"), "fresh.db")
        env = dict(os.environ)
        env["PENTDB_DB"] = db
        env["PYTHONPATH"] = PENTDB_DIR + os.pathsep + env.get("PYTHONPATH", "")
        cp = subprocess.run([sys.executable, "-c", self.CHILD],
                            capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(cp.returncode, 0,
                         "子进程失败（原 bug 复现？）:\nSTDOUT:%s\nSTDERR:%s"
                         % (cp.stdout, cp.stderr))
        self.assertIn("CHILD-OK", cp.stdout)

    def test_mig_v12_idempotent(self):
        """F1b：已含 profile 列的库再跑迁移步不报错、列不丢、版本不被回拨。"""
        c = pentdb.connect()
        try:
            pdb_core._mig_v12_projects_profile(c)  # 列已存在 → OperationalError → return
            pdb_core._mig_v12_projects_profile(c)  # 连跑两次仍幂等
            cols = [r[1] for r in c.execute("PRAGMA table_info(projects)")]
            self.assertIn("profile", cols)
            self.assertEqual(c.execute("PRAGMA user_version").fetchone()[0], 12)
            # /api/projects 同款 SQL 在共享库上同样不炸
            list(c.execute("SELECT name, profile, archived FROM projects "
                           "ORDER BY archived, name"))
        finally:
            c.close()


class F2DropCascade(unittest.TestCase):
    PROJ = "bugfix-drop-ut"

    def test_drop_clears_intents_plans_hints(self):
        pentdb.cmd_init(argparse.Namespace(project=self.PROJ))
        pentdb.cmd_add(ns(project=self.PROJ, kind="domain", value="drop.example.com",
                          status="confirmed"))
        c = pentdb.connect()
        c.execute("INSERT INTO intents(project,goal,status,created_at) VALUES(?,?,?,?)",
                  (self.PROJ, "ut 意图", "active", pentdb.now()))
        c.execute("INSERT INTO plan_steps(project,seq,title,status,created_at) "
                  "VALUES(?,?,?,?,?)", (self.PROJ, 1, "ut 步骤", "ready", pentdb.now()))
        c.execute("INSERT INTO hints(project,text,status,created_at) VALUES(?,?,?,?)",
                  (self.PROJ, "ut 提示", "open", pentdb.now()))
        c.commit()
        for t in ("intents", "plan_steps", "hints", "raw_events"):
            self.assertGreater(count(c, t, self.PROJ), 0, f"前置失败：{t} 应有行")
        c.close()

        pentdb.cmd_drop(argparse.Namespace(project=self.PROJ, confirm=True))

        c = pentdb.connect()
        try:
            for t in ("intents", "plan_steps", "hints", "raw_events", "assets",
                      "pending_tests", "waives", "evidence"):
                self.assertEqual(count(c, t, self.PROJ), 0, f"drop 后 {t} 应清零")
            self.assertIsNone(c.execute("SELECT name FROM projects WHERE name=?",
                                        (self.PROJ,)).fetchone())
            tomb = c.execute("SELECT detail FROM changelog WHERE action='drop' "
                             "AND detail LIKE ?", ("%" + self.PROJ + "%",)).fetchone()
            self.assertIsNotNone(tomb, "changelog 墓碑留痕丢失")
            # 审计触发器必须已恢复（drop 短暂解除后 executescript(SCHEMA) 幂等重建）
            with self.assertRaises(sqlite3.IntegrityError):
                c.execute("UPDATE changelog SET detail='x' WHERE action='drop'")
            c.rollback()
        finally:
            c.close()
        # 套件共享库洁癖：三表已空，归还 AUTOINCREMENT 序号——
        # 后续模块（test_intents 等）对首张行 id 有硬编码假设，不能因本用例消耗而漂移
        c = pentdb.connect()
        try:
            c.execute("DELETE FROM sqlite_sequence WHERE name IN "
                      "('intents','plan_steps','hints')")
            c.commit()
        finally:
            c.close()

    def test_drop_empty_project_no_crash(self):
        """边缘：空项目（各表 0 行）drop 不崩，墓碑照样留。"""
        proj = "bugfix-drop-empty"
        pentdb.cmd_init(argparse.Namespace(project=proj))
        pentdb.cmd_drop(argparse.Namespace(project=proj, confirm=True))
        c = pentdb.connect()
        try:
            self.assertIsNone(c.execute("SELECT name FROM projects WHERE name=?",
                                        (proj,)).fetchone())
            self.assertIsNotNone(c.execute(
                "SELECT 1 FROM changelog WHERE action='drop' AND detail LIKE ?",
                ("%" + proj + "%",)).fetchone())
        finally:
            c.close()

    def test_drop_requires_confirm(self):
        proj = "bugfix-drop-noconfirm"
        pentdb.cmd_init(argparse.Namespace(project=proj))
        with self.assertRaises(SystemExit):
            pentdb.cmd_drop(argparse.Namespace(project=proj, confirm=False))
        c = pentdb.connect()
        try:
            self.assertIsNotNone(c.execute("SELECT name FROM projects WHERE name=?",
                                           (proj,)).fetchone())
        finally:
            c.close()


class F3CmdAddReturnsId(unittest.TestCase):
    PROJ = "bugfix-add-ut"

    @classmethod
    def setUpClass(cls):
        pentdb.cmd_init(argparse.Namespace(project=cls.PROJ))

    def test_new_event_returns_row_id(self):
        eid = pentdb.cmd_add(ns(project=self.PROJ, kind="domain",
                                value="newid.example.com", status="confirmed"))
        c = pentdb.connect()
        try:
            row = c.execute("SELECT id, kind, value FROM raw_events WHERE id=?",
                            (eid,)).fetchone()
        finally:
            c.close()
        self.assertIsNotNone(row, "返回值必须是真实落库行 id")
        self.assertEqual((row["kind"], row["value"]), ("domain", "newid.example.com"))

    def test_rescan_update_returns_existing_id(self):
        eid1 = pentdb.cmd_add(ns(project=self.PROJ, kind="domain",
                                 value="rescan.example.com", status="confirmed"))
        eid2 = pentdb.cmd_add(ns(project=self.PROJ, kind="domain",
                                 value="rescan.example.com", status="confirmed",
                                 update=True, note="重扫"))
        self.assertEqual(eid2, eid1, "重扫更新必须返回既有记录 id")
        c = pentdb.connect()
        try:
            self.assertEqual(c.execute(
                "SELECT count(*) FROM raw_events WHERE project=? AND value=?",
                (self.PROJ, "rescan.example.com")).fetchone()[0], 1)
        finally:
            c.close()

    def test_dedup_merge_returns_master_id(self):
        d = tempfile.mkdtemp(prefix="pentdb-bugfix-ev-")
        req1, resp1 = os.path.join(d, "req1.txt"), os.path.join(d, "resp1.txt")
        req2, resp2 = os.path.join(d, "req2.txt"), os.path.join(d, "resp2.txt")
        for p, t in ((req1, "GET /a HTTP/1.1"), (resp1, "HTTP/1.1 200"),
                     (req2, "GET /a HTTP/1.1\r\nX-2: 1"), (resp2, "HTTP/1.1 200 ok")):
            with open(p, "w", encoding="utf-8") as f:
                f.write(t)
        kw = dict(project=self.PROJ, kind="finding", title="ut去重漏洞")
        master = pentdb.cmd_add(ns(req=req1, resp=resp1,
                                   value="https://t.example.com/a", **kw))
        # 同指纹不同原文（剥 scheme://host 后同路径）：撞 dedup 归并而非 kind+value 重复门禁
        merged = pentdb.cmd_add(ns(req=req2, resp=resp2,
                                   value="https://other.example.com/a", **kw))
        self.assertEqual(merged, master, "dedup 合并必须返回主条目 id（未新建行）")
        c = pentdb.connect()
        try:
            self.assertEqual(c.execute(
                "SELECT count(*) FROM raw_events WHERE project=? AND kind='finding' "
                "AND title=?", (self.PROJ, kw["title"])).fetchone()[0], 1)
            n_ev = c.execute("SELECT count(*) FROM evidence WHERE project=? AND event_id=?",
                             (self.PROJ, master)).fetchone()[0]
            self.assertGreaterEqual(n_ev, 4, "两次报文都应挂在主条目上")
        finally:
            c.close()

    def test_test_idempotent_still_rejected(self):
        """边缘：test 幂等命中仍 sys.exit 拒写（本批不得为返回 id 而放行）。"""
        kw = dict(project=self.PROJ, kind="test", value="ut-test-idem",
                  title="幂等测试", detail="d", source="ut-cmd-idem",
                  parent_ext="1", status="confirmed", auto=True)
        pentdb.cmd_add(ns(**kw))
        with self.assertRaises(SystemExit):
            pentdb.cmd_add(ns(**kw))
        c = pentdb.connect()
        try:
            self.assertEqual(c.execute(
                "SELECT count(*) FROM raw_events WHERE project=? AND kind='test' "
                "AND source=?", (self.PROJ, "ut-cmd-idem")).fetchone()[0], 1)
        finally:
            c.close()


class F3ExecEvidenceBinding(unittest.TestCase):
    PROJ = "bugfix-exec-ut"

    def test_exec_evidence_on_returned_event_id(self):
        pentdb.cmd_init(argparse.Namespace(project=self.PROJ))
        asset_id = pentdb.cmd_add(ns(project=self.PROJ, kind="domain",
                                     value="exec.example.com", status="confirmed"))
        cmd = "echo bugfix-exec-ut-marker"
        pentdb.cmd_exec(argparse.Namespace(
            project=self.PROJ, parent_ext=str(asset_id), cmd=cmd, timeout=30,
            action="ut-echo", title="ut exec 绑定验证", detail="", note="",
            confidence="high", severity="", probe_parse=False, probe_host="",
            intent_id=0))
        c = pentdb.connect()
        try:
            ev = c.execute("SELECT id FROM raw_events WHERE project=? AND kind='test' "
                           "AND source=?", (self.PROJ, cmd)).fetchone()
            self.assertIsNotNone(ev, "exec 落库的 test 事件不存在")
            tid = ev["id"]
            rows = list(c.execute("SELECT event_id, note FROM evidence "
                                  "WHERE project=? AND event_id!=0", (self.PROJ,)))
            self.assertTrue(rows, "exec 输出未挂证据")
            for r in rows:
                self.assertEqual(r["event_id"], tid,
                                 "证据必须挂在 cmd_add 返回的事件 id 上")
        finally:
            c.close()
        # 回归区分点：之后再产生更新的行，旧证据也不得“猜最后一行”挂错
        pentdb.cmd_add(ns(project=self.PROJ, kind="note", value="decoy-after-exec"))
        c = pentdb.connect()
        try:
            newer = c.execute("SELECT max(id) FROM raw_events WHERE project=?",
                              (self.PROJ,)).fetchone()[0]
            self.assertGreater(newer, tid, "前置失败：应存在比 test 事件更新的行")
            bad = c.execute("SELECT count(*) FROM evidence WHERE project=? AND event_id=?",
                            (self.PROJ, newer)).fetchone()[0]
            self.assertEqual(bad, 0, "证据挂到了最后一行而非真实事件 id（旧 bug 复发）")
        finally:
            c.close()


class F4LintFixTexts(unittest.TestCase):
    PROJ = "bugfix-lint-ut"

    def test_lint_fix_texts_truthful(self):
        pentdb.cmd_init(argparse.Namespace(project=self.PROJ))
        # 触发 R-501：plan-review 复盘 detail 无 # 引用
        pentdb.cmd_add(ns(project=self.PROJ, kind="note", value="plan-review",
                          detail="复盘结论但无观测引用"))
        # 触发 F-503：finding 无 parent_ext（waive 通道免报文门禁）
        pentdb.cmd_add(ns(project=self.PROJ, kind="finding",
                          value="https://lint.example.com/x", title="ut lint 漏洞",
                          waive_capture="ut 豁免草稿"))
        c = pentdb.connect()
        try:
            rep = pentdb.lint_report(c, self.PROJ, journal_check=False)
        finally:
            c.close()
        items = rep["items"]["errors"] + rep["items"]["warns"]
        self.assertTrue(items, "前置失败：lint 应有产出")
        for it in items:
            self.assertNotIn("update --id", it["fix"],
                             f"[{it['code']}] 指引再次说谎：引用了不存在的 update --id")
        for line in rep["errors"] + rep["warns"]:
            self.assertNotIn("update --id", line)
        codes = {it["code"]: it for it in items}
        self.assertIn("R-501", codes)
        self.assertIn("--update", codes["R-501"]["fix"])
        self.assertIn("F-503", codes)
        self.assertIn("--parent-ext", codes["F-503"]["fix"])


if __name__ == "__main__":
    unittest.main()
