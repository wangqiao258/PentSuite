#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PentDB exec 单通道单测（stdlib unittest，零依赖）。运行：python -m unittest test_exec -v

覆盖：
  1. 正常执行：输出落盘 + test 事件（confirmed/auto/agent/source=命令）+ 证据挂库（etype=file）
  2. 超时：命令被杀仍留痕（note 标超时）
  3. 非零退出码：照常入库，exit 码进 detail
  4. 守卫：缺命令 / 缺 parent-ext 拒绝
"""
import argparse
import os
import sqlite3
import sys
import tempfile
import unittest

# 必须在 import pentdb 前设置：测试用独立临时库，绝不触碰真实数据
_TMPDIR = tempfile.mkdtemp(prefix="pentdb-exec-test-")
os.environ["PENTDB_DB"] = os.path.join(_TMPDIR, "test.db")
import pentdb  # noqa: E402

PROJ = "exec-ut"
PY = sys.executable  # 测试内嵌命令用当前解释器，路径无空格


def ns(**kw):
    base = dict(project=PROJ, parent_ext="1", stage="", action="", title="",
                note="", detail="", severity="", confidence="high",
                timeout=30, cmd="")
    base.update(kw)
    return argparse.Namespace(**base)


def db():
    c = pentdb.connect()
    c.row_factory = sqlite3.Row
    return c


class ExecBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pentdb.cmd_init(argparse.Namespace(project=PROJ))

    def query(self, sql, *params):
        c = db()
        try:
            return [dict(r) for r in c.execute(sql, params)]
        finally:
            c.close()


class TestExec(ExecBase):
    def test_happy_path(self):
        pentdb.cmd_exec(ns(cmd=PY + ' -c "print(\'hello-exec-ut\')"'))
        ev = self.query("SELECT * FROM raw_events WHERE project=? AND kind='test' "
                        "ORDER BY id DESC LIMIT 1", PROJ)[0]
        self.assertIn("hello-exec-ut", ev["source"])  # source=完整命令
        self.assertIn("exec: ", ev["title"])
        self.assertEqual(ev["status"], "confirmed")
        self.assertEqual(ev["origin"], "agent")
        self.assertEqual(ev["confidence"], "high")
        self.assertIn("exit=0", ev["detail"])
        # 证据：输出文件随库，etype=file
        evid = self.query("SELECT * FROM evidence WHERE project=? AND event_id=? "
                          "ORDER BY id DESC LIMIT 1", PROJ, ev["id"])[0]
        self.assertEqual(evid["etype"], "file")
        self.assertTrue(os.path.exists(evid["path"]))
        with open(evid["path"], encoding="utf-8") as f:
            content = f.read()
        self.assertIn("hello-exec-ut", content)
        self.assertIn("exit=0", content)
        # exec 目录里有落盘文件（evidence 复制件之外还有原始落盘）
        exec_dir = os.path.join(os.path.dirname(pentdb.DB_PATH), "exec", PROJ)
        self.assertTrue(any(f.endswith(".log") for f in os.listdir(exec_dir)))

    def test_timeout_still_lands(self):
        pentdb.cmd_exec(ns(timeout=1, cmd=PY + ' -c "import time;time.sleep(5)"'))
        ev = self.query("SELECT * FROM raw_events WHERE project=? AND kind='test' "
                        "ORDER BY id DESC LIMIT 1", PROJ)[0]
        self.assertIn("超时", ev["note"])

    def test_nonzero_exit_lands(self):
        pentdb.cmd_exec(ns(cmd=PY + ' -c "import sys;sys.exit(3)"'))
        ev = self.query("SELECT * FROM raw_events WHERE project=? AND kind='test' "
                        "ORDER BY id DESC LIMIT 1", PROJ)[0]
        self.assertIn("exit=3", ev["detail"])

    def test_missing_command_rejected(self):
        with self.assertRaises(SystemExit):
            pentdb.cmd_exec(ns(cmd=""))

    def test_missing_parent_ext_rejected(self):
        with self.assertRaises(SystemExit):
            pentdb.cmd_exec(ns(parent_ext="", cmd=PY + ' -c "print(1)"'))


if __name__ == "__main__":
    unittest.main()
