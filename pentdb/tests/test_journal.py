"""执行流水（journal）对账单测：probe_like 启发式 + journal_unmatched 平账语义。"""
import json
import os
import sqlite3
import tempfile
import unittest

# 多模块同跑时与 import 顺序无关：先加载者建隔离库，全套件共享（必须先于 import pentdb）
os.environ.setdefault("PENTDB_DB", os.path.join(tempfile.mkdtemp(prefix="pentdb-journal-test-"), "test.db"))
import pentdb


class TestProbeLike(unittest.TestCase):
    def test_url_hit(self):
        self.assertTrue(pentdb.probe_like('curl http://target.com/api'))
        self.assertTrue(pentdb.probe_like("python scan.py https://x.com"))

    def test_tool_word_hit(self):
        self.assertTrue(pentdb.probe_like("nmap -sV 10.0.0.1"))
        self.assertTrue(pentdb.probe_like("sqlmap -u target --batch"))

    def test_plain_cmd_miss(self):
        self.assertFalse(pentdb.probe_like("cd /tmp && ls -la"))
        self.assertFalse(pentdb.probe_like("python -m unittest discover"))
        self.assertFalse(pentdb.probe_like(""))

    def test_pentdb_bookkeeping_exempt(self):
        # 套件自身调用是记账/自录通道，即使带 URL 也不算探测
        self.assertFalse(pentdb.probe_like(
            "python pentdb/pentdb.py exec --project P --parent-ext 1 --cmd 'curl http://x.com'"))
        self.assertFalse(pentdb.probe_like("python pentdb/pentdb.py recon --project P --domain x.com"))


class TestJournalUnmatched(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.old_dir = pentdb.JOURNAL_DIR
        pentdb.JOURNAL_DIR = self.tmp
        self.con = sqlite3.connect(":memory:")
        self.con.row_factory = sqlite3.Row
        self.con.execute("CREATE TABLE raw_events(id INTEGER PRIMARY KEY, kind TEXT, source TEXT)")

    def tearDown(self):
        pentdb.JOURNAL_DIR = self.old_dir
        self.con.close()

    def _write(self, *cmds):
        with open(os.path.join(self.tmp, "2026-09-30.log"), "a", encoding="utf-8") as f:
            for cmd in cmds:
                f.write(json.dumps({"ts": "t", "cmd": cmd}, ensure_ascii=False) + "\n")

    def _add_test(self, source):
        self.con.execute("INSERT INTO raw_events(kind, source) VALUES('test', ?)", (source,))

    def test_empty_dir(self):
        self.assertEqual(pentdb.journal_unmatched(self.con), {})

    def test_covered_by_exec_source(self):
        # exec 落库 source=完整命令：journal 命令里包含该 source 即平账
        self._write("python pentdb/pentdb.py exec --project P --cmd 'curl http://x.com'")
        self._add_test("curl http://x.com")
        self.assertEqual(pentdb.journal_unmatched(self.con), {})

    def test_unmatched_probe_is_error_material(self):
        self._write("curl http://never-recorded.com/api")
        out = pentdb.journal_unmatched(self.con)
        self.assertIn("curl http://never-recorded.com/api", out)
        self.assertEqual(out["curl http://never-recorded.com/api"], 1)

    def test_non_probe_ignored(self):
        self._write("python -m unittest test_journal", "git status")
        self.assertEqual(pentdb.journal_unmatched(self.con), {})

    def test_corrupt_lines_tolerated(self):
        with open(os.path.join(self.tmp, "2026-09-30.log"), "a", encoding="utf-8") as f:
            f.write("not-json\n\n")
            f.write(json.dumps({"ts": "t", "cmd": ""}) + "\n")
        self.assertEqual(pentdb.journal_unmatched(self.con), {})

    def test_short_source_never_covers(self):
        # 极短手填 source（'s'/'ut' 实测踩过）不得把无关命令误判为已记录
        self._add_test("s")
        self._write("curl http://real-target.com/api")
        out = pentdb.journal_unmatched(self.con)
        self.assertIn("curl http://real-target.com/api", out)

    def test_short_source_exact_still_covers(self):
        # 命令与 source 完全一致（cmd ⊆ s）不受长度下限限制
        self._add_test("nmap -sV 1.2.3.4")
        self._write("nmap -sV 1.2.3.4")
        self.assertEqual(pentdb.journal_unmatched(self.con), {})

    def test_count_aggregated(self):
        cmd = "curl http://miss.com/a"
        self._write(cmd, cmd, cmd)
        self.assertEqual(pentdb.journal_unmatched(self.con)[cmd], 3)

    def test_other_session_cwd_filtered(self):
        # 并行会话/其他工作目录的探测命令不归因本项目（cwd 会话隔离，实测踩过）
        with open(os.path.join(self.tmp, "2026-09-30.log"), "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": "t", "cmd": "curl http://other-session.com/api",
                                "cwd": "c:/other/workspace-x"}) + "\n")
        self.assertEqual(pentdb.journal_unmatched(self.con), {})


if __name__ == "__main__":
    unittest.main()
