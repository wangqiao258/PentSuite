"""归因防呆单测（stdlib unittest，零依赖）。运行：python -m unittest test_parent_semantics -v

覆盖 U1（2026-10-13，动机：demo-juiceshop 复测 DOM XSS 结论三连错挂 #4655 登录 SQLi）：
  1. check_parent_semantics 函数级：XSS 信号 ↔ CWE-89/564 注入族、SQL 信号 ↔ CWE-79/80 XSS 族
     双向告警；其他组合（pyc→CWE-552）、非 finding parent、CWE 空、parent=None 一律放行
  2. 写入口通道级：cmd_add test 挂错配 parent → stdout 出 [warn] 归因存疑（不阻断、事件正常入库）；
     正确挂接与跨族安全组合零告警（宁缺勿滥，防误报训练人忽略）
"""
import argparse
import contextlib
import io
import os
import sqlite3
import sys
import tempfile
import unittest

os.environ.setdefault("PENTDB_DB", os.path.join(tempfile.mkdtemp(prefix="pentdb-sem-test-"), "test.db"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pentdb  # noqa: E402
import pdb_assets  # noqa: E402
from pdb_core import connect, require_project  # noqa: E402

PROJ = "sem-ut"


class Row(dict):
    """最小 Row 替身：sqlite3.Row 的字符串下标访问语义。"""

    def __getitem__(self, k):
        return dict.__getitem__(self, k)


def frow(**kw):
    base = dict(id=1, kind="finding", ext_id="", title="", value="")
    base.update(kw)
    return Row(**base)


def ns_add(**kw):
    base = dict(project=PROJ, ext_id="", kind="test", value="v", title="", detail="",
                note="", source="ut", parent_ext="", merge_key="", status="new",
                confidence="high", severity="", code="", tech="", service="", scope="in",
                auto=False, update=False, origin="agent",
                req="", resp="", waive_capture="", no_dedupe=False, intent_id=0)
    base.update(kw)
    return argparse.Namespace(**base)


def run_add(**kw):
    try:
        pdb_assets.cmd_add(ns_add(**kw))
    except SystemExit as e:
        return str(e)
    return ""


def add_output(**kw):
    """跑 cmd_add 并回传 (退出文本, stdout 全文)。"""
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            pdb_assets.cmd_add(ns_add(**kw))
        return "", buf.getvalue()
    except SystemExit as e:
        return str(e), buf.getvalue()


def seed_finding(ext_id, value, fid_hint=""):
    """造一条 CWE finding（带 req/resp 过门禁），返回其 id。"""
    c = connect()
    try:
        require_project(c, PROJ)
        c.execute("INSERT INTO raw_events(project,ext_id,kind,value,title,note,parent_ext,"
                  "status,confidence,source,origin,created_at,updated_at) "
                  "VALUES(?,?,?,?,?,'','4653','new','high','ut','agent',datetime('now'),datetime('now'))",
                  (PROJ, ext_id, "finding", value, fid_hint or value))
        c.commit()
        return c.execute("SELECT last_insert_rowid()").fetchone()[0]
    finally:
        c.close()


def seed_domain():
    c = connect()
    try:
        require_project(c, PROJ)
        c.execute("INSERT INTO raw_events(project,kind,value,merge_key,status,source,origin,"
                  "created_at,updated_at) VALUES(?,'domain','d.example.com','d.example.com',"
                  "'confirmed','ut','agent',datetime('now'),datetime('now'))", (PROJ,))
        c.commit()
        return c.execute("SELECT last_insert_rowid()").fetchone()[0]
    finally:
        c.close()


class TestFunctionLevel(unittest.TestCase):
    """check_parent_semantics 纯函数行为。"""

    def test_01_xss_vs_cwe89_warns(self):
        w = pdb_assets.check_parent_semantics(
            "DOM XSS 执行级复现", "待复测 ｜ 依据：弹窗截图", frow(id=7, ext_id="CWE-89", title="登录SQLi"))
        self.assertIn("归因存疑", w)
        self.assertIn("#7", w)

    def test_02_sql_vs_cwe79_warns(self):
        w = pdb_assets.check_parent_semantics(
            "搜索 UNION 拖库", "复现 ｜ 依据：sql 注入 24 用户", frow(id=8, ext_id="CWE-79", title="DOM XSS"))
        self.assertIn("归因存疑", w)
        self.assertIn("#8", w)

    def test_03_chinese_signal_warns(self):
        w = pdb_assets.check_parent_semantics("搜索页 弹窗 验证", "", frow(id=9, ext_id="CWE-89"))
        self.assertIn("归因存疑", w)

    def test_04_cross_family_safe_passes(self):
        self.assertEqual("", pdb_assets.check_parent_semantics(
            "pyc 算法还原", "待复测", frow(id=10, ext_id="CWE-552", title="/ftp")))
        self.assertEqual("", pdb_assets.check_parent_semantics(
            "IDOR 量化", "复现", frow(id=11, ext_id="CWE-639", title="IDOR")))

    def test_05_non_finding_parent_passes(self):
        self.assertEqual("", pdb_assets.check_parent_semantics(
            "xss 任意", "", frow(id=12, kind="domain", ext_id="CWE-89")))

    def test_06_none_and_empty_cwe_pass(self):
        self.assertEqual("", pdb_assets.check_parent_semantics("xss", "", None))
        self.assertEqual("", pdb_assets.check_parent_semantics("xss", "", frow(id=13, ext_id="")))

    def test_07_xss_family_cwe80_warns(self):
        w = pdb_assets.check_parent_semantics("sql 注入复测", "", frow(id=14, ext_id="CWE-80"))
        self.assertIn("归因存疑", w)

    def test_08_injection_family_cwe564_warns(self):
        w = pdb_assets.check_parent_semantics("domx 弹窗", "", frow(id=15, ext_id="CWE-564"))
        self.assertIn("归因存疑", w)


class TestWriteGate(unittest.TestCase):
    """写入口通道级：add test 错配 parent → [warn] 但不阻断；正确挂接零告警。"""

    @classmethod
    def setUpClass(cls):
        pdb_assets.cmd_init(argparse.Namespace(project=PROJ))
        cls.f_sql = seed_finding("CWE-89", "登录SQLi finding")
        cls.f_xss = seed_finding("CWE-79", "DOM XSS finding")
        cls.dom = seed_domain()

    def test_01_mismatch_warns_but_writes(self):
        err, out = add_output(project=PROJ, kind="test", value="DOM XSS 静态链",
                              note="待复测 ｜ 依据：innerHTML", source="ut-xss",
                              parent_ext=str(self.f_sql), confidence="high")
        self.assertEqual("", err, "错配只警告不阻断：事件必须正常入库")
        self.assertIn("[warn] 归因存疑", out)
        self.assertIn(str(self.f_sql), out)

    def test_02_correct_attach_silent(self):
        err, out = add_output(project=PROJ, kind="test", value="搜索 UNION 拖库复测",
                              note="复现 ｜ 依据：报文", source="ut-sql",
                              parent_ext=str(self.f_sql), confidence="high")
        self.assertEqual("", err)
        self.assertNotIn("[warn]", out)

    def test_03_xss_finding_with_xss_test_silent(self):
        err, out = add_output(project=PROJ, kind="test", value="搜索页 DOM XSS 复现",
                              note="复现 ｜ 依据：弹窗", source="ut-xss2",
                              parent_ext=str(self.f_xss), confidence="high")
        self.assertEqual("", err)
        self.assertNotIn("[warn]", out)

    def test_04_multi_parent_warns_per_bad(self):
        err, out = add_output(project=PROJ, kind="test", value="xss 复测多 parent",
                              note="待复测", source="ut-multi",
                              parent_ext=f"{self.dom},{self.f_sql}", confidence="high")
        self.assertEqual("", err)
        self.assertEqual(1, out.count("[warn]"), "domain parent 不告警，CWE-89 那条告警一次")

    def test_05_no_parent_silent(self):
        err, out = add_output(project=PROJ, kind="test", value="无 parent 的 test",
                              note="待复测", source="ut-nop", confidence="high")
        self.assertEqual("", err)
        self.assertNotIn("[warn]", out)

    def test_06_non_test_kind_silent(self):
        err, out = add_output(project=PROJ, kind="note", value="xss 笔记",
                              note="记录", source="ut-note",
                              parent_ext=str(self.f_sql), confidence="high")
        self.assertEqual("", err)
        self.assertNotIn("[warn]", out, "防呆只作用于 test 结论（osint/finding 由 F-301 门禁管）")


if __name__ == "__main__":
    unittest.main()
