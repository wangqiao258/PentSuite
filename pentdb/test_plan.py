"""A+B 决策链可见性单测（stdlib unittest，零依赖）。运行：python -m unittest test_plan -v

覆盖：
  1. test note 两段式：机读结论+「依据」→ 无缺依据 warn；有机读结论无依据 → warn
  2. suggestion 三段式：detail 缺【下一步】→ warn；三段齐全 → 无 warn
  3. pentest 报告「复测计划」节自动引用最新 suggestion
"""
import argparse
import os
import tempfile
import unittest

os.environ.setdefault("PENTDB_DB", os.path.join(tempfile.mkdtemp(prefix="pentdb-plan-test-"), "test.db"))
import pentdb  # noqa: E402

pentdb.JOURNAL_DIR = os.path.join(tempfile.mkdtemp(prefix="pentdb-plan-test-"), "journal")

PROJ = "plan-ut"
BASIS_KW = "缺判断依据"
NEXT_KW = "缺【下一步】"


def ns(**kw):
    base = dict(project=PROJ, ext_id="", kind="note", value="v", title="", detail="",
                note="", source="ut", parent_ext="1", merge_key="", status="new",
                confidence="high", severity="", code="", tech="", service="", scope="in",
                auto=False, update=False, origin="agent", stage="",
                req="", resp="", waive_capture="", no_dedupe=False)
    base.update(kw)
    return argparse.Namespace(**base)


def add(**kw):
    pentdb.cmd_add(ns(**kw))


def lint():
    c = pentdb.connect()
    try:
        return pentdb.lint_report(c, PROJ, journal_check=False)
    finally:
        c.close()


def hits(rep, kw):
    return [x for x in rep["warns"] + rep["errors"] if kw in x]


class BasisSegment(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        c = pentdb.connect()
        if not c.execute("SELECT 1 FROM projects WHERE name=?", (PROJ,)).fetchone():
            pentdb.cmd_init(argparse.Namespace(project=PROJ))
        c.close()

    def test_conclusion_with_basis_no_warn(self):
        add(kind="test", value="探测A", note="复现 ｜ 依据：响应包含 SQL 语法错误回显（exit=0 输出 #12 行）")
        self.assertEqual(hits(lint(), BASIS_KW), [])

    def test_conclusion_without_basis_warns(self):
        add(kind="test", value="探测B", source="ut-basis-b", note="未复现")
        rep = lint()
        self.assertTrue(hits(rep, BASIS_KW), "机读结论无依据应报 warn")
        self.assertIn("#", hits(rep, BASIS_KW)[0])  # 能定位到具体记录


class SuggestionPlan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        c = pentdb.connect()
        if not c.execute("SELECT 1 FROM projects WHERE name=?", (PROJ,)).fetchone():
            pentdb.cmd_init(argparse.Namespace(project=PROJ))
        c.close()

    def test_missing_next_section_warns(self):
        add(kind="suggestion", value="plan-x", title="批次计划",
            detail="【已做】curl 探测 /admin\n【结论】403 疑似有墙")
        self.assertTrue(hits(lint(), NEXT_KW))

    def test_full_three_sections_no_warn(self):
        add(kind="suggestion", value="plan-y", title="批次计划",
            detail="【已做】curl 探测 /admin\n【结论】403 WAF 拦截\n"
                   "【下一步】用 curl.exe 复测 GetWebPage 的 orderBy 注入点")
        self.assertEqual(hits(lint(), NEXT_KW), [])

    def test_report_includes_latest_plan(self):
        # 字母序下前面用例已插入 plan-x/plan-y，这里补一条最新计划再验证报告引用"最新"
        add(kind="suggestion", value="plan-z", title="批次计划",
            detail="【已做】curl 探测 /admin\n【结论】403 WAF 拦截\n"
                   "【下一步】用 curl.exe 复测 GetWebPage 的 orderBy 注入点")
        c = pentdb.connect()
        try:
            text = pentdb._pentest_report(c, PROJ)
        finally:
            c.close()
        self.assertIn("复测计划", text)
        self.assertIn("GetWebPage 的 orderBy 注入点", text)
        self.assertIn("## 5 附录", text)  # 附录顺延编号


if __name__ == "__main__":
    unittest.main()
