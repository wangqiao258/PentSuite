#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PentDB 对账门禁 + 生命周期 CLI 单测（stdlib unittest，零依赖）。
运行：python -m unittest test_audit -v

覆盖：
  1. lifecycle CLI：finding 机读结论落 attrs+changelog；非 finding 拒绝
  2. 对账①：evidence 文件丢失 → lint error
  3. 对账②：test 零证据输出 → lint warn
  4. 结论机读词：note 不以机读词开头 → lint warn；以机读词开头 → 无该 warn
  5. 报文写入口门禁：finding 无 --req/--resp 拒绝；--waive-capture 起草豁免（不生效），
     人工 waive --wid N --confirm 后生效；report 出口门禁 error 拒出、--force 放行
"""
import argparse
import os
import sqlite3
import tempfile
import unittest

_TMPDIR = tempfile.mkdtemp(prefix="pentdb-audit-test-")
os.environ["PENTDB_DB"] = os.path.join(_TMPDIR, "test.db")
import pentdb  # noqa: E402

PROJ = "audit-ut"


def ns(**kw):
    base = dict(project=PROJ, ext_id="", kind="note", value="v", title="", detail="",
                note="", source="unittest", parent_ext="", merge_key="", status="new",
                confidence="", severity="", code="", tech="", service="", scope="in",
                auto=False, update=False, origin="agent", stage="",
                req="", resp="", waive_capture="")
    base.update(kw)
    return argparse.Namespace(**base)


def _pkt_files(tag):
    """造一对最小 req/resp 证据文件，返回路径。"""
    reqf = os.path.join(_TMPDIR, f"{tag}.req.txt")
    respf = os.path.join(_TMPDIR, f"{tag}.resp.txt")
    with open(reqf, "w", encoding="utf-8") as f:
        f.write("GET / HTTP/1.1\r\nHost: t\r\n\r\n")
    with open(respf, "w", encoding="utf-8") as f:
        f.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    return reqf, respf


def lint():
    c = pentdb.connect()
    try:
        return pentdb.lint_report(c, PROJ)
    finally:
        c.close()


class AuditBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pentdb.cmd_init(argparse.Namespace(project=PROJ))


class TestLifecycle(AuditBase):
    def test_finding_lifecycle(self):
        reqf, respf = _pkt_files("lc")
        pentdb.cmd_add(ns(kind="finding", value="http://t/a", title="测试漏洞",
                          source="ut", origin="agent", confidence="high", auto=False,
                          req=reqf, resp=respf))
        c = pentdb.connect()
        fid = c.execute("SELECT id FROM raw_events WHERE project=? AND kind='finding' "
                        "ORDER BY id DESC LIMIT 1", (PROJ,)).fetchone()[0]
        c.close()
        pentdb.cmd_lifecycle(argparse.Namespace(project=PROJ, id=fid,
                                                code="not-reproduced", note="三轮未复现"))
        c = pentdb.connect()
        c.row_factory = sqlite3.Row
        attrs = c.execute("SELECT attrs FROM raw_events WHERE id=?", (fid,)).fetchone()["attrs"]
        import json
        self.assertEqual(json.loads(attrs or "{}")["lifecycle"], "not-reproduced")
        log = c.execute("SELECT detail FROM changelog WHERE project=? AND action='lifecycle' "
                        "ORDER BY id DESC LIMIT 1", (PROJ,)).fetchone()["detail"]
        c.close()
        self.assertIn(f"#{fid} → not-reproduced", log)
        self.assertIn("（CLI）", log)

    def test_lifecycle_rejects_non_finding(self):
        pentdb.cmd_add(ns(kind="test", value="动作", title="t", note="复现：三步",
                          source="ut", origin="agent", confidence="high",
                          auto=True, status="confirmed", parent_ext="1"))
        c = pentdb.connect()
        tid = c.execute("SELECT id FROM raw_events WHERE project=? AND kind='test' "
                        "ORDER BY id DESC LIMIT 1", (PROJ,)).fetchone()[0]
        c.close()
        with self.assertRaises(SystemExit):
            pentdb.cmd_lifecycle(argparse.Namespace(project=PROJ, id=tid,
                                                    code="reproduced", note=""))


class TestReconcileLint(AuditBase):
    def test_missing_evidence_file_is_error(self):
        c = pentdb.connect()
        c.execute("INSERT INTO evidence(project,event_id,path,sha256,note,etype,created_at) "
                  "VALUES(?,?,?,?,?,?,?)",
                  (PROJ, 0, os.path.join(_TMPDIR, "ghost.txt"), "deadbeef", "request",
                   "request", pentdb.now()))
        c.commit()
        c.close()
        rep = lint()
        self.assertTrue(any("文件丢失" in e for e in rep["errors"]))

    def test_test_without_evidence_warns(self):
        pentdb.cmd_add(ns(kind="test", value="扫描", title="裸跑测试", note="复现：无输出",
                          source="ut", origin="agent", confidence="high",
                          auto=True, status="confirmed", parent_ext="1"))
        rep = lint()
        self.assertTrue(any("无任何证据输出" in w for w in rep["warns"]))

    def test_conclusion_prefix_warn(self):
        pentdb.cmd_add(ns(kind="test", value="探测", title="结论不规范", note="随手写的散文结论",
                          source="ut", origin="agent", confidence="high",
                          auto=True, status="confirmed", parent_ext="1"))
        rep = lint()
        self.assertTrue(any("机读词" in w for w in rep["warns"]))

    def test_proper_conclusion_no_warn(self):
        pentdb.cmd_add(ns(kind="test", value="探测2", title="结论规范", note="未复现：三轮均 403",
                          source="ut", origin="agent", confidence="high",
                          auto=True, status="confirmed", parent_ext="1"))
        c = pentdb.connect()
        rid = c.execute("SELECT id FROM raw_events WHERE project=? AND kind='test' "
                        "ORDER BY id DESC LIMIT 1", (PROJ,)).fetchone()[0]
        c.close()
        rep = lint()
        self.assertFalse(any("机读词" in w and f"#{rid}" in w for w in rep["warns"]))


class TestCaptureGate(AuditBase):
    """报文写入口门禁 + 豁免起草/确认分离 + 报告出口门禁。"""

    def test_finding_without_packets_rejected(self):
        with self.assertRaises(SystemExit):
            pentdb.cmd_add(ns(kind="finding", value="http://t/gate-nopkt", title="无包漏洞",
                              source="ut", origin="agent", confidence="high"))

    def test_waive_capture_draft_not_effective_until_confirm(self):
        pentdb.cmd_add(ns(kind="finding", value="http://t/gate-waived", title="丢包漏洞",
                          source="ut", origin="agent", confidence="high",
                          waive_capture="初测报文丢失"))
        rep = lint()
        self.assertTrue(any("缺请求/响应证据" in e for e in rep["errors"]))
        self.assertTrue(any("待人工确认的豁免" in w for w in rep["warns"]))
        c = pentdb.connect()
        wid = c.execute("SELECT id FROM waives WHERE project=? AND confirmed=0 "
                        "ORDER BY id DESC LIMIT 1", (PROJ,)).fetchone()[0]
        c.close()
        pentdb.cmd_waive(argparse.Namespace(project=PROJ, id=None, wid=wid, confirm=True,
                                            term="", reason=""))
        rep = lint()
        self.assertFalse(any("缺请求/响应证据" in e for e in rep["errors"]))
        self.assertFalse(any("待人工确认的豁免" in w for w in rep["warns"]))

    def test_waive_confirm_requires_wid(self):
        with self.assertRaises(SystemExit):
            pentdb.cmd_waive(argparse.Namespace(project=PROJ, id=None, wid=0, confirm=True,
                                                term="", reason=""))

    def test_report_gate_blocks_on_error_and_force_passes(self):
        pentdb.cmd_add(ns(kind="finding", value="http://t/gate-report", title="报告门禁用例",
                          source="ut", origin="agent", confidence="high",
                          waive_capture="报文未补"))
        self.assertTrue(lint()["errors"])
        with self.assertRaises(SystemExit):
            pentdb.cmd_report(argparse.Namespace(project=PROJ, out="",
                                                 template="assets", force=False))
        pentdb.cmd_report(argparse.Namespace(project=PROJ, out="",
                                             template="assets", force=True))
        c = pentdb.connect()
        wid = c.execute("SELECT id FROM waives WHERE project=? AND confirmed=0 "
                        "ORDER BY id DESC LIMIT 1", (PROJ,)).fetchone()[0]
        c.close()
        pentdb.cmd_waive(argparse.Namespace(project=PROJ, id=None, wid=wid, confirm=True,
                                            term="", reason=""))
        self.assertFalse(lint()["errors"])


if __name__ == "__main__":
    unittest.main()
