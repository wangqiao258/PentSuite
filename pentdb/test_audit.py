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
  6. osint 取证门禁：无 --resp/--req 拒绝；豁免起草→确认闭环；双 term 匹配
  7. finding 去重指纹：同指纹并入主条目（报文转挂 dedup-merge 留痕）/无报文拒写/
     --no-dedupe 逃生成条 + lint 同指纹归并 warn；note/osint 不参与
  6. osint 取证门禁：无 --req/--resp 拒绝；--resp 任一即可入库；--waive-capture 起草
     （term=无取证待补）不生效、人工确认后 lint 不再报；finding 抓包豁免 term 匹配不受影响
"""
import argparse
import os
import sqlite3
import tempfile
import unittest

_TMPDIR = tempfile.mkdtemp(prefix="pentdb-audit-test-")
# setdefault：多模块同跑时先加载者建临时库、全套件共享隔离库（与 import 顺序无关）
os.environ.setdefault("PENTDB_DB", os.path.join(_TMPDIR, "test.db"))
import pentdb  # noqa: E402

# journal 隔离：lint 对账不读真实执行流水，保证测试确定性
pentdb.JOURNAL_DIR = os.path.join(tempfile.mkdtemp(prefix="pentdb-audit-test-"), "journal")

PROJ = "audit-ut"


def ns(**kw):
    base = dict(project=PROJ, ext_id="", kind="note", value="v", title="", detail="",
                note="", source="unittest", parent_ext="", merge_key="", status="new",
                confidence="", severity="", code="", tech="", service="", scope="in",
                auto=False, update=False, origin="agent", stage="",
                req="", resp="", waive_capture="", no_dedupe=False)
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


class TestLifecycleAutoSync(AuditBase):
    """test 结论 → finding lifecycle 自动联动：机读词触发+留痕 tag、待复测/散文不触发、
    已同值不重复写、parent_ext 多 id 全联动且跳过非 finding、exec 通道同样联动。"""

    @staticmethod
    def _finding(tag):
        reqf, respf = _pkt_files("sync-" + tag)
        pentdb.cmd_add(ns(kind="finding", value="http://t/sync-" + tag, title="联动-" + tag,
                          source="ut", origin="agent", confidence="high", auto=False,
                          req=reqf, resp=respf))
        c = pentdb.connect()
        fid = c.execute("SELECT id FROM raw_events WHERE project=? AND kind='finding' "
                        "ORDER BY id DESC LIMIT 1", (PROJ,)).fetchone()[0]
        c.close()
        return fid

    @staticmethod
    def _add_test(value, note, parent_ext):
        pentdb.cmd_add(ns(kind="test", value=value, title=value, note=note, source="ut",
                          origin="agent", confidence="high", auto=True,
                          status="confirmed", parent_ext=parent_ext))
        c = pentdb.connect()
        tid = c.execute("SELECT id FROM raw_events WHERE project=? AND kind='test' "
                        "ORDER BY id DESC LIMIT 1", (PROJ,)).fetchone()[0]
        c.close()
        return tid

    def _life(self, fid):
        import json
        c = pentdb.connect()
        c.row_factory = sqlite3.Row
        r = c.execute("SELECT attrs FROM raw_events WHERE id=?", (fid,)).fetchone()
        c.close()
        return (json.loads(r["attrs"] or "{}") or {}).get("lifecycle", "")

    def _log_count(self, fid):
        c = pentdb.connect()
        n = c.execute("SELECT COUNT(*) FROM changelog WHERE project=? AND action='lifecycle' "
                      "AND detail LIKE ?", (PROJ, f"#{fid} →%")).fetchone()[0]
        c.close()
        return n

    def test_machine_word_triggers_and_tagged(self):
        fid = self._finding("repro")
        tid = self._add_test("复测动作A", "复现：三步稳定复现", str(fid))
        self.assertEqual(self._life(fid), "reproduced")
        c = pentdb.connect()
        log = c.execute("SELECT detail FROM changelog WHERE project=? AND action='lifecycle' "
                        "ORDER BY id DESC LIMIT 1", (PROJ,)).fetchone()["detail"]
        c.close()
        self.assertIn(f"#{fid} → reproduced", log)
        self.assertIn(f"（test#{tid} 自动）", log)

    def test_pending_word_no_trigger(self):
        fid = self._finding("pending")
        self._add_test("复测动作B", "待复测：安排下一轮", str(fid))
        self.assertEqual(self._life(fid), "")

    def test_prose_note_no_trigger(self):
        fid = self._finding("prose")
        self._add_test("复测动作C", "看了一眼，服务还在跑", str(fid))
        self.assertEqual(self._life(fid), "")

    def test_same_value_not_rewritten(self):
        import json
        fid = self._finding("idem")
        self._add_test("复测动作D1", "复现：第一轮", str(fid))
        c = pentdb.connect()
        c.row_factory = sqlite3.Row
        at1 = json.loads(c.execute("SELECT attrs FROM raw_events WHERE id=?",
                                   (fid,)).fetchone()["attrs"])["lifecycle_at"]
        n1 = self._log_count(fid)
        c.close()
        self._add_test("复测动作D2", "复现：第二轮", str(fid))
        c = pentdb.connect()
        c.row_factory = sqlite3.Row
        at2 = json.loads(c.execute("SELECT attrs FROM raw_events WHERE id=?",
                                   (fid,)).fetchone()["attrs"])["lifecycle_at"]
        c.close()
        self.assertEqual(at1, at2)  # 已同值：lifecycle_at 不刷新 = 未重复写
        self.assertEqual(self._log_count(fid), n1)

    def test_multi_parent_ext_synced_and_nonfinding_skipped(self):
        fid_a = self._finding("multi-a")
        fid_b = self._finding("multi-b")
        other_tid = self._add_test("无关测试", "复现：无关事件（作为被跳过的非 finding 引用）", "")
        self._add_test("复测动作E", "复现：多目标联动",
                       f"{fid_a},{other_tid},{fid_b}")
        self.assertEqual(self._life(fid_a), "reproduced")
        self.assertEqual(self._life(fid_b), "reproduced")
        c = pentdb.connect()
        n_other = c.execute("SELECT COUNT(*) FROM changelog WHERE project=? AND "
                            "action='lifecycle' AND detail LIKE ?",
                            (PROJ, f"#{other_tid} →%")).fetchone()[0]
        c.close()
        self.assertEqual(n_other, 0)  # 非 finding id 被跳过

    def test_exec_channel_syncs(self):
        fid = self._finding("exec")
        pentdb.cmd_exec(argparse.Namespace(
            project=PROJ, parent_ext=str(fid), action="", title="",
            note="已修复：补丁上线验证通过", detail="", severity="", confidence="high",
            timeout=30, cmd="echo exec-sync-ut"))
        self.assertEqual(self._life(fid), "fixed")


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


class TestOsintEvidence(AuditBase):
    """osint 情报参考的取证门禁：与 finding 报文门禁同一套豁免/确认机制。"""

    def test_osint_without_material_rejected(self):
        with self.assertRaises(SystemExit):
            pentdb.cmd_add(ns(kind="osint", value="sub.example.com", title="裸情报",
                              source="ut", origin="agent", confidence="medium"))

    def test_osint_with_resp_only_persists_and_lint_clean(self):
        respf = os.path.join(_TMPDIR, "osint1.resp.txt")
        with open(respf, "w", encoding="utf-8") as f:
            f.write("HTTP/1.1 200 OK\r\n\r\n{ \"org\": \"example\" }")
        pentdb.cmd_add(ns(kind="osint", value="sub.example.com", title="资产测绘情报",
                          source="ut", origin="agent", confidence="medium", resp=respf))
        c = pentdb.connect()
        c.row_factory = sqlite3.Row
        oid = c.execute("SELECT id FROM raw_events WHERE project=? AND kind='osint' "
                        "ORDER BY id DESC LIMIT 1", (PROJ,)).fetchone()["id"]
        ev = c.execute("SELECT note FROM evidence WHERE project=? AND event_id=? "
                       "AND note LIKE 'response%'", (PROJ, oid)).fetchone()
        c.close()
        self.assertIsNotNone(ev)  # response 材料已挂 evidence
        rep = lint()
        self.assertFalse(any("情报缺取证" in e and f"#{oid}" in e for e in rep["errors"]))

    def test_osint_waive_draft_then_confirm(self):
        pentdb.cmd_add(ns(kind="osint", value="mail.example.com", title="丢材料情报",
                          source="ut", origin="agent", confidence="medium",
                          waive_capture="情报源响应未留档"))
        c = pentdb.connect()
        c.row_factory = sqlite3.Row
        oid = c.execute("SELECT id FROM raw_events WHERE project=? AND kind='osint' "
                        "ORDER BY id DESC LIMIT 1", (PROJ,)).fetchone()["id"]
        w = c.execute("SELECT id,term,confirmed FROM waives WHERE project=? AND event_id=? "
                      "ORDER BY id DESC LIMIT 1", (PROJ, oid)).fetchone()
        c.close()
        self.assertEqual(w["term"], "无取证待补")  # osint 豁免专用 term
        self.assertEqual(w["confirmed"], 0)  # 起草态不生效
        rep = lint()
        self.assertTrue(any("情报缺取证" in e and f"#{oid}" in e for e in rep["errors"]))
        # 人工确认（waive --wid N --confirm 的函数级等价调用）后生效
        pentdb.cmd_waive(argparse.Namespace(project=PROJ, id=None, wid=w["id"], confirm=True,
                                            term="", reason=""))
        rep = lint()
        self.assertFalse(any("情报缺取证" in e and f"#{oid}" in e for e in rep["errors"]))

    def test_waived_capture_term_matching(self):
        # "无取证待补"（osint）与 "无抓包待补"（finding）双 term 均应被 waived_capture 命中
        pentdb.cmd_add(ns(kind="finding", value="http://t/term-match", title="term匹配用例",
                          source="ut", origin="agent", confidence="high",
                          waive_capture="抓包豁免term匹配验证"))
        c = pentdb.connect()
        c.row_factory = sqlite3.Row
        fid = c.execute("SELECT id FROM raw_events WHERE project=? AND kind='finding' "
                        "ORDER BY id DESC LIMIT 1", (PROJ,)).fetchone()["id"]
        wid = c.execute("SELECT id FROM waives WHERE project=? AND event_id=? AND confirmed=0 "
                        "ORDER BY id DESC LIMIT 1", (PROJ, fid)).fetchone()["id"]
        c.close()
        rep = lint()
        self.assertTrue(any("缺请求/响应证据" in e and f"#{fid}" in e for e in rep["errors"]))
        pentdb.cmd_waive(argparse.Namespace(project=PROJ, id=None, wid=wid, confirm=True,
                                            term="", reason=""))
        rep = lint()
        self.assertFalse(any("缺请求/响应证据" in e and f"#{fid}" in e for e in rep["errors"]))


class TestDedupe(AuditBase):
    """finding 去重指纹：写入即并入（报文转挂）/无材料拒写/--no-dedupe 逃生/lint 同指纹 warn"""

    def _last_finding(self):
        c = pentdb.connect()
        c.row_factory = sqlite3.Row
        r = c.execute("SELECT id, value, title, dedup_key FROM raw_events WHERE project=? "
                      "AND kind='finding' ORDER BY id DESC LIMIT 1", (PROJ,)).fetchone()
        c.close()
        return r

    def _ev_count(self, fid):
        c = pentdb.connect()
        n = c.execute("SELECT COUNT(*) FROM evidence WHERE project=? AND event_id=?",
                      (PROJ, fid)).fetchone()[0]
        c.close()
        return n

    def test_same_fingerprint_merges_with_packets(self):
        reqf, respf = _pkt_files("dd1")
        pentdb.cmd_add(ns(kind="finding", value="http://t/Dup", title="SQL 注入 测试",
                          source="ut", origin="agent", confidence="high", req=reqf, resp=respf))
        m1 = self._last_finding()
        self.assertTrue(m1["dedup_key"])  # 指纹已落库
        n_ev1 = self._ev_count(m1["id"])
        # 端点顺序不同 + title 大小写/空白差异 + 多了 host 前缀：规范化后同指纹
        reqf2, respf2 = _pkt_files("dd2")
        pentdb.cmd_add(ns(kind="finding", value="HTTP://T/Dup/,/dup", title="sql注入测试",
                          source="ut", origin="agent", confidence="high", req=reqf2, resp=respf2))
        m2 = self._last_finding()
        self.assertEqual(m2["id"], m1["id"])  # 未新建条目
        self.assertEqual(self._ev_count(m1["id"]), n_ev1 + 2)  # 报文转挂主条目
        c = pentdb.connect()
        act = c.execute("SELECT action FROM changelog WHERE project=? AND action='dedup-merge' "
                        "ORDER BY id DESC LIMIT 1", (PROJ,)).fetchone()
        c.close()
        self.assertTrue(act)  # 留痕存在

    def test_same_fingerprint_without_packets_rejected(self):
        # 同指纹但无报文：写入口拒收（豁免场景提示作用于主条目）
        with self.assertRaises(SystemExit):
            pentdb.cmd_add(ns(kind="finding", value="http://t/dup", title="Sql 注入 测试",
                              source="ut", origin="agent", confidence="high",
                              waive_capture="重复登记走豁免"))

    def test_no_dedupe_forces_independent_row(self):
        # 先立主条目，再 --no-dedupe 强制同指纹独立成条 → lint 出归并 warn
        reqf, respf = _pkt_files("dd3")
        pentdb.cmd_add(ns(kind="finding", value="http://t/dup2", title="独立成条用例",
                          source="ut", origin="agent", confidence="high", req=reqf, resp=respf))
        master_id = self._last_finding()["id"]
        reqf2, respf2 = _pkt_files("dd4")
        pentdb.cmd_add(ns(kind="finding", value="HTTP://T/dup2/", title="独立成条用例",
                          source="ut", origin="agent", confidence="high",
                          req=reqf2, resp=respf2, no_dedupe=True))
        self.assertNotEqual(self._last_finding()["id"], master_id)
        rep = lint()
        self.assertTrue(any("同指纹 finding" in w for w in rep["warns"]))

    def test_other_kinds_unaffected(self):
        # 去重只作用于 finding：note 同 title 不同 value 照常各自入库（不并、不拒）
        pentdb.cmd_add(ns(kind="note", value="http://t/n1", title="sql注入测试",
                          source="ut", origin="agent", confidence="high"))
        pentdb.cmd_add(ns(kind="note", value="http://t/n2", title="sql注入测试",
                          source="ut", origin="agent", confidence="high"))
        c = pentdb.connect()
        n = c.execute("SELECT COUNT(*) FROM raw_events WHERE project=? AND kind='note' "
                      "AND title='sql注入测试'", (PROJ,)).fetchone()[0]
        c.close()
        self.assertEqual(n, 2)


if __name__ == "__main__":
    unittest.main()
