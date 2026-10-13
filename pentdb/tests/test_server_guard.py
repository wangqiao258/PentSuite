#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""R2/N6 面板 server 顶层兜底回归单测（stdlib unittest，零依赖）。

背景（2026-10-12 实证评审 P0）：server.py do_GET/do_POST 路由体裸奔——
GET /api/evidence?event_id=abc、POST 畸形 JSON 等直接杀死连接（客户端收不到
任何 JSON 响应）；且异常逃逸后无日志可排查（N6）。
修法：
  R2  do_GET/do_POST 顶层 except Exception → 500 JSON（响应头已发则仅记日志）；
      POST body 非法 JSON → 400 {"error":"invalid json"}；
      /api/void ids、/api/waive/draft id 非数字 → 400 JSON。
  N6  兜底异常追加落盘 logs/panel_server.log（时间戳+位置+摘要+traceback）。

起服务模式（沿用套件既有隔离思路）：setUpClass 把 pdb_core.DB_PATH 指到临时库
（等价 PENTDB_DB 隔离语义，且不污染套件共享库与仓库 data/），ThreadingHTTPServer
绑 127.0.0.1:0 临时端口 + 守护线程 serve_forever，客户端用 stdlib http.client。
日志路径同样重定向到临时文件，避免用例往仓库 logs/ 写噪音。
"""
import argparse
import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pdb_core  # noqa: E402
import pentdb  # noqa: E402
import server  # noqa: E402

PROJ = "guard-ut"


def ns(**kw):
    """cmd_add 参数桩（与 test_bugfix_r1r5 同款，保证 CLI 入参面一致）。"""
    base = dict(project="", ext_id="", kind="note", value="v", title="", detail="",
                note="", source="guard-ut", parent_ext="", merge_key="", status="new",
                confidence="", severity="", code="", tech="", service="", scope="in",
                auto=False, update=False, origin="human",
                req="", resp="", waive_capture="", no_dedupe=False, intent_id=0)
    base.update(kw)
    return argparse.Namespace(**base)


class ServerGuardBase(unittest.TestCase):
    """起一份指向临时库的 ThreadingHTTPServer，全部用例共享。"""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="pentdb-server-guard-")
        cls.db_path = os.path.join(cls.tmp, "guard.db")
        cls.log_path = os.path.join(cls.tmp, "guard.log")
        # 隔离：库与日志都指临时文件；tearDownClass 原样恢复（不影响套件其他模块）
        cls._saved = (pdb_core.DB_PATH, pentdb.DB_PATH,
                      server.LOG_DIR, server.LOG_PATH)
        pdb_core.DB_PATH = cls.db_path
        pentdb.DB_PATH = cls.db_path
        server.LOG_DIR = cls.tmp
        server.LOG_PATH = cls.log_path
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.srv.server_address[1]
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.thread.join(timeout=5)
        (pdb_core.DB_PATH, pentdb.DB_PATH,
         server.LOG_DIR, server.LOG_PATH) = cls._saved
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # ---- HTTP 辅助 ----
    def get(self, path):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            c.request("GET", path)
            r = c.getresponse()
            return r.status, r.read()
        finally:
            c.close()

    def post(self, path, payload):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            c.request("POST", path, body=payload.encode("utf-8"),
                      headers={"Content-Type": "application/json"})
            r = c.getresponse()
            return r.status, r.read()
        finally:
            c.close()

    def jload(self, body):
        return json.loads(body.decode("utf-8"))


class TestGetGuard(ServerGuardBase):
    def test_bad_event_id_returns_500_json_and_connection_survives(self):
        """R2 核心：修复前 GET /api/evidence?event_id=abc 裸 ValueError → 连接被杀，
        客户端收不到任何响应。修复后：500 + JSON error，且同一连接紧接着再发合法
        请求仍正常（证明服务/连接未被杀死）。"""
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            c.request("GET", "/api/evidence?event_id=abc")
            r = c.getresponse()
            body = r.read()
            self.assertEqual(r.status, 500)
            self.assertIn("error", self.jload(body))
            # 同一 HTTPConnection 再发一个合法请求（修复前此处必炸 RemoteDisconnected）
            c.request("GET", "/api/projects")
            r2 = c.getresponse()
            body2 = r2.read()
            self.assertEqual(r2.status, 200)
            self.assertIn("projects", self.jload(body2))
        finally:
            c.close()

    def test_exception_logged_to_file(self):
        """N6：兜底捕获的异常必须落盘（时间戳/位置/摘要/traceback），
        且日志写的是测试重定向后的临时文件（不污染仓库 logs/）。"""
        status, _ = self.get("/api/evidence?event_id=abc")
        self.assertEqual(status, 500)
        with open(self.log_path, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("do_GET", content)
        self.assertIn("ValueError", content)
        self.assertIn("Traceback", content)
        self.assertTrue(content.startswith("["), "日志行应以时间戳开头")


class TestPostBadRequest(ServerGuardBase):
    def test_malformed_json_body_returns_400(self):
        """畸形 JSON / 空 body：所有 POST 路由统一 400 {"error":"invalid json"}。"""
        for path in ("/api/review", "/api/retest", "/api/manual-add",
                     "/api/waive/confirm", "/api/waive/draft", "/api/void"):
            status, body = self.post(path, "{not json")
            self.assertEqual(status, 400, path)
            self.assertEqual(self.jload(body), {"error": "invalid json"})
        status, body = self.post("/api/review", "")
        self.assertEqual(status, 400)
        self.assertEqual(self.jload(body), {"error": "invalid json"})

    def test_non_object_json_body_returns_400(self):
        status, body = self.post("/api/review", "[1,2,3]")
        self.assertEqual(status, 400)
        self.assertEqual(self.jload(body), {"error": "invalid json"})

    def test_void_non_numeric_id_returns_400(self):
        status, body = self.post("/api/void", json.dumps(
            {"project": PROJ, "ids": ["abc"], "reason": "ut 误录"}))
        self.assertEqual(status, 400)
        self.assertIn("error", self.jload(body))

    def test_waive_draft_non_numeric_id_returns_400(self):
        status, body = self.post("/api/waive/draft", json.dumps(
            {"project": PROJ, "id": "abc", "term": "t", "reason": "r"}))
        self.assertEqual(status, 400)
        self.assertIn("error", self.jload(body))


class TestSanity(ServerGuardBase):
    def test_normal_read_write_not_broken_by_guard(self):
        """sanity：兜底没把正常读写改坏——init/add → GET 读 → POST 人审写全链路 200。"""
        pentdb.cmd_init(argparse.Namespace(project=PROJ))
        eid = pentdb.cmd_add(ns(project=PROJ, kind="domain",
                                value="guard.example.com", status="new"))
        status, body = self.get("/api/events?project=" + PROJ)
        self.assertEqual(status, 200)
        values = [e["value"] for e in self.jload(body)["events"]]
        self.assertIn("guard.example.com", values)
        status, body = self.post("/api/review", json.dumps(
            {"action": "confirmed", "ids": [eid], "note": "ut 确认"}))
        self.assertEqual(status, 200)
        obj = self.jload(body)
        self.assertTrue(obj["ok"])
        self.assertEqual(obj["updated"], [eid])
        self.assertEqual(obj["missing"], [])


class TestPendingParentSummary(ServerGuardBase):
    """/api/pending 母发现摘要（2026-10-13 待审队列改造·平铺+链接模式：
    审一条复测结论必须看到被审对象——母发现标题/严重度/人审态/生命周期；
    缺了它队列只剩 120 字备注，人无从决策）。"""

    def test_pending_test_rows_carry_parent_summary(self):
        pentdb.cmd_init(argparse.Namespace(project=PROJ))
        # finding 写入口硬门禁要真实报文文件：先落盘再 add
        reqf = os.path.join(self.tmp, "p.req.txt")
        respf = os.path.join(self.tmp, "p.resp.txt")
        with open(reqf, "w", encoding="utf-8") as f:
            f.write("POST /login HTTP/1.1\r\nHost: t\r\n\r\n{}")
        with open(respf, "w", encoding="utf-8") as f:
            f.write("HTTP/1.1 200 OK\r\n\r\nok")
        fid = pentdb.cmd_add(ns(project=PROJ, kind="finding", value="http://pend/login",
                                title="待审队列母发现用例", severity="high",
                                origin="human", status="confirmed",
                                req=reqf, resp=respf))
        # 已确认的旧 test（不应出现在 pending）+ 一条 new 的待审 test
        old = pentdb.cmd_add(ns(project=PROJ, kind="test", value="已确认旧复测",
                                title="t-old", note="复现 ｜ 依据：ut",
                                parent_ext=str(fid)))
        pentdb.cmd_review(argparse.Namespace(project=PROJ, id=old, confirm=True,
                                             reject=False, reviewer="human", note="ut"))
        new = pentdb.cmd_add(ns(project=PROJ, kind="test", value="待审新复测",
                                title="t-new", note="待复测 ｜ 依据：ut",
                                parent_ext=str(fid)))
        # parent_ext 非数字 id → parent=None（归因存疑，UI 提示）
        bad = pentdb.cmd_add(ns(project=PROJ, kind="test", value="无母复测",
                                title="t-bad", note="复现 ｜ 依据：ut",
                                parent_ext="pend.example.com"))
        status, body = self.get("/api/pending?project=" + PROJ)
        self.assertEqual(status, 200)
        rows = self.jload(body)["pending"]
        row = next(r for r in rows if r["id"] == new)
        self.assertEqual(row["parent"]["id"], fid)
        self.assertEqual(row["parent"]["title"], "待审队列母发现用例")
        self.assertEqual(row["parent"]["severity"], "high")
        self.assertEqual(row["parent"]["status"], "confirmed")
        # 已确认旧 test 不进 pending 队列
        self.assertNotIn(old, [r["id"] for r in rows])
        # parent_ext 不可解析 → parent=None（不误导链接）
        self.assertIsNone(next(r for r in rows if r["id"] == bad)["parent"])
        # 非 test 行一律 parent=None
        for r in rows:
            if r["kind"] != "test":
                self.assertIsNone(r["parent"])


class TestCascadeReview(ServerGuardBase):
    """B 方案父子继承：/api/review 支持 cascade_from——人审一次 finding 决定时
    连带处置其下待审 test（reviews note 保持批注原文，changelog 逐条标注级联来源）。"""

    def _mk(self, note_word):
        """落一条 finding（带真实报文文件过写入口门禁）+ N 条待审 test。"""
        reqf = os.path.join(self.tmp, "c.req.txt")
        respf = os.path.join(self.tmp, "c.resp.txt")
        with open(reqf, "w", encoding="utf-8") as f:
            f.write("POST /login HTTP/1.1\r\nHost: t\r\n\r\n{}")
        with open(respf, "w", encoding="utf-8") as f:
            f.write("HTTP/1.1 200 OK\r\n\r\nok")
        return reqf, respf

    def test_cascade_review_marks_changelog_and_keeps_note(self):
        import sqlite3
        pentdb.cmd_init(argparse.Namespace(project=PROJ))
        reqf, respf = self._mk("x")
        fid = pentdb.cmd_add(ns(project=PROJ, kind="finding", value="http://cas/login",
                                title="级联母发现用例", severity="high",
                                origin="human", status="new", req=reqf, resp=respf))
        t1 = pentdb.cmd_add(ns(project=PROJ, kind="test", value="级联复测1",
                               title="t1", note="复现 ｜ 依据：ut", parent_ext=str(fid)))
        t2 = pentdb.cmd_add(ns(project=PROJ, kind="test", value="级联复测2",
                               title="t2", note="复现 ｜ 依据：ut", parent_ext=str(fid)))
        status, body = self.post("/api/review", json.dumps(
            {"ids": [fid, t1, t2], "action": "confirmed", "note": "ut 级联批注",
             "cascade_from": fid}))
        self.assertEqual(status, 200)
        obj = self.jload(body)
        self.assertEqual(obj["updated"], [fid, t1, t2])
        self.assertEqual(obj["missing"], [])
        c = sqlite3.connect(self.db_path)
        c.row_factory = sqlite3.Row
        # 三条都确认
        st = {r["id"]: r["status"] for r in c.execute(
            "SELECT id, status FROM raw_events WHERE project=?", (PROJ,))}
        self.assertEqual(st[fid], "confirmed")
        self.assertEqual(st[t1], "confirmed")
        self.assertEqual(st[t2], "confirmed")
        # reviews：三条各一条，note 保持批注原文（不带级联标注）
        notes = [r["note"] for r in c.execute(
            "SELECT note FROM reviews WHERE event_id IN (?,?,?)", (fid, t1, t2))]
        self.assertEqual(notes, ["ut 级联批注"] * 3)
        # changelog：母条目无标注，子条目标注级联来源
        ch = {r["detail"]: r for r in c.execute(
            "SELECT detail, actor FROM changelog WHERE project=? AND action='review'", (PROJ,))}
        self.assertIn(f"#{fid} -> confirmed", ch)
        self.assertNotIn("父子继承", ch[f"#{fid} -> confirmed"]["detail"])
        for tid in (t1, t2):
            key = next(d for d in ch if d.startswith(f"#{tid} -> confirmed"))
            self.assertIn("父子继承", ch[key]["detail"])
            self.assertIn(f"#{fid}", ch[key]["detail"])
        # actor 全部 human
        self.assertTrue(all(r["actor"] == "human" for r in ch.values()))
        c.close()

    def test_bad_cascade_from_returns_400(self):
        status, body = self.post("/api/review", json.dumps(
            {"id": 1, "action": "confirmed", "note": "ut", "cascade_from": "abc"}))
        self.assertEqual(status, 400)
        self.assertIn("error", self.jload(body))


if __name__ == "__main__":
    unittest.main()
