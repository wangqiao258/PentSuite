#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PentDB probe 观测层单测（stdlib unittest，零依赖）。运行：python -m unittest test_probe -v

覆盖：
  1. 解析器 probe_parse_file / probe_parse_text / probe_parse_rows（JSON、dirscan log、gobuster、ffuf、URL 拆分）
  2. probe_ingest 批量入库（attrs 写入、同观测去重跳过、不参与资产归并、append-only 重观测）
  3. kind 白名单：probe ∈ VALID_KINDS/FACT_KINDS（--auto 可确认）且 ∉ ASSET_KINDS（不立 endpoint）
"""
import argparse
import json
import os
import tempfile
import unittest

os.environ.setdefault("PENTDB_DB", os.path.join(tempfile.mkdtemp(prefix="pentdb-probe-test-"), "test.db"))
import pentdb  # noqa: E402
from pdb_assets import probe_ingest, probe_parse_file, probe_parse_rows, probe_parse_text  # noqa: E402
from pdb_core import ASSET_KINDS, FACT_KINDS, VALID_KINDS  # noqa: E402

PROJ = "probe-ut"


def _conn():
    import pentdb as _p
    c = _p.connect()
    if not c.execute("SELECT 1 FROM projects WHERE name=?", (PROJ,)).fetchone():
        _p.cmd_init(argparse.Namespace(project=PROJ))
    return c


def _counts(c):
    # 只数本用例的 host，避免与 cmd_add 用例（x.com）交叉计数
    return c.execute("SELECT count(*) FROM raw_events WHERE project=? AND kind='probe' AND value='h.com'", (PROJ,)).fetchone()[0]


class Parse(unittest.TestCase):
    def test_parse_rows_json_fields(self):
        rows = probe_parse_rows([
            {"host": "CA.Example.com.", "path": "/a", "status": 200, "len": 123, "location": "", "ctype": "text/html", "server": "nginx"},
            {"url": "https://b.example.com:8443/x/y?z=1", "status": "301", "len": 5, "location": "/"},
            {"path": "/nohost", "status": "200"},
            {"host": "h", "path": "/", "status": "abc"},
            "junk",
        ])
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["host"], "ca.example.com")  # 小写去尾点
        self.assertEqual(rows[0]["status"], "200")           # 统一字符串
        self.assertEqual(rows[1]["host"], "b.example.com")   # URL 拆 host（端口剥除）
        self.assertEqual(rows[1]["path"], "/x/y?z=1")

    def test_parse_text_dirscan_log_format(self):
        raw = "$ python dirscan.py\nexit=0\n\n[plan] requests=3\n== results (status/len/loc) ==\n" \
              "/api/orders  200 len=128999  ct=text/html;charset=UTF-8  loc=\n" \
              "/rnd816  301 len=1533  ct=text/html  loc=https://h.com/en_CA/404\n" \
              "== notable bodies ==\n--- /x ---\n"
        rows = probe_parse_text(raw, "ca.example.com")
        self.assertEqual(len(rows), 2)
        self.assertEqual((rows[0]["host"], rows[0]["path"], rows[0]["status"], rows[0]["len"]),
                         ("ca.example.com", "/api/orders", "200", "128999"))
        self.assertEqual(rows[1]["location"], "https://h.com/en_CA/404")

    def test_parse_text_gobuster_and_ffuf(self):
        raw = "200 1234 https://h.com/admin\n" \
              "403 29 https://h.com/.env\n" \
              "https://h.com/api 200 100 50 1234\n"
        rows = probe_parse_text(raw, "")
        self.assertEqual([r["status"] for r in rows], ["200", "403", "200"])
        self.assertEqual(rows[2]["path"], "/api")
        self.assertEqual({r["host"] for r in rows}, {"h.com"})

    def test_parse_file_auto_json_and_text(self):
        with tempfile.TemporaryDirectory() as d:
            jp = os.path.join(d, "r.json")
            with open(jp, "w", encoding="utf-8") as f:
                json.dump([{"host": "h.com", "path": "/a", "status": "200", "len": 1}], f)
            self.assertEqual(probe_parse_file(jp)[0]["path"], "/a")
            tp = os.path.join(d, "r.log")
            with open(tp, "w", encoding="utf-8") as f:
                f.write("/b  404 len=0  ct=text/html  loc=\n")
            rows = probe_parse_file(tp, host_default="h.com")
            self.assertEqual((rows[0]["host"], rows[0]["path"], rows[0]["status"]), ("h.com", "/b", "404"))


class Ingest(unittest.TestCase):
    def test_ingest_dedup_and_no_asset(self):
        c = _conn()
        rows = probe_parse_rows([{"host": "h.com", "path": "/a", "status": "200", "len": 10},
                                 {"host": "h.com", "path": "/b", "status": "404", "len": 0}])
        ins, skip = probe_ingest(c, PROJ, rows, "ut-src", "601")
        c.commit()
        self.assertEqual((ins, skip), (2, 0))
        # 完全同观测重导入：跳过（幂等回填）
        ins2, skip2 = probe_ingest(c, PROJ, rows, "ut-src", "601")
        self.assertEqual((ins2, skip2), (0, 2))
        # 同路径不同状态码 = 合法新观测（append-only 时间线）
        ins3, _ = probe_ingest(c, PROJ, probe_parse_rows([{"host": "h.com", "path": "/a", "status": "500", "len": 9}]), "ut-src2")
        self.assertEqual(ins3, 1)
        self.assertEqual(_counts(c), 3)
        # attrs 结构与 status/parent_ext 落库
        row = c.execute("SELECT * FROM raw_events WHERE project=? AND kind='probe' AND value='h.com' "
                        "ORDER BY id LIMIT 1", (PROJ,)).fetchone()
        at = json.loads(row["attrs"])
        self.assertEqual((at["path"], at["status"]), ("/a", "200"))
        self.assertEqual(row["status"], "confirmed")  # 机器事实直接 confirmed
        self.assertEqual(row["parent_ext"], "601")
        # probe 不参与资产归并：assets 里不能出现 probe 派生的实体
        pentdb.rebuild_assets(c, PROJ)
        c.commit()
        ents = c.execute("SELECT atype, akey FROM assets WHERE project=?", (PROJ,)).fetchall()
        self.assertNotIn(("host", "h.com"), [tuple(r) for r in ents])
        self.assertNotIn(("endpoint", "h.com/a"), [tuple(r) for r in ents])
        c.close()

    def test_kind_whitelists(self):
        self.assertIn("probe", VALID_KINDS)
        self.assertIn("probe", FACT_KINDS)      # 机器事实：允许 --auto
        self.assertNotIn("probe", ASSET_KINDS)  # 纯观测：不参与归并

    def test_add_kind_probe_via_cmd_add(self):
        c = _conn()
        before = c.execute("SELECT count(*) FROM raw_events WHERE project=? AND kind='probe' AND value='add-ut.com'",
                           (PROJ,)).fetchone()[0]
        pentdb.cmd_add(argparse.Namespace(
            project=PROJ, ext_id="", kind="probe", value="add-ut.com", title="200 add-ut.com/y",
            detail="", note="", source="ut", parent_ext="", merge_key="", status="confirmed",
            confidence="high", severity="", code="", tech="", service="", scope="in",
            auto=True, update=False, origin="agent", stage="", req="", resp="", waive_capture=""))
        after = c.execute("SELECT count(*) FROM raw_events WHERE project=? AND kind='probe' AND value='add-ut.com'",
                          (PROJ,)).fetchone()[0]
        self.assertEqual(after, before + 1)
        c.close()


if __name__ == "__main__":
    unittest.main()
