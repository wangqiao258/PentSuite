#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PentDB 资产实体层单测（stdlib unittest，零依赖）。运行：python -m unittest test_assets -v

覆盖三块最易回归的纯逻辑：
  1. key 规范化 _norm_domain / _split_hostport（注册域、二级后缀、host:port）
  2. rebuild_assets 归并（domain/host/service/endpoint、param 并入 endpoint、parent 统一、IP 误录 host）
  3. 聚合语义 asset_review_state / asset_is_stale（人审聚合、生命周期老化）
"""
import argparse
import datetime
import os
import tempfile
import unittest

# 必须在 import pentdb 前设置：测试用独立临时库，绝不触碰真实数据
_TMPDB = os.path.join(tempfile.mkdtemp(prefix="pentdb-assets-test-"), "test.db")
os.environ["PENTDB_DB"] = _TMPDB
import pentdb  # noqa: E402

PROJ = "assets-ut"


def ns(**kw):
    base = dict(project=PROJ, ext_id="", kind="note", value="v", title="", detail="",
                note="", source="unittest", parent_ext="", merge_key="", status="new",
                confidence="", severity="", code="", tech="", service="", scope="in",
                auto=False, update=False, origin="agent", stage="")
    base.update(kw)
    return argparse.Namespace(**base)


def add(**kw):
    pentdb.cmd_add(ns(**kw))


def entities():
    import json
    c = pentdb.connect()
    rows = {}
    for r in c.execute("SELECT * FROM assets WHERE project=?", (PROJ,)):
        d = dict(r)
        d["attrs"] = json.loads(d["attrs"] or "{}")
        rows[(d["atype"], d["akey"])] = d
    c.close()
    return rows


class KeyNorm(unittest.TestCase):
    def test_norm_domain(self):
        self.assertEqual(pentdb._norm_domain("API.Example.com."),
                         ("api.example.com", "example.com"))
        self.assertEqual(pentdb._norm_domain("a.b.co.uk"), ("a.b.co.uk", "b.co.uk"))
        self.assertEqual(pentdb._norm_domain("not a domain"), (None, None))
        self.assertEqual(pentdb._norm_domain("single"), (None, None))

    def test_split_hostport(self):
        self.assertEqual(pentdb._split_hostport("1.2.3.4:8080"), ("1.2.3.4", "8080"))
        self.assertEqual(pentdb._split_hostport("1.2.3.4"), ("1.2.3.4", ""))
        self.assertEqual(pentdb._split_hostport("host:bad"), ("host:bad", ""))


class RebuildMerge(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        c = pentdb.connect()
        c.execute("INSERT OR IGNORE INTO projects(name, created_at) VALUES(?,?)", (PROJ, pentdb.now()))
        c.commit()
        c.close()
        add(kind="domain", value="App.Example.COM.", tech="cloudflare", origin="human",
            status="confirmed")
        add(kind="domain", value="api.example.com", parent_ext="t1", origin="human")
        add(kind="port", value="5.6.7.8:8080", service="http", tech="nginx",
            origin="human", status="confirmed")
        add(kind="domain", value="5.6.7.8", title="误录为 domain 的 IP",
            origin="human", status="confirmed")
        add(kind="path", value="/admin/login", parent_ext="5.6.7.8",
            origin="human", status="confirmed")
        add(kind="param", value="user", parent_ext="/admin/login", origin="human")
        add(kind="param", value="pass", parent_ext="/admin/login", origin="human")
        add(kind="finding", value="x", title="非资产不入实体层", origin="human")

    def test_domain_merge_and_parent(self):
        es = entities()
        d = es[("domain", "api.example.com")]
        self.assertEqual(d["parent_akey"], "example.com")
        self.assertEqual(es[("domain", "app.example.com")]["attrs"]["techs"], ["cloudflare"])

    def test_host_merges_ip_and_port(self):
        es = entities()
        h = es[("host", "5.6.7.8")]
        self.assertEqual(h["attrs"]["ports"], ["8080"])
        self.assertIn("误录为 domain 的 IP", h["attrs"]["titles"])
        s = es[("service", "5.6.7.8:8080")]
        self.assertEqual(s["parent_akey"], "5.6.7.8")
        self.assertEqual(s["attrs"]["services"], ["http"])

    def test_param_merges_into_endpoint(self):
        es = entities()
        e = es[("endpoint", "5.6.7.8/admin/login")]
        self.assertEqual(e["parent_akey"], "5.6.7.8")
        self.assertEqual(e["attrs"]["params"], ["user", "pass"])
        self.assertNotIn(("endpoint", "?/user"), es)  # param 不再单独成行

    def test_non_asset_kinds_excluded(self):
        es = entities()
        self.assertFalse(any("x" == k for (_, k) in es))

    def test_times_and_scope(self):
        es = entities()
        d = es[("domain", "api.example.com")]
        self.assertTrue(d["first_seen"])
        self.assertIn("scopes", d["attrs"])


class AggregateSemantics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        c = pentdb.connect()
        c.execute("INSERT OR IGNORE INTO projects(name, created_at) VALUES(?,?)", (PROJ, pentdb.now()))
        c.commit()
        c.close()

    def test_review_state(self):
        self.assertEqual(pentdb.asset_review_state(["new", "confirmed"]), "pending")
        self.assertEqual(pentdb.asset_review_state(["confirmed"]), "confirmed")
        self.assertEqual(pentdb.asset_review_state(["confirmed", "rejected"]), "confirmed")
        self.assertEqual(pentdb.asset_review_state(["rejected"]), "rejected")
        self.assertEqual(pentdb.asset_review_state([]), "pending")

    def test_stale(self):
        now = datetime.datetime.now().astimezone()
        fresh = (now - datetime.timedelta(days=1)).isoformat(timespec="seconds")
        old = (now - datetime.timedelta(days=60)).isoformat(timespec="seconds")
        self.assertFalse(pentdb.asset_is_stale(fresh))
        self.assertTrue(pentdb.asset_is_stale(old))
        self.assertTrue(pentdb.asset_is_stale(""))

    def test_rescan_bumps_last_seen(self):
        add(kind="domain", value="rs.example.com", origin="human", status="confirmed")
        c = pentdb.connect()
        c.execute("UPDATE raw_events SET updated_at='2020-01-01T00:00:00+08:00' "
                  "WHERE project=? AND kind='domain' AND value='rs.example.com'", (PROJ,))
        c.commit()
        c.close()
        add(kind="domain", value="rs.example.com", note="重扫", update=True,
            origin="human", status="confirmed")
        es = entities()
        self.assertTrue(es[("domain", "rs.example.com")]["last_seen"].startswith("20"))


if __name__ == "__main__":
    unittest.main()
