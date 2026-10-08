#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PentDB 人看面板（stdlib，零依赖）。端口 8766，避免与旧 assetdb 面板 8765 冲突。"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "data", "pentdb.db")
WEB = os.path.join(BASE, "web", "index.html")
# 静态资源白名单（web/ 目录按视图域拆分：html/css + 5 个 app.*.js）
STATIC = {
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/app.core.js": ("app.core.js", "text/javascript; charset=utf-8"),
    "/app.findings.js": ("app.findings.js", "text/javascript; charset=utf-8"),
    "/app.assets.js": ("app.assets.js", "text/javascript; charset=utf-8"),
    "/app.queue.js": ("app.queue.js", "text/javascript; charset=utf-8"),
    "/app.report.js": ("app.report.js", "text/javascript; charset=utf-8"),
}


def db():
    import pentdb
    return pentdb.connect()


def rows_to_dicts(rows):
    return [dict(r) for r in rows]


def int_param(q, name, default="0"):
    """query 参数安全转 int：非数字/缺失返回 None（路由层转 400 JSON，
    不让裸 ValueError 逃出 do_GET 造成客户端连接断开）。"""
    try:
        return int(q.get(name, [default])[0])
    except (TypeError, ValueError, IndexError):
        return None


# 漏洞生命周期（与 raw_events.status 人审态分离；存 finding 行 attrs JSON）
LIFE_CODES = ("open", "reproduced", "not-reproduced", "fixed", "reopened")


def set_lifecycle(c, project, fid, code, note=""):
    import pentdb
    pentdb.set_lifecycle(c, project, fid, code,
                         note=note or "面板快捷修改", tag="（面板）")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path in ("/", "/index.html"):
            with open(WEB, encoding="utf-8") as f:
                body = f.read().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if u.path in STATIC:
            fname, ctype = STATIC[u.path]
            with open(os.path.join(BASE, "web", fname), encoding="utf-8") as f:
                body = f.read().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        c = db()
        try:
            if u.path == "/api/projects":
                self._json({"projects": [
                    {"name": r["name"], "profile": r["profile"] or "attack-surface",
                     "archived": bool(r["archived"])}
                    for r in c.execute("SELECT name, profile, archived FROM projects "
                                       "ORDER BY archived, name")]})
            elif u.path == "/api/overview":
                p = q.get("project", [""])[0]
                if not c.execute("SELECT 1 FROM projects WHERE name=?", (p,)).fetchone():
                    return self._json({"error": "project not found"}, 404)
                by_kind = {r["kind"]: r["n"] for r in c.execute(
                    "SELECT kind, COUNT(*) n FROM raw_events WHERE project=? GROUP BY kind", (p,))}
                by_status = {r["status"]: r["n"] for r in c.execute(
                    "SELECT status, COUNT(*) n FROM raw_events WHERE project=? GROUP BY status", (p,))}
                domains = rows_to_dicts(c.execute(
                    "SELECT id, value, note, status, source, created_at, tech, scope, verified_at "
                    "FROM raw_events WHERE project=? AND kind='domain' ORDER BY value", (p,)))
                self._json({"by_kind": by_kind, "by_status": by_status, "domains": domains})
            elif u.path == "/api/events":
                p = q.get("project", [""])[0]
                sql = "SELECT * FROM raw_events WHERE project=? AND voided=0"
                args = [p]
                if q.get("kind"):
                    sql += " AND kind=?"; args.append(q["kind"][0])
                if q.get("ids"):  # 按观测 id 列表取（资产实体下钻）
                    ids = [int(x) for x in q["ids"][0].split(",") if x.strip().isdigit()]
                    if ids:
                        sql += " AND id IN (%s)" % ",".join("?" * len(ids))
                        args += ids
                if q.get("kinds"):  # 多类型过滤（逗号分隔），资产明细页默认 domain,port,path,param
                    kinds = [k.strip() for k in q["kinds"][0].split(",") if k.strip()]
                    if kinds:
                        sql += " AND kind IN (%s)" % ",".join("?" * len(kinds))
                        args += kinds
                if q.get("value"):  # 精确按值取（待审队列下钻：同值观测）
                    sql += " AND value=?"; args.append(q["value"][0])
                if q.get("status"):
                    sql += " AND status=?"; args.append(q["status"][0])
                if q.get("q"):
                    sql += " AND (value LIKE ? OR note LIKE ? OR title LIKE ? OR detail LIKE ?)"
                    args += ["%" + q["q"][0] + "%"] * 4
                sql += " ORDER BY id DESC LIMIT 500"
                events = rows_to_dicts(c.execute(sql, args))
                evc = {r["event_id"]: r["n"] for r in c.execute(
                    "SELECT event_id, COUNT(*) n FROM evidence WHERE project=? GROUP BY event_id", (p,))}
                for e in events:
                    e["ev_count"] = evc.get(e["id"], 0)
                self._json({"events": events})
            elif u.path == "/api/assets":
                p = q.get("project", [""])[0]
                if not c.execute("SELECT 1 FROM projects WHERE name=?", (p,)).fetchone():
                    return self._json({"error": "project not found"}, 404)
                import pentdb
                rows = [dict(r) for r in c.execute(
                    "SELECT * FROM assets WHERE project=? ORDER BY atype, akey", (p,))]
                ev_status = {r["id"]: r["status"] for r in c.execute(
                    "SELECT id, status FROM raw_events WHERE project=?", (p,))}
                atype = q.get("atype", [""])[0]
                status_f = q.get("status", [""])[0]
                qry = q.get("q", [""])[0].lower()
                # 响应码语义组多选（逗号分隔）：2xx/3xx/wall(401,403)/404/5xx/none(无码未探测)
                cgs = [g.strip() for g in q.get("code_group", [""])[0].split(",") if g.strip()]
                def code_hit(codes):
                    if "none" in cgs and not codes:
                        return True
                    for x in codes or []:
                        try:
                            n = int(str(x)[:3])
                        except (ValueError, TypeError):
                            continue
                        if "2xx" in cgs and 200 <= n < 300: return True
                        if "3xx" in cgs and 300 <= n < 400: return True
                        if "wall" in cgs and n in (401, 403): return True
                        if "404" in cgs and 400 <= n < 500 and n not in (401, 403): return True
                        if "5xx" in cgs and 500 <= n < 600: return True
                    return False
                out = []
                for r in rows:
                    eids = json.loads(r["event_ids"] or "[]")
                    statuses = [ev_status[i] for i in eids if i in ev_status]
                    review = pentdb.asset_review_state(statuses)
                    if status_f and review != status_f:
                        continue
                    if atype and r["atype"] != atype:
                        continue
                    attrs = json.loads(r["attrs"] or "{}")
                    if qry and qry not in r["akey"].lower() \
                            and qry not in json.dumps(attrs, ensure_ascii=False).lower():
                        continue
                    if cgs and not code_hit(attrs.get("codes")):
                        continue
                    out.append({
                        "atype": r["atype"], "akey": r["akey"], "display": r["display"],
                        "parent_atype": r["parent_atype"], "parent_akey": r["parent_akey"],
                        "attrs": attrs, "event_ids": eids,
                        "first_seen": r["first_seen"], "last_seen": r["last_seen"],
                        "review": review,
                        "stale": pentdb.asset_is_stale(r["last_seen"]),
                        "obs": len(eids),
                    })
                summary = {}
                for a in out:
                    summary[a["atype"]] = summary.get(a["atype"], 0) + 1
                self._json({"assets": out, "summary": summary})
            elif u.path == "/api/asset-detail":
                # 资产下钻明细：关联漏洞（parent_ext 归属解析）+ 观测事件所挂证据（只读）
                p = q.get("project", [""])[0]
                if not c.execute("SELECT 1 FROM projects WHERE name=?", (p,)).fetchone():
                    return self._json({"error": "project not found"}, 404)
                atype = q.get("atype", [""])[0]
                akey = q.get("akey", [""])[0]
                arow = c.execute("SELECT event_ids FROM assets WHERE project=? AND atype=? AND akey=?",
                                 (p, atype, akey)).fetchone()
                if not arow:
                    return self._json({"error": "asset not found"}, 404)
                import pentdb
                eids = json.loads(arow["event_ids"] or "[]")
                ev_sql = ("SELECT e.*, r.kind AS ev_kind, r.title AS ev_title FROM evidence e "
                          "LEFT JOIN raw_events r ON r.id=e.event_id WHERE e.project=?")
                args = [p]
                if eids:
                    ev_sql += " AND e.event_id IN (%s)" % ",".join("?" * len(eids))
                    args += eids
                else:
                    ev_sql += " AND 0"  # 无观测事件：直接空证据集
                evidence = []
                for r in rows_to_dicts(c.execute(ev_sql + " ORDER BY e.id", args)):
                    r["exists"] = os.path.exists(r["path"])
                    evidence.append(r)
                self._json({"findings": pentdb.findings_for_asset(c, p, atype, akey),
                            "exec_packets": pentdb.exec_packets_for_asset(c, p, atype, akey),
                            "evidence": evidence})
            elif u.path == "/api/evidence":
                p = q.get("project", [""])[0]
                sql = "SELECT e.*, r.kind AS ev_kind, r.title AS ev_title FROM evidence e " \
                      "LEFT JOIN raw_events r ON r.id=e.event_id WHERE e.project=?"
                args = [p]
                if q.get("event_id"):
                    sql += " AND e.event_id=?"; args.append(int(q["event_id"][0]))
                if q.get("event_ids"):
                    ids = [int(x) for x in q["event_ids"][0].split(",") if x.strip().isdigit()]
                    if ids:
                        sql += " AND e.event_id IN (%s)" % ",".join("?" * len(ids))
                        args += ids
                rows = []
                for r in rows_to_dicts(c.execute(sql + " ORDER BY e.id DESC", args)):
                    r["exists"] = os.path.exists(r["path"])
                    rows.append(r)
                self._json({"evidence": rows})
            elif u.path == "/api/evidence/view":
                eid = int_param(q, "id")
                if eid is None:
                    return self._json({"error": "bad id"}, 400)
                row = c.execute("SELECT * FROM evidence WHERE id=?", (eid,)).fetchone()
                if not row:
                    return self._json({"error": "no evidence"}, 404)
                path = row["path"]
                if not os.path.exists(path):
                    return self._json({"error": "file missing", "path": path}, 404)
                import pentdb
                with open(path, "rb") as f:
                    raw = f.read(pentdb.EVIDENCE_READ_LIMIT)
                content, binary = "", False
                for enc in ("utf-8", "gbk"):
                    try:
                        content = raw.decode(enc)
                        break
                    except (UnicodeDecodeError, ValueError):
                        if enc == "gbk":
                            binary = True
                if b"\x00" in raw:
                    binary = True
                self._json({"id": eid, "name": os.path.basename(path), "path": path,
                            "note": row["note"], "sha256": row["sha256"],
                            "binary": binary, "content": "" if binary else content})
            elif u.path == "/api/evidence/packet":
                # exec .log → request/response 报文只读投影（不写库不改 evidence 表）。
                # 解析失败/非 exec 日志返回 ok=false，前端降级回原文文件卡。
                eid = int_param(q, "id")
                if eid is None:
                    return self._json({"error": "bad id"}, 400)
                row = c.execute("SELECT * FROM evidence WHERE id=?", (eid,)).fetchone()
                if not row:
                    return self._json({"error": "no evidence"}, 404)
                path = row["path"]
                if not os.path.exists(path):
                    return self._json({"error": "file missing", "path": path}, 404)
                import pentdb
                pkt = pentdb.parse_exec_log_file(path)  # 读盘/解码/解析全链路降级：意外返回 None
                if pkt is None:
                    return self._json({"ok": False, "id": eid,
                                       "reason": "非 exec curl 日志或解析失败"})
                self._json({"ok": True, "id": eid,
                            "request": pkt["request"], "response": pkt["response"],
                            "flags": pkt["flags"], "raw_path": path})
            elif u.path == "/api/timeline":
                p = q.get("project", [""])[0]
                events = rows_to_dicts(c.execute(
                    "SELECT id, kind, value, status, origin, source, created_at FROM raw_events "
                    "WHERE project=? ORDER BY created_at DESC, id DESC LIMIT 100", (p,)))
                changes = rows_to_dicts(c.execute(
                    "SELECT action, detail, at, actor FROM changelog WHERE project=? "
                    "ORDER BY id DESC LIMIT 50", (p,)))
                self._json({"events": events, "changes": changes})
            elif u.path == "/api/findings":
                p = q.get("project", [""])[0]
                rows = rows_to_dicts(c.execute(
                    "SELECT * FROM raw_events WHERE project=? AND kind IN ('finding','osint') "
                    "AND voided=0 ORDER BY id DESC", (p,)))
                # 豁免决定跟随记录上下文（对齐成熟产品：门禁页只读）：
                # 把该记录的起草态豁免带出来，发现页行内即可确认/作废；
                # no_pkt/no_ev 与 lint F-301/O-301 同口径（finding 需 req+resp 成对，osint 任一证据）
                wvs = rows_to_dicts(c.execute(
                    "SELECT id, event_id, term, reason FROM waives "
                    "WHERE project=? AND confirmed=0", (p,)))
                wv_map = {}
                for w in wvs:
                    wv_map.setdefault(str(w["event_id"]), w)
                ev_req = {r["event_id"] for r in c.execute(
                    "SELECT event_id FROM evidence WHERE project=? AND note LIKE 'request%'", (p,))}
                ev_resp = {r["event_id"] for r in c.execute(
                    "SELECT event_id FROM evidence WHERE project=? AND note LIKE 'response%'", (p,))}
                ev_any = {r["event_id"] for r in c.execute(
                    "SELECT DISTINCT event_id FROM evidence WHERE project=? AND event_id != 0", (p,))}
                for r in rows:
                    w = wv_map.get(str(r["id"]))
                    if w:
                        r["wv"] = w
                    if r["kind"] == "finding":
                        r["no_pkt"] = (r["id"] not in ev_req) or (r["id"] not in ev_resp)
                    elif r["kind"] == "osint":
                        r["no_ev"] = r["id"] not in ev_any
                self._json({"findings": rows})
            elif u.path == "/api/probes":
                # probe 观测查询（只读）：host 参数支持精确与子域聚合（domain 节点查其下全部 host）
                p = q.get("project", [""])[0]
                host = q.get("host", [""])[0]
                sql = ("SELECT id, value, title, attrs, status, origin, source, created_at "
                       "FROM raw_events WHERE project=? AND kind='probe'")
                args = [p]
                if host:
                    sql += " AND (value=? OR value LIKE ?)"
                    args += [host, "%." + host]
                rows = rows_to_dicts(c.execute(sql + " ORDER BY id DESC LIMIT 5000", args))
                for r in rows:
                    try:
                        r["attrs"] = json.loads(r["attrs"] or "{}")
                    except (ValueError, TypeError):
                        r["attrs"] = {}
                self._json({"probes": rows})
            elif u.path == "/api/suggestions":
                p = q.get("project", [""])[0]
                rows = rows_to_dicts(c.execute(
                    "SELECT * FROM raw_events WHERE project=? AND kind='suggestion' "
                    "AND voided=0 ORDER BY id DESC LIMIT 30", (p,)))
                self._json({"suggestions": rows})
            elif u.path == "/api/lint":
                p = q.get("project", [""])[0]
                import pentdb
                self._json(pentdb.lint_report(c, p))
            elif u.path == "/api/backup":
                import pentdb, datetime
                with open(pentdb.DB_PATH, "rb") as f:
                    body = f.read()
                fname = "pentdb-backup-%s.db" % datetime.date.today()
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f"attachment; filename={fname}")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            elif u.path == "/api/pending":
                p = q.get("project", [""])[0]
                rows = rows_to_dicts(c.execute(
                    "SELECT * FROM raw_events WHERE project=? AND status='new' AND voided=0 "
                    "ORDER BY id", (p,)))
                # 去重前置：同值已有 confirmed/rejected 的条目在队列里直接打标（成熟 inbox 模式）
                vals = sorted({r["value"] for r in rows if r["value"]})
                stat = {}
                if vals:
                    ph = ",".join("?" * len(vals))
                    for r in c.execute(
                            "SELECT value, status, COUNT(*) AS n FROM raw_events "
                            f"WHERE project=? AND value IN ({ph}) AND status!='new' "
                            "GROUP BY value, status", (p, *vals)):
                        stat.setdefault(r["value"], {})[r["status"]] = r["n"]
                for r in rows:
                    s = stat.get(r["value"], {})
                    r["dup_confirmed"] = s.get("confirmed", 0)
                    r["dup_rejected"] = s.get("rejected", 0)
                self._json({"pending": rows})
            elif u.path == "/api/report":
                p = q.get("project", [""])[0]
                template = q.get("template", ["assets"])[0]
                import pentdb
                try:
                    rep = pentdb.lint_report(c, p)
                except Exception as e:  # journal/lint 对账读盘异常：返回 500 JSON，不打断连接
                    return self._json({"error": "lint 对账失败：" + str(e)}, 500)
                if rep["errors"] and q.get("force", ["0"])[0] != "1":
                    self._json({"error": f"报告出口门禁：{len(rep['errors'])} 项阻断——"
                                         "逐条修复或人工确认豁免（带错出报告需人工加 force=1）",
                                "lint": rep}, 409)
                    return
                if template == "pentest":
                    self._json({"report": pentdb._pentest_report(c, p)})
                else:
                    import io
                    buf = io.StringIO()
                    old = __import__("sys").stdout
                    try:
                        __import__("sys").stdout = buf
                        import argparse as ap
                        pentdb.cmd_report(ap.Namespace(project=p, out="", template="assets"))
                    finally:
                        __import__("sys").stdout = old
                    self._json({"report": buf.getvalue()})
            else:
                self._json({"error": "not found"}, 404)
        finally:
            c.close()

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/api/retest":
            n = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(n).decode("utf-8"))
            import argparse
            import pentdb
            fid = data.get("finding_id")
            action = (data.get("action") or "").strip()
            conclusion = (data.get("conclusion") or "").strip()
            source = (data.get("source") or "面板手工复测").strip()
            lifecycle = (data.get("lifecycle") or "").strip()
            if not fid or (not action and not lifecycle):
                return self._json({"error": "finding_id 必填，action/lifecycle 至少一项"}, 400)
            if lifecycle and lifecycle not in LIFE_CODES:
                return self._json({"error": "lifecycle 必须是 " + "/".join(LIFE_CODES)}, 400)
            c0 = db()
            try:
                row = c0.execute(
                    "SELECT project, parent_ext FROM raw_events WHERE id=? AND kind='finding'",
                    (fid,)).fetchone()
                if not row:
                    return self._json({"error": "finding not found"}, 404)
                if lifecycle:
                    set_lifecycle(c0, row["project"], fid, lifecycle, note=conclusion or "面板快捷修改")
                    c0.commit()
            finally:
                c0.close()
            if not action:
                return self._json({"ok": True, "lifecycle": lifecycle, "id": None})
            parents = ",".join([str(fid)] + [x.strip() for x in (row["parent_ext"] or "").split(",")
                                             if x.strip().isdigit()])
            ns = argparse.Namespace(
                project=row["project"], ext_id="", kind="test", value=action,
                title="复测: " + action[:60], detail="", note=conclusion, source=source,
                parent_ext=parents, merge_key="", status="confirmed", confidence="",
                severity="", code="", tech="", service="", scope="in",
                auto=True, update=False, origin="human")
            try:
                pentdb.cmd_add(ns)
            except SystemExit as e:
                return self._json({"error": str(e)}, 400)
            c2 = db()
            try:
                r2 = c2.execute("SELECT id FROM raw_events WHERE project=? AND kind='test' "
                                "ORDER BY id DESC LIMIT 1", (row["project"],)).fetchone()
                return self._json({"ok": True, "id": r2["id"] if r2 else None})
            finally:
                c2.close()
        if u.path == "/api/manual-add":
            n = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(n).decode("utf-8"))
            import argparse
            import pentdb
            kind, value = data.get("kind"), (data.get("value") or "").strip()
            source = (data.get("source") or "").strip()
            if kind not in pentdb.VALID_KINDS or not value or not source:
                return self._json({"error": "kind/value/source 必填且 kind 必须合法"}, 400)
            scope = data.get("scope") if data.get("scope") in pentdb.VALID_SCOPE else "in"
            severity = data.get("severity") if data.get("severity") in pentdb.VALID_SEVERITY else ""
            ns = argparse.Namespace(
                project=data.get("project"), ext_id="", kind=kind, value=value,
                title="", detail="", note=data.get("note", ""), source=source,
                parent_ext="", merge_key="", status="confirmed", confidence="",
                severity=severity, code="", tech="", service="", scope=scope,
                auto=False, update=bool(data.get("update")), origin="human")
            try:
                pentdb.cmd_add(ns)
            except SystemExit as e:
                return self._json({"error": str(e)}, 400)
            c2 = db()
            try:
                row = c2.execute(
                    "SELECT id FROM raw_events WHERE project=? AND kind=? AND value=? "
                    "ORDER BY id DESC LIMIT 1", (data.get("project"), kind, value)).fetchone()
                return self._json({"ok": True, "id": row["id"] if row else None})
            finally:
                c2.close()
        if u.path in ("/api/waive/confirm", "/api/waive/reject"):
            # 豁免确认/作废（人的决定，对齐 CLI waive --wid N --confirm/--reject）：
            # 面板点击=人工操作，actor=human 留痕；wid 支持单值或 wids 数组批量
            n = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(n).decode("utf-8"))
            project = (data.get("project") or "").strip()
            wids = data.get("wids") or ([data.get("wid")] if data.get("wid") else [])
            try:
                wids = [int(w) for w in wids]
            except (TypeError, ValueError):
                return self._json({"error": "bad wid"}, 400)
            if not project or not wids:
                return self._json({"error": "project/wid 必填"}, 400)
            confirm_act = u.path.endswith("/confirm")
            c0 = db()
            try:
                from pdb_findings import log_change
                done, skipped = [], []
                for wid in wids:
                    row = c0.execute("SELECT id, event_id, term, reason, confirmed FROM waives "
                                     "WHERE id=? AND project=?", (wid, project)).fetchone()
                    if not row:
                        skipped.append({"wid": wid, "why": "不存在"})
                        continue
                    if confirm_act and row["confirmed"] == 2:
                        return self._json({"error": f"wid={wid} 已作废，不能确认"}, 409)
                    if (not confirm_act) and row["confirmed"] == 1:
                        return self._json({"error": f"wid={wid} 已确认生效，不能作废"}, 409)
                    newv = 1 if confirm_act else 2
                    if row["confirmed"] != newv:
                        c0.execute("UPDATE waives SET confirmed=? WHERE id=?", (newv, wid))
                        log_change(c0, project,
                                   "waive-confirm" if confirm_act else "waive-reject",
                                   f"wid={wid} #{row['event_id']} {row['term']}: {row['reason']}"
                                   f"（面板{'确认' if confirm_act else '作废'}）", actor="human")
                        c0.commit()
                    else:
                        skipped.append({"wid": wid, "why": "已是目标态"})
                return self._json({"ok": True, "done": done or [w for w in wids],
                                   "skipped": skipped})
            finally:
                c0.close()
        if u.path == "/api/waive/draft":
            # 豁免起草（AI/面板均可起草，确认生效仍需人在发现页或 CLI --confirm）：
            # 复用 cmd_waive 同一实现——校验记录归属、强制 term/reason、留痕（起草，待人工确认）
            n = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(n).decode("utf-8"))
            project = (data.get("project") or "").strip()
            eid = data.get("id")
            term = (data.get("term") or "").strip()
            reason = (data.get("reason") or "").strip()
            if not project or eid is None or not term or not reason:
                return self._json({"error": "project/id/term/reason 必填"}, 400)
            import argparse as _ap
            import pentdb
            try:
                pentdb.cmd_waive(_ap.Namespace(project=project, id=int(eid), wid=0,
                                               term=term, reason=reason,
                                               confirm=False, reject=False))
            except SystemExit as e:
                return self._json({"error": str(e).strip() or "起草失败"}, 400)
            c3 = db()
            try:
                row = c3.execute("SELECT id FROM waives WHERE project=? AND event_id=? AND term=? "
                                 "ORDER BY id DESC LIMIT 1", (project, int(eid), term)).fetchone()
                return self._json({"ok": True, "wid": row["id"] if row else None})
            finally:
                c3.close()
        if u.path == "/api/void":
            # 记录作废/恢复（人的决定，对齐 CLI void）：冗余/误录数据清理通道，
            # 作废记录退出 lint 阻断/报告/面板主视图；复用 cmd_void 同一实现留痕 actor=human
            n = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(n).decode("utf-8"))
            project = (data.get("project") or "").strip()
            ids = data.get("ids") or []
            reason = (data.get("reason") or "").strip()
            undo = bool(data.get("undo"))
            if not project or not ids:
                return self._json({"error": "project/ids 必填"}, 400)
            if not undo and not reason:
                return self._json({"error": "作废必须写明 reason（留痕可追溯）"}, 400)
            import argparse as _ap
            import pentdb
            try:
                pentdb.cmd_void(_ap.Namespace(project=project, id=0,
                                              ids=",".join(str(int(i)) for i in ids),
                                              reason=reason, undo=undo))
            except SystemExit as e:
                return self._json({"error": str(e).strip() or "void 失败"}, 400)
            return self._json({"ok": True})
        if u.path != "/api/review":
            return self._json({"error": "not found"}, 404)
        n = int(self.headers.get("Content-Length", 0))
        data = json.loads(self.rfile.read(n).decode("utf-8"))
        action = data.get("action")
        ids = data.get("ids") or ([data["id"]] if data.get("id") is not None else [])
        note = (data.get("note") or "").strip()
        try:
            ids = [int(i) for i in ids]
        except (TypeError, ValueError):
            return self._json({"error": "bad ids"}, 400)
        if action not in ("confirmed", "rejected"):
            return self._json({"error": "bad action"}, 400)
        if not ids:
            return self._json({"error": "no ids"}, 400)
        if len(ids) > 1 and not note:
            return self._json({"error": "批量操作必须留批注（写入每条留痕，防止无脑盖章）"}, 400)
        # 人审落库统一走 pdb 层 apply_review（与 CLI review 同一实现）：
        # reviews 留痕 + changelog actor=human 语义一致；批量共用单连接单事务，finally 统一提交。
        import pdb_assets
        c = db()
        try:
            ok, missing = [], []
            for eid in ids:
                r = pdb_assets.apply_review(c, eid, action, note=note, reviewer="human")
                if r is None:
                    missing.append(eid)
                    continue
                ok.append(eid)
            c.commit()
            self._json({"ok": True, "updated": ok, "missing": missing})
        finally:
            c.close()


def run(port=8766):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"PentDB panel: http://127.0.0.1:{port}/")
    srv.serve_forever()


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=8766)
    p.add_argument("--db", default="", help="SQLite 路径（默认读 PENTDB_DB 或副本内 data/）")
    args = p.parse_args()
    if args.db:
        os.environ["PENTDB_DB"] = args.db
    run(args.port)
