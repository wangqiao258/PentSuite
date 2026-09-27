#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PentDB 人看面板（stdlib，零依赖）。端口 8766，避免与旧 assetdb 面板 8765 冲突。"""
import json
import os
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "data", "pentdb.db")
WEB = os.path.join(BASE, "web", "index.html")


def db():
    import pentdb
    return pentdb.connect()


def rows_to_dicts(rows):
    return [dict(r) for r in rows]


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
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        c = db()
        try:
            if u.path == "/api/projects":
                self._json({"projects": [
                    {"name": r["name"], "profile": r["profile"] or "attack-surface"}
                    for r in c.execute("SELECT name, profile FROM projects ORDER BY name")]})
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
                sql = "SELECT * FROM raw_events WHERE project=?"
                args = [p]
                if q.get("kind"):
                    sql += " AND kind=?"; args.append(q["kind"][0])
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
            elif u.path == "/api/timeline":
                p = q.get("project", [""])[0]
                events = rows_to_dicts(c.execute(
                    "SELECT id, kind, value, status, origin, source, created_at FROM raw_events "
                    "WHERE project=? ORDER BY created_at DESC, id DESC LIMIT 100", (p,)))
                changes = rows_to_dicts(c.execute(
                    "SELECT action, detail, at FROM changelog WHERE project=? "
                    "ORDER BY id DESC LIMIT 50", (p,)))
                self._json({"events": events, "changes": changes})
            elif u.path == "/api/findings":
                p = q.get("project", [""])[0]
                rows = rows_to_dicts(c.execute(
                    "SELECT * FROM raw_events WHERE project=? AND kind IN ('finding','osint') "
                    "ORDER BY id DESC", (p,)))
                self._json({"findings": rows})
            elif u.path == "/api/sop":
                p = q.get("project", [""])[0]
                import pentdb
                self._json(pentdb.sop_report(c, p))
            elif u.path == "/api/stages":
                p = q.get("project", [""])[0]
                import pentdb
                if not c.execute("SELECT 1 FROM projects WHERE name=?", (p,)).fetchone():
                    return self._json({"error": "project not found"}, 404)
                all_stages = pentdb.load_sop_cfg().get("stages", [])
                prow = c.execute("SELECT stages_enabled FROM projects WHERE name=?", (p,)).fetchone()
                enabled = [s.strip() for s in (prow["stages_enabled"] or "").split(",") if s.strip()]
                self._json({"all": all_stages, "enabled": enabled or all_stages,
                            "custom": bool(enabled)})
            elif u.path == "/api/suggestions":
                p = q.get("project", [""])[0]
                rows = rows_to_dicts(c.execute(
                    "SELECT * FROM raw_events WHERE project=? AND kind='suggestion' "
                    "ORDER BY id DESC LIMIT 30", (p,)))
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
                    "SELECT * FROM raw_events WHERE project=? AND status='new' ORDER BY id", (p,)))
                self._json({"pending": rows})
            elif u.path == "/api/report":
                p = q.get("project", [""])[0]
                template = q.get("template", ["assets"])[0]
                import pentdb
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
        if u.path == "/api/stages":
            n = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(n).decode("utf-8"))
            import datetime
            c = db()
            try:
                if not c.execute("SELECT 1 FROM projects WHERE name=?", (data.get("project"),)).fetchone():
                    return self._json({"error": "project not found"}, 404)
                import pentdb
                all_stages = pentdb.load_sop_cfg().get("stages", [])
                enabled = [s for s in data.get("enabled", []) if s in all_stages]
                now = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
                c.execute("UPDATE projects SET stages_enabled=? WHERE name=?",
                          (",".join(enabled), data["project"]))
                c.execute("INSERT INTO changelog(project, action, detail, at) VALUES(?,?,?,?)",
                          (data["project"], "stages",
                           "启用阶段: " + ("、".join(enabled) if enabled else "全部") + "（面板）", now))
                c.commit()
                return self._json({"ok": True, "enabled": enabled or all_stages})
            finally:
                c.close()
        if u.path == "/api/waive":
            n = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(n).decode("utf-8"))
            eid, term, reason = data.get("id"), data.get("term", ""), (data.get("reason") or "").strip()
            if eid is None or not term or not reason:
                return self._json({"error": "id/term/reason 必填，豁免必须留痕"}, 400)
            import datetime
            c = db()
            try:
                if int(eid) == 0:
                    project = data.get("project", "")
                    if not c.execute("SELECT 1 FROM projects WHERE name=?", (project,)).fetchone():
                        return self._json({"error": "project not found"}, 404)
                else:
                    row = c.execute("SELECT project FROM raw_events WHERE id=?", (eid,)).fetchone()
                    if not row:
                        return self._json({"error": "no event"}, 404)
                    project = row["project"]
                now = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
                c.execute("INSERT INTO waives(project,event_id,term,reason,at) VALUES(?,?,?,?,?)",
                          (project, int(eid), term, reason, now))
                c.execute("INSERT INTO changelog(project, action, detail, at) VALUES(?,?,?,?)",
                          (project, "waive", f"#{eid} {term}: {reason}（面板）", now))
                c.commit()
                return self._json({"ok": True})
            finally:
                c.close()
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
        c = db()
        try:
            import datetime
            now = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
            ok, missing, projects = [], [], {}
            for eid in ids:
                row = c.execute("SELECT project FROM raw_events WHERE id=?", (eid,)).fetchone()
                if not row:
                    missing.append(eid)
                    continue
                c.execute("UPDATE raw_events SET status=? WHERE id=?", (action, eid))
                c.execute("INSERT INTO reviews(event_id, action, reviewer, note, at) VALUES(?,?,?,?,?)",
                          (eid, action, "human", note, now))
                ok.append(eid)
                projects.setdefault(row["project"], []).append(eid)
            for proj, eids in projects.items():
                detail = ("批量 " if len(eids) > 1 else "") + f"{action} #{','.join(map(str, eids))}"
                if note:
                    detail += f" ｜ {note}"
                c.execute("INSERT INTO changelog(project, action, detail, at) VALUES(?,?,?,?)",
                          (proj, "review", detail + "（面板）", now))
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
