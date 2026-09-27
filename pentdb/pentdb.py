#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PentDB — AI 渗透信息收集库（事实层，写库唯一入口）。

数据模型（三张表）:
  raw_events  append-only 原始事件（AI/迁移/人写入，禁止 UPDATE 内容字段）
  reviews     人审流水（确认/驳回，只追加）
  changelog   全部写操作留痕（只追加）

规矩继承自 pentest-asset-db:
  - source 必填（实际执行的命令或 URL），缺失=lint error
  - 状态机 new -> confirmed / rejected，只有人审（review 命令）能改状态
  - AI 推断（origin=agent）必须带 confidence，且默认状态=new 进待审队列
  - 写库路径唯一: 一切写入必须经本 CLI，禁止手编 SQLite
"""
import argparse
import datetime
import json
import os
import sqlite3
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
# 数据根唯一：默认在项目副本 data/ 下；skill 自包含副本通过 PENTDB_DB 指向同一数据文件
DB_PATH = os.environ.get("PENTDB_DB") or os.path.join(BASE, "data", "pentdb.db")
SOP_CFG = os.environ.get("PENTDB_SOP") or os.path.join(BASE, "sop", "default.json")

VALID_KINDS = ("domain", "port", "path", "param", "finding", "osint", "note", "test", "suggestion")
VALID_STATUS = ("new", "confirmed", "rejected")
VALID_ORIGIN = ("agent", "human", "migrate")
VALID_SEVERITY = ("crit", "high", "med", "low", "info")
VALID_SCOPE = ("in", "out", "unknown")
FACT_KINDS = ("domain", "port", "path", "param", "test")  # 机器可验证事实：允许 --auto 自动确认

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
  name       TEXT PRIMARY KEY,
  stages_enabled TEXT DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS raw_events (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  project    TEXT NOT NULL,
  ext_id     TEXT,
  kind       TEXT NOT NULL,
  value      TEXT NOT NULL,
  title      TEXT DEFAULT '',
  detail     TEXT DEFAULT '',
  note       TEXT DEFAULT '',
  parent_ext TEXT DEFAULT '',
  merge_key  TEXT DEFAULT '',
  status     TEXT NOT NULL DEFAULT 'new',
  confidence TEXT DEFAULT '',
  severity   TEXT DEFAULT '',
  code       TEXT DEFAULT '',
  tech       TEXT DEFAULT '',
  service    TEXT DEFAULT '',
  scope      TEXT DEFAULT 'unknown',
  verified_at TEXT DEFAULT '',
  source     TEXT NOT NULL,
  origin     TEXT NOT NULL DEFAULT 'agent',
  stage      TEXT DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  project    TEXT NOT NULL,
  event_id   INTEGER NOT NULL,
  path       TEXT NOT NULL,
  sha256     TEXT DEFAULT '',
  note       TEXT DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pending_tests (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  project    TEXT NOT NULL,
  event_id   INTEGER NOT NULL,
  term       TEXT NOT NULL,
  stage      TEXT DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS waives (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  project    TEXT NOT NULL,
  event_id   INTEGER NOT NULL,
  term       TEXT NOT NULL,
  reason     TEXT NOT NULL,
  at         TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reviews (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id   INTEGER NOT NULL,
  action     TEXT NOT NULL,
  reviewer   TEXT NOT NULL DEFAULT 'human',
  note       TEXT DEFAULT '',
  at         TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS changelog (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  project TEXT,
  action  TEXT NOT NULL,
  detail  TEXT DEFAULT '',
  at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_project ON raw_events(project);
CREATE INDEX IF NOT EXISTS idx_events_status  ON raw_events(project, status);
"""


def now():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.executescript(SCHEMA)
    try:
        c.execute("ALTER TABLE raw_events ADD COLUMN severity TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE raw_events ADD COLUMN code TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    for col, dft in (("tech", "''"), ("service", "''"), ("scope", "'unknown'"), ("verified_at", "''")):
        try:
            c.execute(f"ALTER TABLE raw_events ADD COLUMN {col} TEXT DEFAULT {dft}")
        except sqlite3.OperationalError:
            pass
    try:
        c.execute("ALTER TABLE projects ADD COLUMN stages_enabled TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE raw_events ADD COLUMN stage TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE pending_tests ADD COLUMN stage TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    return c


def log_change(c, project, action, detail=""):
    c.execute("INSERT INTO changelog(project, action, detail, at) VALUES(?,?,?,?)",
              (project, action, detail, now()))


def require_project(c, project):
    row = c.execute("SELECT name FROM projects WHERE name=?", (project,)).fetchone()
    if not row:
        sys.exit(f"[x] 项目不存在: {project}，先执行 init --project {project}")


# ---------------- 命令 ----------------

def cmd_panel(a):
    """面板生命周期（幂等）：活着复用，没起拉起，被占无响应报 PID。AI 在批次结束后调用并播报。
    探测一律 socket 直连 127.0.0.1 —— 本机代理环境（http_proxy）会污染 urlopen 结果。"""
    import socket as _socket
    import subprocess
    import time
    port = a.port
    url = f"http://127.0.0.1:{port}/"

    def alive():
        try:
            s = _socket.create_connection(("127.0.0.1", port), timeout=1.5)
            s.sendall(b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
            data = s.recv(64)
            s.close()
            return data.startswith(b"HTTP/")
        except Exception:
            return False

    if alive():
        print(f"[=] 面板已在运行，复用: {url}")
    else:
        flags = 0x00000008 | 0x00000200 if os.name == "nt" else 0  # DETACHED_PROCESS | NEW_PROCESS_GROUP
        env = {**os.environ, "PENTDB_DB": DB_PATH}
        subprocess.Popen([sys.executable, os.path.join(BASE, "server.py"), "--port", str(port)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         creationflags=flags, close_fds=True, env=env)
        time.sleep(1.2)
        if alive():
            print(f"[ok] 面板已启动: {url}")
        else:
            out = subprocess.run(["netstat", "-ano"], capture_output=True).stdout.decode("gbk", errors="ignore")
            pids = {ln.split()[-1] for ln in out.splitlines()
                    if f":{port}" in ln and "LISTENING" in ln.upper()}
            if pids:
                print(f"[x] 端口 {port} 被 PID {','.join(pids)} 占用但无 HTTP 响应（旧面板残留？）。"
                      f"执行 taskkill /PID {','.join(pids)} /F 后重试")
            else:
                print(f"[x] 面板启动失败且端口未被占用，请手动执行: python server.py --port {port} "
                      f"（注意：AI 会话沙箱内 detached 子进程可能不存活，改用会话后台任务方式拉起）")
            sys.exit(1)
    if a.project:
        c = connect()
        try:
            require_project(c, a.project)
            new_n = c.execute("SELECT COUNT(*) n FROM raw_events WHERE project=? AND status='new'",
                              (a.project,)).fetchone()["n"]
        finally:
            c.close()
        print(f"project: {a.project}")
        print(f"url: {url}?project={a.project}")
        print(f"pending: {new_n}")


def cmd_init(a):
    c = connect()
    if c.execute("SELECT 1 FROM projects WHERE name=?", (a.project,)).fetchone():
        print(f"[=] 项目已存在: {a.project}")
        return
    c.execute("INSERT INTO projects(name, created_at) VALUES(?,?)", (a.project, now()))
    log_change(c, a.project, "init", "阶段默认全开，AI/面板按目标与授权收窄")
    c.commit()
    print(f"[ok] 项目已建立: {a.project}  db={DB_PATH}")


def cmd_add(a):
    if a.kind not in VALID_KINDS:
        sys.exit(f"[x] kind 必须是 {'/'.join(VALID_KINDS)}")
    if not a.source:
        sys.exit("[x] source 必填（实际执行的命令或 URL）——无溯源不入库")
    if a.origin not in VALID_ORIGIN:
        sys.exit(f"[x] origin 必须是 {'/'.join(VALID_ORIGIN)}")
    status = a.status
    if a.origin == "agent" and status == "confirmed":
        if not (a.auto and a.kind in FACT_KINDS):
            sys.exit("[x] AI 写入不允许直接置 confirmed（机器可验证事实加 --auto，仅限 "
                     + "/".join(FACT_KINDS) + "；推断类 finding/osint/suggestion 一律 new 进待审）")
    if a.origin == "agent" and status not in ("new", "confirmed", "rejected"):
        sys.exit("[x] AI 写入 status 只能 new/confirmed/rejected")
    if a.origin == "agent" and not a.confidence:
        sys.exit("[x] AI 写入必须声明 --confidence high/medium/low")
    if a.severity and a.severity not in VALID_SEVERITY:
        sys.exit(f"[x] severity 必须是 {'/'.join(VALID_SEVERITY)} 或留空")
    if a.scope not in VALID_SCOPE:
        sys.exit(f"[x] scope 必须是 {'/'.join(VALID_SCOPE)}")
    if (a.stage or "") and a.stage not in load_sop_cfg().get("stages", []):
        sys.exit(f"[x] stage 必须是 SOP 定义的阶段之一: {'/'.join(load_sop_cfg().get('stages', []))}")
    c = connect()
    require_project(c, a.project)
    if a.kind != "test":  # test 是事件流允许重复；事实类重复时：拒绝或按 --update 重扫语义更新
        dup = c.execute("SELECT * FROM raw_events WHERE project=? AND kind=? AND value=? ORDER BY id LIMIT 1",
                        (a.project, a.kind, a.value)).fetchone()
        if dup:
            if not a.update:
                sys.exit(f"[x] 重复记录：{a.kind}:{a.value} 已存在 #{dup['id']}，"
                         f"引用该 id，或加 --update 走重扫更新（刷新观测字段，保留状态与人审结论）")
            changes = []
            if (a.note or "") != (dup["note"] or ""):
                changes.append(f"note {dup['note']!r} -> {a.note!r}")
            if str(a.code or "") != (dup["code"] or ""):
                changes.append(f"code {dup['code']} -> {a.code}")
            if (a.tech or "") != (dup["tech"] or ""):
                changes.append(f"tech {dup['tech']} -> {a.tech}")
            if (a.service or "") != (dup["service"] or ""):
                changes.append(f"service {dup['service']} -> {a.service}")
            c.execute("UPDATE raw_events SET note=?, code=?, tech=?, service=?, source=?, verified_at=? "
                      "WHERE id=?",
                      (a.note or "", str(a.code or ""), a.tech or "", a.service or "",
                       a.source, now(), dup["id"]))
            summary = "; ".join(changes) if changes else "观测未变，仅刷新验证时间与来源"
            log_change(c, a.project, "rescan-update", f"#{dup['id']} {a.kind}:{a.value[:50]} | {summary}")
            c.commit()
            print(f"[ok] 重扫更新 #{dup['id']} ({a.kind}: {a.value[:50]}) ｜ {summary}")
            return
    merge_key = a.merge_key or (a.value if a.kind == "domain" else "")
    verified = now() if status == "confirmed" else ""
    cur = c.execute(
        "INSERT INTO raw_events(project,ext_id,kind,value,title,detail,note,parent_ext,"
        "merge_key,status,confidence,severity,code,tech,service,scope,verified_at,source,origin,stage,created_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (a.project, a.ext_id, a.kind, a.value, a.title or "", a.detail or "",
         a.note or "", a.parent_ext or "", merge_key, status, a.confidence or "",
         a.severity or "", str(a.code or ""), a.tech or "", a.service or "",
         a.scope, verified, a.source, a.origin, a.stage or "", now()))
    log_change(c, a.project, "add", f"#{cur.lastrowid} {a.kind}:{a.value[:60]}")
    c.commit()
    print(f"[ok] 事件 #{cur.lastrowid} 已入库 ({a.kind}: {a.value[:60]}) status={status}")


def cmd_query(a):
    c = connect()
    require_project(c, a.project)
    sql = "SELECT * FROM raw_events WHERE project=?"
    args = [a.project]
    if a.kind:
        sql += " AND kind=?"
        args.append(a.kind)
    if a.status:
        sql += " AND status=?"
        args.append(a.status)
    sql += " ORDER BY id"
    rows = c.execute(sql, args).fetchall()
    for r in rows:
        line = f"#{r['id']} [{r['status']:9s}] {r['kind']:8s} {r['value']}"
        if r["title"]:
            line += f" ｜ {r['title']}"
        if r["note"]:
            line += f" ｜ {r['note'][:80]}"
        print(line)
        print(f"      source: {r['source'][:120]}")
    print(f"-- 共 {len(rows)} 条")


def cmd_pending(a):
    c = connect()
    require_project(c, a.project)
    rows = c.execute(
        "SELECT * FROM raw_events WHERE project=? AND status='new' ORDER BY id",
        (a.project,)).fetchall()
    for r in rows:
        print(f"#{r['id']} [{r['origin']:7s}/{r['confidence'] or '-':6s}] "
              f"{r['kind']:8s} {r['value'][:70]} ｜ {(r['note'] or r['title'] or '')[:60]}")
    print(f"-- 待审 {len(rows)} 条")


def cmd_review(a):
    if not a.confirm and not a.reject:
        sys.exit("[x] 必须指定 --confirm 或 --reject")
    action = "confirmed" if a.confirm else "rejected"
    c = connect()
    require_project(c, a.project)
    row = c.execute("SELECT * FROM raw_events WHERE id=? AND project=?",
                    (a.id, a.project)).fetchone()
    if not row:
        sys.exit(f"[x] 事件不存在: #{a.id}")
    if row["status"] == action:
        print(f"[=] #{a.id} 已是 {action}，跳过")
        return
    c.execute("UPDATE raw_events SET status=? WHERE id=?", (action, a.id))
    c.execute("INSERT INTO reviews(event_id, action, reviewer, note, at) VALUES(?,?,?,?,?)",
              (a.id, action, a.reviewer, a.note or "", now()))
    log_change(c, a.project, "review", f"#{a.id} -> {action}")
    c.commit()
    print(f"[ok] #{a.id} -> {action}")


def lint_report(c, project):
    """lint 扫描（面板/CLI 共用），返回 errors/warns 列表。"""
    errors, warns = [], []
    for r in c.execute("SELECT * FROM raw_events WHERE project=?", (project,)):
        rid = r["id"]
        if not (r["source"] or "").strip():
            errors.append(f"#{rid} source 为空（无溯源）")
        if r["status"] not in VALID_STATUS:
            errors.append(f"#{rid} 非法状态 {r['status']}")
        if r["kind"] not in VALID_KINDS:
            errors.append(f"#{rid} 非法 kind {r['kind']}")
        if r["origin"] == "agent" and not (r["confidence"] or "").strip():
            warns.append(f"#{rid} AI 写入缺 confidence")
        if (r["severity"] or "") and r["severity"] not in VALID_SEVERITY:
            warns.append(f"#{rid} 非法 severity {r['severity']}")
        if (r["scope"] or "unknown") not in VALID_SCOPE:
            errors.append(f"#{rid} 非法 scope {r['scope']}")
        if r["kind"] == "test" and not (r["parent_ext"] or "").strip():
            errors.append(f"#{rid} test 事件缺 parent_ext（测试必须归因到被测记录，多对象用逗号分隔）")
    return {"errors": errors, "warns": warns}


def cmd_lint(a):
    c = connect()
    require_project(c, a.project)
    rep = lint_report(c, a.project)
    for e in rep["errors"]:
        print(f"ERROR {e}")
    for w in rep["warns"]:
        print(f"WARN  {w}")
    print(f"-- lint: {len(rep['errors'])} error, {len(rep['warns'])} warn")
    sys.exit(1 if rep["errors"] else 0)


def cmd_migrate(a):
    kind_map = {"targets": "domain", "ports": "port", "paths": "path",
                "params": "param", "findings": "finding", "tests": "test"}
    c = connect()
    require_project(c, a.project)
    total = 0
    for fn, kind in kind_map.items():
        path = os.path.join(a.from_dir, fn + ".jsonl")
        if not os.path.exists(path):
            continue
        n = 0
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                o = json.loads(line)
                src = o.get("source", "")
                if not src:
                    print(f"[!] 跳过无 source 记录 {fn}: {o.get('id')}")
                    continue
                status = o.get("status", "new")
                if status not in VALID_STATUS:
                    status = "new"
                value = o.get("value") or o.get("title") or ""
                c.execute(
                    "INSERT INTO raw_events(project,ext_id,kind,value,title,detail,note,"
                    "parent_ext,merge_key,status,confidence,source,origin,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (a.project, o.get("id"), kind, value, o.get("title", ""),
                     o.get("detail", ""), o.get("note", ""), o.get("parent", ""),
                     value if kind == "domain" else "", status, "", src,
                     "migrate", o.get("time") or now()))
                n += 1
        log_change(c, a.project, "migrate", f"{fn}: {n} 条")
        print(f"[ok] {fn} -> {kind}: {n} 条")
        total += n
    c.commit()
    print(f"-- 迁移完成，共 {total} 条")


FINDING_MARKS = ("【描述】", "【原因】", "【手工验证】", "【修复】")


def _parse_finding_detail(detail):
    out = {"描述": [], "原因": [], "手工验证": [], "修复": []}
    cur = "描述"
    for line in (detail or "").splitlines():
        s = line.strip()
        mark = next((m for m in FINDING_MARKS if s.startswith(m)), None)
        if mark:
            cur = mark.strip("【】")
            rest = s[len(mark):].strip()
            if rest:
                out[cur].append(rest)
            continue
        out[cur].append(line)
    return {k: "\n".join(v).strip() for k, v in out.items()}


VERIFY_FRAME = ("1. 构造请求：（curl 命令 / 浏览器操作，AI 实战时补充具体参数）\n"
                "2. 观察点：（预期出现的异常响应或行为）\n"
                "3. 影响确认：（该漏洞可造成的实际危害演示）")


def _pentest_report(c, project):
    rows = c.execute("SELECT * FROM raw_events WHERE project=? ORDER BY id", (project,)).fetchall()
    findings = [r for r in rows if r["kind"] == "finding" and r["status"] == "confirmed"]
    pending = [r for r in rows if r["status"] == "new"]
    domains_in = [r["value"] for r in rows if r["kind"] == "domain" and r["scope"] == "in"]
    now_s = now()
    out = [f"# {project} 渗透测试报告", "",
           f"生成时间: {now_s} ｜ 模板: pentest", "",
           "## 1 执行摘要",
           f"- 测试对象: {project}",
           f"- confirmed 发现: {len(findings)} 条 ｜ 待审项: {len(pending)} 条",
           f"- 资产: 域名 {sum(1 for r in rows if r['kind']=='domain')} 条（in-scope {len(domains_in)}）",
           "", "## 2 范围与授权",
           "- in-scope 资产: " + (", ".join(domains_in[:30]) if domains_in else "（见附录）"),
           "- 授权边界以 notes.md §0 为准", "",
           "## 3 发现详情"]
    if not findings:
        out.append("（暂无 confirmed 发现）")
    for i, r in enumerate(findings, 1):
        sec = _parse_finding_detail(r["detail"])
        sev = r["severity"] or "未定级"
        out += ["", f"### 3.{i} {r['title'] or r['value']}（{sev}）",
                f"- 记录: #{r['id']} ｜ 来源: {r['source']}", "",
                f"**描述**: {sec['描述'] or r['value']}", "",
                f"**原因分析**: {sec['原因'] or '（待补充：漏洞产生的根因）'}", "",
                "**手工验证步骤**:"]
        if sec["手工验证"]:
            out.append(sec["手工验证"])
        else:
            out.append(VERIFY_FRAME)
        out += ["", f"**修复建议**: {sec['修复'] or '（待补充：针对根因的修复方案）'}"]
        evs = c.execute("SELECT path, sha256 FROM evidence WHERE event_id=?", (r["id"],)).fetchall()
        if evs:
            out.append("")
            out.append("**证据**:")
            for e in evs:
                out.append(f"- `{e['path']}`（sha256={e['sha256'][:16]}…）")
    out += ["", "## 4 附录：资产清单",
            "完整资产分组与状态见面板目标总览，或 `pentdb.py report --project " + project + "`（资产模式）。"]
    return "\n".join(out)


def cmd_report(a):
    if getattr(a, "template", "") == "pentest":
        c = connect()
        require_project(c, a.project)
        text = _pentest_report(c, a.project)
        if a.out:
            parent = os.path.dirname(os.path.abspath(a.out))
            os.makedirs(parent, exist_ok=True)
            with open(a.out, "w", encoding="utf-8") as f:
                f.write(text)
            print(f"[ok] 报告已写入 {a.out}")
        else:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8")
            print(text)
        return
    c = connect()
    require_project(c, a.project)
    rows = c.execute("SELECT * FROM raw_events WHERE project=? ORDER BY kind, id",
                     (a.project,)).fetchall()
    domains = [r for r in rows if r["kind"] == "domain"]
    findings = [r for r in rows if r["kind"] == "finding"]
    others = [r for r in rows if r["kind"] not in ("domain", "finding")]
    pending = [r for r in rows if r["status"] == "new"]
    out = [f"# {a.project} 侦察报告", "", f"生成时间: {now()}", ""]
    out.append(f"## 统计")
    out.append(f"- 域名/子域: {len(domains)}（confirmed {sum(1 for r in domains if r['status']=='confirmed')}）")
    out.append(f"- 发现: {len(findings)}，其他事件: {len(others)}，待审: {len(pending)}")
    out.append("")
    groups = {}
    for r in domains:
        parts = r["value"].rsplit(".", 3)
        base = ".".join(parts[-3:]) if len(parts) >= 3 else r["value"]
        groups.setdefault(base, []).append(r)
    out.append("## 资产分组（按主域聚合）")
    for base in sorted(groups):
        out.append(f"\n### {base}（{len(groups[base])}）")
        for r in groups[base]:
            flag = "" if r["status"] == "confirmed" else ("（待审）" if r["status"] == "new" else "（驳回）")
            note = f" — {r['note']}" if r["note"] else ""
            out.append(f"- {r['value']}{flag}{note}  [#{r['id']}]")
    if findings:
        out.append("\n## 发现与关键情报")
        for r in findings:
            out.append(f"\n### {r['title'] or r['value']}  [#{r['id']}] ({r['status']})")
            if r["detail"]:
                out.append(r["detail"])
            out.append(f"来源: {r['source']}")
    if pending:
        out.append("\n## 待人工审核")
        for r in pending:
            out.append(f"- #{r['id']} [{r['kind']}] {r['value']} ｜ {(r['note'] or '')[:80]}")
    text = "\n".join(out)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"[ok] 报告已写入 {a.out}")
    else:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        print(text)


def cmd_js(a):
    sys.path.insert(0, BASE)
    import recon
    recon.run_js(a)


def cmd_recon(a):
    sys.path.insert(0, BASE)
    import recon
    recon.run(a)


def cmd_serve(a):
    if a.db:
        os.environ["PENTDB_DB"] = a.db
    sys.path.insert(0, BASE)
    import server
    server.run(a.port)


# ---------------- 经验库（pentest-kb，Supabase 云库；核心逻辑在 kb.py） ----------------

def _kb_tags(s):
    return [t.strip() for t in (s or "").split(",") if t.strip()]


def cmd_kb(a):
    sys.path.insert(0, BASE)
    sys.path.insert(0, os.path.join(BASE, "kb"))
    import kb
    c = a.kb_cmd
    if c == "search":
        out = kb.search_experience(a.keyword, tags_filter=_kb_tags(a.tags), limit=a.limit)
    elif c == "add":
        detail = a.detail
        if a.from_file:
            if detail:
                sys.exit("[x] --detail 与 --from-file 二选一")
            with open(a.from_file, encoding="utf-8") as f:
                detail = f.read()
        if not detail:
            sys.exit("[x] 需要 --detail 或 --from-file 提供经验详情（长文本用 --from-file 防转义问题）")
        out = kb.add_experience(a.title, detail, scenario_tags=_kb_tags(a.tags),
                                tool_code=a.tool_code or None,
                                tool_type=a.tool_type or None)
    elif c == "find-similar":
        out = kb.find_similar(a.title, a.detail)
    elif c == "list":
        out = kb.list_all_experiences(a.limit, a.offset)
    elif c == "pending":
        out = kb.list_pending_experiences()
    elif c == "approve":
        if not a.confirm:
            sys.exit("[x] 审批是人的决定：必须在用户明示同意后加 --confirm 执行"
                     "（对应 skill 阶段六门禁；草稿永远由 kb-add 产生）")
        out = kb.approve_experience(a.id, a.merge_with)
    elif c == "reject":
        out = kb.reject_experience(a.id)
    elif c == "delete":
        out = kb.delete_experience(a.id)
    elif c == "restore":
        out = kb.restore_experience(a.id)
    elif c == "deleted":
        out = kb.list_deleted_experiences()
    elif c == "purge":
        out = kb.purge_experiences(a.days)
    elif c == "get":
        out = kb.get_experience(a.id)
    elif c == "update":
        out = kb.update_experience(a.id, title=a.title, detail=a.detail,
                                   scenario_tags=_kb_tags(a.tags) or None,
                                   tool_code=a.tool_code, tool_type=a.tool_type)
    else:
        sys.exit(f"[x] 未知 kb 子命令: {c}")
    print(out)


# ---------------- 套件引导（可选：venv/依赖/凭据迁移） ----------------

ROOT = os.path.dirname(BASE)  # 套件根（pentdb/ 的上一级）
VENV_DIR = os.path.join(ROOT, ".venv")
KB_CREDS = os.path.join(BASE, "kb", "creds.json")
KB_ENV_KEYS = ("PENTEST_KB_DB_HOST", "PENTEST_KB_DB_PORT", "PENTEST_KB_DB_NAME",
               "PENTEST_KB_DB_USER", "PENTEST_KB_DB_PASSWORD")


def _venv_python():
    return os.path.join(VENV_DIR, "Scripts", "python.exe") if os.name == "nt" \
        else os.path.join(VENV_DIR, "bin", "python")


def _bootstrap_deps():
    vp = _venv_python()
    if os.path.exists(vp):
        print("[=] 套件 .venv 已存在，跳过创建")
    else:
        print("[*] 创建套件 .venv ...")
        subprocess.run([sys.executable, "-m", "venv", VENV_DIR], check=True)
    print("[*] 安装经验层依赖（psycopg2/jieba/rank-bm25）...")
    # 清华镜像缺部分包；腾讯镜像实测可用（2026-09）
    subprocess.run([vp, "-m", "pip", "install", "-i",
                    "https://mirrors.cloud.tencent.com/pypi/simple",
                    "-r", os.path.join(BASE, "kb", "requirements.txt")], check=True)
    print("[ok] 依赖就绪（PentDB 零依赖，此 venv 仅供 kb-* 子命令使用）")


_CREDS_OUT_KEYS = {"PENTEST_KB_DB_HOST": "host", "PENTEST_KB_DB_PORT": "port",
                   "PENTEST_KB_DB_NAME": "dbname", "PENTEST_KB_DB_USER": "user",
                   "PENTEST_KB_DB_PASSWORD": "password"}


def _bootstrap_creds(src):
    """从旧机器的 mcp.json（MCP 时代遗留）或 creds.json 抓取经验库凭据，统一写小写键。"""
    old = json.load(open(src, encoding="utf-8"))
    env = (old.get("mcpServers", {}).get("pentest-kb", {}) or {}).get("env", {})
    creds = {out: env.get(up, "") or old.get(out, "")
             for up, out in _CREDS_OUT_KEYS.items()}
    if not creds.get("host"):
        sys.exit(f"[x] {src} 中未找到经验库凭据（mcpServers.env 或 creds.json 格式）")
    with open(KB_CREDS, "w", encoding="utf-8") as f:
        json.dump(creds, f, ensure_ascii=False, indent=2)
    print(f"[ok] 经验库凭据已写入 {KB_CREDS}（仅存本机）")


def _creds_skeleton():
    if not os.path.exists(KB_CREDS):
        with open(KB_CREDS, "w", encoding="utf-8") as f:
            json.dump({"host": "", "port": "5432", "dbname": "postgres",
                       "user": "", "password": ""}, f, ensure_ascii=False, indent=2)
        print(f"[ok] 已生成凭据骨架 {KB_CREDS}：填入 host / user / password 三项即用")

def cmd_bootstrap(a):
    if not a.skip_deps:
        _bootstrap_deps()
    if a.kb_creds:
        _bootstrap_creds(a.kb_creds)
    print("\n===== 经验库（可选）=====")
    _creds_skeleton()
    if os.path.exists(KB_CREDS):
        print(f"[=] 凭据文件: {KB_CREDS}（未填值不影响 PentDB 其余功能）；验证: pentdb.py kb list")
    print("===== PentDB =====")
    print(f"数据根（缺省即此）: {os.path.join(BASE, 'data', 'pentdb.db')}")
    print("  开面板: pentdb.py panel --project <目标>")
    print("  回归  : cd pentdb && python -m unittest test_sop")


# ---------------- SOP 引擎（自 assetdb 移植，语义适配 raw_events 单表） ----------------

STATE_ICON = {"done": "✓ 已测", "registered": "◐ 已登记", "missing": "○ 未登记", "waived": "⊘ 已豁免"}
SOP_KINDS = ("domain", "port", "path", "param", "finding")


def load_sop_cfg():
    with open(SOP_CFG, encoding="utf-8") as f:
        return json.load(f)


def _term_in(term, text):
    return any(alt.lower() in (text or "").lower() for alt in term.split("|"))


def _match(rec, m):
    for k, v in m.items():
        if k == "kind":
            if rec["kind"] != v:
                return False
        elif k == "service_or_note_contains":
            text = (str(rec["service"]) if "service" in rec.keys() else "") + " " + \
                   (str(rec["note"]) if "note" in rec.keys() else "")
            if str(v).lower() not in text.lower():
                return False
        elif k.endswith("_contains"):
            f = k[:-len("_contains")]
            if str(v).lower() not in str(rec[f] if f in rec.keys() else "").lower():
                return False
        elif k == "code":
            if str(rec["code"] or "") != str(v):
                return False
        elif k == "parent_code":
            if str(rec["_parent_code"] or "") != str(v):
                return False
        else:
            if str(rec[k] if k in rec.keys() else "") != str(v):
                return False
    return True


def sop_report(c, project):
    cfg = load_sop_cfg()
    prow = c.execute("SELECT stages_enabled FROM projects WHERE name=?", (project,)).fetchone()
    enabled = [s.strip() for s in (prow["stages_enabled"] or "").split(",") if s.strip()]
    stages_all = load_sop_cfg().get("stages", [])
    stages = [s for s in stages_all if not enabled or s in enabled]
    rows = [dict(r) for r in c.execute(
        "SELECT * FROM raw_events WHERE project=? AND kind IN (%s)"
        % ",".join("?" * len(SOP_KINDS)), (project,) + SOP_KINDS)]
    path_code = {r["ext_id"] or str(r["id"]): r["code"]
                 for r in c.execute("SELECT * FROM raw_events WHERE project=? AND kind='path'", (project,))}
    for r in rows:
        r["_parent_code"] = path_code.get(r["parent_ext"]) if r["kind"] == "param" else None
    tests = [dict(r) for r in c.execute(
        "SELECT * FROM raw_events WHERE project=? AND kind='test'", (project,))]
    tests_by_target = {}
    for t in tests:
        for pid in (t["parent_ext"] or "").split(","):
            pid = pid.strip()
            if pid:
                tests_by_target.setdefault(pid, []).append(t)
    pend = {(str(p["event_id"]), p["term"]) for p in c.execute(
        "SELECT * FROM pending_tests WHERE project=?", (project,))}
    waives = [dict(w) for w in c.execute("SELECT * FROM waives WHERE project=?", (project,))]

    per, total, done, registered, missing, waived = {}, 0, 0, 0, 0, 0
    for rec in rows:
        required = []
        for rule in cfg.get("rules", []):
            if _match(rec, rule.get("match", {})):
                for term in rule.get("require_tests", []):
                    if term not in required:
                        required.append(term)
        if not required:
            continue
        rid = rec["id"]
        tlist = tests_by_target.get(str(rid), [])
        items = []
        for term in required:
            hit_test = next((t for t in tlist
                             if _term_in(term, t["value"] + " " + t["note"] + " " + t["source"])), None)
            hit_waive = next((w for w in waives if w["event_id"] == rid
                              and (_term_in(term, w["term"]) or _term_in(w["term"], term))), None)
            if hit_test:
                items.append({"term": term, "state": "done", "ev": "#" + str(hit_test["id"])})
            elif hit_waive:
                items.append({"term": term, "state": "waived", "ev": hit_waive["reason"]})
            elif (str(rid), term) in pend:
                items.append({"term": term, "state": "registered", "ev": "pending"})
            else:
                items.append({"term": term, "state": "missing", "ev": None})
            st = items[-1]["state"]
            total += 1
            if st == "done":
                done += 1
            elif st == "registered":
                registered += 1
            elif st == "waived":
                waived += 1
            else:
                missing += 1
        per[rid] = {"label": (rec["value"] or rec["title"])[:26], "kind": rec["kind"], "items": items,
                    "done": sum(1 for i in items if i["state"] == "done"),
                    "waived": sum(1 for i in items if i["state"] == "waived"),
                    "total": len(items)}

    test_texts = {t["id"]: t["value"] + " " + t["note"] + " " + t["source"] for t in tests}
    pend_rows = [dict(p) for p in c.execute("SELECT * FROM pending_tests WHERE project=?", (project,))]
    pend_terms = [p["term"] for p in pend_rows]
    waives0 = [w for w in waives if w["event_id"] == 0]

    # 术语 -> 阶段映射：规则带 stage 字段（缺省归漏洞探测）+ stage_required 菜单
    term_stage = {}
    for rule in cfg.get("rules", []):
        rst = rule.get("stage", "漏洞探测")
        for term in rule.get("require_tests", []):
            term_stage.setdefault(term, rst)
    required_map = cfg.get("stage_required", {})

    def _match_stage(text):
        for s2, terms in required_map.items():
            if any(_term_in(t2, text) for t2 in terms):
                return s2
        for term, s2 in term_stage.items():
            if _term_in(term, text):
                return s2
        return ""

    # 幂等回填：旧数据（pending_tests / test 事件）缺 stage 的按术语反查补上
    dirty = 0
    for p in pend_rows:
        if not (p["stage"] or "").strip():
            st = _match_stage(p["term"])
            if st:
                c.execute("UPDATE pending_tests SET stage=? WHERE id=?", (st, p["id"]))
                dirty += 1
    for t in tests:
        if not (t["stage"] or "").strip():
            st = _match_stage(test_texts[t["id"]])
            if st:
                c.execute("UPDATE raw_events SET stage=? WHERE id=?", (st, t["id"]))
                t["stage"] = st
                dirty += 1
    if dirty:
        log_change(c, project, "stage-backfill", f"术语反查回填 stage {dirty} 条")
        c.commit()

    # 阶段视图：计划（菜单=stage_required+规则映射术语）× 执行（该阶段 test 流水）
    stage_view = []
    for s in stages:
        menu_terms = list(required_map.get(s, []))
        for term, st in term_stage.items():
            if st == s and term not in menu_terms:
                menu_terms.append(term)
        items, executed_ids = [], set()
        for term in menu_terms:
            hit_test = next((t for t in tests if _term_in(term, test_texts[t["id"]])), None)
            hit_waive = next((w for w in waives0
                              if _term_in(term, w["term"]) or _term_in(w["term"], term)), None)
            if hit_test:
                items.append({"term": term, "state": "done", "ev": "#" + str(hit_test["id"])})
                executed_ids.add(hit_test["id"])
            elif any(_term_in(term, p) for p in pend_terms):
                items.append({"term": term, "state": "registered", "ev": "pending"})
            elif hit_waive:
                items.append({"term": term, "state": "waived", "ev": hit_waive["reason"]})
            else:
                items.append({"term": term, "state": "missing", "ev": None})
        executed = [t for t in tests if (t["stage"] or "") == s]
        executed += [t for t in tests if not (t["stage"] or "").strip()
                     and t["id"] in executed_ids and t not in executed]
        sdone = sum(1 for i in items if i["state"] == "done")
        swaiv = sum(1 for i in items if i["state"] == "waived")
        sreg = sum(1 for i in items if i["state"] == "registered")
        stage_view.append({
            "stage": s, "menu": items, "done": sdone, "waived": swaiv,
            "total": len(items),
            "complete": bool(items) and sdone + swaiv == len(items),
            "executed": [{"id": t["id"], "value": t["value"], "note": t["note"], "status": t["status"],
                          "parent_ext": t["parent_ext"], "source": t["source"],
                          "created_at": t["created_at"]} for t in executed],
            "pending": [{"term": p["term"], "at": p["created_at"]}
                        for p in pend_rows if (p["stage"] or "") == s],
        })
        total += len(items); done += sdone; waived += swaiv
        registered += sreg; missing += len(items) - sdone - swaiv - sreg

    texts = test_texts.values()
    special_cfg = cfg.get("stage_special", {})
    kinds_present = {r["kind"] for r in rows}
    view_by_stage = {v["stage"]: v for v in stage_view}
    flags = []
    for s in stages:
        v = view_by_stage.get(s)
        if v and v["menu"]:
            # 有菜单的阶段：完成判定 = 菜单全部 done/waived（权威），启发式只兜底
            flags.append(v["complete"])
        else:
            spec = special_cfg.get(s, "")
            if spec.startswith("text:"):
                kw = spec[len("text:"):]
                flags.append(any(_term_in(kw, t) for t in texts))
            elif spec.startswith("has:"):
                flags.append(spec[4:] in kinds_present)
            else:
                flags.append(any(_term_in(s, t) for t in texts))
    cur = len(stages)
    for i, ok in enumerate(flags):
        if not ok:
            cur = i
            break
    stage = {"current": stages[cur] if cur < len(stages) else "(全部完成)",
             "index": cur, "total": len(stages), "flags": dict(zip(stages, flags))}
    return {"stage": stage, "stages_all": stages_all, "stages_enabled": stages,
            "stage_view": stage_view,
            "per": per, "total": total, "done": done,
            "registered": registered, "missing": missing, "waived": waived}

def cmd_sop(a):
    c = connect()
    require_project(c, a.project)
    rep = sop_report(c, a.project)
    print("== SOP check: %s ==" % a.project)
    print("当前阶段: %s (%d/%d)" % (rep["stage"]["current"], rep["stage"]["index"], rep["stage"]["total"]))
    cov = rep["done"] * 100 // rep["total"] if rep["total"] else 100
    print("覆盖: 必测 %d | 已测 %d | 已登记 %d | 已豁免 %d | 未登记 %d | 完成率 %d%%"
          % (rep["total"], rep["done"], rep["registered"], rep["waived"], rep["missing"], cov))
    for v in rep.get("stage_view", []):
        mark = "✓" if v["complete"] else " "
        print("  %s %-6s %d/%d  执行流水 %d 条" % (mark, v["stage"], v["done"] + v["waived"],
                                                  v["total"], len(v["executed"])))
    print("-" * 56)
    for rid, info in rep["per"].items():
        clear = info["done"] + info["waived"] == info["total"]
        print("%s #%s %-8s %-26s %d/%d" % (" " if clear else "!", rid, info["kind"],
                                           info["label"], info["done"], info["total"]))
        for it in info["items"]:
            print("      %-14s %s%s" % (STATE_ICON[it["state"]], it["term"],
                                        "" if it["state"] in ("done", "waived") else "  ← " + str(it["ev"] or "建议登记")))
    if a.apply:
        n = 0
        for rid, info in rep["per"].items():
            for it in info["items"]:
                if it["state"] == "missing":
                    c.execute("INSERT INTO pending_tests(project,event_id,term,created_at,stage) "
                              "VALUES(?,?,?,?,?)",
                              (a.project, int(rid), it["term"], now(), it.get("stage", "")))
                    n += 1
        for v in rep.get("stage_view", []):
            for it in v["menu"]:
                if it["state"] == "missing":
                    c.execute("INSERT INTO pending_tests(project,event_id,term,created_at,stage) "
                              "VALUES(?,?,?,?,?)",
                              (a.project, 0, it["term"], now(), v["stage"]))
                    n += 1
        log_change(c, a.project, "sop-apply", f"新增 pending {n} 条")
        c.commit()
        print(f"-- apply: 未登记项已转 pending_tests {n} 条")


def cmd_waive(a):
    if not a.reason:
        sys.exit("[x] 豁免必须写明 --reason（收尾时豁免清单提交用户裁决）")
    c = connect()
    require_project(c, a.project)
    if a.id != 0:
        row = c.execute("SELECT id FROM raw_events WHERE id=? AND project=?", (a.id, a.project)).fetchone()
        if not row:
            sys.exit(f"[x] 记录不存在: #{a.id}（id=0 表示项目级/阶段必测豁免）")
    c.execute("INSERT INTO waives(project,event_id,term,reason,at) VALUES(?,?,?,?,?)",
              (a.project, a.id, a.term, a.reason, now()))
    log_change(c, a.project, "waive", f"#{a.id} {a.term}: {a.reason}")
    c.commit()
    print(f"[ok] #{a.id} 豁免 {a.term} ← {a.reason}")


def cmd_evidence(a):
    """证据指针入库：文件留在原处，库内存路径+SHA256，与记录强关联。"""
    if not os.path.exists(a.path):
        sys.exit(f"[x] 证据文件不存在: {a.path}")
    import hashlib
    h = hashlib.sha256()
    with open(a.path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    c = connect()
    require_project(c, a.project)
    row = c.execute("SELECT id FROM raw_events WHERE id=? AND project=?",
                    (a.event_id, a.project)).fetchone()
    if not row:
        sys.exit(f"[x] 记录不存在: #{a.event_id}")
    cur = c.execute("INSERT INTO evidence(project,event_id,path,sha256,note,created_at) VALUES(?,?,?,?,?,?)",
                    (a.project, a.event_id, a.path, h.hexdigest(), a.note or "", now()))
    log_change(c, a.project, "evidence", f"#{a.event_id} ← {os.path.basename(a.path)}")
    c.commit()
    print(f"[ok] 证据 #{cur.lastrowid} 已挂到 #{a.event_id}（sha256={h.hexdigest()[:16]}…）")


def cmd_verify(a):
    """复测打点：更新最后验证时间（数据时效）。"""
    c = connect()
    require_project(c, a.project)
    row = c.execute("SELECT id FROM raw_events WHERE id=? AND project=?", (a.id, a.project)).fetchone()
    if not row:
        sys.exit(f"[x] 记录不存在: #{a.id}")
    c.execute("UPDATE raw_events SET verified_at=? WHERE id=?", (now(), a.id))
    log_change(c, a.project, "verify", f"#{a.id} 复测打点")
    c.commit()
    print(f"[ok] #{a.id} 已更新验证时间")


def cmd_stages(a):
    """查看/设置本项目启用的 SOP 阶段（空=全部启用）。"""
    c = connect()
    require_project(c, a.project)
    all_stages = load_sop_cfg().get("stages", [])
    prow = c.execute("SELECT stages_enabled FROM projects WHERE name=?", (a.project,)).fetchone()
    enabled = [s.strip() for s in (prow["stages_enabled"] or "").split(",") if s.strip()]
    if a.enable:
        req = [s.strip() for s in a.enable.split(",") if s.strip()]
        bad = [s for s in req if s not in all_stages]
        if bad:
            sys.exit(f"[x] 未知阶段: {'、'.join(bad)}；可选: {'/'.join(all_stages)}")
        c.execute("UPDATE projects SET stages_enabled=? WHERE name=?", (",".join(req), a.project))
        log_change(c, a.project, "stages", f"启用阶段: {'、'.join(req)}")
        c.commit()
        enabled = req
        print(f"[ok] 启用阶段已更新: {'、'.join(req)}")
    print(f"-- 当前启用（{'自定义' if enabled else '全部'}）: {' / '.join(enabled or all_stages)}")


def cmd_drop(a):
    """删除整个项目及其数据（高危操作，必须 --confirm）。changelog 留墓碑记录。"""
    if not a.confirm:
        sys.exit("[x] 删除项目是高危操作，必须显式加 --confirm")
    c = connect()
    require_project(c, a.project)
    n = c.execute("SELECT COUNT(*) FROM raw_events WHERE project=?", (a.project,)).fetchone()[0]
    for t in ("raw_events", "pending_tests", "waives", "evidence"):
        c.execute(f"DELETE FROM {t} WHERE project=?", (a.project,))
    c.execute("DELETE FROM projects WHERE name=?", (a.project,))
    log_change(c, "__system__", "drop", f"项目 {a.project} 已删除（含 {n} 条事件）")
    c.commit()
    print(f"[ok] 项目 {a.project} 已删除（{n} 条事件），changelog 留痕")


def main():
    p = argparse.ArgumentParser(description="PentDB 写库唯一入口")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("init")
    sp.add_argument("--project", required=True)
    sp.set_defaults(fn=cmd_init)

    sp = sub.add_parser("panel")
    sp.add_argument("--project", default="", help="可选：拼出带 project 的直达 URL 并输出待审数（播报用）")
    sp.add_argument("--port", type=int, default=8766)
    sp.set_defaults(fn=cmd_panel)


    sp = sub.add_parser("add")
    sp.add_argument("--project", required=True)
    sp.add_argument("--kind", required=True)
    sp.add_argument("--value", required=True)
    sp.add_argument("--title", default="")
    sp.add_argument("--detail", default="")
    sp.add_argument("--note", default="")
    sp.add_argument("--source", required=True)
    sp.add_argument("--ext-id", dest="ext_id", default="")
    sp.add_argument("--parent-ext", dest="parent_ext", default="")
    sp.add_argument("--merge-key", dest="merge_key", default="")
    sp.add_argument("--status", default="new", choices=VALID_STATUS)
    sp.add_argument("--confidence", default="")
    sp.add_argument("--severity", default="")
    sp.add_argument("--code", default="", help="HTTP 状态码（扫描器实测值）")
    sp.add_argument("--tech", default="", help="指纹/技术栈（cloudflare/tomcat/istio…）")
    sp.add_argument("--service", default="", help="端口服务（mysql/http/ssh…）")
    sp.add_argument("--scope", default="unknown", help="范围标记 in/out/unknown")
    sp.add_argument("--stage", default="", help="所属 SOP 阶段（test 事件建议必带，面板按阶段聚合）")
    sp.add_argument("--auto", action="store_true", help="机器可验证事实，允许自动 confirmed")
    sp.add_argument("--update", action="store_true",
                    help="重扫更新：同 kind+value 已存在时刷新观测字段（note/code/tech/service/来源/验证时间），状态与人审结论保留")
    sp.add_argument("--origin", default="agent", choices=VALID_ORIGIN)
    sp.set_defaults(fn=cmd_add)

    sp = sub.add_parser("query")
    sp.add_argument("--project", required=True)
    sp.add_argument("--kind"); sp.add_argument("--status")
    sp.set_defaults(fn=cmd_query)

    sp = sub.add_parser("pending"); sp.add_argument("--project", required=True); sp.set_defaults(fn=cmd_pending)

    sp = sub.add_parser("review")
    sp.add_argument("--project", required=True)
    sp.add_argument("--id", type=int, required=True)
    sp.add_argument("--confirm", action="store_true")
    sp.add_argument("--reject", action="store_true")
    sp.add_argument("--reviewer", default="human")
    sp.add_argument("--note", default="")
    sp.set_defaults(fn=cmd_review)

    sp = sub.add_parser("lint"); sp.add_argument("--project", required=True); sp.set_defaults(fn=cmd_lint)

    sp = sub.add_parser("migrate")
    sp.add_argument("--from", dest="from_dir", required=True)
    sp.add_argument("--project", required=True)
    sp.set_defaults(fn=cmd_migrate)

    sp = sub.add_parser("report")
    sp.add_argument("--project", required=True)
    sp.add_argument("--out", default="")
    sp.add_argument("--template", default="assets", choices=("assets", "pentest"),
                    help="assets=资产清单（默认）；pentest=渗透测试报告（描述/原因/手工验证/修复）")
    sp.set_defaults(fn=cmd_report)

    sp = sub.add_parser("serve"); sp.add_argument("--port", type=int, default=8766)
    sp.add_argument("--db", default=""); sp.set_defaults(fn=cmd_serve)

    sp = sub.add_parser("sop")
    sp.add_argument("--project", required=True)
    sp.add_argument("--apply", action="store_true", help="未登记项自动转 pending_tests")
    sp.set_defaults(fn=cmd_sop)

    sp = sub.add_parser("waive")
    sp.add_argument("--project", required=True)
    sp.add_argument("--id", type=int, required=True)
    sp.add_argument("--term", required=True)
    sp.add_argument("--reason", required=True)
    sp.set_defaults(fn=cmd_waive)

    sp = sub.add_parser("drop")
    sp.add_argument("--project", required=True)
    sp.add_argument("--confirm", action="store_true")
    sp.set_defaults(fn=cmd_drop)

    sp = sub.add_parser("evidence")
    sp.add_argument("--project", required=True)
    sp.add_argument("--event-id", type=int, required=True)
    sp.add_argument("--path", required=True)
    sp.add_argument("--note", default="")
    sp.set_defaults(fn=cmd_evidence)

    sp = sub.add_parser("verify")
    sp.add_argument("--project", required=True)
    sp.add_argument("--id", type=int, required=True)
    sp.set_defaults(fn=cmd_verify)

    sp = sub.add_parser("stages")
    sp.add_argument("--project", required=True)
    sp.add_argument("--enable", default="", help="逗号分隔的启用阶段列表（缺省仅查看）")
    sp.set_defaults(fn=cmd_stages)

    sp = sub.add_parser("recon")
    sp.add_argument("--project", required=True)
    sp.add_argument("--domain", required=True, help="主域名（子域枚举目标）")
    sp.add_argument("--proxy", default="",
                    help="HTTP 代理 URL；默认读 PENTDB_PROXY 环境变量，都没有则直连")
    sp.add_argument("--timeout", type=int, default=10)
    sp.add_argument("--workers", type=int, default=16)
    sp.add_argument("--limit", type=int, default=300, help="枚举子域上限")
    sp.add_argument("--single", action="store_true",
                    help="跳过子域枚举，仅探测该主机（目标方禁止子域/单应用项目时由 AI 决定使用）")
    sp.set_defaults(fn=cmd_recon)

    sp = sub.add_parser("js")
    sp.add_argument("--project", required=True)
    sp.add_argument("--proxy", default="",
                    help="HTTP 代理 URL；默认读 PENTDB_PROXY 环境变量，都没有则直连")
    sp.add_argument("--timeout", type=int, default=10)
    sp.add_argument("--limit", type=int, default=15, help="每主机最多拉取 JS 数")
    sp.set_defaults(fn=cmd_js)

    # ---- kb：经验库子命令（pentest-kb 云库，核心逻辑 kb/kb.py；凭据 env 或 kb/creds.json） ----
    sp = sub.add_parser("kb", help="经验库操作（沉淀/检索/审批，存储在用户自建云库）")
    kbsub = sp.add_subparsers(dest="kb_cmd", required=True)

    s = kbsub.add_parser("search", help="检索已审批经验（BM25 相关性）")
    s.add_argument("--keyword", required=True)
    s.add_argument("--tags", default="", help="逗号分隔的场景标签过滤")
    s.add_argument("--limit", type=int, default=5)
    s.set_defaults(kb_cmd="search")

    s = kbsub.add_parser("add", help="新增经验（一律 draft 草稿，写入前脱敏校验）")
    s.add_argument("--title", required=True)
    s.add_argument("--detail", default="", help="经验详情短文本；长文本用 --from-file")
    s.add_argument("--from-file", default="", help="从文件读详情（如 report 产出的 kb-draft.md）")
    s.add_argument("--tags", default="", help="逗号分隔的场景标签")
    s.add_argument("--tool-code", default="")
    s.add_argument("--tool-type", default="")
    s.set_defaults(kb_cmd="add")

    s = kbsub.add_parser("find-similar", help="查重：找相似的已入库经验")
    s.add_argument("--title", required=True)
    s.add_argument("--detail", default="")
    s.set_defaults(kb_cmd="find-similar")

    s = kbsub.add_parser("list", help="列出已审批经验")
    s.add_argument("--limit", type=int, default=50)
    s.add_argument("--offset", type=int, default=0)
    s.set_defaults(kb_cmd="list")

    s = kbsub.add_parser("pending", help="列出待审批草稿（附可能重复提示）")
    s.set_defaults(kb_cmd="pending")

    s = kbsub.add_parser("approve", help="审批通过草稿（人的决定，需 --confirm）")
    s.add_argument("--id", required=True)
    s.add_argument("--merge-with", default=None, help="合并进目标记录后删除草稿")
    s.add_argument("--confirm", action="store_true",
                   help="必须由用户明示同意后由 AI 加上；防止 AI 自行审批")
    s.set_defaults(kb_cmd="approve")

    s = kbsub.add_parser("reject", help="拒绝草稿（软删除）")
    s.add_argument("--id", required=True)
    s.set_defaults(kb_cmd="reject")

    s = kbsub.add_parser("delete", help="软删除已审批经验")
    s.add_argument("--id", required=True)
    s.set_defaults(kb_cmd="delete")

    s = kbsub.add_parser("restore", help="恢复软删除记录")
    s.add_argument("--id", required=True)
    s.set_defaults(kb_cmd="restore")

    s = kbsub.add_parser("deleted", help="列出软删除记录")
    s.set_defaults(kb_cmd="deleted")

    s = kbsub.add_parser("purge", help="物理删除超过 N 天的软删除记录")
    s.add_argument("--days", type=int, default=30)
    s.set_defaults(kb_cmd="purge")

    s = kbsub.add_parser("get", help="按 id 查看经验完整内容")
    s.add_argument("--id", required=True)
    s.set_defaults(kb_cmd="get")

    s = kbsub.add_parser("update", help="更新经验字段（不含 status；审批走 approve --confirm）")
    s.add_argument("--id", required=True)
    s.add_argument("--title", default=None)
    s.add_argument("--detail", default=None)
    s.add_argument("--tags", default=None, help="逗号分隔的场景标签")
    s.add_argument("--tool-code", default=None)
    s.add_argument("--tool-type", default=None)
    s.set_defaults(kb_cmd="update")

    sp.set_defaults(fn=cmd_kb)

    sp = sub.add_parser("bootstrap", help="新机器引导：建 .venv/装 kb 依赖/迁移经验库凭据")
    sp.add_argument("--skip-deps", action="store_true", help="跳过 venv/依赖")
    sp.add_argument("--kb-creds", default="",
                    help="旧 mcp.json / kb_creds.json 路径：迁移经验库凭据到 pentdb/kb/creds.json")
    sp.set_defaults(fn=cmd_bootstrap)

    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    main()
