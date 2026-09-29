#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PentDB — AI 渗透信息收集库（事实层，写库唯一入口）。

数据模型:
  raw_events  append-only 原始观测流（AI/迁移/人写入，禁止 UPDATE 内容字段）
  assets      资产实体层（纯派生表：观测按规范 akey 归并，rebuild-assets 幂等重建）
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
import re
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
ASSET_KINDS = ("domain", "port", "path", "param")         # 资产类观测：参与实体归并
VALID_ATYPES = ("domain", "host", "service", "endpoint")
STALE_DAYS = 30  # 资产生命周期：last_seen 超过 N 天视为 stale

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
  attrs      TEXT DEFAULT '{}',          -- JSON 元数据（lifecycle 等面板侧状态；不动观测正文）
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  project    TEXT NOT NULL,
  event_id   INTEGER NOT NULL,
  path       TEXT NOT NULL,
  sha256     TEXT DEFAULT '',
  note       TEXT DEFAULT '',
  etype      TEXT DEFAULT '',              -- 证据类型：request/response/file（面板按类型渲染报文）
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
  at         TEXT NOT NULL,
  confirmed  INTEGER DEFAULT 0                     -- 0=起草（AI 可起草不得自批）1=人工确认生效
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

-- 资产实体层（纯派生表：由 raw_events 的资产类观测归并而来，rebuild-assets 幂等重建）
CREATE TABLE IF NOT EXISTS assets (
  project     TEXT NOT NULL,
  atype       TEXT NOT NULL,             -- domain / host / service / endpoint
  akey        TEXT NOT NULL,             -- 规范身份 key（归并去重的唯一依据）
  display     TEXT DEFAULT '',
  parent_atype TEXT DEFAULT '',          -- 统一父引用（替代 parent_ext 的 id/value 混用）
  parent_akey TEXT DEFAULT '',
  attrs       TEXT DEFAULT '{}',         -- JSON：端口/技术栈/服务/参数/状态码等聚合属性
  event_ids   TEXT DEFAULT '[]',         -- JSON：支撑本实体的观测 id（溯源/人审聚合）
  first_seen  TEXT DEFAULT '',
  last_seen   TEXT DEFAULT '',
  PRIMARY KEY (project, atype, akey)
);
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
    try:
        c.execute("ALTER TABLE raw_events ADD COLUMN updated_at TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE raw_events ADD COLUMN attrs TEXT DEFAULT '{}'")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE evidence ADD COLUMN etype TEXT DEFAULT ''")
        # 仅在首次加列时做存量回填（request/response/file），随即 commit 释放写锁
        c.execute("UPDATE evidence SET etype='request' WHERE note LIKE 'request%'")
        c.execute("UPDATE evidence SET etype='response' WHERE note LIKE 'response%'")
        c.execute("UPDATE evidence SET etype='file' WHERE etype IS NULL OR etype=''")
        c.commit()
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE waives ADD COLUMN confirmed INTEGER DEFAULT 0")
        # 仅首次加列时回填存量=已确认（祖传豁免不追溯，存量复核另行走 waive --wid N --confirm），随即 commit 释放写锁
        c.execute("UPDATE waives SET confirmed=1")
        c.commit()
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
    if getattr(a, "detail_file", ""):
        with open(a.detail_file, encoding="utf-8") as f:
            a.detail = f.read()
    req_val = getattr(a, "req", "") or ""
    resp_val = getattr(a, "resp", "") or ""
    req_text = sys.stdin.read() if req_val == "-" else None
    resp_text = sys.stdin.read() if resp_val == "-" else None
    if req_val and req_val != "-" and not os.path.exists(req_val):
        sys.exit(f"[x] --req 文件不存在: {req_val}")
    if resp_val and resp_val != "-" and not os.path.exists(resp_val):
        sys.exit(f"[x] --resp 文件不存在: {resp_val}")
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
    # test 是过程记录不是空壳：必须带 title/detail/note 至少一项，否则待审页全是空白噪音
    if a.kind == "test" and not ((a.title or "").strip() or (a.detail or "").strip() or (a.note or "").strip()):
        sys.exit("[x] test 事件必须带 --title 或 --detail 或 --note（过程描述），"
                 "纯脚本执行痕迹请勿入库——待审页只收可读记录")
    c = connect()
    require_project(c, a.project)
    # test 幂等：同 project+source+title+detail 指纹相同视为重复执行（如脚本双跑），拒绝入库
    if a.kind == "test":
        dup_t = c.execute(
            "SELECT id FROM raw_events WHERE project=? AND kind='test' AND source=? "
            "AND title=? AND detail=? ORDER BY id LIMIT 1",
            (a.project, a.source, a.title or "", a.detail or "")).fetchone()
        if dup_t:
            sys.exit(f"[x] 重复 test 事件：与 #{dup_t['id']} 来源与内容完全相同（脚本重复执行？），拒绝入库")
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
            if a.detail is not None and a.detail != (dup["detail"] or ""):
                changes.append("detail 复测物料增补")
            if str(a.code or "") != (dup["code"] or ""):
                changes.append(f"code {dup['code']} -> {a.code}")
            if (a.tech or "") != (dup["tech"] or ""):
                changes.append(f"tech {dup['tech']} -> {a.tech}")
            if (a.service or "") != (dup["service"] or ""):
                changes.append(f"service {dup['service']} -> {a.service}")
            if (a.title or "") and a.title != (dup["title"] or ""):
                changes.append(f"title {dup['title']!r} -> {a.title!r}")
            c.execute("UPDATE raw_events SET note=?, detail=?, code=?, tech=?, service=?, title=?, source=?, "
                      "verified_at=?, updated_at=? WHERE id=?",
                      (a.note or "", a.detail if a.detail is not None else dup["detail"],
                       str(a.code or ""), a.tech or "", a.service or "",
                       a.title if (a.title or "") else (dup["title"] or ""),
                       a.source, now(), now(), dup["id"]))
            summary = "; ".join(changes) if changes else "观测未变，仅刷新验证时间与来源"
            log_change(c, a.project, "rescan-update", f"#{dup['id']} {a.kind}:{a.value[:50]} | {summary}")
            c.commit()
            if a.kind in ASSET_KINDS:
                rebuild_assets(c, a.project)
                c.commit()
            print(f"[ok] 重扫更新 #{dup['id']} ({a.kind}: {a.value[:50]}) ｜ {summary}")
            return
    # 写入口硬门禁：判定漏洞必须带真实报文（此前只在 lint 事后报 error，AI 不跑 lint 即绕过——收口到写入即拒绝）
    if a.kind == "finding" and (not req_val or not resp_val):
        if not (getattr(a, "waive_capture", "") or "").strip():
            sys.exit("[x] 判定漏洞必须带真实报文：--req <文件|-> --resp <文件|->（写入口强制）；"
                     "初测报文确实已丢的，加 --waive-capture '原因' 起草豁免——"
                     "豁免待人工确认生效，确认前 lint 仍报 error，AI 不得代批")
    merge_key = a.merge_key or (a.value if a.kind == "domain" else "")
    verified = now() if status == "confirmed" else ""
    ts = now()
    cur = c.execute(
        "INSERT INTO raw_events(project,ext_id,kind,value,title,detail,note,parent_ext,"
        "merge_key,status,confidence,severity,code,tech,service,scope,verified_at,source,origin,stage,created_at,updated_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (a.project, a.ext_id, a.kind, a.value, a.title or "", a.detail or "",
         a.note or "", a.parent_ext or "", merge_key, status, a.confidence or "",
         a.severity or "", str(a.code or ""), a.tech or "", a.service or "",
         a.scope, verified, a.source, a.origin, a.stage or "", ts, ts))
    log_change(c, a.project, "add", f"#{cur.lastrowid} {a.kind}:{a.value[:60]}")
    c.commit()
    if a.kind == "finding" and (req_val or resp_val):
        ev_ids = []
        if req_val:
            ev_ids.append(attach_evidence(c, a.project, cur.lastrowid,
                                          path="" if req_text is not None else req_val,
                                          text=req_text, note="request"))
        if resp_val:
            ev_ids.append(attach_evidence(c, a.project, cur.lastrowid,
                                          path="" if resp_text is not None else resp_val,
                                          text=resp_text, note="response"))
        c.commit()
        print(f"[ok] 请求/响应证据已挂 #{cur.lastrowid}（evidence {'/'.join(map(str, ev_ids))}）")
    if a.kind == "finding" and (getattr(a, "waive_capture", "") or "").strip():
        reason = a.waive_capture.strip()
        wcur = c.execute("INSERT INTO waives(project,event_id,term,reason,at,confirmed) VALUES(?,?,?,?,?,0)",
                         (a.project, cur.lastrowid, "无抓包待补", reason, now()))
        log_change(c, a.project, "waive",
                   f"wid={wcur.lastrowid} #{cur.lastrowid} 无抓包待补（起草，待人工确认）: {reason}")
        c.commit()
        print(f"[!] 无报文建档：豁免 wid={wcur.lastrowid} 已起草——待人工确认后生效："
              f"waive --project {a.project} --wid {wcur.lastrowid} --confirm（确认前 lint 仍报 error）")
    if a.kind in ASSET_KINDS:
        rebuild_assets(c, a.project)
        c.commit()
    print(f"[ok] 事件 #{cur.lastrowid} 已入库 ({a.kind}: {a.value[:60]}) status={status}")


# ---------------- 资产实体层（观测流之上的归并层：成熟 ASM 通用三层之一） ----------------
# raw_events = append-only 观测流（保持不动）；assets = 按 akey 归并的稳定实体（纯派生，可随时重建）。
# 归并规则：
#   domain   akey=小写 FQDN 去尾点              parent=注册域
#   host     akey=ip/主机名（从 port 观测提取）  parent=无
#   service  akey=host:port                     parent=host
#   endpoint akey=host+path（param 并入 attrs.params，不再单独成行） parent=host

def _norm_domain(value):
    """规范化域名 -> (akey, 注册域)；非法输入返回 (None, None)。"""
    d = (value or "").strip().lower().rstrip(".")
    if not d or " " in d or "/" in d:
        return None, None
    labels = d.split(".")
    if len(labels) < 2 or not all(labels):
        return None, None
    base = ".".join(labels[-2:])
    if len(labels) >= 3 and len(labels[-2]) <= 3:  # co.uk / com.cn 类二级后缀
        base = ".".join(labels[-3:])
    return d, base


def _split_hostport(value):
    """'ip:port' -> (host, port)；无端口/非法端口整体视作 host。"""
    v = (value or "").strip().lower()
    if ":" not in v:
        return v, ""
    host, _, port = v.rpartition(":")
    if not host or not port.isdigit():
        return v, ""
    return host, port


def _resolve_host(parent_ext, by_id, path_host, seen=None):
    """把观测的 parent_ext 统一解析成主机 akey（终结 id/value/path 三种历史语义混用）。"""
    pe = (parent_ext or "").strip()
    if not pe:
        return ""
    seen = seen if seen is not None else set()
    for p in [x.strip() for x in pe.split(",") if x.strip()]:
        if p.isdigit():  # 旧数据：引用事件 id
            r = by_id.get(int(p))
            if not r:
                continue
            if r["kind"] == "port":
                return _split_hostport(r["value"])[0]
            return (r["value"] or "").strip().lower()
        if p.startswith("/"):  # 旧数据：引用 path 值（param -> path -> host 两跳）
            if p in seen:
                continue
            seen.add(p)
            pid = path_host.get(p)
            if pid is not None:
                r = by_id.get(pid)
                if r:
                    return _resolve_host(r["parent_ext"], by_id, path_host, seen)
            continue
        if "/" in p:  # 'host/path' 混合写法：取 host 段
            return p.split("/", 1)[0]
        return p.lower()  # 直接就是 host
    return ""


def rebuild_assets(c, project):
    """从资产类观测全量重建 assets 实体层。幂等、只派生、不触碰 raw_events。返回分类型计数。"""
    rows = [dict(r) for r in c.execute(
        "SELECT * FROM raw_events WHERE project=? AND kind IN (%s) ORDER BY id"
        % ",".join("?" * len(ASSET_KINDS)), (project,) + ASSET_KINDS)]
    by_id = {r["id"]: r for r in rows}
    path_host = {}
    for r in rows:
        if r["kind"] == "path" and r["value"] not in path_host:
            path_host[r["value"]] = r["id"]

    ent = {}

    def put(atype, akey, display, patype, pkey, ev):
        e = ent.setdefault((atype, akey), {
            "atype": atype, "akey": akey, "display": "",
            "parent_atype": "", "parent_akey": "",
            "attrs": {}, "event_ids": [],
            "first": ev["created_at"], "last": ev["updated_at"] or ev["created_at"]})
        if display and (not e["display"] or len(display) < len(e["display"])):
            e["display"] = display
        if patype and not e["parent_atype"]:
            e["parent_atype"], e["parent_akey"] = patype, pkey
        e["event_ids"].append(ev["id"])
        e["first"] = min(e["first"], ev["created_at"])
        e["last"] = max(e["last"], ev["updated_at"] or ev["created_at"])
        mul(e, "scopes", ev["scope"])
        return e

    def mul(e, key, val):
        val = str(val or "").strip()
        if val and val not in e["attrs"].setdefault(key, []):
            e["attrs"][key].append(val)

    for r in rows:
        val = (r["value"] or "").strip()
        if r["kind"] == "domain":
            akey, base = _norm_domain(val)
            if not akey:
                continue
            labels = akey.split(".")
            if len(labels) == 4 and all(x.isdigit() for x in labels):  # IP 误录为 domain：按主机归并
                e = put("host", akey, akey, "", "", r)
                mul(e, "techs", r["tech"]); mul(e, "codes", r["code"]); mul(e, "titles", r["title"])
                continue
            e = put("domain", akey, akey, "domain", base, r)
            mul(e, "techs", r["tech"]); mul(e, "codes", r["code"]); mul(e, "titles", r["title"])
        elif r["kind"] == "port":
            host, port = _split_hostport(val)
            if not host:
                continue
            he = put("host", host, host, "", "", r)
            if port:
                mul(he, "ports", port)
                se = put("service", f"{host}:{port}", f"{host}:{port}", "host", host, r)
                mul(se, "services", r["service"]); mul(se, "techs", r["tech"]); mul(se, "codes", r["code"])
            else:
                mul(he, "techs", r["tech"]); mul(he, "codes", r["code"])
        elif r["kind"] == "path":
            host = _resolve_host(r["parent_ext"], by_id, path_host)
            p = val if val.startswith("/") else "/" + val
            akey = (host + p) if host else ("?" + p)
            e = put("endpoint", akey, akey, "host", host, r)
            mul(e, "codes", r["code"]); mul(e, "titles", r["title"])
        elif r["kind"] == "param":
            host = _resolve_host(r["parent_ext"], by_id, path_host)
            # param 归属于它所属的 endpoint：从 parent_ext 提取全部路径段，逐一并入
            paths = re.findall(r"/[^\s,]*", r["parent_ext"] or "")
            paths = [p for p in paths if len(p) > 1] or [""]
            for p in paths:
                akey = ((host + p) if host else ("?" + p)) if p else ("?" + val)
                e = put("endpoint", akey, akey, "host", host, r)
                mul(e, "params", val); mul(e, "codes", r["code"]); mul(e, "titles", r["title"])

    c.execute("DELETE FROM assets WHERE project=?", (project,))
    for (atype, akey), e in ent.items():
        c.execute(
            "INSERT INTO assets(project,atype,akey,display,parent_atype,parent_akey,"
            "attrs,event_ids,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (project, atype, akey, e["display"], e["parent_atype"], e["parent_akey"],
             json.dumps(e["attrs"], ensure_ascii=False), json.dumps(e["event_ids"]),
             e["first"], e["last"]))
    counts = {}
    for (atype, _), _e in ent.items():
        counts[atype] = counts.get(atype, 0) + 1
    return counts


def asset_review_state(statuses):
    """实体级人审聚合：任一待审=pending；否则任一 confirmed=confirmed；全驳回=rejected。"""
    s = set(statuses)
    if not s:
        return "pending"
    if "new" in s:
        return "pending"
    return "confirmed" if "confirmed" in s else "rejected"


def asset_is_stale(last_seen, days=STALE_DAYS):
    """生命周期：last_seen 距今超过 N 天视为 stale（域名下线/资产过期不再永远 confirmed）。"""
    s = (last_seen or "")[:19]
    if not s:
        return True
    try:
        last = datetime.datetime.fromisoformat(s)
        if last.tzinfo is None:
            last = last.astimezone()
        return (datetime.datetime.now().astimezone() - last).days >= days
    except ValueError:
        return True


def cmd_rebuild_assets(a):
    c = connect()
    require_project(c, a.project)
    counts = rebuild_assets(c, a.project)
    log_change(c, a.project, "rebuild-assets",
               " | ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "0")
    c.commit()
    total = sum(counts.values())
    detail = " ｜ ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "空"
    print(f"[ok] 实体层已重建: {a.project} ｜ {detail} ｜ 共 {total}")


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
    # test 事件缺 parent_ext 无补录通道（test 是事件流，--update 不适用），
    # 允许用 waive(event_id=该事件, term 含 parent_ext) 留痕豁免；豁免清单收尾提交用户裁决。
    wrows = c.execute("SELECT id,event_id,term,confirmed FROM waives WHERE project=?",
                      (project,)).fetchall()
    # 豁免只有"已确认"（confirmed=1）才生效——AI 可起草豁免但不得自批（对齐 kb approve 的人审门）
    waived_pe = {w["event_id"] for w in wrows
                 if "parent_ext" in (w["term"] or "") and w["confirmed"]}
    waived_capture = {w["event_id"] for w in wrows
                      if "抓包" in (w["term"] or "") and w["confirmed"]}
    draft_waives = [w for w in wrows if not w["confirmed"]]
    ev_req = {r[0] for r in c.execute(
        "SELECT event_id FROM evidence WHERE project=? AND note LIKE 'request%'", (project,))}
    ev_resp = {r[0] for r in c.execute(
        "SELECT event_id FROM evidence WHERE project=? AND note LIKE 'response%'", (project,))}
    # 对账①：evidence 登记的文件在磁盘上丢了 = 证据链断裂（report/kb 沉淀会引用不到）
    for er in c.execute("SELECT id, path FROM evidence WHERE project=?", (project,)):
        if (er["path"] or "") and not os.path.exists(er["path"]):
            errors.append(f"证据 #{er['id']} 文件丢失: {er['path']}（证据链断裂，复测时重建或补挂）")
    # 对账②：test 执行了但零证据输出（跑过没留痕，测了没记的变体；exec 产出天然豁免）
    ev_any = {r[0] for r in c.execute(
        "SELECT DISTINCT event_id FROM evidence WHERE project=? AND event_id != 0", (project,))}
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
        if (r["kind"] == "test" and not (r["parent_ext"] or "").strip()
                and rid not in waived_pe):
            errors.append(f"#{rid} test 事件缺 parent_ext（测试必须归因到被测记录，多对象用逗号分隔）")
        if (r["kind"] == "test" and not ((r["title"] or "").strip()
                or (r["detail"] or "").strip() or (r["note"] or "").strip())):
            errors.append(f"#{rid} test 事件 title/detail/note 全空（空壳待审噪音）")
        if r["kind"] == "test" and rid not in ev_any:
            warns.append(f"#{rid} test 无任何证据输出（跑过但零留痕——探测/测试命令建议走 exec 单通道，"
                         f"输出自动随库；手工落库的补 evidence）")
        if r["kind"] == "test" and (r["note"] or "").strip() \
                and not (r["note"] or "").strip().startswith(TEST_CONCLUSIONS):
            warns.append(f"#{rid} test 结论未以机读词开头（{'/'.join(TEST_CONCLUSIONS)}）"
                         f"——复测时间轴聚合与 lifecycle 同步依赖它")
        if (r["kind"] in ("finding", "osint", "suggestion")
                and not (r["title"] or "").strip()):
            errors.append(f"#{rid} {r['kind']} 缺 title（待审页无标题不可读）")
        if r["kind"] == "finding" and (r["detail"] or "") and "【" not in r["detail"]:
            warns.append(f"#{rid} finding detail 无【节】结构（建议按【描述】/【复测结论】/【修复建议】分节落库）")
        if r["kind"] == "finding" and (r["detail"] or "") and "【请求】" not in r["detail"] \
                and "【payload】" not in r["detail"]:
            warns.append(f"#{rid} finding 缺【请求】/【payload】段（测试用例建议分节落库；"
                         f"注意【请求】是用例不是事实，事实报文=evidence 的 request/response 对）")
        if r["kind"] == "finding" and rid not in waived_capture \
                and (rid not in ev_req or rid not in ev_resp):
            errors.append(f"#{rid} 漏洞缺请求/响应证据（写入口已强制：add --kind finding "
                          f"--req <文件|-> --resp <文件|->；初测报文已丢的走 --waive-capture 起草豁免，"
                          f"人工 waive --wid N --confirm 确认后生效）")
        if r["kind"] == "finding" and not (r["parent_ext"] or "").strip():
            warns.append(f"#{rid} finding 缺 parent_ext（应归因到被测资产 record id，目标上下文断裂）")
    if draft_waives:
        warns.append("待人工确认的豁免 " + "、".join(
            f"wid={w['id']}(#{w['event_id']} {w['term']})" for w in draft_waives)
            + " ——起草态不生效，人工确认：waive --wid N --confirm")
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
                    "parent_ext,merge_key,status,confidence,source,origin,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (a.project, o.get("id"), kind, value, o.get("title", ""),
                     o.get("detail", ""), o.get("note", ""), o.get("parent", ""),
                     value if kind == "domain" else "", status, "", src,
                     "migrate", o.get("time") or now(), o.get("time") or now()))
                n += 1
        log_change(c, a.project, "migrate", f"{fn}: {n} 条")
        print(f"[ok] {fn} -> {kind}: {n} 条")
        total += n
    c.commit()
    print(f"-- 迁移完成，共 {total} 条")


FINDING_MARKS = ("【描述】", "【请求】", "【payload】", "【判据】", "【原因】", "【手工验证】", "【修复】")


def _parse_finding_detail(detail):
    out = {"描述": [], "请求": [], "payload": [], "判据": [], "原因": [], "手工验证": [], "修复": []}
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
                f"**描述**: {sec['描述'] or r['value']}", ""]
        if sec["请求"] or sec["payload"]:  # 复现包：可直接复制重放
            out += ["**复现包**:", "", "```",
                    (sec["请求"] or "") + (("\n\npayload: " + sec["payload"]) if sec["payload"] else ""),
                    "```", ""]
        out += [f"**原因分析**: {sec['原因'] or '（待补充：漏洞产生的根因）'}", "",
                "**手工验证步骤**:"]
        if sec["手工验证"]:
            out.append(sec["手工验证"])
        else:
            out.append(VERIFY_FRAME)
        if sec["判据"]:
            out += ["", f"**复现判据**: {sec['判据']}"]
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
    c = connect()
    require_project(c, a.project)
    # 报告出口门禁：lint 有 error 拒绝出报告（防"收尾忘了跑 lint"绕过；--force 仅限人工解除）
    rep = lint_report(c, a.project)
    if rep["errors"] and not getattr(a, "force", False):
        for e in rep["errors"]:
            print(f"ERROR {e}")
        sys.exit(f"[x] 报告出口门禁：lint {len(rep['errors'])} error——先修复或经人工确认豁免；"
                 f"确需带错出报告用 --force（人的决定，AI 不得使用）")
    if getattr(a, "template", "") == "pentest":
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


# ---------------- SOP 提示清单（给 AI 的查漏补缺提示层，非门禁） ----------------

STATE_ICON = {"done": "✓ 已测", "registered": "◐ 已登记", "missing": "○ 未测(提示)"}


def load_sop_cfg():
    with open(SOP_CFG, encoding="utf-8") as f:
        return json.load(f)


def _term_in(term, text):
    return any(alt.lower() in (text or "").lower() for alt in term.split("|"))


def _hints_menu(cfg):
    """stage_hints -> 每阶段提示菜单（术语去重保序）。返回 {stage: [{"term","when"}]}"""
    menu = {}
    for stage, hints in cfg.get("stage_hints", {}).items():
        items, seen = [], set()
        for h in hints:
            for term in h.get("check", []):
                if term not in seen:
                    seen.add(term)
                    items.append({"term": term, "when": h.get("when", "")})
        menu[stage] = items
    return menu


def sop_report(c, project):
    cfg = load_sop_cfg()
    stages_all = cfg.get("stages", [])
    stages = list(stages_all)
    menu_map = _hints_menu(cfg)

    tests = [dict(r) for r in c.execute(
        "SELECT * FROM raw_events WHERE project=? AND kind='test'", (project,))]
    test_texts = {t["id"]: (t["value"] or "") + " " + (t["note"] or "") + " " + (t["source"] or "")
                  for t in tests}
    pend_rows = [dict(p) for p in c.execute("SELECT * FROM pending_tests WHERE project=?", (project,))]
    pend_terms = [p["term"] for p in pend_rows]

    # 术语 -> 阶段映射（供旧数据 stage 回填）
    term_stage = {}
    for stage, items in menu_map.items():
        for it in items:
            term_stage.setdefault(it["term"], stage)

    def _stage_for_term(term):
        if term in term_stage:
            return term_stage[term]
        for mt, s2 in term_stage.items():
            if _term_in(mt, term) or _term_in(term, mt):
                return s2
        return ""

    # 幂等回填：旧数据（pending_tests / test 事件）缺 stage 的按术语反查补上
    dirty = 0
    for p in pend_rows:
        if not (p["stage"] or "").strip():
            st = _stage_for_term(p["term"])
            if st:
                c.execute("UPDATE pending_tests SET stage=? WHERE id=?", (st, p["id"]))
                dirty += 1
    for t in tests:
        if not (t["stage"] or "").strip():
            st = _stage_for_term(test_texts[t["id"]])
            if st:
                c.execute("UPDATE raw_events SET stage=? WHERE id=?", (st, t["id"]))
                t["stage"] = st
                dirty += 1
    if dirty:
        log_change(c, project, "stage-backfill", f"术语反查回填 stage {dirty} 条")
        c.commit()

    # 阶段视图：提示菜单（when 触发语义 + check 术语）× 执行（该阶段 test 流水）
    # 状态匹配仅作参考展示（供 AI 自查），不构成门禁——覆盖度由 AI 显式申报、人背书
    stage_view = []
    total = done = registered = missing = 0
    for s in stages:
        items, executed_ids = [], set()
        for it in menu_map.get(s, []):
            term = it["term"]
            hit_test = next((t for t in tests if _term_in(term, test_texts[t["id"]])), None)
            if hit_test:
                items.append({"term": term, "when": it["when"], "state": "done", "ev": "#" + str(hit_test["id"])})
                executed_ids.add(hit_test["id"])
            elif any(_term_in(term, p) for p in pend_terms):
                items.append({"term": term, "when": it["when"], "state": "registered", "ev": "pending"})
            else:
                items.append({"term": term, "when": it["when"], "state": "missing", "ev": None})
            st = items[-1]["state"]
            total += 1
            if st == "done":
                done += 1
            elif st == "registered":
                registered += 1
            else:
                missing += 1
        executed = [t for t in tests if (t["stage"] or "") == s]
        executed += [t for t in tests if not (t["stage"] or "").strip()
                     and t["id"] in executed_ids and t not in executed]
        sdone = sum(1 for i in items if i["state"] == "done")
        sreg = sum(1 for i in items if i["state"] == "registered")
        stage_view.append({
            "stage": s, "menu": items, "done": sdone,
            "total": len(items),
            "complete": bool(items) and sdone == len(items),
            "executed": [{"id": t["id"], "value": t["value"], "note": t["note"], "status": t["status"],
                          "parent_ext": t["parent_ext"], "source": t["source"],
                          "created_at": t["created_at"]} for t in executed],
            "pending": [{"term": p["term"], "at": p["created_at"]}
                        for p in pend_rows if (p["stage"] or "") == s],
        })

    # 当前阶段判定：菜单全部已测视为走完（仅展示参考，不拦截任何动作）
    flags = [v["complete"] for v in stage_view if v["menu"]]
    cur = len(stages)
    for i, ok in enumerate(flags):
        if not ok:
            cur = i
            break
    stage = {"current": stages[cur] if cur < len(stages) else "(全部完成)",
             "index": cur, "total": len(stages), "flags": dict(zip(stages, flags))}
    return {"stage": stage, "stages_all": stages_all,
            "stage_view": stage_view, "total": total, "done": done,
            "registered": registered, "missing": missing}

def cmd_sop(a):
    c = connect()
    require_project(c, a.project)
    rep = sop_report(c, a.project)
    print("== SOP hints: %s ==" % a.project)
    print("当前阶段: %s (%d/%d)" % (rep["stage"]["current"], rep["stage"]["index"], rep["stage"]["total"]))
    cov = rep["done"] * 100 // rep["total"] if rep["total"] else 100
    print("参考覆盖: 提示项 %d | 已测 %d | 已登记 %d | 未测 %d | 参考完成率 %d%%"
          % (rep["total"], rep["done"], rep["registered"], rep["missing"], cov))
    print("-- 按语义判断 when 是否命中当前目标面，命中才对照 check 查漏；未命中/不适用可跳过（提示层，非门禁）--")
    for v in rep["stage_view"]:
        mark = "✓" if v["complete"] else " "
        print("%s %-6s 参考 %d/%d  执行流水 %d 条" % (mark, v["stage"], v["done"],
                                                    v["total"], len(v["executed"])))
        for it in v["menu"]:
            ctx = "（%s）" % it["when"] if it["state"] == "missing" and it["when"] else ""
            tail = "" if it["state"] == "done" else "  ← 命中则补测，未命中/不适用跳过并在收尾申报"
            print("      %-12s %-14s %s%s" % (STATE_ICON[it["state"]], it["term"], ctx, tail))


def cmd_waive(a):
    c = connect()
    require_project(c, a.project)
    confirm = getattr(a, "confirm", False)
    wid = getattr(a, "wid", 0) or 0
    if confirm:
        # 确认生效是人的决定（对齐 kb approve --confirm 模式），AI 只能起草
        if not wid:
            sys.exit("[x] 确认豁免必须指定 --wid <豁免记录id>（waive 起草时输出）——豁免生效是人的决定，AI 只能起草")
        row = c.execute("SELECT * FROM waives WHERE id=? AND project=?", (wid, a.project)).fetchone()
        if not row:
            sys.exit(f"[x] 豁免记录不存在: wid={wid}")
        if row["confirmed"]:
            print(f"[ok] wid={wid} 已是确认态，无需重复确认")
            return
        c.execute("UPDATE waives SET confirmed=1 WHERE id=?", (wid,))
        log_change(c, a.project, "waive-confirm",
                   f"wid={wid} #{row['event_id']} {row['term']}: {row['reason']}")
        c.commit()
        print(f"[ok] wid={wid} 豁免已确认生效（#{row['event_id']} {row['term']}）")
        return
    if not a.reason:
        sys.exit("[x] 豁免必须写明 --reason；豁免为起草态，需人工 waive --wid N --confirm 确认后才生效")
    if not (a.term or "").strip():
        sys.exit("[x] 起草豁免必须写明 --term（豁免条目，如 无抓包待补 / test事件缺parent_ext）")
    if a.id is None:
        sys.exit("[x] 起草豁免必须指定 --id <事件id>（报文豁免挂 finding、归因豁免挂 test，豁免只作用于具体事件）；"
                 "确认已有豁免用 --wid N --confirm")
    row = c.execute("SELECT id FROM raw_events WHERE id=? AND project=?", (a.id, a.project)).fetchone()
    if not row:
        sys.exit(f"[x] 记录不存在: #{a.id}（豁免只作用于具体事件；SOP 提示项非义务，无需豁免）")
    wcur = c.execute("INSERT INTO waives(project,event_id,term,reason,at,confirmed) VALUES(?,?,?,?,?,0)",
                     (a.project, a.id, a.term, a.reason, now()))
    log_change(c, a.project, "waive",
               f"wid={wcur.lastrowid} #{a.id} {a.term}: {a.reason}（起草，待人工确认）")
    c.commit()
    print(f"[ok] wid={wcur.lastrowid} 豁免已起草（#{a.id} {a.term}）——待人工确认后生效："
          f"waive --project {a.project} --wid {wcur.lastrowid} --confirm")


def attach_evidence(c, project, event_id, path="", text=None, note="", keep_in_place=False):
    """证据落库核心（CLI/面板/add --req 共用）。event_id=0 表示项目级物料。
    默认把文件复制进 <db目录>/evidence/<project>/（随库走）；--text 直存文本；keep_in_place 只存指针。
    返回 evidence id。"""
    import hashlib
    import shutil

    ev_dir = os.path.join(os.path.dirname(DB_PATH), "evidence", project)
    if text is not None:
        os.makedirs(ev_dir, exist_ok=True)
        import uuid
        fname = "ev_%s_%s_%s.txt" % (event_id, now().replace(":", "").replace("+", "p"),
                                     uuid.uuid4().hex[:6])  # 秒级时间戳会撞车，加随机尾防覆盖
        stored = os.path.join(ev_dir, fname)
        with open(stored, "w", encoding="utf-8") as f:
            f.write(text)
        src_desc = "text"
    else:
        if not path or not os.path.exists(path):
            sys.exit(f"[x] 证据文件不存在: {path}")
        if keep_in_place:
            stored = path
        else:
            os.makedirs(ev_dir, exist_ok=True)
            base = os.path.basename(path)
            stored = os.path.join(ev_dir, base)
            if os.path.abspath(stored) != os.path.abspath(path):
                n = 1
                while os.path.exists(stored):
                    root, ext = os.path.splitext(base)
                    stored = os.path.join(ev_dir, f"{root}_{n}{ext}")
                    n += 1
                shutil.copy2(path, stored)
        src_desc = path
    h = hashlib.sha256()
    with open(stored, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    if event_id != 0:
        row = c.execute("SELECT id FROM raw_events WHERE id=? AND project=?",
                        (event_id, project)).fetchone()
        if not row:
            sys.exit(f"[x] 记录不存在: #{event_id}")
    cur = c.execute("INSERT INTO evidence(project,event_id,path,sha256,note,etype,created_at) VALUES(?,?,?,?,?,?,?)",
                    (project, event_id, stored, h.hexdigest(), note or "",
                     "request" if (note or "").startswith("request")
                     else "response" if (note or "").startswith("response") else "file",
                     now()))
    log_change(c, project, "evidence",
               (f"#{event_id}" if event_id else "项目级") + f" ← {os.path.basename(stored)}")
    return cur.lastrowid


def cmd_evidence(a):
    """证据入库：event_id=0 表示项目级物料（凭据表/报告等，不属于单个漏洞）。
    默认把文件复制进套件 evidence/（随库走）；--keep-in-place 只存指针；
    --text 直接把文本内容存为证据文件（复测的请求/响应原文零摩擦落库）。"""
    c = connect()
    require_project(c, a.project)
    eid = attach_evidence(c, a.project, a.event_id, path=a.path, text=a.text,
                          note=a.note, keep_in_place=a.keep_in_place)
    c.commit()
    tag = "引用" if a.keep_in_place else ("文本" if a.text is not None else "复制")
    target = f"#{a.event_id}" if a.event_id else "项目级"
    print(f"[ok] 证据 #{eid} 已挂到 {target}（{tag}）")


def cmd_evidence_move(a):
    """改挂证据归属：--event-id 0 = 转项目级物料。归属判定=复测该漏洞时必须用到。"""
    c = connect()
    require_project(c, a.project)
    row = c.execute("SELECT id, event_id FROM evidence WHERE id=? AND project=?",
                    (a.id, a.project)).fetchone()
    if not row:
        sys.exit(f"[x] 证据不存在: #{a.id}")
    if a.event_id != 0:
        r = c.execute("SELECT id FROM raw_events WHERE id=? AND project=?",
                      (a.event_id, a.project)).fetchone()
        if not r:
            sys.exit(f"[x] 目标记录不存在: #{a.event_id}")
    c.execute("UPDATE evidence SET event_id=? WHERE id=?", (a.event_id, a.id))
    log_change(c, a.project, "evidence-move",
               f"证据 #{a.id}: #{row['event_id']} -> {'项目级' if a.event_id == 0 else '#' + str(a.event_id)}")
    c.commit()
    print(f"[ok] 证据 #{a.id} 已改挂到 {'项目级' if a.event_id == 0 else '#' + str(a.event_id)}")


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


def cmd_exec(a):
    """执行落库单通道（recon 模式的推广）：AI 的探测/测试命令一律经本命令执行——
    输出强制落盘 + test 事件自动入库 + 原始输出自动挂证据，杜绝"测了没记"。
    用法：pentdb.py exec --project P --parent-ext N -- <命令...>（-- 后接实际命令，非交互）"""
    import subprocess
    import uuid
    if not (a.parent_ext or "").strip():
        sys.exit("[x] --parent-ext 必填：测试必须归因到被测对象 record id（多对象逗号分隔）")
    cmd_str = (a.cmd or "").strip()
    if not cmd_str:
        sys.exit("[x] 缺 --cmd：exec --project P --parent-ext N --cmd '<完整命令>'（命令串原样执行）")
    c = connect()
    require_project(c, a.project)
    t0 = datetime.datetime.now()
    timed_out = False
    try:
        cp = subprocess.run(cmd_str, shell=True, capture_output=True, timeout=a.timeout)
        raw = (cp.stdout or b"") + (cp.stderr or b"")
        code = cp.returncode
    except subprocess.TimeoutExpired as e:
        raw = (e.stdout or b"") + (e.stderr or b"")
        code = -1
        timed_out = True
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("gbk", "ignore")
    exec_dir = os.path.join(os.path.dirname(DB_PATH), "exec", a.project)
    os.makedirs(exec_dir, exist_ok=True)
    slug = re.sub(r"[^A-Za-z0-9_\-]+", "-", (a.action or cmd_str))[:40].strip("-") or "exec"
    fname = "%s-%s-%s.log" % (t0.strftime("%H%M%S"), slug, uuid.uuid4().hex[:6])
    out_path = os.path.join(exec_dir, fname)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("$ %s\nexit=%s\n\n%s" % (cmd_str, code, text))
    note = (a.note or "").strip()
    if timed_out:
        note = ("命令超时(%ss)被终止；" % a.timeout) + note
    detail = (a.detail + "\n" if a.detail else "") + \
        "exit=%s ｜ 原始输出 %d 字节已随库（证据链 output 文件）" % (code, len(raw))
    ns = argparse.Namespace(
        project=a.project, ext_id="", kind="test",
        value=(a.action or cmd_str)[:80],
        title=a.title or ("exec: " + cmd_str[:57] + ("…" if len(cmd_str) > 57 else "")),
        detail=detail, note=note, source=cmd_str,
        parent_ext=a.parent_ext, merge_key="", status="confirmed",
        confidence=a.confidence, severity=a.severity, code="", tech="", service="",
        scope="in", auto=True, update=False, origin="agent", stage=a.stage or "")
    try:
        cmd_add(ns)
    except SystemExit as e:
        sys.exit(f"[x] exec 落库被拒: {e}")
    row = c.execute("SELECT id FROM raw_events WHERE project=? AND kind='test' "
                    "ORDER BY id DESC LIMIT 1", (a.project,)).fetchone()
    eid = row["id"] if row else 0
    ev_id = attach_evidence(c, a.project, eid, path=out_path, note="output " + slug)
    c.commit()
    print(f"[exec] #{eid} exit={code} ｜ 输出已挂证据 #{ev_id} ｜ {out_path}")
    shown = text[:6000]
    if len(text) > 6000:
        shown += "\n…（截断，完整输出见上面证据文件）"
    try:
        sys.stdout.write(shown + "\n")
    except UnicodeEncodeError:
        sys.stdout.write(shown.encode("gbk", "ignore").decode("gbk", "ignore") + "\n")


# ---------------- 漏洞生命周期（CLI/面板共用；存 finding 行 attrs JSON，与 status 人审态分离） ----------------

LIFE_CODES = ("open", "reproduced", "not-reproduced", "fixed", "reopened")
# test note 机读结论词（复测时间轴聚合与 lifecycle 同步依赖；note 必须以其一开头）
TEST_CONCLUSIONS = ("复现", "未复现", "已修复", "部分修复", "仍存在", "待复测")


def set_lifecycle(c, project, fid, code, note="", tag=""):
    """生命周期写入核心：attrs JSON + changelog 留痕。tag 用于区分操作来源（面板/CLI）。"""
    row = c.execute("SELECT attrs FROM raw_events WHERE id=?", (fid,)).fetchone()
    try:
        attrs = json.loads(row["attrs"] or "{}") if row else {}
    except (TypeError, ValueError):
        attrs = {}
    attrs["lifecycle"] = code
    attrs["lifecycle_at"] = now()
    c.execute("UPDATE raw_events SET attrs=? WHERE id=?",
              (json.dumps(attrs, ensure_ascii=False), fid))
    c.execute("INSERT INTO changelog(project, action, detail, at) VALUES(?,?,?,?)",
              (project, "lifecycle",
               f"#{fid} → {code}" + (f" ｜ {note}" if note else "") + tag, attrs["lifecycle_at"]))


def cmd_lifecycle(a):
    """复测结论同步：把机读结论落到 finding 生命周期（AI 走 CLI 的正式通道，面板同款留痕）。"""
    c = connect()
    require_project(c, a.project)
    row = c.execute("SELECT id, kind FROM raw_events WHERE id=? AND project=?",
                    (a.id, a.project)).fetchone()
    if not row:
        sys.exit(f"[x] 记录不存在: #{a.id}")
    if row["kind"] != "finding":
        sys.exit("[x] lifecycle 只对 finding 生效（test 的结论走 note=，复测时间轴按机读词聚合）")
    set_lifecycle(c, a.project, a.id, a.code, note=a.note, tag="（CLI）")
    c.commit()
    print(f"[ok] #{a.id} 生命周期 → {a.code}")


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
    sp.add_argument("--detail", default=None,
                    help="详情；--update 重扫时缺省=保留原 detail（多行物料建议经面板或脚本传 JSON）")
    sp.add_argument("--detail-file", dest="detail_file", default="",
                    help="从文件读 detail（复测物料包推荐方式，优先于 --detail）")
    sp.add_argument("--note", default="")
    sp.add_argument("--req", default="",
                    help="finding 专用：真实请求原文（文件路径或 - 接 stdin），自动挂 evidence note=request")
    sp.add_argument("--resp", default="",
                    help="finding 专用：真实响应原文（文件路径或 - 接 stdin），自动挂 evidence note=response")
    sp.add_argument("--waive-capture", dest="waive_capture", default="",
                    help="finding 专用：初测报文已丢时的豁免原因（无报文建档，豁免起草待人确认生效）")
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

    sp = sub.add_parser("exec", help="执行落库单通道：命令输出自动落盘+test 事件+证据挂库（防『测了没记』）")
    sp.add_argument("--project", required=True)
    sp.add_argument("--parent-ext", dest="parent_ext", required=True,
                    help="被测对象 record id（多对象逗号分隔）")
    sp.add_argument("--cmd", required=True,
                    help="完整命令串，原样执行（如 --cmd 'curl -is \"http://x\"'；外层单引号保内层双引号）")
    sp.add_argument("--stage", default="", help="所属 SOP 阶段（建议必带）")
    sp.add_argument("--action", default="", help="动作标签（进 value；缺省用命令本身）")
    sp.add_argument("--title", default="")
    sp.add_argument("--note", default="", help="结论（AI 判定写这里，复测时间轴展示）")
    sp.add_argument("--detail", default="")
    sp.add_argument("--severity", default="")
    sp.add_argument("--confidence", default="high", help="AI 写入置信度（缺省 high）")
    sp.add_argument("--timeout", type=int, default=120, help="命令超时秒数（超时仍落盘留痕）")
    sp.set_defaults(fn=cmd_exec)

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

    sp = sub.add_parser("rebuild-assets", help="从资产类观测重建 assets 实体层（幂等；add/recon 后自动触发）")
    sp.add_argument("--project", required=True)
    sp.set_defaults(fn=cmd_rebuild_assets)

    sp = sub.add_parser("migrate")
    sp.add_argument("--from", dest="from_dir", required=True)
    sp.add_argument("--project", required=True)
    sp.set_defaults(fn=cmd_migrate)

    sp = sub.add_parser("report")
    sp.add_argument("--project", required=True)
    sp.add_argument("--out", default="")
    sp.add_argument("--force", action="store_true",
                    help="带 lint error 强制出报告（人的决定，AI 不得使用；缺省 error 即拒绝）")
    sp.add_argument("--template", default="assets", choices=("assets", "pentest"),
                    help="assets=资产清单（默认）；pentest=渗透测试报告（描述/原因/手工验证/修复）")
    sp.set_defaults(fn=cmd_report)

    sp = sub.add_parser("serve"); sp.add_argument("--port", type=int, default=8766)
    sp.add_argument("--db", default=""); sp.set_defaults(fn=cmd_serve)

    sp = sub.add_parser("sop", help="SOP 提示清单（AI 查漏补缺用，非门禁；覆盖度由 AI 显式申报、人背书）")
    sp.add_argument("--project", required=True)
    sp.set_defaults(fn=cmd_sop)

    sp = sub.add_parser("waive", help="豁免：AI 起草（confirmed=0，不生效），人工 --wid N --confirm 确认后生效")
    sp.add_argument("--project", required=True)
    sp.add_argument("--id", type=int, default=None,
                    help="起草豁免：目标事件 id（报文豁免挂 finding，归因豁免挂 test）")
    sp.add_argument("--wid", type=int, default=0, help="确认豁免：waive 起草时输出的豁免记录 id")
    sp.add_argument("--confirm", action="store_true", help="人工确认豁免生效（人的决定，配合 --wid）")
    sp.add_argument("--term", default="")
    sp.add_argument("--reason", default="")
    sp.set_defaults(fn=cmd_waive)

    sp = sub.add_parser("drop")
    sp.add_argument("--project", required=True)
    sp.add_argument("--confirm", action="store_true")
    sp.set_defaults(fn=cmd_drop)

    sp = sub.add_parser("evidence")
    sp.add_argument("--project", required=True)
    sp.add_argument("--event-id", type=int, required=True)
    sp.add_argument("--path", default="", help="证据文件路径（默认复制进套件 evidence/，--keep-in-place 只存指针）")
    sp.add_argument("--text", default=None, help="直接存文本内容为证据文件（请求/响应原文）")
    sp.add_argument("--keep-in-place", dest="keep_in_place", action="store_true",
                    help="不复制，文件留在原处只存路径指针")
    sp.add_argument("--note", default="")
    sp.set_defaults(fn=cmd_evidence)

    sp = sub.add_parser("evidence-move", help="改挂证据归属（--event-id 0 = 转项目级物料）")
    sp.add_argument("--project", required=True)
    sp.add_argument("--id", type=int, required=True, help="evidence 表 id")
    sp.add_argument("--event-id", type=int, required=True, help="目标事件 id（0=项目级）")
    sp.set_defaults(fn=cmd_evidence_move)

    sp = sub.add_parser("verify")
    sp.add_argument("--project", required=True)
    sp.add_argument("--id", type=int, required=True)
    sp.set_defaults(fn=cmd_verify)

    sp = sub.add_parser("lifecycle", help="复测结论同步 finding 生命周期（" + "/".join(LIFE_CODES) + "；AI 的 CLI 正式通道）")
    sp.add_argument("--project", required=True)
    sp.add_argument("--id", required=True, type=int, help="finding record id")
    sp.add_argument("--code", required=True, choices=LIFE_CODES)
    sp.add_argument("--note", default="", help="结论说明（进 changelog）")
    sp.set_defaults(fn=cmd_lifecycle)

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
