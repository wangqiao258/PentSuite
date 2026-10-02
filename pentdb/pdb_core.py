#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PDB Core — PentDB 共享内核（从 pentdb.py 拆出的零行为变更重构）。

承载被全部命令域共用的模块级常量与数据库基础函数：
  - 路径常量（BASE / DB_PATH / SOP_CFG）与合法性枚举常量
  - SCHEMA 建表语句
  - now / connect / log_change / require_project / attach_evidence

规矩继承自 pentdb.py：
  - 写库路径唯一: 一切写入必须经 PentDB CLI，禁止手编 SQLite
  - 零第三方依赖（纯 stdlib）
"""
import datetime
import hashlib
import json
import os
import re
import sqlite3
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
# 数据根唯一：默认在项目副本 data/ 下；skill 自包含副本通过 PENTDB_DB 指向同一数据文件
DB_PATH = os.environ.get("PENTDB_DB") or os.path.join(BASE, "data", "pentdb.db")
SOP_CFG = os.environ.get("PENTDB_SOP") or os.path.join(BASE, "sop", "default.json")

VALID_KINDS = ("domain", "port", "path", "param", "finding", "osint", "note", "test", "suggestion", "probe")
VALID_STATUS = ("new", "confirmed", "rejected")
VALID_ORIGIN = ("agent", "human", "migrate")
VALID_SEVERITY = ("crit", "high", "med", "low", "info")
VALID_SCOPE = ("in", "out", "unknown")
FACT_KINDS = ("domain", "port", "path", "param", "test", "probe")  # 机器可验证事实：允许 --auto 自动确认
ASSET_KINDS = ("domain", "port", "path", "param")         # 资产类观测：参与实体归并（probe 是纯观测，不归并）
STALE_DAYS = 30  # 资产生命周期：last_seen 超过 N 天视为 stale

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
  name       TEXT PRIMARY KEY,
  stages_enabled TEXT DEFAULT '',
  archived   INTEGER DEFAULT 0,
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

-- P0 防绕过审计触发器（2026-10-02）：纪律从"CLI 自觉"下沉为"DB 强制"——
-- 任何写路径（含手编 SQLite）都被数据库本身拒绝。唯一例外通道：
-- cmd_drop（人工 --confirm 高危操作）先 DROP 再经 executescript(SCHEMA) 恢复。
CREATE TRIGGER IF NOT EXISTS trg_changelog_no_update
BEFORE UPDATE ON changelog
BEGIN
  SELECT RAISE(ABORT, 'changelog 为 append-only 审计流，禁止 UPDATE（防洗库）');
END;
CREATE TRIGGER IF NOT EXISTS trg_changelog_no_delete
BEFORE DELETE ON changelog
BEGIN
  SELECT RAISE(ABORT, 'changelog 为 append-only 审计流，禁止 DELETE（防洗库）');
END;
CREATE TRIGGER IF NOT EXISTS trg_reviews_no_update
BEFORE UPDATE ON reviews
BEGIN
  SELECT RAISE(ABORT, 'reviews 为 append-only 人审流，禁止 UPDATE');
END;
CREATE TRIGGER IF NOT EXISTS trg_reviews_no_delete
BEFORE DELETE ON reviews
BEGIN
  SELECT RAISE(ABORT, 'reviews 为 append-only 人审流，禁止 DELETE（真删除走 drop --confirm）');
END;
CREATE TRIGGER IF NOT EXISTS trg_waives_only_confirm
BEFORE UPDATE ON waives
WHEN NOT (OLD.confirmed = 0 AND NEW.confirmed = 1
          AND OLD.project IS NEW.project AND OLD.event_id IS NEW.event_id
          AND OLD.term IS NEW.term AND OLD.reason IS NEW.reason AND OLD.at IS NEW.at)
BEGIN
  SELECT RAISE(ABORT, 'waives 仅允许 confirmed 0→1（改字段/倒退改写一律拒绝）');
END;
CREATE TRIGGER IF NOT EXISTS trg_waives_no_delete
BEFORE DELETE ON waives
BEGIN
  SELECT RAISE(ABORT, 'waives 为 append-only，禁止 DELETE（真删除走 drop --confirm）');
END;
CREATE TRIGGER IF NOT EXISTS trg_events_agent_insert
BEFORE INSERT ON raw_events
WHEN NEW.origin = 'agent' AND NEW.status = 'confirmed'
     AND NEW.kind NOT IN ('domain','port','path','param','test','probe')
BEGIN
  SELECT RAISE(ABORT, 'agent 写入 confirmed 仅限机器可验证事实 kind（--auto 门禁 DB 侧兜底）');
END;
CREATE TRIGGER IF NOT EXISTS trg_events_no_core_update
BEFORE UPDATE ON raw_events
WHEN OLD.kind IS NOT NEW.kind
  OR OLD.project IS NOT NEW.project
  OR OLD.created_at IS NOT NEW.created_at
BEGIN
  SELECT RAISE(ABORT, 'raw_events append-only：kind/project/created_at 不可改（观测归并锚点）');
END;
"""

# P0 审计触发器清单（与 SCHEMA 末尾 DDL 一一对应；cmd_drop 级联删除需短暂解除后恢复）
AUDIT_TRIGGERS = (
    "trg_changelog_no_update", "trg_changelog_no_delete",
    "trg_reviews_no_update", "trg_reviews_no_delete",
    "trg_waives_only_confirm", "trg_waives_no_delete",
    "trg_events_agent_insert", "trg_events_no_core_update",
)


def now():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def dedup_key_for(value, title):
    """finding 去重指纹：目标端点集合 + 漏洞身份（title）规范化后哈希前 16 位。
    规范化：逗号分隔端点集排序去重（顺序无关）、剥 scheme://host 只留路径、
    小写去空白；title 空白折叠小写。两端全空返回 ''（不参与去重）。
    极端同指纹异漏洞（误并）可 --no-dedupe 逃生，changelog 全留痕可追溯。"""
    def norm_val(v):
        items = []
        for part in (v or "").split(","):
            p = part.strip().lower()
            if not p:
                continue
            m = re.match(r"^[a-z][a-z0-9+.\-]*://[^/]+(/.*)$", p)  # 剥 scheme://host
            if m:
                p = m.group(1)
            p = p.rstrip("/")
            if p:
                items.append(p)
        return ",".join(sorted(set(items)))

    def norm_title(t):
        return re.sub(r"\s+", "", (t or "")).lower()

    nv, nt = norm_val(value), norm_title(title)
    if not nv and not nt:
        return ""
    basis = (nv or "-") + "||" + (nt or "-")
    return hashlib.sha1(basis.encode("utf-8")).hexdigest()[:16]


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
        # projects.archived：归档标记（0=活跃，1=已归档）；面板下拉默认隐藏，数据保留可查
        c.execute("ALTER TABLE projects ADD COLUMN archived INTEGER DEFAULT 0")
        c.commit()
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
    try:
        # changelog.actor：操作者（agent/human/机器采集），空=历史记录未知，不回填
        c.execute("ALTER TABLE changelog ADD COLUMN actor TEXT DEFAULT ''")
        c.commit()
    except sqlite3.OperationalError:
        pass
    try:
        # raw_events.dedup_key：finding 去重指纹（写入口强制判重）。
        # 仅首次加列时回填存量 finding 的指纹——只填列不合并，存量归并由人依 lint warn 裁决
        c.execute("ALTER TABLE raw_events ADD COLUMN dedup_key TEXT DEFAULT ''")
        for row in c.execute("SELECT id, value, title FROM raw_events WHERE kind='finding'").fetchall():
            c.execute("UPDATE raw_events SET dedup_key=? WHERE id=?",
                      (dedup_key_for(row["value"], row["title"]), row["id"]))
        c.commit()
    except sqlite3.OperationalError:
        pass
    return c


def log_change(c, project, action, detail="", actor="agent"):
    """留痕追加。actor：agent=AI 经 CLI 操作（默认）/ human=人审动作 / 机器采集名。
    人的决定（review/waive-confirm）必须显式传 human 系 actor，与 AI 操作可区分。"""
    c.execute("INSERT INTO changelog(project, action, detail, at, actor) VALUES(?,?,?,?,?)",
              (project, action, detail, now(), actor))


def require_project(c, project):
    row = c.execute("SELECT name FROM projects WHERE name=?", (project,)).fetchone()
    if not row:
        sys.exit(f"[x] 项目不存在: {project}，先执行 init --project {project}")


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
