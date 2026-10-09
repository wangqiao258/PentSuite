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

-- 探索血缘层（v9/v10，借鉴 ARTEX 探索图+共享 todolist 的本地化落地）：
-- intents 一条=一条带假设的推进方向，观测经 raw_events.intent_id 挂接成 方向→观测 血缘链；
-- plan_steps 共享 todolist：串行攻击链按依赖逐步放行（plan next 只出前置已满足的步骤）
CREATE TABLE IF NOT EXISTS intents (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  project    TEXT NOT NULL,
  parent_id  INTEGER DEFAULT 0,              -- 父意图 id（血缘链上游方向，0=根意图）
  goal       TEXT NOT NULL,                  -- 推进方向一句话（具体到目标/动作）
  hypothesis TEXT DEFAULT '',                -- 假设/依据（为什么值得测）
  status     TEXT NOT NULL DEFAULT 'active', -- active 进行中 / done 有产出关闭 / dead 方向作废
  note       TEXT DEFAULT '',
  created_at TEXT NOT NULL,
  closed_at  TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_intents_project ON intents(project);
CREATE TABLE IF NOT EXISTS plan_steps (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  project    TEXT NOT NULL,
  seq        INTEGER NOT NULL,               -- 派发顺序（追加式递增，list/next 按 seq 排）
  title      TEXT NOT NULL,                  -- 本步做什么（具体到目标/命令/假设）
  depends_on TEXT DEFAULT '',                -- 前置步骤 id（逗号分隔）
  intent_id  INTEGER DEFAULT 0,              -- 归属探索意图（可空）
  status     TEXT NOT NULL DEFAULT 'ready',  -- blocked 受阻 / ready 可执行 / doing 执行中 / done 完成 / skip 跳过
  note       TEXT DEFAULT '',
  created_at TEXT NOT NULL,
  closed_at  TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_plan_project ON plan_steps(project);

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
WHEN NOT (OLD.confirmed = 0 AND NEW.confirmed IN (1, 2)
          AND OLD.project IS NEW.project AND OLD.event_id IS NEW.event_id
          AND OLD.term IS NEW.term AND OLD.reason IS NEW.reason AND OLD.at IS NEW.at)
BEGIN
  SELECT RAISE(ABORT, 'waives 仅允许 confirmed 0→1（确认生效）或 0→2（人工作废）；改字段/倒退一律拒绝');
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


# ---------------- exec 日志/证据读取统一口径（读上限 + 容错解码） ----------------

EVIDENCE_READ_LIMIT = 262144  # 单次读取上限：server /api/evidence/* 与 exec 报文投影共用


def decode_text_compat(raw):
    """bytes 容错解码：utf-8 优先，失败转 gbk ignore（Windows 工具输出常见 GBK）。"""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("gbk", "ignore")


def read_text_compat(path, limit=EVIDENCE_READ_LIMIT):
    """读文件前 limit 字节并容错解码——exec 日志/证据原文读取统一入口；OSError 由调用方处置。"""
    with open(path, "rb") as f:
        return decode_text_compat(f.read(limit))


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


# ---------------- schema 迁移器（PRAGMA user_version 驱动） ----------------
# connect() 正常路径只建连接（零 DDL/DML——裸 DML 会隐式持写锁，与面板/CLI 并发撞
# "database is locked"）。建表/加列/回填只在 user_version 落后时由迁移步跑一次，每步
# 完成即 commit 并推进 user_version。铁律：
#   - sqlite connect() 禁裸 DML；
#   - 迁移回填只能放在对应 ALTER 首次成功的分支内做，随即 commit 释放写锁；
#   - 新增列一律追加迁移步并递增 SCHEMA_VERSION，不回改 SCHEMA 基线。
SCHEMA_VERSION = 10


def _mig_v1_schema(c):
    """v0→v1：首次建表（SCHEMA 幂等，含全部基线列与 P0 审计触发器；executescript 自带隐式提交）。"""
    c.executescript(SCHEMA)


def _mig_v2_columns(c):
    """v1→v2：历史列补齐（祖传库逐列 ALTER，撞重名列静默跳过；纯 DDL 无回填）。"""
    for sql in (
        "ALTER TABLE raw_events ADD COLUMN severity TEXT DEFAULT ''",
        "ALTER TABLE raw_events ADD COLUMN code TEXT DEFAULT ''",
        "ALTER TABLE raw_events ADD COLUMN tech TEXT DEFAULT ''",
        "ALTER TABLE raw_events ADD COLUMN service TEXT DEFAULT ''",
        "ALTER TABLE raw_events ADD COLUMN scope TEXT DEFAULT 'unknown'",
        "ALTER TABLE raw_events ADD COLUMN verified_at TEXT DEFAULT ''",
        "ALTER TABLE projects ADD COLUMN stages_enabled TEXT DEFAULT ''",
        # projects.archived：归档标记（0=活跃，1=已归档）；面板下拉默认隐藏，数据保留可查
        "ALTER TABLE projects ADD COLUMN archived INTEGER DEFAULT 0",
        "ALTER TABLE raw_events ADD COLUMN stage TEXT DEFAULT ''",
        "ALTER TABLE pending_tests ADD COLUMN stage TEXT DEFAULT ''",
        "ALTER TABLE raw_events ADD COLUMN updated_at TEXT DEFAULT ''",
        "ALTER TABLE raw_events ADD COLUMN attrs TEXT DEFAULT '{}'",
    ):
        try:
            c.execute(sql)
        except sqlite3.OperationalError:
            pass
    c.commit()


def _mig_v3_evidence_etype(c):
    """v2→v3：evidence.etype（证据类型 request/response/file）。
    仅在 ALTER 首次成功分支内做存量回填，随即 commit 释放写锁。"""
    try:
        c.execute("ALTER TABLE evidence ADD COLUMN etype TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        return
    c.execute("UPDATE evidence SET etype='request' WHERE note LIKE 'request%'")
    c.execute("UPDATE evidence SET etype='response' WHERE note LIKE 'response%'")
    c.execute("UPDATE evidence SET etype='file' WHERE etype IS NULL OR etype=''")
    c.commit()


def _mig_v4_waives_confirmed(c):
    """v3→v4：waives.confirmed（0=起草，AI 可起草不得自批；1=人工确认生效）。
    仅首次加列时回填存量=已确认（祖传豁免不追溯，存量复核另走 waive --wid N --confirm）。"""
    try:
        c.execute("ALTER TABLE waives ADD COLUMN confirmed INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        return
    c.execute("UPDATE waives SET confirmed=1")
    c.commit()


def _mig_v5_changelog_actor(c):
    """v4→v5：changelog.actor（操作者 agent/human/机器采集名）；空=历史记录未知，不回填。"""
    try:
        c.execute("ALTER TABLE changelog ADD COLUMN actor TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        return
    c.commit()


def _mig_v6_dedup_key(c):
    """v5→v6：raw_events.dedup_key（finding 去重指纹，写入口强制判重）。
    仅首次加列时回填存量 finding 的指纹——只填列不合并，存量归并由人依 lint warn 裁决。"""
    try:
        c.execute("ALTER TABLE raw_events ADD COLUMN dedup_key TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        return
    for row in c.execute("SELECT id, value, title FROM raw_events WHERE kind='finding'").fetchall():
        c.execute("UPDATE raw_events SET dedup_key=? WHERE id=?",
                  (dedup_key_for(row["value"], row["title"]), row["id"]))
    c.commit()


def _mig_v7_waive_reject(c):
    """v6→v7：豁免作废通道——重建 trg_waives_only_confirm，放行 confirmed 0→2（人工作废）。
    语义不变量保留：改字段/倒退（1→0、2→x）仍拒绝；作废后不可再翻转（trg 只放行 0→{1,2}）。"""
    c.execute("DROP TRIGGER IF EXISTS trg_waives_only_confirm")
    c.executescript("""
CREATE TRIGGER trg_waives_only_confirm
BEFORE UPDATE ON waives
WHEN NOT (OLD.confirmed = 0 AND NEW.confirmed IN (1, 2)
          AND OLD.project IS NEW.project AND OLD.event_id IS NEW.event_id
          AND OLD.term IS NEW.term AND OLD.reason IS NEW.reason AND OLD.at IS NEW.at)
BEGIN
  SELECT RAISE(ABORT, 'waives 仅允许 confirmed 0→1（确认生效）或 0→2（人工作废）；改字段/倒退一律拒绝');
END;
""")
    c.commit()


def _mig_v8_voided(c):
    """v7→v8：raw_events.voided（0=正常，1=人工作废）。
    作废=记录级墓碑（冗余/误录数据清理通道，区别于豁免的"有效但证据取不回"）：
    作废记录退出 lint 阻断、报告与面板主视图、资产派生；仅人经 CLI void 命令操作并留痕。"""
    try:
        c.execute("ALTER TABLE raw_events ADD COLUMN voided INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        return
    c.commit()


def _mig_v9_intents(c):
    """v8→v9：探索血缘层——intents 意图表 + raw_events.intent_id 归属列。
    一条 intent=一条带假设的推进方向（借鉴 ARTEX 探索图）：事实/漏洞经 intent_id
    挂到意图，形成 方向→观测 血缘链。存量观测 intent_id 缺省 0（无归属），不回填。"""
    c.executescript("""
CREATE TABLE IF NOT EXISTS intents (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  project    TEXT NOT NULL,
  parent_id  INTEGER DEFAULT 0,
  goal       TEXT NOT NULL,
  hypothesis TEXT DEFAULT '',
  status     TEXT NOT NULL DEFAULT 'active',
  note       TEXT DEFAULT '',
  created_at TEXT NOT NULL,
  closed_at  TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_intents_project ON intents(project);
""")
    try:
        c.execute("ALTER TABLE raw_events ADD COLUMN intent_id INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # 列已存在（部分迁移过的副本库）：幂等跳过
    c.commit()


def _mig_v10_plan_steps(c):
    """v9→v10：计划层——plan_steps 共享 todolist（借鉴 ARTEX planner 多轮共享清单）。
    串行攻击链按依赖逐步放行：plan next 只出前置步骤已全部 done/skip 的 ready 步骤，
    链路不错序、不重复。表在 v1 基线与 v9 已就绪的库上幂等 no-op。"""
    c.executescript("""
CREATE TABLE IF NOT EXISTS plan_steps (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  project    TEXT NOT NULL,
  seq        INTEGER NOT NULL,
  title      TEXT NOT NULL,
  depends_on TEXT DEFAULT '',
  intent_id  INTEGER DEFAULT 0,
  status     TEXT NOT NULL DEFAULT 'ready',
  note       TEXT DEFAULT '',
  created_at TEXT NOT NULL,
  closed_at  TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_plan_project ON plan_steps(project);
""")
    c.commit()


# 迁移步注册表：下标 i 的函数把 user_version i 推进到 i+1（与 SCHEMA_VERSION 同步维护）
_MIGRATIONS = (_mig_v1_schema, _mig_v2_columns, _mig_v3_evidence_etype,
               _mig_v4_waives_confirmed, _mig_v5_changelog_actor, _mig_v6_dedup_key,
               _mig_v7_waive_reject, _mig_v8_voided, _mig_v9_intents, _mig_v10_plan_steps)


def _migrate(c):
    """user_version 落后时逐版本跑迁移，每步完成即 commit；版本已最新则零 DDL/DML 直通。"""
    ver = c.execute("PRAGMA user_version").fetchone()[0]
    while ver < SCHEMA_VERSION:
        _MIGRATIONS[ver](c)
        ver += 1
        c.execute(f"PRAGMA user_version={ver}")
        c.commit()


def connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    # 并发基础（面板 ThreadingHTTPServer 每请求新建连接 × CLI 并发写）：
    # busy_timeout 每连接必设——撞锁时最多等 5s 而非立刻报 "database is locked"；
    # journal_mode=WAL 持久化在库文件上，设一次即可——先查当前值，非 WAL 才写（PRAGMA 无锁开销）。
    c.execute("PRAGMA busy_timeout=5000")
    try:
        if (c.execute("PRAGMA journal_mode").fetchone()[0] or "").lower() != "wal":
            c.execute("PRAGMA journal_mode=WAL")
    except sqlite3.OperationalError:
        pass  # 个别文件系统/并发窗口下 WAL 不可用：退回默认 journal 模式，busy_timeout 仍兜底
    _migrate(c)
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
