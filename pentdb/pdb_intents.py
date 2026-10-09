#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PDB 探索血缘与计划层（借鉴 ARTEX 探索图 + planner 共享 todolist 的本地化落地）。

intents    探索意图：一条 intent = 一条带假设的推进方向（goal + hypothesis）。
           事实/漏洞经 raw_events.intent_id 挂到意图（add/exec --intent N），
           形成 方向→观测 的血缘链，回答"这个方向为什么测、派生自哪个观察、产出了什么"。
plan_steps 共享 todolist：串行攻击链（发现注入点→取凭据→横向）按依赖逐步派发——
           plan next 只放行"前置步骤已全部 done/skip"的步骤，链路不错序、不重复；
           blocked 步骤在依赖满足时自动晋升 ready（晋升留痕），不依赖 AI 自觉。

规矩：
  - 写库唯一入口仍是 PentDB CLI，状态推进全走本模块命令，changelog 全留痕；
  - intent 关闭后（done/dead）不再接受新观测挂接（add/exec --intent 校验拒绝）；
  - plan next 的依赖晋升是显式可审计的写操作（log_change plan-ready），不做隐式推导。
"""
import sys

from pdb_core import connect, log_change, now, require_project

VALID_INTENT_STATUS = ("active", "done", "dead")
VALID_PLAN_STATUS = ("blocked", "ready", "doing", "done", "skip")
PLAN_CLOSED = ("done", "skip")          # 视为"已完成"的依赖终态
PLAN_OPEN = ("blocked", "ready", "doing")


# ---------------- 意图层（探索血缘） ----------------

def _intent_row(c, project, iid):
    """取意图行（不存在返回 None，不在此处报错——调用方按语义处置）。"""
    if not iid or iid <= 0:
        return None
    return c.execute("SELECT * FROM intents WHERE id=? AND project=?",
                     (iid, project)).fetchone()


def _require_intent(c, project, iid, allow_closed=False):
    """校验意图存在且（默认）仍在进行中——关闭后的意图不再接受新挂接。"""
    row = _intent_row(c, project, iid)
    if not row:
        sys.exit(f"[x] 探索意图不存在: #{iid}（先 intent add 创建，注意 --project 一致）")
    if not allow_closed and row["status"] != "active":
        sys.exit(f"[x] 探索意图 #{iid} 已关闭（{row['status']}）：关闭后不再接受新挂接，"
                 "确属补录请先人工重开或改挂其他意图")
    return row


def intent_add(c, project, goal, hypothesis="", parent_id=0):
    """新建意图（cmd_intent 与测试共用的落库主体；连接由调用方持有）。"""
    require_project(c, project)
    if not (goal or "").strip():
        sys.exit("[x] --goal 必填：一条意图=一条推进方向（如：验证后台是否存在默认口令）")
    if parent_id:
        p = _intent_row(c, project, parent_id)
        if not p:
            sys.exit(f"[x] 父意图不存在: #{parent_id}")
        if p["status"] != "active":
            sys.exit(f"[x] 父意图 #{parent_id} 已关闭（{p['status']}）：血缘链只能挂在进行中的方向下")
    cur = c.execute(
        "INSERT INTO intents(project,parent_id,goal,hypothesis,status,created_at) "
        "VALUES(?,?,?,?,?,?)",
        (project, parent_id or 0, goal.strip(), (hypothesis or "").strip(), "active", now()))
    log_change(c, project, "intent-add",
               f"#{cur.lastrowid} {goal.strip()[:60]}" + (f" ← 父 #{parent_id}" if parent_id else ""))
    c.commit()
    return cur.lastrowid


def intent_close(c, project, iid, status, note=""):
    """关闭意图（done=有产出/验证完成；dead=方向作废）。"""
    require_project(c, project)
    _require_intent(c, project, iid, allow_closed=True)
    if status not in ("done", "dead"):
        sys.exit("[x] 关闭状态只能是 done（有产出）或 dead（方向作废）")
    c.execute("UPDATE intents SET status=?, closed_at=?, note=CASE WHEN ?='' THEN note ELSE ? END "
              "WHERE id=? AND project=?",
              (status, now(), note or "", note or "", iid, project))
    log_change(c, project, "intent-close", f"#{iid} → {status}" + (f" ｜ {note}" if note else ""))
    c.commit()


def intent_chain(c, project, iid):
    """父链上溯（根→…→本意图的 goal 列表），防御环：超过 10 层截断。"""
    chain, guard = [], 0
    cur_id = iid
    while cur_id and guard < 10:
        row = _intent_row(c, project, cur_id)
        if not row:
            break
        chain.append(row)
        cur_id = row["parent_id"]
        guard += 1
    chain.reverse()
    return chain


def cmd_intent(a):
    """intent 子命令入口：add / list / show / close。"""
    c = connect()
    try:
        if a.intent_cmd == "add":
            iid = intent_add(c, a.project, a.goal, a.hypothesis, a.parent)
            print(f"[ok] 意图 #{iid} 已建立：{a.goal.strip()}"
                  + (f"（父 #{a.parent}）" if a.parent else ""))
            print(f"     挂接观测: add/exec --project {a.project} --intent {iid} …")
        elif a.intent_cmd == "list":
            require_project(c, a.project)
            show_all = getattr(a, "all_", False)
            sql = "SELECT * FROM intents WHERE project=?"
            args = [a.project]
            if not show_all:
                sql += " AND status='active'"
            rows = c.execute(sql + " ORDER BY id", args).fetchall()
            if not rows:
                print(f"[i] {'无意图' if show_all else '无进行中的意图（--all 查看含已关闭）'}；"
                      f"intent add --project {a.project} --goal '<方向>' 新建")
                return
            for r in rows:
                n = c.execute("SELECT COUNT(*) n FROM raw_events WHERE intent_id=? AND voided=0",
                              (r["id"],)).fetchone()["n"]
                mark = {"active": "[进行中]", "done": "[已产出]", "dead": "[已作废]"}[r["status"]]
                par = f" ← #{r['parent_id']}" if r["parent_id"] else ""
                print(f"#{r['id']} {mark}{par} {r['goal']} ｜ 挂接 {n} 条 ｜ {r['created_at']}")
        elif a.intent_cmd == "show":
            require_project(c, a.project)
            row = _require_intent(c, a.project, a.id, allow_closed=True)
            print(f"== 意图 #{row['id']} [{row['status']}] {row['goal']}")
            if row["hypothesis"]:
                print(f"   假设: {row['hypothesis']}")
            if row["note"]:
                print(f"   备注: {row['note']}")
            chain = intent_chain(c, a.project, a.id)
            if len(chain) > 1:
                print("   血缘: " + " → ".join(f"#{r['id']} {r['goal'][:24]}" for r in chain))
            evs = c.execute(
                "SELECT id, kind, value, title, status FROM raw_events "
                "WHERE intent_id=? AND voided=0 ORDER BY id", (a.id,)).fetchall()
            print(f"-- 挂接观测 {len(evs)} 条:")
            for e in evs:
                t = e["title"] or e["value"]
                print(f"   #{e['id']} [{e['kind']}] ({e['status']}) {t[:70]}")
        elif a.intent_cmd == "close":
            intent_close(c, a.project, a.id, a.status, a.note)
            print(f"[ok] 意图 #{a.id} → {a.status}" + (f" ｜ {a.note}" if a.note else ""))
    finally:
        c.close()


# ---------------- 计划层（共享 todolist） ----------------

def _plan_deps(step):
    """depends_on 逗号串 → [int]（脏数据静默丢弃）。"""
    return [int(x) for x in (step["depends_on"] or "").split(",") if x.strip().isdigit()]


def _plan_row(c, project, sid):
    if not sid or sid <= 0:
        return None
    return c.execute("SELECT * FROM plan_steps WHERE id=? AND project=?",
                     (sid, project)).fetchone()


def _plan_promote(c, project):
    """依赖晋升：blocked 步骤的前置全部 done/skip → ready（留痕，幂等）。
    返回本次新晋升的 [(id, title)]。循环至不动点（依赖链逐级解锁）。"""
    promoted = []
    while True:
        moved = False
        rows = c.execute("SELECT * FROM plan_steps WHERE project=? AND status='blocked' ORDER BY seq",
                         (project,)).fetchall()
        done_ids = {r["id"] for r in c.execute(
            "SELECT id FROM plan_steps WHERE project=? AND status IN ('done','skip')", (project,))}
        for r in rows:
            deps = _plan_deps(r)
            if deps and all(d in done_ids for d in deps):
                c.execute("UPDATE plan_steps SET status='ready' WHERE id=?", (r["id"],))
                log_change(c, project, "plan-ready", f"#{r['id']} 前置已满足 → ready ｜ {r['title'][:50]}")
                promoted.append((r["id"], r["title"]))
                moved = True
        if not moved:
            break
    if promoted:
        c.commit()
    return promoted


def cmd_plan(a):
    """plan 子命令入口：add / next / done / skip / list。"""
    c = connect()
    try:
        if a.plan_cmd == "add":
            require_project(c, a.project)
            if not (a.title or "").strip():
                sys.exit("[x] --title 必填：本步做什么（具体到目标/命令/假设）")
            intent_id = getattr(a, "intent_id", 0) or 0
            if intent_id:
                _require_intent(c, a.project, intent_id)
            deps = []
            for x in (a.depends or "").split(","):
                x = x.strip()
                if not x:
                    continue
                if not x.isdigit():
                    sys.exit(f"[x] --depends 只认步骤 id（逗号分隔），收到: {x}")
                d = _plan_row(c, a.project, int(x))
                if not d:
                    sys.exit(f"[x] 前置步骤不存在: #{x}")
                if d["status"] not in VALID_PLAN_STATUS:
                    sys.exit(f"[x] 前置步骤 #{x} 状态非法: {d['status']}")
                deps.append(int(x))
            seq = (c.execute("SELECT COALESCE(MAX(seq),0) m FROM plan_steps WHERE project=?",
                             (a.project,)).fetchone()["m"] or 0) + 1
            status = "ready" if not deps else "blocked"
            cur = c.execute(
                "INSERT INTO plan_steps(project,seq,title,depends_on,intent_id,status,created_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (a.project, seq, a.title.strip(), ",".join(map(str, deps)), intent_id, status, now()))
            log_change(c, a.project, "plan-add",
                       f"#{cur.lastrowid} seq={seq} [{status}] {a.title.strip()[:50]}"
                       + (f" ｜ 依赖 {','.join(map(str, deps))}" if deps else ""))
            c.commit()
            print(f"[ok] 计划步骤 #{cur.lastrowid}（seq={seq}，{status}）: {a.title.strip()}"
                  + (f" ｜ 前置 {','.join(map(str, deps))}" if deps else ""))
        elif a.plan_cmd == "next":
            require_project(c, a.project)
            promoted = _plan_promote(c, a.project)
            rows = c.execute(
                "SELECT * FROM plan_steps WHERE project=? AND status IN ('ready','doing') "
                "ORDER BY seq", (a.project,)).fetchall()
            if promoted:
                print(f"[解锁] 前置已满足 → 可执行: " + "；".join(f"#{i} {t[:40]}" for i, t in promoted))
            if not rows:
                print("[i] 无可执行步骤：plan add 追加，或确认所有方向已收口（intent list 核对）")
                return
            imap = {r["id"]: r["goal"] for r in c.execute(
                "SELECT id, goal FROM intents WHERE project=?", (a.project,)).fetchall()}
            print(f"== 可执行步骤 {len(rows)} 条（按 seq 领取；做完 plan done --id N 写回，"
                  "探测落库带 --intent 挂血缘）==")
            for r in rows:
                doing = "（执行中）" if r["status"] == "doing" else ""
                ig = f" ｜ 意图 #{r['intent_id']} {imap.get(r['intent_id'], '')[:36]}" if r["intent_id"] else ""
                print(f"#{r['id']} seq={r['seq']} {doing}{r['title']}{ig}")
        elif a.plan_cmd in ("done", "skip"):
            require_project(c, a.project)
            row = _plan_row(c, a.project, a.id)
            if not row:
                sys.exit(f"[x] 计划步骤不存在: #{a.id}")
            if row["status"] in PLAN_CLOSED:
                sys.exit(f"[x] 步骤 #{a.id} 已是终态（{row['status']}），不可重复关闭")
            c.execute("UPDATE plan_steps SET status=?, closed_at=?, "
                      "note=CASE WHEN ?='' THEN note ELSE note || ' ｜ ' || ? END WHERE id=?",
                      (a.plan_cmd, now(), getattr(a, "note", "") or "",
                       getattr(a, "note", "") or "", a.id))
            log_change(c, a.project, f"plan-{a.plan_cmd}",
                       f"#{a.id} {row['title'][:50]}" + (f" ｜ {a.note}" if getattr(a, "note", "") else ""))
            c.commit()
            print(f"[ok] 步骤 #{a.id} → {a.plan_cmd}: {row['title']}")
            promoted = _plan_promote(c, a.project)
            if promoted:
                print("[解锁] " + "；".join(f"#{i} {t[:40]}" for i, t in promoted))
        elif a.plan_cmd == "list":
            require_project(c, a.project)
            show_all = getattr(a, "all_", False)
            sql = "SELECT * FROM plan_steps WHERE project=?"
            args = [a.project]
            if not show_all:
                sql += " AND status IN ('blocked','ready','doing')"
            rows = c.execute(sql + " ORDER BY seq", args).fetchall()
            if not rows:
                print(f"[i] 无未完成步骤（--all 查看含 done/skip）；plan add 追加")
                return
            for r in rows:
                deps = _plan_deps(r)
                dep_s = f" ｜ 前置 {','.join(map(str, deps))}" if deps else ""
                ig = f" ｜ 意图 #{r['intent_id']}" if r["intent_id"] else ""
                print(f"#{r['id']} seq={r['seq']} [{r['status']}] {r['title'][:60]}{dep_s}{ig}")
    finally:
        c.close()
