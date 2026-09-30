#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PDB Findings — 漏洞/证据/生命周期域（从 pentdb.py 拆出的零行为变更重构）。

  - cmd_waive：豁免起草/人工确认
  - cmd_evidence / cmd_evidence_move：证据挂库与改挂（落库核心 attach_evidence 在 pdb_core）
  - cmd_verify / cmd_exec：复测打点与执行落库单通道
  - cmd_migrate / cmd_drop：历史迁移与项目删除
  - set_lifecycle / cmd_lifecycle + LIFE_CODES：漏洞生命周期

向下依赖 pdb_core 与 pdb_assets（cmd_exec 复用 cmd_add 写入口，依赖方向无环）。
"""
import argparse
import datetime
import json
import os
import re
import sys

from pdb_assets import cmd_add
from pdb_core import (DB_PATH, VALID_STATUS, attach_evidence, connect,
                      log_change, now, require_project)

# ---------------- 漏洞生命周期（CLI/面板共用；存 finding 行 attrs JSON，与 status 人审态分离） ----------------

LIFE_CODES = ("open", "reproduced", "not-reproduced", "fixed", "reopened")
# test note 机读结论词（复测时间轴聚合与 lifecycle 同步依赖；note 必须以其一开头）
TEST_CONCLUSIONS = ("复现", "未复现", "已修复", "部分修复", "仍存在", "待复测")


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
                   f"wid={wid} #{row['event_id']} {row['term']}: {row['reason']}", actor="human")
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
        scope="in", auto=True, update=False, origin="agent")
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
    """删除整个项目及其数据（高危操作，必须 --confirm）。changelog 留墓碑记录。
    级联清 assets/reviews——reviews 无 project 列，按被删事件的 id 集合清；
    changelog 故意保留（墓碑留痕）。"""
    if not a.confirm:
        sys.exit("[x] 删除项目是高危操作，必须显式加 --confirm")
    c = connect()
    require_project(c, a.project)
    n = c.execute("SELECT COUNT(*) FROM raw_events WHERE project=?", (a.project,)).fetchone()[0]
    ev_ids = [r[0] for r in c.execute("SELECT id FROM raw_events WHERE project=?", (a.project,))]
    for t in ("raw_events", "assets", "pending_tests", "waives", "evidence"):
        c.execute(f"DELETE FROM {t} WHERE project=?", (a.project,))
    if ev_ids:
        c.execute("DELETE FROM reviews WHERE event_id IN (%s)" %
                  ",".join("?" * len(ev_ids)), ev_ids)
    c.execute("DELETE FROM projects WHERE name=?", (a.project,))
    log_change(c, "__system__", "drop", f"项目 {a.project} 已删除（含 {n} 条事件）")
    c.commit()
    print(f"[ok] 项目 {a.project} 已删除（{n} 条事件），changelog 留痕")


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
