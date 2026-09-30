#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PDB Assets — 资产域（从 pentdb.py 拆出的零行为变更重构）。

观测入库（init/add）与资产实体归并层：
  - cmd_init / cmd_add：写入口（含 AI 门禁、test 幂等、重扫更新）
  - _norm_domain / _split_hostport / _resolve_host / rebuild_assets：实体归并
  - asset_review_state / asset_is_stale：实体人审聚合与生命周期
  - cmd_rebuild_assets / cmd_query / cmd_pending / cmd_review：查询与人审 CLI

向下只依赖 pdb_core（attach_evidence 因 cmd_add/exec 双向需要上提到 core，见 pentdb.py 拆分说明）。
"""
import datetime
import json
import os
import re
import sys

from pdb_core import (ASSET_KINDS, DB_PATH, FACT_KINDS, STALE_DAYS, VALID_KINDS,
                      VALID_ORIGIN, VALID_SEVERITY, VALID_SCOPE, attach_evidence,
                      connect, log_change, now, require_project)


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
        "merge_key,status,confidence,severity,code,tech,service,scope,verified_at,source,origin,created_at,updated_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (a.project, a.ext_id, a.kind, a.value, a.title or "", a.detail or "",
         a.note or "", a.parent_ext or "", merge_key, status, a.confidence or "",
         a.severity or "", str(a.code or ""), a.tech or "", a.service or "",
         a.scope, verified, a.source, a.origin, ts, ts))
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

    # parent_atype 语义修正：parent 解析值若实为库内域名（且无同名 host 实体），记真实类型 domain
    dom_keys = {k for (at, k) in ent if at == "domain"}
    host_keys = {k for (at, k) in ent if at == "host"}
    for (at, k), e in ent.items():
        if at in ("endpoint", "service") and e["parent_akey"] in dom_keys and e["parent_akey"] not in host_keys:
            e["parent_atype"] = "domain"

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
    log_change(c, a.project, "review", f"#{a.id} -> {action}", actor=a.reviewer or "human")
    c.commit()
    print(f"[ok] #{a.id} -> {action}")
