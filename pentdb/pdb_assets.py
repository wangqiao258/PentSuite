#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PDB Assets — 资产域（从 pentdb.py 拆出的零行为变更重构）。

观测入库（init/add）与资产实体归并层：
  - cmd_init / cmd_add：写入口（含 AI 门禁、test 幂等、重扫更新）
  - _norm_domain / _split_hostport / _resolve_host / rebuild_assets：实体归并
  - _asset_host_ctx / _hosts_of / _match_asset / _rows_for_asset：归属下钻共享核心
  - findings_for_asset / tests_for_asset：finding·osint / test 按资产归属下钻（纯查询）
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
                      connect, dedup_key_for, log_change, now, require_project)


def cmd_init(a):
    c = connect()
    try:
        if c.execute("SELECT 1 FROM projects WHERE name=?", (a.project,)).fetchone():
            print(f"[=] 项目已存在: {a.project}")
            return
        c.execute("INSERT INTO projects(name, created_at) VALUES(?,?)", (a.project, now()))
        log_change(c, a.project, "init", "阶段默认全开，AI/面板按目标与授权收窄")
        c.commit()
        print(f"[ok] 项目已建立: {a.project}  db={DB_PATH}")
    finally:
        c.close()


def _set_archived(project, flag):
    """归档/取消归档的公共核心：只翻标记，不动任何数据。真删除仍走 drop（--confirm）。"""
    c = connect()
    try:
        require_project(c, project)
        c.execute("UPDATE projects SET archived=? WHERE name=?", (flag, project))
        action = "archive" if flag else "unarchive"
        word = "已归档" if flag else "已取消归档"
        log_change(c, project, action, f"项目 {project} {word}")
        c.commit()
        tip = "面板下拉默认隐藏，「含归档」开关可见；数据保留可查" if flag else "面板下拉恢复显示"
        print(f"[ok] 项目 {project} {word}（{tip}）")
    finally:
        c.close()


def cmd_archive(a):
    """项目归档：面板项目下拉默认隐藏，数据/证据全部保留可查；真删除仍走 drop。"""
    _set_archived(a.project, 1)


def cmd_unarchive(a):
    """取消归档：恢复面板下拉默认显示。"""
    _set_archived(a.project, 0)


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
    if a.scope and a.scope not in VALID_SCOPE:
        sys.exit(f"[x] scope 必须是 {'/'.join(VALID_SCOPE)}")
    # test 是过程记录不是空壳：必须带 title/detail/note 至少一项，否则待审页全是空白噪音
    if a.kind == "test" and not ((a.title or "").strip() or (a.detail or "").strip() or (a.note or "").strip()):
        sys.exit("[x] test 事件必须带 --title 或 --detail 或 --note（过程描述），"
                 "纯脚本执行痕迹请勿入库——待审页只收可读记录")
    c = connect()
    try:
        _add_write(c, a, status, req_val, resp_val, req_text, resp_text)
    finally:
        c.close()


def _add_write(c, a, status, req_val, resp_val, req_text, resp_text):
    """cmd_add 的落库主体（连接由 cmd_add 持有并在 finally 关闭，测试直调不留泄漏连接）。"""
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
            # scope 显式传入时允许重扫更新修正（缺省空串=保留原值；旧数据空/unknown 视为 unknown）
            old_scope = dup["scope"] or "unknown"
            if a.scope and a.scope != old_scope:
                changes.append(f"scope {old_scope} -> {a.scope}")
            c.execute("UPDATE raw_events SET note=?, detail=?, code=?, tech=?, service=?, title=?, scope=?, source=?, "
                      "dedup_key=?, verified_at=?, updated_at=? WHERE id=?",
                      (a.note or "", a.detail if a.detail is not None else dup["detail"],
                       str(a.code or ""), a.tech or "", a.service or "",
                       a.title if (a.title or "") else (dup["title"] or ""),
                       a.scope or old_scope,
                       a.source, dedup_key_for(a.value, a.title or dup["title"]),
                       now(), now(), dup["id"]))
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
    # osint（情报参考）同理收口：被动情报至少一份事实取证材料（--resp 或 --req 任一，不强制成对）
    if a.kind == "osint" and not req_val and not resp_val:
        if not (getattr(a, "waive_capture", "") or "").strip():
            sys.exit("[x] 情报参考必须带事实取证材料：--resp <文件|->（API 响应/页面原文/工具输出）"
                     "或 --req 任一（写入口强制）；"
                     "材料确实取不回的，加 --waive-capture '原因' 起草豁免——"
                     "豁免待人工确认生效，确认前 lint 仍报 error，AI 不得代批")
    # finding 去重指纹：同 project+dedup_key（目标端点集+漏洞身份相同）视为同一漏洞。
    # 有新报文 → 证据转挂主条目（dedup-merge 留痕）不新建；无新报文 → 拒写；--no-dedupe 逃生强制独立成条。
    # （放在报文门禁之后：走到这里 finding 必有 req/resp 或已起草豁免）
    dedup = ""
    if a.kind == "finding":
        dedup = dedup_key_for(a.value, a.title)
        if dedup and not getattr(a, "no_dedupe", False):
            master = c.execute(
                "SELECT id, title FROM raw_events WHERE project=? AND kind='finding' "
                "AND dedup_key=? AND status!='rejected' ORDER BY id LIMIT 1",
                (a.project, dedup)).fetchone()
            if master:
                if not (req_val or resp_val):
                    sys.exit(f"[x] 同指纹 finding 已存在 #{master['id']}（{master['title'][:40]}）："
                             f"无新报文的重复登记不入库——补材料 --req/--resp（自动转挂主条目），"
                             f"豁免请作用于主条目；确属不同漏洞加 --no-dedupe 强制独立成条")
                ev_ids = []
                if req_val:
                    ev_ids.append(attach_evidence(c, a.project, master["id"],
                                  path="" if req_text is not None else req_val,
                                  text=req_text, note="request"))
                if resp_val:
                    ev_ids.append(attach_evidence(c, a.project, master["id"],
                                  path="" if resp_text is not None else resp_val,
                                  text=resp_text, note="response"))
                log_change(c, a.project, "dedup-merge",
                           f"重复 finding 并入 #{master['id']}（指纹 {dedup}）：{a.title or a.value} ｜ "
                           f"报文转挂 evidence {'/'.join(map(str, ev_ids))}")
                c.commit()
                print(f"[ok] 同指纹重复：报文已转挂主条目 #{master['id']}（指纹 {dedup}），"
                      f"不新建待审条目；强制独立成条加 --no-dedupe")
                return
    merge_key = a.merge_key or (a.value if a.kind == "domain" else "")
    verified = now() if status == "confirmed" else ""
    ts = now()
    cur = c.execute(
        "INSERT INTO raw_events(project,ext_id,kind,value,title,detail,note,parent_ext,"
        "merge_key,status,confidence,severity,code,tech,service,scope,dedup_key,verified_at,source,origin,created_at,updated_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (a.project, a.ext_id, a.kind, a.value, a.title or "", a.detail or "",
         a.note or "", a.parent_ext or "", merge_key, status, a.confidence or "",
         a.severity or "", str(a.code or ""), a.tech or "", a.service or "",
         a.scope or "unknown", dedup, verified, a.source, a.origin, ts, ts))
    log_change(c, a.project, "add", f"#{cur.lastrowid} {a.kind}:{a.value[:60]}")
    c.commit()
    if a.kind == "test":
        # test 结论 → finding 生命周期自动联动（add 与 exec 两通道都经本写入口，天然全覆盖）。
        # 幂等克制：note 非机读词开头（散文）/「待复测」/目标已同值 均不触发、不报错；
        # 留痕复用 set_lifecycle，tag=（test#N 自动）与手动 CLI 的（CLI）可区分。
        from pdb_findings import sync_lifecycle_from_test  # 函数级延迟导入：pdb_findings 顶层依赖本模块，避免环
        linked = sync_lifecycle_from_test(c, a.project, cur.lastrowid, a.note, a.parent_ext)
        if linked:
            c.commit()
    if a.kind in ("finding", "osint") and (req_val or resp_val):
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
    if a.kind in ("finding", "osint") and (getattr(a, "waive_capture", "") or "").strip():
        reason = a.waive_capture.strip()
        # term 用于 lint 对账匹配：finding=无抓包待补、osint=无取证待补（lint 按 抓包/取证 双词命中）
        term = "无取证待补" if a.kind == "osint" else "无抓包待补"
        verb = "无取证建档" if a.kind == "osint" else "无报文建档"
        wcur = c.execute("INSERT INTO waives(project,event_id,term,reason,at,confirmed) VALUES(?,?,?,?,?,0)",
                         (a.project, cur.lastrowid, term, reason, now()))
        log_change(c, a.project, "waive",
                   f"wid={wcur.lastrowid} #{cur.lastrowid} {term}（起草，待人工确认）: {reason}")
        c.commit()
        print(f"[!] {verb}：豁免 wid={wcur.lastrowid} 已起草——待人工确认后生效："
              f"waive --project {a.project} --wid {wcur.lastrowid} --confirm（确认前 lint 仍报 error）")
    if a.kind in ASSET_KINDS:
        rebuild_assets(c, a.project)
        c.commit()
    print(f"[ok] 事件 #{cur.lastrowid} 已入库 ({a.kind}: {a.value[:60]}) status={status}")


# ---------------- probe 观测层（Burp 式：扫描所见逐条入 raw_events，零门槛、纯观测、不参与资产归并） ----------------
# 动机：目录扫描的逐路径结果此前只活在 exec .log 与 osint 散文摘要里（观测层断流）——
# 面板无信息、不可查、不可过滤。probe 事件 = 一次 HTTP 探测的机器事实（host/path/status/len/...），
# append-only 可重观测（同路径不同状态码是合法新观测），经 /api/probes 供面板按 host 下钻与过滤。
# 注意：probe 不进 ASSET_KINDS——endpoint 准入门槛（确认的 path 事件）不变，防止 404 灌爆资产树。

# 文本行解析器（按序尝试，命中即止）：①本套件 dirscan log 格式 ②gobuster/dirb 通用 ③ffuf 标准输出
_PROBE_TEXT_RES = (
    re.compile(r"^(?P<path>\S+)\s+(?P<status>\d{3})\s+len=(?P<len>\d+)"
               r"(?:\s+ct=(?P<ct>\S+))?(?:\s+loc=(?P<loc>\S*))?\s*$"),
    re.compile(r"^(?P<status>\d{3})\s+(?P<len>\d+)\s+(?P<url>\S+)\s*$"),
    re.compile(r"^(?P<url>https?://\S+)\s+(?P<status>\d{3})\s+(?P<words>\d+)\s+(?P<lines>\d+)\s+(?P<len>\d+)\s*$"),
)


def _probe_split_url(url):
    """'https://ca.jbl.com/en_CA/404' -> ('ca.jbl.com', '/en_CA/404')；解析失败返回 (None, None)。"""
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/\s:]+)(?::\d+)?(/\S*)?$", url.strip())
    if not m:
        return None, None
    return m.group(1).lower(), m.group(2) or "/"


def probe_parse_text(raw, host_default=""):
    """文本逐行解析（dirscan log / gobuster / ffuf 行格式）-> 标准化 probe 行。
    无法确定 host 的行跳过；注释/日志装饰行（$ exit= [ == --- 开头）忽略。"""
    rows = []
    for line in raw.splitlines():
        line = line.rstrip()
        if not line or line.startswith(("$ ", "exit=", "[", "==", "---")):
            continue
        m = next((rx.match(line) for rx in _PROBE_TEXT_RES if rx.match(line)), None)
        if not m:
            continue
        g = m.groupdict()
        if g.get("url"):
            host, ph = _probe_split_url(g["url"])
        else:
            host, ph = (host_default or "").strip().lower().rstrip("."), g["path"]
        if not host or not ph:
            continue
        rows.append({"host": host, "path": ph, "status": g.get("status", ""),
                     "len": g.get("len") or g.get("size") or "",
                     "location": (g.get("loc") or g.get("location") or "").strip(),
                     "ctype": g.get("ct") or "", "server": ""})
    return rows


def probe_parse_file(path, host_default="", fmt="auto"):
    """解析扫描结果文件 -> 标准化 probe 行列表 [{host,path,status,len,location,ctype,server}]。
    fmt: auto=先按 JSON 试、失败回退文本逐行 ｜ json ｜ text。"""
    with open(path, encoding="utf-8", errors="ignore") as f:
        raw = f.read()
    if fmt in ("auto", "json"):
        try:
            data = json.loads(raw)
            if isinstance(data, list) and (not data or isinstance(data[0], dict)):
                return probe_parse_rows(data, host_default)
        except (ValueError, TypeError):
            if fmt == "json":
                raise
    return probe_parse_text(raw, host_default)


def probe_parse_rows(data, host_default=""):
    """JSON 行列表 -> 标准化 probe 行。支持 {host,path,status,len,location,ctype,server}
    与 {url,status,len,...}（url 拆 host/path）；缺 host 用 host_default；仍缺则跳过。"""
    out, skipped = [], 0
    for r in data:
        if not isinstance(r, dict):
            skipped += 1
            continue
        url = (r.get("url") or "").strip()
        if url:
            host, ph = _probe_split_url(url)
        else:
            host, ph = (r.get("host") or host_default or "").strip().lower().rstrip("."), (r.get("path") or "").strip()
        status = str(r.get("status") or "").strip()
        if not host or not ph or not status.isdigit():
            skipped += 1
            continue
        out.append({"host": host, "path": ph, "status": status,
                    "len": str(r.get("len") or r.get("size") or "").strip(),
                    "location": str(r.get("location") or r.get("loc") or "").strip(),
                    "ctype": str(r.get("ctype") or r.get("ct") or "").strip(),
                    "server": str(r.get("server") or "").strip()})
    return out


def probe_ingest(c, project, rows, source, parent_ext="", origin="agent"):
    """标准化 probe 行批量入库（单事务+单条 changelog）。同 (host, attrs 全量) 已存在则跳过——
    重扫描同路径同状态视为重复，状态/长度变化视为新观测（append-only 时间线）。返回 (入库数, 跳过数)。"""
    ins = skip = 0
    for r in rows:
        attrs = json.dumps({k: v for k, v in r.items() if k != "host" and v != ""},
                           ensure_ascii=False, sort_keys=True)
        dup = c.execute("SELECT 1 FROM raw_events WHERE project=? AND kind='probe' AND value=? AND attrs=? LIMIT 1",
                        (project, r["host"], attrs)).fetchone()
        if dup:
            skip += 1
            continue
        ts = now()
        c.execute(
            "INSERT INTO raw_events(project,ext_id,kind,value,title,detail,note,parent_ext,"
            "merge_key,status,confidence,severity,code,tech,service,scope,dedup_key,verified_at,source,origin,created_at,updated_at,attrs) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (project, "", "probe", r["host"], ("%s %s%s" % (r["status"], r["host"], r["path"]))[:120],
             "", "", parent_ext or "", "", "confirmed", "high", "", "", "", "", "in",
             "", ts, source, origin, ts, ts, attrs))
        ins += 1
    if ins:
        log_change(c, project, "probe-import", "%d 条探测观测入库 (source=%s)" % (ins, source[:60]))
    return ins, skip


def cmd_probe_import(a):
    """CLI：probe-import --project P --file <json|log> [--host H] [--source S] [--parent-ext N] [--format auto|json|text] [--dry-run]"""
    if not os.path.exists(a.file):
        sys.exit(f"[x] 文件不存在: {a.file}")
    c = connect()
    try:
        require_project(c, a.project)
        rows = probe_parse_file(a.file, a.host or "", a.format or "auto")
        if not rows:
            sys.exit("[x] 未解析出任何探测行（检查 --format / --host / 文件格式）")
        per_host = {}
        for r in rows:
            per_host[r["host"]] = per_host.get(r["host"], 0) + 1
        print(f"[=] 解析 {len(rows)} 行 ｜ host {len(per_host)} 个 ｜ "
              + " ｜ ".join(f"{h}:{n}" for h, n in sorted(per_host.items(), key=lambda x: -x[1])[:8])
              + (" …" if len(per_host) > 8 else ""))
        if a.dry_run:
            print("[=] --dry-run：未入库")
            return
        ins, skip = probe_ingest(c, a.project, rows, a.source or a.file, a.parent_ext or "")
        c.commit()
        print(f"[ok] probe 观测入库 {ins} 条，跳过重复 {skip} 条 ｜ 面板资产页 host 详情「探测观测」页签可查")
    finally:
        c.close()



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

    # endpoint 归属拍板（2026-10）：一律归 host（parent_atype=host、parent_akey=host akey），
    # 接受副作用（akey 无 scheme/端口；同 host 的 http/https 同路径归并为一行）。
    # host 观测可能先于/后于 path 出现，服务键需预先收集：parent_ext 若直指 service
    # （'host:port'），上溯剥离端口归挂其 host；host 实体不存在时保持解析值兜底（面板合成挂靠，不引入新状态）。
    svc_keys = set()
    for r in rows:
        if r["kind"] == "port":
            h, p = _split_hostport(r["value"])
            if h and p:
                svc_keys.add(f"{h}:{p}")

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
            if host in svc_keys:  # parent_ext 指向 service：上溯一层归其 host
                host = host.rsplit(":", 1)[0]
            p = val if val.startswith("/") else "/" + val
            akey = (host + p) if host else ("?" + p)
            e = put("endpoint", akey, akey, "host", host, r)
            mul(e, "codes", r["code"]); mul(e, "titles", r["title"])
        elif r["kind"] == "param":
            host = _resolve_host(r["parent_ext"], by_id, path_host)
            if host in svc_keys:  # 同 path：service 引用上溯归 host
                host = host.rsplit(":", 1)[0]
            # param 归属于它所属的 endpoint：从 parent_ext 提取全部路径段，逐一并入
            paths = re.findall(r"/[^\s,]*", r["parent_ext"] or "")
            paths = [p for p in paths if len(p) > 1] or [""]
            for p in paths:
                akey = ((host + p) if host else ("?" + p)) if p else ("?" + val)
                e = put("endpoint", akey, akey, "host", host, r)
                mul(e, "params", val); mul(e, "codes", r["code"]); mul(e, "titles", r["title"])

    # parent_atype 语义修正（仅 service）：parent 解析值若实为库内域名（且无同名 host 实体），记真实类型 domain。
    # endpoint 不参与本修正（拍板：endpoint 一律归 host，即使父值同时是域名/库内无 host 实体，保持 parent_atype=host）
    dom_keys = {k for (at, k) in ent if at == "domain"}
    host_keys = {k for (at, k) in ent if at == "host"}
    for (at, k), e in ent.items():
        if at == "service" and e["parent_akey"] in dom_keys and e["parent_akey"] not in host_keys:
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


def _finding_hosts(parent_ext, by_id, path_host, depth=0):
    """findings_for_asset 专用：把一条 finding 的 parent_ext 解析成 host akey 列表。

    与 _resolve_host 的差别（_resolve_host 被 rebuild_assets 复用、语义冻结，不可改）：
    数字 id 指向 path 观测时继续上溯——真实库里 finding 常按 '#115,116,117' 引用
    path 事件，path 的 parent_ext 再一跳才指向 host；_resolve_host 的数字 id 分支
    对 path 只返回其 value（路径文本），解析不出 host。逗号拆分逐个 id 解析并收集
    全部 host（finding 横跨多端点/多主机时每个 id 都参与归属，只看首个会漏），
    depth 上限 3 防环。返回去重后的非空 host 列表，保持 token 出现顺序。
    """
    pe = (parent_ext or "").strip()
    if not pe or depth > 3:
        return []
    hosts = []
    for p in [x.strip() for x in pe.split(",") if x.strip()]:
        if p.isdigit():  # 数字 id：引用事件（port/path/domain 等资产类观测）
            r = by_id.get(int(p))
            if not r:
                continue
            if r["kind"] == "port":
                hosts.append(_split_hostport(r["value"])[0])
            elif r["kind"] == "path":  # 两跳：path 观测的 parent_ext 才指向 host
                hosts += _finding_hosts(r["parent_ext"], by_id, path_host, depth + 1)
            else:
                hosts.append((r["value"] or "").strip().lower())
        elif p.startswith("/"):  # path 文本引用：path_host 两跳上溯（同 _resolve_host 语义）
            pid = path_host.get(p)
            if pid is not None:
                r = by_id.get(pid)
                if r:
                    hosts += _finding_hosts(r["parent_ext"], by_id, path_host, depth + 1)
        elif "/" in p:  # 'host/path' 混合写法：取 host 段
            hosts.append(p.split("/", 1)[0])
        else:
            hosts.append(p.lower())  # 直接就是 host（或 service 键，由 svc_keys 事后剥离）
    out = []
    for h in hosts:
        if h and h not in out:
            out.append(h)
    return out


def _asset_host_ctx(c, project):
    """归属解析共用上下文：资产类观测索引 (by_id, path_host, svc_keys)。

    findings/osint/test 都不参与 rebuild_assets 归并（asset.event_ids 里没有它们），
    归属全靠 parent_ext 经 _finding_hosts 解析后做 host 级归因——本函数只建索引，
    被 findings_for_asset / tests_for_asset 共用（勿在此做任何匹配逻辑）。"""
    asset_rows = [dict(r) for r in c.execute(
        "SELECT * FROM raw_events WHERE project=? AND kind IN (%s) ORDER BY id"
        % ",".join("?" * len(ASSET_KINDS)), (project,) + ASSET_KINDS)]
    by_id = {r["id"]: r for r in asset_rows}
    path_host = {}
    for r in asset_rows:
        if r["kind"] == "path" and r["value"] not in path_host:
            path_host[r["value"]] = r["id"]
    # service 键集合：parent_ext 直指 'host:port' 时上溯剥端口归 host（对齐 rebuild_assets）
    svc_keys = set()
    for r in asset_rows:
        if r["kind"] == "port":
            h, p = _split_hostport(r["value"])
            if h and p:
                svc_keys.add(f"{h}:{p}")
    return by_id, path_host, svc_keys


def _hosts_of(parent_ext, by_id, path_host, svc_keys):
    """parent_ext -> host akey 列表（_finding_hosts 解析 + service 键剥端口）。"""
    hs = _finding_hosts(parent_ext, by_id, path_host)
    return [h.rsplit(":", 1)[0] if h in svc_keys else h for h in hs]


def _match_asset(hs, atype, akey):
    """host 级归因匹配（拍板规则，findings/tests 共用）：
      host     解析列表含 akey
      service  解析列表含 akey 冒号前的 host
      endpoint 解析列表含 akey 首个 '/' 前的 host（路径段不参与匹配）
      domain   解析列表任一 == akey 或以 '.'+akey 结尾（子域归主域资产）
    解析不出 host（空列表）或未知 atype 一律不归属。"""
    if not hs:
        return False
    if atype == "host":
        return akey in hs
    if atype == "service":
        return akey.split(":", 1)[0] in hs
    if atype == "endpoint":
        return akey.split("/", 1)[0] in hs  # host 级归因：路径段不参与匹配
    if atype == "domain":
        return any(h == akey or h.endswith("." + akey) for h in hs)
    return False


def _rows_for_asset(c, project, kinds, atype, akey):
    """归属下钻共享核心：kinds 观测按 parent_ext 归属解析到指定资产，按 id 倒序。"""
    rows = [dict(r) for r in c.execute(
        "SELECT * FROM raw_events WHERE project=? AND kind IN (%s) ORDER BY id DESC"
        % ",".join("?" * len(kinds)), (project,) + tuple(kinds))]
    if not rows:
        return []
    by_id, path_host, svc_keys = _asset_host_ctx(c, project)
    akey = (akey or "").strip().lower()
    return [f for f in rows
            if _match_asset(_hosts_of(f.get("parent_ext"), by_id, path_host, svc_keys),
                            atype, akey)]


def findings_for_asset(c, project, atype, akey):
    """资产下钻：解析出归属该资产的 finding/osint 观测（纯查询只读，供面板 /api/asset-detail）。

    findings 不参与 rebuild_assets 归并，归属靠 parent_ext 经 _finding_hosts 解析成
    host akey 列表后做 **host 级归因**（匹配规则见 _match_asset，与 tests_for_asset
    共用同一套，见任务拍板：资产明细页 exec 报文按同规则归属）。返回按 id 倒序的
    dict 行列表。"""
    return _rows_for_asset(c, project, ("finding", "osint"), atype, akey)


def tests_for_asset(c, project, atype, akey):
    """资产下钻：解析出归属该资产的 test 事件（复测/探测过程记录，纯查询只读）。

    与 findings_for_asset 完全同一套归属规则（_rows_for_asset 共用核心）：
    parent_ext 经 _finding_hosts 解析为 host 列表后按资产类型匹配——真实库里 exec
    落库的 test 常带 parent_ext='jbl.com' / 'cn.jbl.com,py.jbl.com'（逗号多对象）/
    数字 id（指向 port/path 观测）三种形态，均按 findings 同语义解析。
    返回按 id 倒序的 dict 行列表（结构对齐 findings_for_asset）。"""
    return _rows_for_asset(c, project, ("test",), atype, akey)


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
    try:
        require_project(c, a.project)
        counts = rebuild_assets(c, a.project)
        log_change(c, a.project, "rebuild-assets",
                   " | ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "0")
        c.commit()
        total = sum(counts.values())
        detail = " ｜ ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "空"
        print(f"[ok] 实体层已重建: {a.project} ｜ {detail} ｜ 共 {total}")
    finally:
        c.close()


def cmd_query(a):
    c = connect()
    try:
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
    finally:
        c.close()


def cmd_pending(a):
    c = connect()
    try:
        require_project(c, a.project)
        rows = c.execute(
            "SELECT * FROM raw_events WHERE project=? AND status='new' ORDER BY id",
            (a.project,)).fetchall()
        for r in rows:
            print(f"#{r['id']} [{r['origin']:7s}/{r['confidence'] or '-':6s}] "
                  f"{r['kind']:8s} {r['value'][:70]} ｜ {(r['note'] or r['title'] or '')[:60]}")
        print(f"-- 待审 {len(rows)} 条")
    finally:
        c.close()


def apply_review(c, eid, action, note="", reviewer="human"):
    """人审落库核心（CLI review 与面板 /api/review 共用，单一实现保证 reviews/changelog/
    actor 语义一致）：改状态 + reviews 追加留痕 + changelog 留痕（actor=reviewer）。
    事件不存在返回 None；已同值幂等跳过返回 "skip"（不重复写 reviews/changelog）；
    正常落库返回所属 project。不 commit——由调用方决定提交时机（面板批量=单事务原子提交）。"""
    row = c.execute("SELECT project, status FROM raw_events WHERE id=?", (eid,)).fetchone()
    if not row:
        return None
    if row["status"] == action:
        return "skip"
    c.execute("UPDATE raw_events SET status=? WHERE id=?", (action, eid))
    c.execute("INSERT INTO reviews(event_id, action, reviewer, note, at) VALUES(?,?,?,?,?)",
              (eid, action, reviewer, note or "", now()))
    log_change(c, row["project"], "review", f"#{eid} -> {action}", actor=reviewer or "human")
    return row["project"]


def cmd_review(a):
    if not a.confirm and not a.reject:
        sys.exit("[x] 必须指定 --confirm 或 --reject")
    action = "confirmed" if a.confirm else "rejected"
    c = connect()
    try:
        require_project(c, a.project)
        if not c.execute("SELECT 1 FROM raw_events WHERE id=? AND project=?",
                         (a.id, a.project)).fetchone():
            sys.exit(f"[x] 事件不存在: #{a.id}")
        r = apply_review(c, a.id, action, note=a.note or "", reviewer=a.reviewer or "human")
        c.commit()
        if r == "skip":
            print(f"[=] #{a.id} 已是 {action}，跳过")
        else:
            print(f"[ok] #{a.id} -> {action}")
    finally:
        c.close()
