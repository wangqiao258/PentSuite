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

拆分说明（零行为变更重构）:
  共享内核/资产域/漏洞证据生命周期域/报告SOP域/面板工具域 分别落在
  pdb_core.py / pdb_assets.py / pdb_findings.py / pdb_report.py / pdb_tooling.py；
  本文件保留：执行流水对账（JOURNAL_DIR/probe_like/journal_unmatched）、lint
  （lint_report/cmd_lint，需裸名读取本模块 JOURNAL_DIR 以支持测试 monkeypatch）、
  cmd_report（依赖 lint_report 出口门禁）、main() 入口，并对全部 pdb_* 符号做
  façade re-export（server.py 与测试以 pentdb.xxx 属性访问，外部引用面不变）。
"""
import argparse
import json
import os
import re
import sqlite3
import sys

# 执行流水（journal）：PreToolUse hook（pentdb/hooks/journal.py）落盘的宿主命令流水，
# lint 收尾对账"测了没记"——journal 里探测类命令在 test 事件找不到对应记录即 error。
JOURNAL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "journal")
PROBE_TOOL_RE = re.compile(
    r"\b(curl|nmap|sqlmap|nikto|gobuster|ffuf|feroxbuster|dirsearch|nuclei|hydra|"
    r"wfuzz|dirb|whatweb|wafw00f|testssl)\b", re.I)
URL_RE = re.compile(r"https?://", re.I)

# ---- façade re-export（保持 pentdb.xxx 外部引用面不变；禁止 pdb_* 反向 import 本文件） ----
from pdb_core import (ASSET_KINDS, BASE, DB_PATH, EVIDENCE_READ_LIMIT,
                      FACT_KINDS, SCHEMA, SOP_CFG, STALE_DAYS, VALID_KINDS,
                      VALID_ORIGIN, VALID_SEVERITY, VALID_SCOPE, VALID_STATUS,
                      attach_evidence, connect, decode_text_compat, log_change,
                      now, read_text_compat, require_project)
from pdb_assets import (_norm_domain, _resolve_host, _split_hostport,
                        apply_review, asset_is_stale, asset_review_state,
                        cmd_add, cmd_archive, cmd_init, cmd_pending,
                        cmd_probe_import, cmd_query, cmd_rebuild_assets,
                        cmd_review, cmd_unarchive, findings_for_asset,
                        probe_ingest, probe_parse_file, rebuild_assets,
                        tests_for_asset)
from pdb_findings import (CONCLUSION_LIFECYCLE, LIFE_CODES, TEST_CONCLUSIONS,
                          cmd_drop, cmd_evidence, cmd_evidence_move, cmd_exec,
                          cmd_lifecycle, cmd_migrate, cmd_verify, cmd_void,
                          cmd_waive,
                          exec_packets_for_asset, parse_exec_log_file,
                          parse_exec_packet, set_lifecycle,
                          sync_lifecycle_from_test)
from pdb_intents import (VALID_INTENT_STATUS, VALID_PLAN_STATUS,
                         cmd_intent, cmd_plan, intent_add, intent_close)
from pdb_report import (FINDING_MARKS, STATE_ICON, VERIFY_FRAME, _hints_menu,
                        _parse_finding_detail, _pentest_report, _term_in,
                        cmd_sop, load_sop_cfg, sop_report)
from pdb_tooling import (_CREDS_OUT_KEYS, _bootstrap_creds, _bootstrap_deps,
                         _creds_skeleton, _kb_tags, _venv_python, cmd_bootstrap,
                         cmd_hook_install, cmd_js, cmd_kb, cmd_panel, cmd_recon,
                         cmd_serve)
import pdb_assets
import pdb_core
import pdb_findings
import pdb_intents
import pdb_report
import pdb_tooling


def probe_like(cmd):
    """journal 命令是否探测/测试类：含 URL 或已知探测工具词即命中。
    pentdb.py 自身调用（exec/add/recon/js）是记账/自录通道，天然豁免。"""
    if not cmd or "pentdb.py" in cmd.replace("/", "\\").replace("\\\\", "\\"):
        return False
    return bool(URL_RE.search(cmd) or PROBE_TOOL_RE.search(cmd))


def journal_unmatched(c):
    """执行流水对账：journal 中探测类命令逐条与全库 test 事件 source 比对
    （命令串 ⊆ source 恒可平账；source ⊆ 命令串须 source≥12 字符才采信）。
    返回 {命令: 出现次数}（仅未落库的）。"""
    if not os.path.isdir(JOURNAL_DIR):
        return {}
    recs = []
    for fn in sorted(os.listdir(JOURNAL_DIR)):
        if not fn.endswith(".log"):
            continue
        try:
            with open(os.path.join(JOURNAL_DIR, fn), encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    # 会话隔离：journal 按日期全局共享，其他 WorkBuddy 会话/工作目录的
                    # 探测命令不应归因本项目（实测踩过：并行会话 urlscan 查询被误报）
                    raw_cwd = rec.get("cwd") or ""
                    cwd = os.path.normcase(os.path.normpath(raw_cwd)) if raw_cwd else ""
                    cur = os.path.normcase(os.path.normpath(os.getcwd()))
                    if cwd and cur and cwd != cur and cur not in cwd and cwd not in cur:
                        continue
                    cmd = (rec.get("cmd") or "").strip()
                    if cmd:
                        recs.append(cmd)
        except OSError:
            continue
    if not recs:
        return {}
    try:
        sources = [r[0] or "" for r in c.execute(
            "SELECT source FROM raw_events WHERE kind='test' AND voided=0")]
    except sqlite3.OperationalError:
        # 兼容单测内存库（仅建 kind/source 两列的假 raw_events）：无 voided 列时退回全量
        sources = [r[0] or "" for r in c.execute(
            "SELECT source FROM raw_events WHERE kind='test'")]
    from collections import Counter
    unmatched = Counter()
    for cmd in recs:
        # cmd ⊆ source（完全一致/exec 记长 source）恒可平账；source ⊆ cmd 方向
        # 须 source 足够长（≥12 字符）才采信——库内存在 's'/'ut' 等极短手填 source，
        # 无长度下限会让所有命令被误判"已记录"（实测踩过）
        if probe_like(cmd) and not any(
                s and (cmd in s or (len(s) >= 12 and s in cmd))
                for s in sources):
            unmatched[cmd] += 1
    return dict(unmatched)


def _lint_item(code, what, why, fix, rid=None, waive=None):
    """lint 结构化条目：code 规则号 / rid 记录 id / what 一句话问题 / why 影响 /
    fix 修法（祈使句）/ waive 豁免提示（可空）。面板按字段渲染，CLI 渲染成行。"""
    return {"code": code, "rid": rid, "what": what, "why": why, "fix": fix, "waive": waive}


def _fmt_lint(it):
    """结构化条目 → 单行文本（CLI/兼容层）。what/why 关键词保持稳定供子串匹配。"""
    head = f"[{it['code']}]" + (f" #{it['rid']}" if it.get("rid") else "") + " " + it["what"]
    parts = [head, it["why"], "修复: " + it["fix"]]
    if it.get("waive"):
        parts.append(it["waive"])
    return " ｜ ".join(parts)


def lint_report(c, project, journal_check=True):
    """lint 扫描（面板/CLI 共用）。条目信息分层：问题(what)/影响(why)/修法(fix)分离，
    豁免单列 draft_waives 不混入 warns（对齐 ESLint/SonarQube 的 rule id+分段文案惯例）。
    返回 {"errors": [渲染行], "warns": [渲染行],
          "items": {"errors": [结构化], "warns": [结构化]},
          "draft_waives": [...], "summary": {blocking, waive_pending, advice}}。"""
    errors, warns = [], []

    def err(**kw):
        errors.append(_lint_item(**kw))

    def warn(**kw):
        warns.append(_lint_item(**kw))

    # test 事件缺 parent_ext 无补录通道（test 是事件流，--update 不适用），
    # 允许用 waive(event_id=该事件, term 含 parent_ext) 留痕豁免；豁免清单收尾提交用户裁决。
    wrows = c.execute("SELECT id,event_id,term,reason,confirmed FROM waives WHERE project=?",
                      (project,)).fetchall()
    # 豁免只有"已确认"（confirmed=1）才生效——AI 可起草豁免但不得自批（对齐 kb approve 的人审门）；
    # confirmed=2 为人工作废态（作废后阻断恢复、不进待确认清单）
    waived_pe = {w["event_id"] for w in wrows
                 if "parent_ext" in (w["term"] or "") and w["confirmed"] == 1}
    waived_capture = {w["event_id"] for w in wrows
                      if ("抓包" in (w["term"] or "") or "取证" in (w["term"] or ""))
                      and w["confirmed"] == 1}
    # 作废记录（voided=1）= 人裁决的无效数据：不进任何对账/阻断（区别于豁免）
    voided_ids = {r[0] for r in c.execute(
        "SELECT id FROM raw_events WHERE project=? AND voided=1", (project,))}
    # 人审驳回（status='rejected'）的事件：其挂起的豁免草稿是历史孤儿
    # （apply_review 联动作废修复前遗留），防御性不再计入"豁免待确认"
    rejected_ids = {r[0] for r in c.execute(
        "SELECT id FROM raw_events WHERE project=? AND status='rejected'", (project,))}
    draft_waives = [w for w in wrows
                    if w["confirmed"] == 0
                    and w["event_id"] not in rejected_ids
                    and w["event_id"] not in voided_ids]
    draft_by_event = {w["event_id"]: w["id"] for w in draft_waives}

    def pe_waive(rid):
        # test 归因豁免：已有起草 → 指明 wid 待确认；没有 → 告知豁免通道
        return (f"豁免 wid={draft_by_event[rid]} 待你确认" if rid in draft_by_event
                else "历史数据无补录通道: 用 waive 命令按事件起草豁免")

    def capture_waive(rid):
        return (f"豁免 wid={draft_by_event[rid]} 待你确认" if rid in draft_by_event
                else "确属取不回可起草豁免（人工确认后生效）")

    ev_req = {r[0] for r in c.execute(
        "SELECT event_id FROM evidence WHERE project=? AND note LIKE 'request%'", (project,))}
    ev_resp = {r[0] for r in c.execute(
        "SELECT event_id FROM evidence WHERE project=? AND note LIKE 'response%'", (project,))}
    # 对账①：evidence 登记的文件在磁盘上丢了 = 证据链断裂（report/kb 沉淀会引用不到）
    for er in c.execute("SELECT id, event_id, path FROM evidence WHERE project=?", (project,)):
        if er["event_id"] in voided_ids:
            continue
        if (er["path"] or "") and not os.path.exists(er["path"]):
            err(code="E-101", rid=er["id"], what="证据文件丢失",
                why="登记在库的证据文件在磁盘上找不到（证据链断裂）",
                fix="重新取证后用 evidence 挂回，或核实后移除该证据登记")
    # 对账②：test 执行了但零证据输出（跑过没留痕，测了没记的变体；exec 产出天然豁免）
    ev_any = {r[0] for r in c.execute(
        "SELECT DISTINCT event_id FROM evidence WHERE project=? AND event_id != 0", (project,))}
    for r in c.execute("SELECT * FROM raw_events WHERE project=? AND voided=0", (project,)):
        rid = r["id"]
        if not (r["source"] or "").strip():
            err(code="E-102", rid=rid, what="记录无溯源",
                why="source 为空，无法追溯这条结论来自哪条命令或 URL",
                fix="补记来源（测试类走 exec 通道自动带 source）")
        if r["status"] not in VALID_STATUS:
            err(code="E-103", rid=rid, what=f"记录状态非法: {r['status']}",
                why="状态机只认 new/confirmed/rejected",
                fix="核实后用 review 命令改回合法状态")
        if r["kind"] not in VALID_KINDS:
            err(code="E-104", rid=rid, what=f"记录类型非法: {r['kind']}",
                why="不在合法类型表内，面板与报告无法归类",
                fix="核实录入时的 kind 参数")
        if r["origin"] == "agent" and not (r["confidence"] or "").strip():
            warn(code="W-501", rid=rid, what="AI 写入缺置信度",
                 why="无 confidence 无法区分推断把握度",
                 fix="补 confidence（high/medium/low）")
        if (r["severity"] or "") and r["severity"] not in VALID_SEVERITY:
            warn(code="W-502", rid=rid, what=f"严重度取值非法: {r['severity']}",
                 why="不在合法严重度表内",
                 fix="改为合法取值（见 README 数据模型）")
        if (r["scope"] or "unknown") not in VALID_SCOPE:
            err(code="E-105", rid=rid, what=f"授权范围字段非法: {r['scope']}",
                 why="scope 决定测试合规边界，取值非法即失效",
                 fix="改为合法取值（in/out，见 README）")
        if (r["kind"] == "test" and not (r["parent_ext"] or "").strip()
                and rid not in waived_pe):
            err(code="T-201", rid=rid, what="测试未关联被测对象",
                why="无法归因，面板与报告看不出这条测试测的是谁",
                fix="test 用 exec 通道录入会自动归因；多对象逗号分隔",
                waive=pe_waive(rid))
        if (r["kind"] == "test" and not ((r["title"] or "").strip()
                or (r["detail"] or "").strip() or (r["note"] or "").strip())):
            warn(code="T-202", rid=rid, what="测试记录无内容",
                 why="title/detail/note 全空，是待审页里的空壳噪音",
                 fix="补写结论或移除该登记")
        if r["kind"] == "test" and rid not in ev_any:
            warn(code="T-503", rid=rid, what="测试零留痕",
                 why="执行过但没有任何证据输出，是「测了没记」的变体",
                 fix="探测/测试走 exec 通道（输出自动随库），手工落库的补 evidence")
        if r["kind"] == "test" and (r["note"] or "").strip() \
                and not (r["note"] or "").strip().startswith(TEST_CONCLUSIONS):
            warn(code="T-504", rid=rid, what="结论未用结论词开头",
                 why="复测时间轴聚合与生命周期联动依赖结论词（复现/未复现/已修复/部分修复/仍存在/待复测）",
                 fix="note 改为以结论词开头")
        if r["kind"] == "test" and (r["note"] or "").strip() \
                and (r["note"] or "").strip().startswith(TEST_CONCLUSIONS) \
                and "依据" not in (r["note"] or ""):
            warn(code="T-505", rid=rid, what="结论缺判断依据",
                 why="建议「结论 ｜ 依据: 关键输出」两段式，决策链在面板可复核",
                 fix="补写依据段")
        if (r["kind"] in ("finding", "osint", "suggestion")
                and not (r["title"] or "").strip()):
            warn(code="C-201", rid=rid, what=f"{r['kind']} 缺标题",
                 why="待审页无标题不可读",
                 fix="补写 title")
        if r["kind"] == "suggestion" and not (r["detail"] or "").strip() \
                and not (r["note"] or "").strip():
            warn(code="S-201", rid=rid, what="批次计划无正文",
                 why="空计划会被报告「复测计划」节引用为最新计划",
                 fix="按【已做】/【结论】/【下一步】三段写 detail")
        if r["kind"] == "suggestion" and (r["detail"] or "") \
                and "【下一步】" not in r["detail"]:
            warn(code="S-503", rid=rid, what="批次计划缺【下一步】段",
                 why="计划是一等公民，缺段后面板与报告看不到后续安排",
                 fix="按【已做】/【结论】/【下一步】三段补全")
        # 人审驳回的 finding/osint 不进报告「发现」节：证据/内容类检查全部跳过
        # （有效性已由人裁决，报文门禁不该再逼豁免——对齐"降级登记"语义）
        rej = r["status"] == "rejected" and r["kind"] in ("finding", "osint")
        if r["kind"] == "finding" and not rej and (r["detail"] or "") and "【" not in r["detail"]:
            warn(code="F-501", rid=rid, what="漏洞描述未分节",
                 why="整段散文不易复核",
                 fix="按【描述】/【复测结论】/【修复建议】分节落库")
        if r["kind"] == "finding" and not rej and (r["detail"] or "") and "【请求】" not in r["detail"] \
                and "【payload】" not in r["detail"]:
            warn(code="F-502", rid=rid, what="漏洞缺用例段",
                 why="建议补【请求】/【payload】段（是用例不是事实，事实报文=evidence 的 request/response 对）",
                 fix="detail 补用例段")
        if r["kind"] == "finding" and not rej and rid not in waived_capture \
                and (rid not in ev_req or rid not in ev_resp):
            err(code="F-301", rid=rid, what="漏洞无可重放报文",
                why="缺 request/response 证据，报告无法举证、复测无法重放",
                fix="exec 重放落盘，或 evidence --event-id 挂报文",
                waive=capture_waive(rid))
        if r["kind"] == "finding" and not rej and not (r["parent_ext"] or "").strip():
            warn(code="F-503", rid=rid, what="漏洞未关联资产",
                 why="应归因到被测资产，目标上下文断裂",
                 fix="update --id 本条 --parent-ext 资产id")
        # osint 对账：情报参考至少一份事实取证材料（与 finding 报文门禁同一套豁免/确认机制）
        if r["kind"] == "osint" and not rej and rid not in waived_capture and rid not in ev_any:
            err(code="O-301", rid=rid, what="情报无取证材料",
                why="只有结论没有原始材料，来源无法复核",
                fix="evidence --event-id 挂原始响应/输出",
                waive=capture_waive(rid))
    # 对账④：同指纹 finding 多条非 rejected（写入即并入生效前的存量/--no-dedupe 产物）——归并裁决交人工
    groups = {}
    for r in c.execute("SELECT id, dedup_key FROM raw_events WHERE project=? AND kind='finding' "
                       "AND status!='rejected' AND dedup_key!='' AND voided=0 ORDER BY id", (project,)):
        groups.setdefault(r["dedup_key"], []).append(r["id"])
    for k, ids in sorted(groups.items()):
        if len(ids) > 1:
            warn(code="F-504", rid=None,
                 what="疑似同一漏洞多登记（同指纹 ×{}: #{}）".format(
                     len(ids), "、#".join(map(str, ids))),
                 why="同指纹按归并语义疑似重复登记",
                 fix="人工归并或驳回；确属不同漏洞可忽略")
    # 对账③：执行流水对账（journal 有探测类命令、test 事件里无对应记录 = 测了没记）
    if journal_check:
        for cmd, n in sorted(journal_unmatched(c).items(), key=lambda kv: -kv[1]):
            shown = cmd if len(cmd) <= 60 else cmd[:57] + "…"
            err(code="J-601", rid=None,
                what=f"命令流水未入库 ×{n}: {shown}",
                why="执行流水里有探测命令，库内无对应 test 记录（测了没记）",
                fix="exec 单通道补记，或 add --kind test 登记结论")
    return {"errors": [_fmt_lint(i) for i in errors],
            "warns": [_fmt_lint(i) for i in warns],
            "items": {"errors": errors, "warns": warns},
            "draft_waives": [{"id": w["id"], "event_id": w["event_id"], "term": w["term"],
                              "reason": w["reason"]} for w in draft_waives],
            "summary": {"blocking": len(errors), "waive_pending": len(draft_waives),
                        "health": len(warns)}}


def cmd_lint(a):
    c = connect()
    try:
        require_project(c, a.project)
        rep = lint_report(c, a.project, journal_check=not getattr(a, "no_journal", False))
        s = rep["summary"]
        print(f"== 门禁: 阻断 {s['blocking']} ｜ 豁免待确认 {s['waive_pending']} ｜ "
              f"健康度提示 {s['health']} ==")
        for e in rep["errors"]:
            print(f"[阻断] {e}")
        for w in rep["draft_waives"]:
            print(f"[豁免待确认] wid={w['id']} #{w['event_id']} {w['term']} — "
                  f"{w['reason'] or '（未写理由）'} ｜ "
                  f"确认: waive --project {a.project} --wid {w['id']} --confirm ｜ "
                  f"作废: waive --project {a.project} --wid {w['id']} --reject")
        if getattr(a, "health", False):
            for w in rep["warns"]:
                print(f"[健康度] {w}")
        elif rep["warns"]:
            print(f"（健康度提示 {len(rep['warns'])} 条不阻断，仅面板可见；--health 查看）")
        sys.exit(1 if rep["errors"] else 0)
    finally:
        c.close()


def cmd_report(a):
    c = connect()
    try:
        _report_run(c, a)
    finally:
        c.close()


def _report_run(c, a):
    """cmd_report 的出报告主体（连接由 cmd_report 持有并在 finally 关闭）。"""
    require_project(c, a.project)
    # 报告出口门禁：lint 有 error 拒绝出报告（防"收尾忘了跑 lint"绕过；--force 仅限人工解除）
    rep = lint_report(c, a.project)
    if rep["errors"] and not getattr(a, "force", False):
        for e in rep["errors"]:
            print(f"[阻断] {e}")
        sys.exit(f"[x] 报告出口门禁：{len(rep['errors'])} 项阻断——逐条修复，或人工确认豁免；"
                 f"带错出报告: --force（人的决定，AI 不得使用）")
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
    rows = c.execute("SELECT * FROM raw_events WHERE project=? AND voided=0 ORDER BY kind, id",
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


def main():
    p = argparse.ArgumentParser(description="PentDB 写库唯一入口")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("init")
    sp.add_argument("--project", required=True)
    sp.set_defaults(fn=cmd_init)

    sp = sub.add_parser("archive", help="项目归档：面板下拉默认隐藏，数据保留可查（真删除仍走 drop --confirm）")
    sp.add_argument("--project", required=True)
    sp.set_defaults(fn=cmd_archive)

    sp = sub.add_parser("unarchive", help="取消归档：恢复面板下拉显示")
    sp.add_argument("--project", required=True)
    sp.set_defaults(fn=cmd_unarchive)

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
                    help="finding/osint：真实请求原文（文件路径或 - 接 stdin），自动挂 evidence note=request（osint 至少 req/resp 一项）")
    sp.add_argument("--resp", default="",
                    help="finding/osint：真实响应原文（文件路径或 - 接 stdin），自动挂 evidence note=response（osint 至少 req/resp 一项）")
    sp.add_argument("--waive-capture", dest="waive_capture", default="",
                    help="finding/osint：报文/取证材料确实取不回时的豁免原因（无报文/无取证建档，豁免起草待人确认生效）")
    sp.add_argument("--source", required=True)
    sp.add_argument("--ext-id", dest="ext_id", default="")
    sp.add_argument("--parent-ext", dest="parent_ext", default="")
    sp.add_argument("--merge-key", dest="merge_key", default="")
    sp.add_argument("--status", default=None, choices=VALID_STATUS,
                    help="缺省规则：--auto 且机器事实 kind → confirmed（零接触）；其余 → new 进待审")
    sp.add_argument("--confidence", default="")
    sp.add_argument("--severity", default="")
    sp.add_argument("--code", default="", help="HTTP 状态码（扫描器实测值）")
    sp.add_argument("--tech", default="", help="指纹/技术栈（cloudflare/tomcat/istio…）")
    sp.add_argument("--service", default="", help="端口服务（mysql/http/ssh…）")
    sp.add_argument("--scope", default="", help="范围标记 in/out/unknown（缺省=保留原值；新建缺省 unknown）")
    sp.add_argument("--auto", action="store_true",
                    help="机器可验证事实：缺省自动 confirmed（可显式 --status new 留待审）")
    sp.add_argument("--update", action="store_true",
                    help="重扫更新：同 kind+value 已存在时刷新观测字段（note/code/tech/service/来源/验证时间），状态与人审结论保留")
    sp.add_argument("--no-dedupe", dest="no_dedupe", action="store_true",
                    help="同指纹 finding 强制独立成条（默认写入即并入主条目：有报文转挂 evidence，无报文拒写）")
    sp.add_argument("--intent", dest="intent_id", type=int, default=0,
                    help="挂到探索意图 id（intent add 创建）：形成 方向→观测 血缘链；已关闭的意图拒绝挂接")
    sp.add_argument("--origin", default="agent", choices=VALID_ORIGIN)
    sp.set_defaults(fn=cmd_add)

    sp = sub.add_parser("exec", help="执行落库单通道：命令输出自动落盘+test 事件+证据挂库（防『测了没记』）")
    sp.add_argument("--project", required=True)
    sp.add_argument("--parent-ext", dest="parent_ext", required=True,
                    help="被测对象 record id（多对象逗号分隔）")
    sp.add_argument("--cmd", required=True,
                    help="完整命令串，原样执行（如 --cmd 'curl -is \"http://x\"'；外层单引号保内层双引号）")
    sp.add_argument("--action", default="", help="动作标签（进 value；缺省用命令本身）")
    sp.add_argument("--title", default="")
    sp.add_argument("--note", default="",
                    help="结论（AI 判定写这里；建议「结论 ｜ 依据：输出关键证据」两段式，复测时间轴展示）")
    sp.add_argument("--detail", default="")
    sp.add_argument("--severity", default="")
    sp.add_argument("--confidence", default="high", help="AI 写入置信度（缺省 high）")
    sp.add_argument("--timeout", type=int, default=120, help="命令超时秒数（超时仍落盘留痕）")
    sp.add_argument("--probe-parse", dest="probe_parse", action="store_true",
                    help="执行后从输出解析逐路径探测结果并批量入库 kind=probe（需 --probe-host 提供缺省 host）")
    sp.add_argument("--probe-host", dest="probe_host", default="",
                    help="--probe-parse 的缺省 host（输出行只有相对路径时必填；行内含完整 URL 则可省）")
    sp.add_argument("--intent", dest="intent_id", type=int, default=0,
                    help="test 事件挂到探索意图 id（intent add 创建；血缘链归属）")
    sp.set_defaults(fn=cmd_exec)

    sp = sub.add_parser("probe-import", help="扫描结果批量入库为 probe 观测（Burp 式全录：JSON 或 log 文本，不参与资产归并）")
    sp.add_argument("--project", required=True)
    sp.add_argument("--file", required=True, help="扫描结果文件（JSON 行列表或 dirscan/gobuster/ffuf 文本）")
    sp.add_argument("--host", default="", help="缺省 host（结果行只有相对路径时必填；行内含完整 URL/host 字段则可省）")
    sp.add_argument("--source", default="", help="溯源（缺省用文件路径；建议写 exec#编号+工具名）")
    sp.add_argument("--parent-ext", dest="parent_ext", default="", help="归属事件 id（多对象逗号分隔，可空）")
    sp.add_argument("--format", default="auto", choices=("auto", "json", "text"))
    sp.add_argument("--dry-run", dest="dry_run", action="store_true", help="只解析统计不入库")
    sp.set_defaults(fn=cmd_probe_import)

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

    sp = sub.add_parser("lint"); sp.add_argument("--project", required=True)
    sp.add_argument("--no-journal", action="store_true",
                    help="跳过执行流水（journal）对账——套件开发/非渗透场景用")
    sp.add_argument("--health", action="store_true",
                    help="输出健康度提示明细（格式类，不阻断；缺省只报条数，明细在面板）")
    sp.set_defaults(fn=cmd_lint)

    sp = sub.add_parser("hook-install", help="生成 PreToolUse journal hook 配置（默认项目级；"
                                             "--global 写用户级全工作区生效。写入后需在宿主 /hooks 面板人工审查才生效）")
    sp.add_argument("--global", dest="global_", action="store_true",
                    help="写用户级 ~/.workbuddy/settings.json（渗透发生在目标工作目录，推荐全局）")
    sp.set_defaults(fn=cmd_hook_install)

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

    sp = sub.add_parser("waive", help="豁免：AI 起草（confirmed=0，不生效），人工 --wid N --confirm 确认后生效；"
                                      "--wid N --reject 作废起草态豁免（留痕，阻断恢复）；--wid 支持逗号分隔批量")
    sp.add_argument("--project", required=True)
    sp.add_argument("--id", type=int, default=None,
                    help="起草豁免：目标事件 id（报文豁免挂 finding，归因豁免挂 test）")
    sp.add_argument("--wid", default="", help="确认/作废豁免：waive 起草时输出的豁免记录 id（逗号分隔可批量，如 34,35,36）")
    sp.add_argument("--confirm", action="store_true", help="人工确认豁免生效（人的决定，配合 --wid）")
    sp.add_argument("--reject", action="store_true", help="人工作废起草态豁免（人的决定，配合 --wid；已确认的不可作废）")
    sp.add_argument("--term", default="")
    sp.add_argument("--reason", default="")
    sp.set_defaults(fn=cmd_waive)

    sp = sub.add_parser("void", help="记录作废/恢复（人的决定）：冗余/误录数据清理通道，"
                                     "区别于豁免（记录有效但证据取不回）；作废记录退出 lint 阻断/报告/面板主视图")
    sp.add_argument("--project", required=True)
    sp.add_argument("--id", type=int, default=0, help="作废/恢复单个事件 id")
    sp.add_argument("--ids", default="", help="批量：逗号分隔事件 id，如 --ids 3391,3392,3393")
    sp.add_argument("--reason", default="", help="作废原因（必填，留痕可追溯）")
    sp.add_argument("--undo", action="store_true", help="恢复误作废的记录（同样留痕）")
    sp.set_defaults(fn=cmd_void)

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

    # ---- intent：探索意图（血缘链；借鉴 ARTEX 探索图，方向→观测可回溯） ----
    sp = sub.add_parser("intent", help="探索意图：一条 intent=一条带假设的推进方向；"
                                       "观测经 add/exec --intent N 挂接成血缘链")
    isub = sp.add_subparsers(dest="intent_cmd", required=True)

    s = isub.add_parser("add", help="新建意图（status=active）")
    s.add_argument("--project", required=True)
    s.add_argument("--goal", required=True, help="推进方向一句话（如：验证后台是否存在默认口令）")
    s.add_argument("--hypothesis", default="", help="假设/依据（为什么值得测）")
    s.add_argument("--parent", type=int, default=0, help="父意图 id（血缘链上游方向，0=根）")
    s.set_defaults(intent_cmd="add")

    s = isub.add_parser("list", help="列意图（缺省只看进行中，--all 含已关闭）")
    s.add_argument("--project", required=True)
    s.add_argument("--all", dest="all_", action="store_true")
    s.set_defaults(intent_cmd="list")

    s = isub.add_parser("show", help="意图详情：血缘父链 + 挂接的全部观测")
    s.add_argument("--project", required=True)
    s.add_argument("--id", type=int, required=True)
    s.set_defaults(intent_cmd="show")

    s = isub.add_parser("close", help="关闭意图（done=有产出/验证完成；dead=方向作废）；关闭后拒绝新挂接")
    s.add_argument("--project", required=True)
    s.add_argument("--id", type=int, required=True)
    s.add_argument("--status", required=True, choices=("done", "dead"))
    s.add_argument("--note", default="")
    s.set_defaults(intent_cmd="close")
    sp.set_defaults(fn=cmd_intent)

    # ---- plan：共享 todolist（借鉴 ARTEX planner 多轮共享清单，串行链按依赖逐步放行） ----
    sp = sub.add_parser("plan", help="共享 todolist：plan next 只出前置已满足的步骤，"
                                     "串行攻击链不错序、不重复（AI 粗筛循环的领取通道）")
    psub = sp.add_subparsers(dest="plan_cmd", required=True)

    s = psub.add_parser("add", help="追加步骤（有未满足前置 → blocked，否则 ready）")
    s.add_argument("--project", required=True)
    s.add_argument("--title", required=True, help="本步做什么（具体到目标/命令/假设）")
    s.add_argument("--depends", default="", help="前置步骤 id（逗号分隔，如 --depends 3,4）")
    s.add_argument("--intent", dest="intent_id", type=int, default=0, help="归属探索意图 id（可空）")
    s.add_argument("--note", default="")
    s.set_defaults(plan_cmd="add")

    s = psub.add_parser("next", help="领取下一步：自动晋升依赖已满足的 blocked 步骤，列出全部可执行项")
    s.add_argument("--project", required=True)
    s.set_defaults(plan_cmd="next")

    s = psub.add_parser("done", help="完成步骤（写回后自动解锁依赖它的下一步）")
    s.add_argument("--project", required=True)
    s.add_argument("--id", type=int, required=True)
    s.add_argument("--note", default="", help="收尾说明（留痕）")
    s.set_defaults(plan_cmd="done")

    s = psub.add_parser("skip", help="跳过步骤（同样视为依赖已满足，解锁下游）")
    s.add_argument("--project", required=True)
    s.add_argument("--id", type=int, required=True)
    s.add_argument("--note", default="", help="跳过原因（留痕）")
    s.set_defaults(plan_cmd="skip")

    s = psub.add_parser("list", help="列未完成步骤（--all 含 done/skip）")
    s.add_argument("--project", required=True)
    s.add_argument("--all", dest="all_", action="store_true")
    s.set_defaults(plan_cmd="list")
    sp.set_defaults(fn=cmd_plan)

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
