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
import sys

# 执行流水（journal）：PreToolUse hook（pentdb/hooks/journal.py）落盘的宿主命令流水，
# lint 收尾对账"测了没记"——journal 里探测类命令在 test 事件找不到对应记录即 error。
JOURNAL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "journal")
PROBE_TOOL_RE = re.compile(
    r"\b(curl|nmap|sqlmap|nikto|gobuster|ffuf|feroxbuster|dirsearch|nuclei|hydra|"
    r"wfuzz|dirb|whatweb|wafw00f|testssl)\b", re.I)
URL_RE = re.compile(r"https?://", re.I)

# ---- façade re-export（保持 pentdb.xxx 外部引用面不变；禁止 pdb_* 反向 import 本文件） ----
from pdb_core import (ASSET_KINDS, BASE, DB_PATH, FACT_KINDS, SCHEMA, SOP_CFG,
                      STALE_DAYS, VALID_KINDS, VALID_ORIGIN, VALID_SEVERITY,
                      VALID_SCOPE, VALID_STATUS, attach_evidence, connect,
                      log_change, now, require_project)
from pdb_assets import (_norm_domain, _resolve_host, _split_hostport,
                        asset_is_stale, asset_review_state, cmd_add, cmd_init,
                        cmd_pending, cmd_query, cmd_rebuild_assets, cmd_review,
                        rebuild_assets)
from pdb_findings import (CONCLUSION_LIFECYCLE, LIFE_CODES, TEST_CONCLUSIONS,
                          cmd_drop, cmd_evidence, cmd_evidence_move, cmd_exec,
                          cmd_lifecycle, cmd_migrate, cmd_verify, cmd_waive,
                          set_lifecycle, sync_lifecycle_from_test)
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


def lint_report(c, project, journal_check=True):
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
    # 对账③：执行流水对账（journal 有探测类命令、test 事件里无对应记录 = 测了没记）
    if journal_check:
        for cmd, n in sorted(journal_unmatched(c).items(),
                             key=lambda kv: -kv[1]):
            shown = cmd if len(cmd) <= 90 else cmd[:87] + "…"
            errors.append(f"执行流水未落库×{n}: {shown}（journal 有记录但无对应 test 事件"
                          f"——走 exec 单通道补记，或 add --kind test 登记结论）")
    return {"errors": errors, "warns": warns}


def cmd_lint(a):
    c = connect()
    require_project(c, a.project)
    rep = lint_report(c, a.project, journal_check=not getattr(a, "no_journal", False))
    for e in rep["errors"]:
        print(f"ERROR {e}")
    for w in rep["warns"]:
        print(f"WARN  {w}")
    print(f"-- lint: {len(rep['errors'])} error, {len(rep['warns'])} warn")
    sys.exit(1 if rep["errors"] else 0)


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

    sp = sub.add_parser("lint"); sp.add_argument("--project", required=True)
    sp.add_argument("--no-journal", action="store_true",
                    help="跳过执行流水（journal）对账——套件开发/非渗透场景用")
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
