#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PDB Report — 报告/SOP 域（从 pentdb.py 拆出的零行为变更重构）。

  - _parse_finding_detail / _pentest_report / cmd_report 的报告正文装配
    （cmd_report 因调用留守 pentdb.py 的 lint_report——journal monkeypatch 语义要求
    JOURNAL_DIR 相关对账函数留在主文件——故 cmd_report 留守 pentdb.py，见拆分说明）
  - load_sop_cfg / _term_in / _hints_menu / sop_report / cmd_sop：SOP 提示清单
    （提示层非门禁；状态为关键词命中参考）

向下只依赖 pdb_core。
"""
import json

from pdb_core import SOP_CFG, connect, now, require_project

FINDING_MARKS = ("【描述】", "【请求】", "【payload】", "【判据】", "【原因】", "【手工验证】", "【修复】")

VERIFY_FRAME = ("1. 构造请求：（curl 命令 / 浏览器操作，AI 实战时补充具体参数）\n"
                "2. 观察点：（预期出现的异常响应或行为）\n"
                "3. 影响确认：（该漏洞可造成的实际危害演示）")

# ---------------- SOP 提示清单（给 AI 的查漏补缺提示层，非门禁） ----------------

STATE_ICON = {"done": "✓ 已测", "missing": "○ 未测(提示)"}


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
    sug = c.execute(
        "SELECT id, title, detail, created_at FROM raw_events "
        "WHERE project=? AND kind='suggestion' ORDER BY id DESC LIMIT 1",
        (project,)).fetchone()
    if sug:
        out += ["", "## 4 复测计划（最新批次收尾）",
                f"- 记录: suggestion #{sug['id']} ｜ 生成: {(sug['created_at'] or '')[:19]}",
                "", sug["detail"] or sug["title"] or "（空计划）"]
    out += ["", "## 5 附录：资产清单",
            "完整资产分组与状态见面板目标总览，或 `pentdb.py report --project " + project + "`（资产模式）。"]
    return "\n".join(out)


def load_sop_cfg():
    with open(SOP_CFG, encoding="utf-8") as f:
        return json.load(f)


def _term_in(term, text):
    return any(alt.lower() in (text or "").lower() for alt in term.split("|"))


def _hints_menu(cfg):
    """hints -> 扁平提示清单 [{term,when}]。同一术语在不同 when 下各自成项（不去重，保留触发语义）"""
    items = []
    for h in cfg.get("hints", []):
        for term in h.get("check", []):
            items.append({"term": term, "when": h.get("when", "")})
    return items


def sop_report(c, project):
    """扁平 SOP 提示对账：when 语义 × check 术语 × 状态参考（AI 自查用；提示层非门禁）。

    状态 = 术语与本项目 test 事件的关键词命中，仅供 AI 参考；
    真实覆盖度由 AI 显式申报、人背书，不做机器判定，也不写库（纯只读）。"""
    menu = _hints_menu(load_sop_cfg())
    tests = [dict(r) for r in c.execute(
        "SELECT * FROM raw_events WHERE project=? AND kind='test'", (project,))]
    test_texts = {t["id"]: (t["value"] or "") + " " + (t["note"] or "") + " " + (t["source"] or "")
                  for t in tests}

    hints = []
    for it in menu:
        term = it["term"]
        hit = next((t for t in tests if _term_in(term, test_texts[t["id"]])), None)
        st, ev = ("done", "#" + str(hit["id"])) if hit else ("missing", None)
        hints.append({"term": term, "when": it["when"], "state": st, "ev": ev})

    cnt = lambda s: sum(1 for h in hints if h["state"] == s)
    return {"hints": hints, "total": len(hints),
            "done": cnt("done"), "missing": cnt("missing")}

def cmd_sop(a):
    c = connect()
    require_project(c, a.project)
    rep = sop_report(c, a.project)
    print("== SOP hints: %s ==" % a.project)
    print("提示项 %d | 已测 %d | 未测 %d（状态为关键词命中参考；真实覆盖由 AI 申报、人背书）"
          % (rep["total"], rep["done"], rep["missing"]))
    print("-- 按语义判断 when 是否命中当前目标面，命中才对照 check 查漏；未命中/不适用跳过并在收尾申报（提示层，非门禁）--")
    for it in rep["hints"]:
        ctx = "（%s）" % it["when"] if it["when"] else ""
        tail = "" if it["state"] == "done" else "  ← 命中则补测，未命中/不适用跳过并在收尾申报"
        print("  %-12s %-14s %s%s" % (STATE_ICON[it["state"]], it["term"], ctx, tail))
