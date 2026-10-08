#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PDB Findings — 漏洞/证据/生命周期域（从 pentdb.py 拆出的零行为变更重构）。

  - cmd_waive：豁免起草/人工确认
  - cmd_evidence / cmd_evidence_move：证据挂库与改挂（落库核心 attach_evidence 在 pdb_core）
  - cmd_verify / cmd_exec：复测打点与执行落库单通道
  - parse_exec_packet / exec_packets_for_asset：exec .log 报文解析与资产下钻投影（只读）
  - cmd_migrate / cmd_drop：历史迁移与项目删除
  - set_lifecycle / cmd_lifecycle + LIFE_CODES：漏洞生命周期

向下依赖 pdb_core 与 pdb_assets（cmd_exec 复用 cmd_add 写入口，依赖方向无环）。
"""
import argparse
import base64
import datetime
import json
import os
import re
import sys
import urllib.parse

from pdb_assets import cmd_add, tests_for_asset
from pdb_core import (AUDIT_TRIGGERS, DB_PATH, SCHEMA, VALID_STATUS,
                      attach_evidence, connect, decode_text_compat, log_change,
                      now, read_text_compat, require_project)

# ---------------- 漏洞生命周期（CLI/面板共用；存 finding 行 attrs JSON，与 status 人审态分离） ----------------

LIFE_CODES = ("open", "reproduced", "not-reproduced", "fixed", "reopened")
# test note 机读结论词（复测时间轴聚合与 lifecycle 同步依赖；note 必须以其一开头）
TEST_CONCLUSIONS = ("复现", "未复现", "已修复", "部分修复", "仍存在", "待复测")
# test 结论 → finding lifecycle 自动联动映射（拍板 2026-10）：
# 部分修复/仍存在=未根除，归 reopened；待复测=结论未定，不联动；映射外机读词与散文 note 一律不触发
CONCLUSION_LIFECYCLE = {
    "复现": "reproduced",
    "未复现": "not-reproduced",
    "已修复": "fixed",
    "部分修复": "reopened",
    "仍存在": "reopened",
}


def cmd_void(a):
    """记录作废/恢复（人的决定，对齐 review 人审语义）：冗余/误录数据的清理通道，
    区别于豁免（记录有效但证据取不回）。作废记录退出 lint 阻断、报告与面板主视图、
    资产派生；只改 voided 标记，内容字段零改动（append-only 语义不破）。"""
    c = connect()
    try:
        require_project(c, a.project)
        undo = getattr(a, "undo", False)
        ids = []
        for raw in (getattr(a, "ids", "") or "").split(","):
            raw = raw.strip()
            if raw:
                ids.append(int(raw))
        if getattr(a, "id", 0):
            ids.append(int(a.id))
        if not ids:
            sys.exit("[x] 必须指定 --id N 或 --ids N,M,…（作废只作用于具体事件）")
        if not undo and not (a.reason or "").strip():
            sys.exit("[x] 作废必须写明 --reason（为什么这条记录无效）——留痕可追溯")
        act, newv, verb = ("un-void", 0, "恢复") if undo else ("void", 1, "作废")
        done, skipped = [], []
        for eid in ids:
            row = c.execute("SELECT id, kind, title, value, voided FROM raw_events "
                            "WHERE id=? AND project=?", (eid, a.project)).fetchone()
            if not row:
                skipped.append(f"#{eid}(不存在)")
                continue
            if row["voided"] == newv:
                skipped.append(f"#{eid}(已是{'作废' if newv else '正常'}态)")
                continue
            c.execute("UPDATE raw_events SET voided=?, updated_at=? WHERE id=?",
                      (newv, now(), eid))
            log_change(c, a.project, act,
                       f"#{eid} {row['kind']} {row['title'] or row['value']}: "
                       f"{(a.reason or '').strip() or '（恢复，未写原因）'}",
                       actor="human")
            done.append(f"#{eid}")
        c.commit()
        if done:
            print(f"[ok] 已{verb} {'、'.join(done)}"
                  f"{'——退出 lint 阻断/报告/面板主视图' if not undo else ''}")
        for s in skipped:
            print(f"[=] 跳过 {s}")
    finally:
        c.close()


def _parse_wids(wid):
    """--wid 支持逗号分隔批量：waive --wid 34,35,36 --confirm。空/0 视为未指定。"""
    out = []
    for part in str(wid or "").replace("，", ",").split(","):
        part = part.strip()
        if part and part != "0":
            out.append(int(part))
    return out


def cmd_waive(a):
    c = connect()
    try:
        require_project(c, a.project)
        confirm = getattr(a, "confirm", False)
        reject = getattr(a, "reject", False)
        wids = _parse_wids(getattr(a, "wid", 0))
        if confirm and reject:
            sys.exit("[x] --confirm 与 --reject 互斥：确认生效或作废二选一")
        if reject:
            # 作废豁免是人的决定：起草态（confirmed=0）终结为 2，留痕不删除；对应阻断随之恢复
            if not wids:
                sys.exit("[x] 作废豁免必须指定 --wid <id>（可逗号分隔批量）——作废是人的决定，AI 不得代行")
            for wid in wids:
                row = c.execute("SELECT * FROM waives WHERE id=? AND project=?",
                                (wid, a.project)).fetchone()
                if not row:
                    print(f"[=] 跳过 wid={wid}（不存在）")
                    continue
                if row["confirmed"] == 2:
                    print(f"[=] 跳过 wid={wid}（已是作废态）")
                    continue
                if row["confirmed"] == 1:
                    sys.exit(f"[x] wid={wid} 已确认生效，不能作废——"
                             f"已生效的豁免代表人的决定，改主意请修复后重录")
                c.execute("UPDATE waives SET confirmed=2 WHERE id=?", (wid,))
                log_change(c, a.project, "waive-reject",
                           f"wid={wid} #{row['event_id']} {row['term']}: {row['reason']}",
                           actor="human")
                c.commit()
                print(f"[ok] wid={wid} 豁免已作废（#{row['event_id']} {row['term']}）——"
                      f"对应 lint 阻断恢复，如需放行请补证据或重新起草豁免")
            return
        if confirm:
            # 确认生效是人的决定（对齐 kb approve --confirm 模式），AI 只能起草
            if not wids:
                sys.exit("[x] 确认豁免必须指定 --wid <id>（可逗号分隔批量）——豁免生效是人的决定，AI 只能起草")
            for wid in wids:
                row = c.execute("SELECT * FROM waives WHERE id=? AND project=?",
                                (wid, a.project)).fetchone()
                if not row:
                    print(f"[=] 跳过 wid={wid}（不存在）")
                    continue
                if row["confirmed"] == 1:
                    print(f"[=] 跳过 wid={wid}（已是确认态）")
                    continue
                if row["confirmed"] == 2:
                    print(f"[=] 跳过 wid={wid}（已作废，不能确认——需要放行请重新起草）")
                    continue
                c.execute("UPDATE waives SET confirmed=1 WHERE id=?", (wid,))
                log_change(c, a.project, "waive-confirm",
                           f"wid={wid} #{row['event_id']} {row['term']}: {row['reason']}",
                           actor="human")
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
    finally:
        c.close()


def cmd_evidence(a):
    """证据入库：event_id=0 表示项目级物料（凭据表/报告等，不属于单个漏洞）。
    默认把文件复制进套件 evidence/（随库走）；--keep-in-place 只存指针；
    --text 直接把文本内容存为证据文件（复测的请求/响应原文零摩擦落库）。"""
    c = connect()
    try:
        require_project(c, a.project)
        eid = attach_evidence(c, a.project, a.event_id, path=a.path, text=a.text,
                              note=a.note, keep_in_place=a.keep_in_place)
        c.commit()
        tag = "引用" if a.keep_in_place else ("文本" if a.text is not None else "复制")
        target = f"#{a.event_id}" if a.event_id else "项目级"
        print(f"[ok] 证据 #{eid} 已挂到 {target}（{tag}）")
    finally:
        c.close()


def cmd_evidence_move(a):
    """改挂证据归属：--event-id 0 = 转项目级物料。归属判定=复测该漏洞时必须用到。"""
    c = connect()
    try:
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
    finally:
        c.close()


def cmd_verify(a):
    """复测打点：更新最后验证时间（数据时效）。"""
    c = connect()
    try:
        require_project(c, a.project)
        row = c.execute("SELECT id FROM raw_events WHERE id=? AND project=?", (a.id, a.project)).fetchone()
        if not row:
            sys.exit(f"[x] 记录不存在: #{a.id}")
        c.execute("UPDATE raw_events SET verified_at=? WHERE id=?", (now(), a.id))
        log_change(c, a.project, "verify", f"#{a.id} 复测打点")
        c.commit()
        print(f"[ok] #{a.id} 已更新验证时间")
    finally:
        c.close()


def cmd_exec(a):
    """执行落库单通道（recon 模式的推广）：AI 的探测/测试命令一律经本命令执行——
    输出强制落盘 + test 事件自动入库 + 原始输出自动挂证据，杜绝"测了没记"。
    test 事件经 cmd_add 写入口落库，结论→lifecycle 自动联动随之继承（单通道，无需另行挂钩）。
    用法：pentdb.py exec --project P --parent-ext N -- <命令...>（-- 后接实际命令，非交互）"""
    if not (a.parent_ext or "").strip():
        sys.exit("[x] --parent-ext 必填：测试必须归因到被测对象 record id（多对象逗号分隔）")
    cmd_str = (a.cmd or "").strip()
    if not cmd_str:
        sys.exit("[x] 缺 --cmd：exec --project P --parent-ext N --cmd '<完整命令>'（命令串原样执行）")
    c = connect()
    try:
        _exec_run(c, a)
    finally:
        c.close()


def _exec_run(c, a):
    """cmd_exec 的执行主体（连接由 cmd_exec 持有并在 finally 关闭）。"""
    import subprocess
    import uuid
    cmd_str = (a.cmd or "").strip()
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
    text = decode_text_compat(raw)
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
    if getattr(a, "probe_parse", False):
        # --probe-parse：从输出解析逐路径探测结果批量入库 kind=probe（Burp 式全录，不参与资产归并）。
        # 解析不出/缺 host 的行跳过并计数，绝不阻断 exec 主流程。
        from pdb_assets import probe_ingest, probe_parse_text  # 函数级导入：保持 pdb_assets→pdb_findings 单向依赖
        rows = probe_parse_text(text, a.probe_host or "")
        if rows:
            ins, skip = probe_ingest(c, a.project, rows, "exec#%s" % eid, a.parent_ext)
            c.commit()
            print(f"[probe] 观测入库 {ins} 条，跳过重复 {skip} 条")
        else:
            print("[probe] 输出中未解析出探测行（非目录扫描输出？或缺 --probe-host），跳过")
    shown = text[:6000]
    if len(text) > 6000:
        shown += "\n…（截断，完整输出见上面证据文件）"
    try:
        sys.stdout.write(shown + "\n")
    except UnicodeEncodeError:
        sys.stdout.write(shown.encode("gbk", "ignore").decode("gbk", "ignore") + "\n")


# ---------------- exec .log 报文解析器（只读投影，不落库） ----------------
# 把 exec 单通道落盘的 .log（首行 "$ <命令串>" / "exit=<码>" / 空行 / stdout+stderr）
# 还原为 request/response 报文投影：curl 命令串重建请求报文，输出原文作响应报文。
# 解析不出（非 exec 日志/非 curl 命令）返回 None；任何意外一律降级不抛异常——
# 调用方（/api/evidence/packet → 面板）拿到 None 走原文文件卡降级展示。

# curl 选项表：取值长选项（值被消费后忽略——连接/输出类参数不进报文）
_CURL_VALUE_LONG = frozenset((
    "--request", "--header", "--data", "--data-raw", "--data-binary",
    "--data-urlencode", "--url", "--user", "--user-agent", "--cookie",
    "--cookie-jar", "--referer", "--form", "--form-string", "--max-time",
    "--connect-timeout", "--retry", "--retry-delay", "--retry-max-time",
    "--proxy", "--noproxy", "--proxy-user", "--range", "--output",
    "--write-out", "--dump-header", "--cert", "--key", "--cacert", "--capath",
    "--resolve", "--connect-to", "--interface", "--upload-file", "--config",
    "--keepalive-time", "--limit-rate", "--speed-time", "--speed-limit",
    "--dns-servers"))
# 短选项里取值的字符（d/H/X/u 有专属语义在解析器内先行处理，不落此表）
_CURL_VALUE_SHORT = frozenset("ABbCcDEFKmMoPQrTtUuWwxyYzZ")
# 短选项布尔字符（i/I/v 在解析器内另有动作）
_CURL_BOOL_SHORT = frozenset("sfgkLnNq")
# Windows curl 进度噪音行（输出开头；实测 data/exec/ 样本形态）
_PROG_LINE = (re.compile(r"^\s*% Total\b"),
              re.compile(r"^\s*Dload\s+Upload\b"),
              re.compile(r"^\s*\d+\s+\d+\s.*--:--:--"))
# 未求值变量：$VAR（AI 常见）或 %VAR%（Windows cmd 形态）
_VAR_RE = re.compile(r"\$|%[A-Za-z_]\w*%")


def _join_continuation(cmd):
    """命令串行续接合并：行尾 ``\\``（sh）或 ``^``（Windows cmd）接下一行。"""
    out, pend = [], ""
    for ln in cmd.splitlines():
        cur = pend + ln.rstrip()
        pend = ""
        if cur.endswith("\\") or cur.endswith("^"):
            pend = cur[:-1].rstrip() + " "
            continue
        out.append(cur)
    if pend:
        out.append(pend.rstrip())
    return "\n".join(out)


def _tokenize_cmd(cmd):
    """命令串分词：单/双引号成段剥除，空白（含换行）分隔。
    返回 (tokens, 引号是否未闭合)；不做反斜杠转义（Windows 路径保真）。"""
    toks, cur, quote = [], [], ""
    for ch in cmd:
        if quote:
            if ch == quote:
                quote = ""
            else:
                cur.append(ch)
        elif ch in "\"'":
            quote = ch
        elif ch in " \t\r\n":
            if cur:
                toks.append("".join(cur))
                cur = []
        else:
            cur.append(ch)
    if cur:
        toks.append("".join(cur))
    return toks, bool(quote)


def _clean_output(out):
    """响应输出净化：\\r 控制字符归一 + 剥离输出开头的 Windows curl 进度噪音行。"""
    out = out.replace("\r\n", "\n").replace("\r", "\n")
    ls = out.split("\n")
    while ls and ((not ls[0].strip()) or any(p.match(ls[0]) for p in _PROG_LINE)):
        ls.pop(0)
    return "\n".join(ls)


def parse_exec_packet(text):
    """exec .log 全文 → {request, response, flags} 只读投影（不落库）；解析不出返回 None。

    降级是产品要求：任何意外（非 exec 日志/非 curl 命令/空串/二进制乱码）
    一律返回 None，绝不抛异常。不确定性记 flags 而不是猜；变量不归一化，
    $TOKEN 之类原样保留并标 has_variables（证据保真）。"""
    try:
        return _parse_exec_packet(text)
    except Exception:  # noqa: BLE001 —— 解析器不允许把异常漏给调用方
        return None


def parse_exec_log_file(path):
    """exec 日志文件 → parse_exec_packet：读盘/解码/解析全链路降级，意外一律返回 None。

    统一 exec_packets_for_asset 与 /api/evidence/packet 的三连样板
    （EVIDENCE_READ_LIMIT 读上限 + utf-8→gbk 容错解码 + 解析降级）——
    调用方只判 None，不再各自复制读文件/解码/异常处理。"""
    try:
        return parse_exec_packet(read_text_compat(path))
    except Exception:  # noqa: BLE001 —— OSError（证据丢失）与意外同权降级
        return None


def _parse_exec_packet(text):
    if not isinstance(text, str):
        return None
    lines = text.split("\n")
    if not lines or not lines[0].startswith("$ "):
        return None
    exit_at = -1
    for idx in range(1, len(lines)):
        if lines[idx].startswith("exit="):
            exit_at = idx
            break
    if exit_at < 0:
        return None  # 无 exit= 行即非 cmd_exec 落盘格式
    # 命令串 = "$ " 后至 exit= 行前的全部内容（cmd 含换行时首行只有第一段）
    cmd_body = _join_continuation("\n".join([lines[0][2:]] + lines[1:exit_at]))
    parsed = _parse_curl_cmd(cmd_body)
    if parsed is None:
        return None
    flags = parsed["flags"]
    # 响应来源 = exit= 行之后的全部输出（跳过 cmd_exec 固定写入的一行空分隔行）
    out_lines = lines[exit_at + 1:]
    if out_lines and out_lines[0] == "":
        out_lines = out_lines[1:]
    response = _clean_output("\n".join(out_lines))
    if not response.strip():
        response = ""
        flags["empty"] = True
    elif not parsed["include"]:
        flags["response_inferred"] = True  # 无 -i/-I：状态行缺失，输出即响应体原文
    return {"request": parsed["request"], "response": response, "flags": flags}


def _parse_curl_cmd(cmd):
    """curl 命令串 → {request, include, flags}；非 curl 程序或无 URL 返回 None。"""
    toks, unclosed = _tokenize_cmd(cmd)
    if not toks:
        return None
    prog = re.split(r"[\\/]", toks[0])[-1].lower()
    if prog not in ("curl", "curl.exe"):
        return None
    method, user = "", ""
    headers, datas, urls = [], [], []
    include = head = verbose = unparsed = False
    i, n = 1, len(toks)
    while i < n:
        t = toks[i]
        i += 1
        if t.startswith("--"):
            name, eq, inline = t.partition("=")

            def long_val():
                nonlocal i
                if eq:
                    return inline
                if i < n:
                    v = toks[i]
                    i += 1
                    return v
                return ""

            nm = name.lower()
            if nm == "--request":
                method = long_val().upper()
            elif nm == "--header":
                h = long_val()
                if ":" in h:
                    headers.append(h)
                else:
                    unparsed = True
            elif nm in ("--data", "--data-raw", "--data-binary", "--data-urlencode"):
                datas.append(long_val())
            elif nm == "--user":
                user = long_val()
            elif nm == "--url":
                urls.append(long_val())
            elif nm == "--include":
                include = True
            elif nm == "--head":
                head = True
            elif nm == "--verbose":
                verbose = True
            elif nm in _CURL_VALUE_LONG:
                long_val()  # 连接/输出类参数：值消费掉，不进报文
            else:
                unparsed = True  # 未识别选项：记 flag 不猜
            continue
        if t.startswith("-") and len(t) > 1:
            j = 1
            while j < len(t):
                ch = t[j]
                j += 1

                def short_val():
                    nonlocal j, i
                    if j < len(t):  # 簇内取值：字符后剩余段（如 -AX "UA"）
                        v = t[j:]
                        j = len(t)
                        return v
                    if i < n:
                        v = toks[i]
                        i += 1
                        return v
                    return ""

                if ch == "H":
                    h = short_val()
                    if ":" in h:
                        headers.append(h)
                    else:
                        unparsed = True
                elif ch == "X":
                    method = short_val().upper()
                elif ch == "d":
                    datas.append(short_val())
                elif ch == "u":
                    user = short_val()
                elif ch in _CURL_VALUE_SHORT:
                    short_val()
                elif ch in _CURL_BOOL_SHORT:
                    pass
                elif ch == "i":
                    include = True
                elif ch == "I":
                    head = True
                elif ch == "v":
                    verbose = True
                else:
                    unparsed = True
            continue
        if t == "-":
            unparsed = True
            continue
        urls.append(t)  # 非选项 token = URL（多个只取第一个，标 truncated）
    if not urls:
        return None
    flags = {"inferred_method": False, "inferred_header": False,
             "has_variables": False, "truncated": len(urls) > 1,
             "response_inferred": False, "empty": False}
    if unparsed:
        flags["has_unparsed_args"] = True
    if verbose:
        flags["verbose"] = True  # stderr 调试行可能混入响应输出
    if unclosed:
        flags["unbalanced_quote"] = True
    if not method:
        if datas:
            method, flags["inferred_method"] = "POST", True
        elif head:
            method, flags["inferred_method"] = "HEAD", True
        else:
            method = "GET"
    # URL → 请求行目标（含 query）+ Host；无 scheme/host 时不猜，整串作目标并记 flag
    sp = urllib.parse.urlsplit(urls[0])
    host, path = sp.netloc, sp.path or "/"
    if sp.query:
        path += "?" + sp.query
    if not host:
        flags["no_host"] = True
        path = urls[0]
    lines = ["%s %s HTTP/1.1" % (method, path)]
    have = {h.split(":", 1)[0].strip().lower() for h in headers if ":" in h}
    if host and "host" not in have:
        lines.append("Host: " + host)
    lines.extend(headers)
    if user and "authorization" not in have:
        if _VAR_RE.search(user):
            lines.append("Authorization: Basic " + user)  # 变量未求值，base64 无意义，照抄
        else:
            lines.append("Authorization: Basic "
                         + base64.b64encode(user.encode("utf-8")).decode("ascii"))
    body = "&".join(datas) if len(datas) > 1 else (datas[0] if datas else "")
    if datas and any(d.startswith("@") for d in datas):
        flags["data_from_file"] = True  # data 为文件引用：@path 原样保留（不读文件）
    if datas and "content-type" not in have:
        lines.append("Content-Type: application/x-www-form-urlencoded")
        flags["inferred_header"] = True
    if _VAR_RE.search(cmd):
        flags["has_variables"] = True
    return {"request": "\n".join(lines) + "\n\n" + body,
            "include": bool(include or head), "flags": flags}


def exec_packets_for_asset(c, project, atype, akey, limit=10):
    """资产下钻：归属该资产的 test 事件所挂 exec .log 证据 → 报文只读投影（不落库）。

    供面板 /api/asset-detail 的「探测报文（exec 自动解析）」分区。归属复用
    tests_for_asset（与 findings 同一套 _finding_hosts 归因，不另写解析）；
    证据特征对齐 cmd_exec 落库形态：etype='file' 且 note 以 'output' 开头、
    挂在 test 事件上。limit 限定参与归因的最近 test 事件数（防响应过大——
    真实库一个资产的 test 流会持续增长）。每条返回
    {ev_id, event_id, sha256, created_at, request, response, flags}。

    降级原则（对齐 /api/evidence/packet）：读文件失败（证据丢失）或
    parse_exec_packet 返回 None（python 脚本等非 curl 日志）一律静默跳过，
    绝不抛异常——面板只收解析成功的报文。evidence.path 在 attach_evidence
    落库时已是绝对路径（cmd_exec/exec 通道写绝对、evidence/ 目录随库走），
    直接按行读，不做任何路径重建。

    放在本模块（与 parse_exec_packet 作伴）而非 pdb_assets：本函数依赖链是
    tests_for_asset(pdb_assets) + parse_exec_packet(本模块)，pdb_findings 顶层
    已 import pdb_assets（cmd_add），依赖方向 assets→findings 单向无环；
    放 pdb_assets 则需反向/delayed import，分层更别扭。"""
    tests = tests_for_asset(c, project, atype, akey)[:limit]  # tests 已按 id 倒序
    if not tests:
        return []
    tids = [t["id"] for t in tests]
    ph = ",".join("?" * len(tids))
    ev_rows = c.execute(
        "SELECT id, event_id, path, sha256, created_at FROM evidence "
        "WHERE project=? AND etype='file' AND note LIKE 'output%' "
        f"AND event_id IN ({ph}) ORDER BY id",
        (project,) + tuple(tids))
    out = []
    for ev in ev_rows:
        pkt = parse_exec_log_file(ev["path"])
        if pkt is None:  # 证据丢失/非 exec curl 日志（python 脚本/空壳）：静默跳过（降级原则不变）
            continue
        out.append({"ev_id": ev["id"], "event_id": ev["event_id"],
                    "sha256": ev["sha256"] or "", "created_at": ev["created_at"] or "",
                    "request": pkt["request"], "response": pkt["response"],
                    "flags": pkt["flags"]})
    return out


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


def sync_lifecycle_from_test(c, project, test_id, note, parent_ext=""):
    """test 结论 → parent finding 生命周期自动同步（add/exec 两写入口共用）。
    从 note 开头提取机读结论词（沿用 TEST_CONCLUSIONS，不另起一套）映射 lifecycle：
    复现→reproduced / 未复现→not-reproduced / 已修复→fixed / 部分修复·仍存在→reopened；
    「待复测」与散文 note 不触发。parent_ext 逗号分隔逐个处理，只对 kind=finding 生效；
    目标 lifecycle 已同值时不重复写（幂等克制）。留痕 tag=（test#<id> 自动）。
    返回发生联动的 finding id 列表（调用方据此决定是否 commit；打印 [link] 行）。"""
    n = (note or "").strip()
    code = ""
    for w in TEST_CONCLUSIONS:
        if n.startswith(w):
            code = CONCLUSION_LIFECYCLE.get(w, "")  # 待复测等无映射词 -> 不联动
            break
    if not code:
        return []
    touched = []
    for p in [x.strip() for x in (parent_ext or "").split(",") if x.strip()]:
        if not p.isdigit():
            continue
        fid = int(p)
        row = c.execute("SELECT kind, attrs FROM raw_events WHERE id=? AND project=?",
                        (fid, project)).fetchone()
        if not row or row["kind"] != "finding":
            continue  # 只对 finding 生效：跳过不存在 id 与其他 kind
        try:
            cur = (json.loads(row["attrs"] or "{}") or {}).get("lifecycle", "")
        except (TypeError, ValueError):
            cur = ""
        if cur == code:
            continue  # 已同值：不重复写，避免 changelog 噪音
        set_lifecycle(c, project, fid, code, tag=f"（test#{test_id} 自动）")
        touched.append(fid)
        print(f"[link] #{fid} 生命周期 -> {code}（test 结论自动同步）")
    return touched


def cmd_lifecycle(a):
    """复测结论同步：把机读结论落到 finding 生命周期（AI 走 CLI 的正式通道，面板同款留痕）。"""
    c = connect()
    try:
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
    finally:
        c.close()


def cmd_drop(a):
    """删除整个项目及其数据（高危操作，必须 --confirm）。changelog 留墓碑记录。
    级联清 assets/reviews——reviews 无 project 列，按被删事件的 id 集合清；
    changelog 故意保留（墓碑留痕）。"""
    if not a.confirm:
        sys.exit("[x] 删除项目是高危操作，必须显式加 --confirm")
    c = connect()
    try:
        require_project(c, a.project)
        n = c.execute("SELECT COUNT(*) FROM raw_events WHERE project=?", (a.project,)).fetchone()[0]
        ev_ids = [r[0] for r in c.execute("SELECT id FROM raw_events WHERE project=?", (a.project,))]
        # drop 是人工 --confirm 的高危操作：级联删除会撞 append-only 触发器，
        # 先短暂解除，删除完成后经 executescript(SCHEMA) 幂等恢复全部审计触发器
        for t in AUDIT_TRIGGERS:
            c.execute(f"DROP TRIGGER IF EXISTS {t}")
        for t in ("raw_events", "assets", "pending_tests", "waives", "evidence"):
            c.execute(f"DELETE FROM {t} WHERE project=?", (a.project,))
        if ev_ids:
            c.execute("DELETE FROM reviews WHERE event_id IN (%s)" %
                      ",".join("?" * len(ev_ids)), ev_ids)
        c.execute("DELETE FROM projects WHERE name=?", (a.project,))
        c.executescript(SCHEMA)  # 幂等恢复全部审计触发器（executescript 自带隐式 COMMIT）
        log_change(c, "__system__", "drop", f"项目 {a.project} 已删除（含 {n} 条事件）")
        c.commit()
        print(f"[ok] 项目 {a.project} 已删除（{n} 条事件），changelog 留痕")
    finally:
        c.close()


def cmd_migrate(a):
    kind_map = {"targets": "domain", "ports": "port", "paths": "path",
                "params": "param", "findings": "finding", "tests": "test"}
    c = connect()
    try:
        _migrate_run(c, a)
    finally:
        c.close()


def _migrate_run(c, a):
    """cmd_migrate 的执行主体（连接由 cmd_migrate 持有并在 finally 关闭）。"""
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
