#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PentDB recon pipeline：被动子域枚举 + 并发存活探测 + 批量落库。

工具自动选择：本机有 subfinder 用 subfinder，否则内置 crt.sh CT 查询（零依赖）。
零主动攻击行为：仅 CT/DNS 查询与 HTTP GET 探测；主动测试仍走授权流程（notes §0）。
代理可移植：--proxy > PENTDB_PROXY 环境变量 > 直连，适配任意机器。
"""
import argparse
import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
UA = "PentDB/1.0 (+recon pipeline)"


def resolve_proxy(args):
    return (args.proxy or os.environ.get("PENTDB_PROXY")
            or os.environ.get("HTTPS_PROXY") or "").strip()


def build_opener(proxy):
    if proxy:
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))  # 显式直连


def _fetch(opener, url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with opener.open(req, timeout=timeout) as r:
        return r.status, dict(r.headers), r.read()


def enum_subdomains(domain, proxy, timeout):
    """返回 (子域集合, 工具名, source 描述)。"""
    sf = shutil.which("subfinder")
    if sf:
        out = subprocess.run([sf, "-d", domain, "-silent", "-passive"],
                             capture_output=True, text=True, timeout=180)
        subs = {l.strip().lower() for l in out.stdout.splitlines() if l.strip()}
        return subs, "subfinder", f"subfinder -d {domain} -silent -passive"
    src = f"https://crt.sh/?q=%25.{domain}&output=json"
    opener = build_opener(proxy)
    last_err = None
    for attempt in range(3):  # crt.sh 不稳定，三次重试
        try:
            status, headers, body = _fetch(opener, src, max(timeout, 40))
            data = json.loads(body.decode("utf-8", "ignore"))
            break
        except Exception as e:
            last_err = e
            print(f"[recon] crt.sh 第 {attempt + 1} 次请求失败（{e}），重试…")
            time.sleep(3 * (attempt + 1))
    else:
        raise SystemExit(f"[x] crt.sh 连续失败，且本机无 subfinder：{last_err}。"
                         f"可安装 subfinder 或配置可用代理后重试。")
    subs = set()
    for entry in data:
        for name in str(entry.get("name_value") or "").split("\n"):
            name = name.strip().lower().lstrip("*").lstrip(".")
            if name and (name == domain or name.endswith("." + domain)):
                subs.add(name)
    return subs, "crt.sh", src


def probe(host, opener, timeout):
    """单主机存活探测。HTTP 错误码（403/503 等）也算存活——与枚举数据风格一致。"""
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            status, headers, body = _fetch(opener, url, timeout)
            server = (headers.get("Server") or "").strip()
            m = TITLE_RE.search(body[:65536].decode("utf-8", "ignore"))
            return {"code": status, "server": server,
                    "title": m.group(1).strip()[:80] if m else "", "url": url}
        except urllib.error.HTTPError as e:
            return {"code": e.code, "server": (e.headers.get("Server") or "").strip(),
                    "title": "", "url": url}
        except Exception:
            continue
    return None


def run(args):
    import pentdb as pdb
    proxy = resolve_proxy(args)
    print(f"[recon] 目标 {args.domain} ｜ 项目 {args.project} ｜ "
          f"代理 {proxy or '直连'} ｜ workers={args.workers}")
    c = pdb.connect()
    pdb.require_project(c, args.project)
    existing = {r[0]: r[1] for r in c.execute(
        "SELECT value, id FROM raw_events WHERE project=? AND kind='domain'", (args.project,))}

    if args.single:
        subs, tool, source = {args.domain}, "single-host", "手工指定目标（未做子域枚举）"
    else:
        subs, tool, source = enum_subdomains(args.domain, proxy, args.timeout)
    subs.add(args.domain)
    subs = sorted(subs)[:args.limit]
    print(f"[recon] {tool} 枚举 {len(subs)} 个子域（其中已入库 "
          f"{sum(1 for s in subs if s in existing)} 个，将走重扫更新），开始探测")

    opener = build_opener(proxy)
    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        for host, res in zip(subs, ex.map(lambda h: probe(h, opener, args.timeout), subs)):
            if res:
                alive.append((host, res))
    print(f"[recon] 存活 {len(alive)} / {len(subs)}，开始落库")

    new = updated = skip = 0
    for host, res in alive:
        is_update = host in existing
        note = f"存活: HTTP {res['code']} server={res['server']} title={res['title']}"
        ns = argparse.Namespace(
            project=args.project, ext_id="", kind="domain", value=host, title="",
            detail="", note=note, source=f"{source}；HTTP 探测 {res['url']}",
            parent_ext="", merge_key="", status="confirmed", confidence="high",
            severity="", code=str(res["code"]), tech=res["server"], service="",
            scope="in", auto=True, update=True, origin="agent", stage="")
        try:
            pdb.cmd_add(ns)
            if is_update:
                updated += 1
            else:
                new += 1
        except SystemExit as e:
            print(f"[!] 跳过 {host}: {e}")
            skip += 1
    pdb.log_change(c, args.project, "recon",
                   f"{tool}: 枚举 {len(subs)} ｜ 存活 {len(alive)} ｜ 新增 {new} ｜ 重扫更新 {updated} ｜ 跳过 {skip}")
    c.commit()
    print(f"[recon] 完成：新增 {new} ｜ 重扫更新 {updated} ｜ 跳过 {skip} ｜ 面板刷新可见")
    return new


# ---------------- JS 深挖：endpoint / 密钥提取 ----------------

KEY_PATTERNS = [
    ("AWS AccessKey", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("通用密钥赋值", re.compile(
        r"(?:api[_\-]?key|apikey|secret|access[_\-]?token)\s*[:=]\s*[\"']([A-Za-z0-9_\-\.]{16,})[\"']", re.I)),
]
ENDPOINT_RE = re.compile(r"[\"'](\/[a-zA-Z0-9_\-\.\/]{2,80})[\"']")
SKIP_EXT = (".png", ".jpg", ".css", ".ico", ".svg", ".woff", ".gif", ".jpeg")


def run_js(args):
    import pentdb as pdb
    proxy = resolve_proxy(args)
    opener = build_opener(proxy)
    print(f"[js] 项目 {args.project} ｜ 代理 {proxy or '直连'}")
    c = pdb.connect()
    pdb.require_project(c, args.project)
    hosts = [r["value"] for r in c.execute(
        "SELECT value FROM raw_events WHERE project=? AND kind='domain' AND status='confirmed' "
        "AND (tech!='' OR code IN ('200','301','302','403')) ORDER BY id LIMIT ?",
        (args.project, args.limit))]
    print(f"[js] 待挖主机 {len(hosts)} 个")
    os.makedirs(dl_dir := os.path.join(os.path.dirname(os.path.abspath(
        __import__("pentdb").__file__)), "downloads", args.project), exist_ok=True)
    n_ep, n_key, n_ev = 0, 0, 0
    for host in hosts:
        js_urls = []
        try:
            _, _, html = _fetch(opener, f"https://{host}/", args.timeout)
            html = html.decode("utf-8", "ignore")
            for m in re.finditer(r"<script[^>]+src=[\"']([^\"']+\.js[^\"']*)[\"']", html, re.I):
                u = m.group(1)
                if u.startswith("//"):
                    u = "https:" + u
                elif u.startswith("/"):
                    u = f"https://{host}{u}"
                elif not u.startswith("http"):
                    u = f"https://{host}/{u}"
                if not u.lower().endswith(SKIP_EXT):
                    js_urls.append(u)
        except Exception:
            continue
        dom_row = c.execute("SELECT id FROM raw_events WHERE project=? AND value=?",
                            (args.project, host)).fetchone()
        for i, u in enumerate(js_urls[:args.limit]):
            try:
                _, _, body = _fetch(opener, u, args.timeout)
            except Exception:
                continue
            text = body.decode("utf-8", "ignore")
            ev_path = os.path.join(dl_dir, f"{host.replace('.', '_')}__{i}.js")
            with open(ev_path, "wb") as f:
                f.write(body)
            if dom_row:
                ns_ev = argparse.Namespace(project=args.project, event_id=dom_row["id"],
                                           path=ev_path, text=None, keep_in_place=False,
                                           note=f"JS 原文：{u}")
                try:
                    pdb.cmd_evidence(ns_ev)
                    n_ev += 1
                except SystemExit:
                    pass
            for m in ENDPOINT_RE.finditer(text):
                ep = m.group(1)
                if ep.lower().endswith(SKIP_EXT) or len(ep) < 3:
                    continue
                ns = argparse.Namespace(
                    project=args.project, ext_id="", kind="path", value=ep,
                    title="", detail="", note=f"来自 JS 提取（未探测，code 空）",
                    source=f"JS 解析 {u}", parent_ext=str(dom_row["id"]) if dom_row else "",
                    merge_key="", status="confirmed", confidence="medium", severity="",
                    code="", tech="", service="", scope="in", auto=True, origin="agent", stage="",
                    update=False, req=None, resp=None, waive_capture=None)
                try:
                    pdb.cmd_add(ns)
                    n_ep += 1
                except SystemExit:
                    pass
            for name, pat in KEY_PATTERNS:
                for m in pat.finditer(text):
                    val = m.group(1) if m.groups() else m.group(0)
                    ns = argparse.Namespace(
                        project=args.project, ext_id="", kind="finding",
                        value=val, title=f"疑似密钥泄露（{name}）",
                        detail=f"在 JS 中发现疑似 {name}：{val[:8]}***。"
                               f"人工验证：①确认是否真实有效密钥 ②测试调用权限 ③评估影响范围。",
                        note=f"自动提取，可能为占位符/测试值，待人审",
                        source=f"JS 解析 {u}", parent_ext="", merge_key="",
                        status="new", confidence="medium", severity="high",
                        code="", tech="", service="", scope="in", auto=False,
                        origin="agent", stage="",
                        req="", resp="",
                        waive_capture="JS 静态发现无报文，人工验证后按七段补 req/resp 或确认豁免")
                    try:
                        pdb.cmd_add(ns)
                        n_key += 1
                    except SystemExit:
                        pass
    pdb.log_change(c, args.project, "js-dig", f"endpoint {n_ep} ｜ 疑似密钥 {n_key} ｜ 证据 {n_ev}")
    c.commit()
    print(f"[js] 完成：endpoint {n_ep} ｜ 疑似密钥 {n_key} ｜ JS 证据 {n_ev}")
