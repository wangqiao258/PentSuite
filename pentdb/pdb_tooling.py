#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PDB Tooling — 面板/工具域（从 pentdb.py 拆出的零行为变更重构）。

  - cmd_panel：面板生命周期（幂等拉起 server.py 子进程）
  - cmd_hook_install：PreToolUse journal hook 配置
  - cmd_js / cmd_recon / cmd_serve：recon.py / server.py 委托入口
  - cmd_kb / _kb_tags：经验库（pentest-kb，核心逻辑在 kb/kb.py）
  - 套件引导：_venv_python / _bootstrap_deps / _bootstrap_creds / _creds_skeleton / cmd_bootstrap

向下只依赖 pdb_core。注：_bootstrap_deps 原文件内使用 subprocess 而未 import
（原 pentdb.py 仅 cmd_panel 函数内局部 import），拆分时在模块级补 import subprocess
——属必要的 import 调整，不改动任何函数体。
"""
import json
import os
import subprocess  # 原 _bootstrap_deps 裸用；补模块级 import（见文件头注），cmd_panel 局部 import 保持原样
import sys

from pdb_core import BASE, DB_PATH, connect, require_project

ROOT = os.path.dirname(BASE)  # 套件根（pentdb/ 的上一级）
VENV_DIR = os.path.join(ROOT, ".venv")
KB_CREDS = os.path.join(BASE, "kb", "creds.json")

_CREDS_OUT_KEYS = {"PENTEST_KB_DB_HOST": "host", "PENTEST_KB_DB_PORT": "port",
                   "PENTEST_KB_DB_NAME": "dbname", "PENTEST_KB_DB_USER": "user",
                   "PENTEST_KB_DB_PASSWORD": "password"}


def cmd_panel(a):
    """面板生命周期（幂等）：活着复用，没起拉起，被占无响应报 PID。AI 在批次结束后调用并播报。
    探测一律 socket 直连 127.0.0.1 —— 本机代理环境（http_proxy）会污染 urlopen 结果。"""
    import socket as _socket
    import subprocess
    import time
    port = a.port
    url = f"http://127.0.0.1:{port}/"

    def alive():
        try:
            s = _socket.create_connection(("127.0.0.1", port), timeout=1.5)
            s.sendall(b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
            data = s.recv(64)
            s.close()
            return data.startswith(b"HTTP/")
        except Exception:
            return False

    if alive():
        print(f"[=] 面板已在运行，复用: {url}")
    else:
        flags = 0x00000008 | 0x00000200 if os.name == "nt" else 0  # DETACHED_PROCESS | NEW_PROCESS_GROUP
        env = {**os.environ, "PENTDB_DB": DB_PATH}
        subprocess.Popen([sys.executable, os.path.join(BASE, "server.py"), "--port", str(port)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         creationflags=flags, close_fds=True, env=env)
        time.sleep(1.2)
        if alive():
            print(f"[ok] 面板已启动: {url}")
        else:
            out = subprocess.run(["netstat", "-ano"], capture_output=True).stdout.decode("gbk", errors="ignore")
            pids = {ln.split()[-1] for ln in out.splitlines()
                    if f":{port}" in ln and "LISTENING" in ln.upper()}
            if pids:
                print(f"[x] 端口 {port} 被 PID {','.join(pids)} 占用但无 HTTP 响应（旧面板残留？）。"
                      f"执行 taskkill /PID {','.join(pids)} /F 后重试")
            else:
                print(f"[x] 面板启动失败且端口未被占用。人手终端: python server.py --port {port}；"
                      f"AI 会话: 改用 skill 随行 panel.py start（detached 子进程在沙箱内不存活）")
            sys.exit(1)
    if a.project:
        c = connect()
        try:
            require_project(c, a.project)
            new_n = c.execute("SELECT COUNT(*) n FROM raw_events WHERE project=? AND status='new'",
                              (a.project,)).fetchone()["n"]
        finally:
            c.close()
        print(f"project: {a.project}")
        print(f"url: {url}?project={a.project}")
        print(f"pending: {new_n}")


def cmd_hook_install(a):
    """生成/更新 PreToolUse journal hook 配置（幂等）。默认项目级
    （<套件根>/.codebuddy/settings.json，仅本工作区生效）；--global 写用户级
    ~/.workbuddy/settings.json（全工作区生效——渗透实际发生在目标工作目录，推荐）。
    只管理本套件自己的 journal hook 条目（按 journal.py 路径识别），不动其他配置。
    宿主安全机制：外部写入的 hooks 需在 /hooks 面板人工审查后才生效——AI 不得代批。"""
    if getattr(a, "global_", False):
        cfg_path = os.path.expanduser("~/.workbuddy/settings.json")
        scope = "用户级（全工作区生效）"
        cfg = {}
        if os.path.exists(cfg_path):
            try:
                with open(cfg_path, encoding="utf-8") as f:
                    cfg = json.load(f)
            except (ValueError, OSError) as e:
                sys.exit(f"[x] 用户级 settings.json 解析失败，拒绝覆盖（先手工修复）: {e}")
    else:
        root = os.path.dirname(BASE)
        cfg_dir = os.path.join(root, ".codebuddy")
        os.makedirs(cfg_dir, exist_ok=True)
        cfg_path = os.path.join(cfg_dir, "settings.json")
        scope = "项目级（仅本工作区生效）"
        cfg = {}
        if os.path.exists(cfg_path):
            try:
                with open(cfg_path, encoding="utf-8") as f:
                    cfg = json.load(f)
            except (ValueError, OSError):
                cfg = {}
    py = os.path.abspath(sys.executable).replace("\\", "/")
    hook_py = os.path.join(BASE, "hooks", "journal.py").replace("\\", "/")
    entry = {"matcher": "Bash|PowerShell",
             "hooks": [{"type": "command",
                        "command": '"%s" "%s"' % (py, hook_py),
                        "timeout": 10}]}
    hooks = cfg.setdefault("hooks", {})
    pre = [m for m in hooks.get("PreToolUse", [])
           if not any("journal.py" in (h.get("command") or "")
                      for h in m.get("hooks", []))]
    pre.append(entry)
    hooks["PreToolUse"] = pre
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"[ok] 已写入 {cfg_path}（{scope}）")
    print("    生效步骤：CLI 终端版经宿主 /hooks 面板审查后生效（外部修改需人工确认，AI 不得代批）；"
          "桌面版实测免审动态生效（验证=新会话跑命令查 journal）")
    print("    验证：生效后任意命令执行一次，检查 pentdb/data/journal/<日期>.log 是否追加")
    if getattr(a, "global_", False):
        # 全局部署后清理项目级旧配置，避免双份（同命令宿主会去重，但留着易困惑）
        proj_cfg = os.path.join(os.path.dirname(BASE), ".codebuddy", "settings.json")
        try:
            if os.path.exists(proj_cfg):
                with open(proj_cfg, encoding="utf-8") as f:
                    pc = json.load(f)
                ph = pc.get("hooks", {}).get("PreToolUse", [])
                rest = [m for m in ph
                        if not any("journal.py" in (h.get("command") or "")
                                   for h in m.get("hooks", []))]
                if rest:
                    pc.setdefault("hooks", {})["PreToolUse"] = rest
                    with open(proj_cfg, "w", encoding="utf-8") as f:
                        json.dump(pc, f, ensure_ascii=False, indent=2)
                        f.write("\n")
                    print("[ok] 项目级旧 journal hook 条目已移除（其余配置保留）:", proj_cfg)
                else:
                    os.remove(proj_cfg)
                    print("[ok] 项目级 hook 配置已移除（全局已覆盖）:", proj_cfg)
        except OSError:
            pass


def cmd_js(a):
    sys.path.insert(0, BASE)
    import recon
    recon.run_js(a)


def cmd_recon(a):
    sys.path.insert(0, BASE)
    import recon
    recon.run(a)


def cmd_serve(a):
    if a.db:
        os.environ["PENTDB_DB"] = a.db
    sys.path.insert(0, BASE)
    import server
    server.run(a.port)


# ---------------- 经验库（pentest-kb，Supabase 云库；核心逻辑在 kb.py） ----------------

def _kb_tags(s):
    return [t.strip() for t in (s or "").split(",") if t.strip()]


def cmd_kb(a):
    sys.path.insert(0, BASE)
    sys.path.insert(0, os.path.join(BASE, "kb"))
    import kb
    c = a.kb_cmd
    if c == "search":
        out = kb.search_experience(a.keyword, tags_filter=_kb_tags(a.tags), limit=a.limit)
    elif c == "add":
        detail = a.detail
        if a.from_file:
            if detail:
                sys.exit("[x] --detail 与 --from-file 二选一")
            with open(a.from_file, encoding="utf-8") as f:
                detail = f.read()
        if not detail:
            sys.exit("[x] 需要 --detail 或 --from-file 提供经验详情（长文本用 --from-file 防转义问题）")
        out = kb.add_experience(a.title, detail, scenario_tags=_kb_tags(a.tags),
                                tool_code=a.tool_code or None,
                                tool_type=a.tool_type or None)
    elif c == "find-similar":
        out = kb.find_similar(a.title, a.detail)
    elif c == "list":
        out = kb.list_all_experiences(a.limit, a.offset)
    elif c == "pending":
        out = kb.list_pending_experiences()
    elif c == "approve":
        if not a.confirm:
            sys.exit("[x] 审批是人的决定：必须在用户明示同意后加 --confirm 执行"
                     "（对应 skill 阶段六门禁；草稿永远由 kb-add 产生）")
        out = kb.approve_experience(a.id, a.merge_with)
    elif c == "reject":
        out = kb.reject_experience(a.id)
    elif c == "delete":
        out = kb.delete_experience(a.id)
    elif c == "restore":
        out = kb.restore_experience(a.id)
    elif c == "deleted":
        out = kb.list_deleted_experiences()
    elif c == "purge":
        out = kb.purge_experiences(a.days)
    elif c == "get":
        out = kb.get_experience(a.id)
    elif c == "update":
        out = kb.update_experience(a.id, title=a.title, detail=a.detail,
                                   scenario_tags=_kb_tags(a.tags) or None,
                                   tool_code=a.tool_code, tool_type=a.tool_type)
    else:
        sys.exit(f"[x] 未知 kb 子命令: {c}")
    print(out)


# ---------------- 套件引导（可选：venv/依赖/凭据迁移） ----------------

def _venv_python():
    return os.path.join(VENV_DIR, "Scripts", "python.exe") if os.name == "nt" \
        else os.path.join(VENV_DIR, "bin", "python")


def _bootstrap_deps():
    vp = _venv_python()
    if os.path.exists(vp):
        print("[=] 套件 .venv 已存在，跳过创建")
    else:
        print("[*] 创建套件 .venv ...")
        subprocess.run([sys.executable, "-m", "venv", VENV_DIR], check=True)
    print("[*] 安装经验层依赖（psycopg2/jieba/rank-bm25）...")
    # 清华镜像缺部分包；腾讯镜像实测可用（2026-09）
    subprocess.run([vp, "-m", "pip", "install", "-i",
                    "https://mirrors.cloud.tencent.com/pypi/simple",
                    "-r", os.path.join(BASE, "kb", "requirements.txt")], check=True)
    print("[ok] 依赖就绪（PentDB 零依赖，此 venv 仅供 kb-* 子命令使用）")


def _bootstrap_creds(src):
    """从旧机器的 mcp.json（MCP 时代遗留）或 creds.json 抓取经验库凭据，统一写小写键。"""
    old = json.load(open(src, encoding="utf-8"))
    env = (old.get("mcpServers", {}).get("pentest-kb", {}) or {}).get("env", {})
    creds = {out: env.get(up, "") or old.get(out, "")
             for up, out in _CREDS_OUT_KEYS.items()}
    if not creds.get("host"):
        sys.exit(f"[x] {src} 中未找到经验库凭据（mcpServers.env 或 creds.json 格式）")
    with open(KB_CREDS, "w", encoding="utf-8") as f:
        json.dump(creds, f, ensure_ascii=False, indent=2)
    print(f"[ok] 经验库凭据已写入 {KB_CREDS}（仅存本机）")


def _creds_skeleton():
    if not os.path.exists(KB_CREDS):
        with open(KB_CREDS, "w", encoding="utf-8") as f:
            json.dump({"host": "", "port": "5432", "dbname": "postgres",
                       "user": "", "password": ""}, f, ensure_ascii=False, indent=2)
        print(f"[ok] 已生成凭据骨架 {KB_CREDS}：填入 host / user / password 三项即用")

def cmd_bootstrap(a):
    if not a.skip_deps:
        _bootstrap_deps()
    if a.kb_creds:
        _bootstrap_creds(a.kb_creds)
    print("\n===== 经验库（可选）=====")
    _creds_skeleton()
    if os.path.exists(KB_CREDS):
        print(f"[=] 凭据文件: {KB_CREDS}（未填值不影响 PentDB 其余功能）；验证: pentdb.py kb list")
    print("===== PentDB =====")
    print(f"数据根（缺省即此）: {os.path.join(BASE, 'data', 'pentdb.db')}")
    print("  开面板: pentdb.py panel --project <目标>")
    print("  回归  : cd pentdb && python -m unittest test_sop")
