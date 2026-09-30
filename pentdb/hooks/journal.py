"""PreToolUse hook：把宿主 Bash/PowerShell 工具的每条命令追加进执行流水（journal）。

目的：堵"测了没记"——AI 绕过 exec 单通道裸跑探测/测试命令时，journal 是唯一
绕不过的观测点（沙箱内一切命令必经宿主 Bash/PowerShell 工具）。lint 收尾对账：
journal 中探测类命令若在 test 事件里找不到对应记录 = error。

部署：pentdb.py hook-install 生成 <套件根>/.codebuddy/settings.json，
然后在宿主 /hooks 面板人工审查后才生效（宿主安全机制，AI 不得代批）。

契约：本脚本任何异常都静默退出 0——hook 永不阻塞正常工作；journal 是尽力而为
的 append-only 流水。journal 路径由 __file__ 相对寻址（随套件整体搬移）。
"""
import datetime
import json
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))  # pentdb/hooks
JOURNAL_DIR = os.path.join(os.path.dirname(BASE), "data", "journal")  # pentdb/data/journal


def record(obj):
    cmd = ((obj.get("tool_input") or {}).get("command") or "").strip()
    if not cmd:
        return
    os.makedirs(JOURNAL_DIR, exist_ok=True)
    rec = {
        "ts": datetime.datetime.now().isoformat(timespec="seconds"),
        "tool": obj.get("tool_name") or "",
        "session": (obj.get("session_id") or "")[:8],
        "cwd": obj.get("cwd") or "",
        "cmd": cmd,
    }
    day = datetime.date.today().isoformat()
    path = os.path.join(JOURNAL_DIR, day + ".log")
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def main():
    try:
        raw = sys.stdin.read()
        if raw.strip():
            record(json.loads(raw))
    except Exception:
        pass  # journal 尽力而为，绝不阻塞命令执行
    return 0


if __name__ == "__main__":
    sys.exit(main())
