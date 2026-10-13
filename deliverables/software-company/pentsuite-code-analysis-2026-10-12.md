# PentSuite/PentDB 实证代码评审报告（2026-10-12）

> 评审口径：**实证优先**。README、注释、docstring 一律视为「待验证声明」，每条结论落实到 文件:行号 + 代码证据。
> 测试基线由主理人于 2026-10-12 独立复跑确认；R2/R6 结论经主理人抽查代码复核。
> 本次评审为只读分析，未修改任何项目文件。

---

## 1. 项目真实形态（实证后）

**4 个可执行入口**：

| 入口 | 位置 | 实证 |
|------|------|------|
| 主 CLI | `pentdb/pentdb.py` | `main()`（pentdb.py:447-843）注册 **31 个顶层子命令**；对 6 个 pdb_* 模块 façade re-export（:41-75），自身保留 journal 对账（:86-137）、lint 引擎（:155-343）、报告出口（:371-444） |
| Web 面板 | `pentdb/server.py` | `ThreadingHTTPServer` 绑 **127.0.0.1:8766**（:621）；do_GET 20 个路由（:65-428）、do_POST 7 个写路由（:430-617），写操作复用 CLI 的 cmd_* 实现 |
| 钩子 | `pentdb/hooks/journal.py` | PreToolUse 钩子，stdin JSON → 追加 `data/journal/<日期>.log`（:22-37），任何异常静默退 0（:45-46） |
| 面板生命周期 | `skill/pentest-kb-workflow/scripts/panel.py` | 存在，未逐行评审 |

**模块依赖（静态 import 实证）**：pdb_core（零依赖内核）← pdb_assets ← pdb_findings（顶层 import pdb_assets 的 cmd_add，反向经函数级 import 化解，pdb_assets.py:249）；pdb_intents/pdb_report/pdb_tooling 仅依赖 pdb_core；pentdb.py 为 façade；server.py/recon.py 延迟 import。无加载期循环。
> 注：主理人上下文所说 "pdb_core/ 目录" 实为**单文件** pdb_core.py；领域模块是扁平 6 个 pdb_*.py，不是包。

**数据层实证**（实库 `mode=ro` 只读核查）：`user_version=12`，projects 表含 profile 列，8 个审计触发器全在。行数：projects 9 / raw_events 4271 / evidence 238 / changelog 3440 / assets 1509 / waives 34 / reviews 317 / **pending_tests 0** / **intents 0 / plan_steps 0 / hints 0**。

**迁移链逐步核对**（pdb_core.py:296-480）：v1 建表→v2 补列→v3 evidence.etype→v4 waives.confirmed→v5 changelog.actor→v6 dedup_key→v7 waives 触发器 0→2→v8 voided→v9 intents→v10 plan_steps→v11 hints→v12 projects.profile。`_MIGRATIONS` 注册 12 步（:477-480），`SCHEMA_VERSION=12`（:293），每步 commit。链完整无缺步。

---

## 2. 旧报告 R1-R13 逐条核实结果

| # | 旧结论 | 核实结果 | 代码证据 |
|---|--------|---------|---------|
| R1 | schema 漂移：新装面板首屏崩 | **已修复（实测验证）** | profile 进 SCHEMA 基线（pdb_core.py:41）+ v12 迁移（:466-473）；test_bugfix_r1r5.py F1（:47-86）。**实测**：全新库起 server，`GET /api/projects` → 200 |
| R2 | server 异常处理缺失 | **未修复（实测复现）** | do_GET 仅 try/finally（server.py:89-90,427-428）；do_POST 的 `json.loads`（:434/475/499/541/567/588）、`/api/void` 的 `int(i)`（:580）、`/api/waive/draft` 的 `int(eid)`（:551）均无保护。**实测**：`GET /api/evidence?event_id=abc` → 连接被杀死、无 JSON 响应；对照组 `/api/review` 有 400 保护——防护不一致 |
| R3 | drop 级联漏 intents/plan_steps/hints | **已修复** | 级联清单含三表（pdb_findings.py:725-727）；回归 F2（test_bugfix_r1r5.py:104-149） |
| R4 | lint 指引引用不存在的 update 命令 | **已修复** | R-501 fix 改 "add --update…"（pentdb.py:288）；F-503 改真实驳回路径（:310）；回归 F4 断言 fix 文本不含 "update --id"（:300-325） |
| R5 | "取最后插入 id" 跨连接竞态 | **基本修复，残留 1 处** | cmd_add 返真实 id（pdb_assets.py:176/:221/:281）；exec/retest/manual-add 已改用返回值；回归 F3a/F3b。**残留**：`/api/waive/draft` 猜 wid（server.py:556-560）→ 新发现 N1 |
| R6 | hook-install --global 可整删 settings.json | **未修复** | pdb_tooling.py:144-151：PreToolUse 中无 journal 条目时 `os.remove(proj_cfg)` 删**整个文件**，从不检查其他顶层键（模型设置等一并丢失） |
| R7 | /api/report 全局 stdout 重定向非线程安全 | **未修复** | server.py:415-424 仍全局替换 `sys.stdout`；同文件 pentest 模板已改直调 `_pentest_report(c, p)`（:413）——修复模式已存在，assets 模板没跟上 |
| R8 | 面板无鉴权 | **未修复（低危，设计内）** | 仅绑 127.0.0.1；7 个 POST 无 token。端口转发/多用户场景是越权面 |
| R9 | 死表/死代码 | **未修复** | pending_tests 全库零读写（实库 0 行）；stages_enabled（:39）、raw_events.stage（:65）零业务读写；server.py:11 模块级 DB_PATH 死代码 |
| R10 | exec shell=True | **未变化（信任模型已知项）** | pdb_findings.py:260 产品核心设计，超时落盘（:263-266）为补偿 |
| R11 | 资源管理瑕疵 | **未修复** | recon.run 连接无 close（recon.py:97）；run_js 同样（:162）；journal.py:36 裸 open 无锁；lint 全量读 journal 文件（pentdb.py:93-115），长期项目线性变慢 |
| R12 | probe 硬编码 scope="in" | **未修复** | pdb_assets.py:391 probe_ingest INSERT 第 16 个值固定 `"in"`——lint E-105 不可能命中 |
| R13 | 迁移 ALTER 静默吞错 | **未修复** | pdb_core.py:318-321、:330-331、:343-344、:353-354、:363-364、:394-395、:471-472——"列已存在"幂等与真失败不可区分，失败后 user_version 照样推进 |

旧报告 §9 文档矛盾 6 条：#1/#2/#3/#4/#5 均已修复；#6（"写库唯一入口"字面表述）仍在。

---

## 3. 新发现问题清单

| # | 级别 | 位置 | 证据与影响 | 修复建议 |
|---|------|------|-----------|---------|
| N1 | 中 | server.py:556-560 | `/api/waive/draft` 在 cmd_waive（自开自关连接）后另开连接 `SELECT id … ORDER BY id DESC LIMIT 1` 猜 wid——R5 同型竞态残留；面板并发起草同事件同 term 可能返回他人 wid | cmd_waive 返回 `wcur.lastrowid`（pdb_findings.py:167-170 已有），面板直接用返回值 |
| N2 | 中 | server.py:367-377 | `/api/backup` 用 `open(DB_PATH,"rb").read()` 拷贝 WAL 模式下活库——备份可能撕裂，WAL 未 checkpoint 时**静默丢近期数据** | 改用 `sqlite3.Connection.backup()` 或 `VACUUM INTO` |
| N3 | 低 | server.py:512,533 | `/api/waive/confirm|reject` 的 `done` 列表从未 append，`done or [全量 wids]` 恒全量——被 skip 的 wid 也报成 done，响应误导前端 | 成功分支 `done.append(wid)` |
| N4 | 低 | server.py:101-104,288-290 | `/api/overview` 统计与 `/api/timeline` 事件流不过滤 `voided=0`，与 /api/events（:111）、/api/findings（:298）的自家规矩不一致——作废记录仍计入总览 | SQL 补 `AND voided=0` |
| N5 | 低 | pdb_findings.py:651-653 | `set_lifecycle` 写 changelog **不带 actor 列**（落 ''），生命周期变更丢失归属 | 改用 `log_change(…, actor=…)` 或补列 |
| N6 | 低 | pdb_tooling.py:55-56 + server.py | 面板以 `stdout=DEVNULL, stderr=DEVNULL` 拉起，`log_message` 又是空实现（:54-55）——R2 异常逃逸后无任何日志，线上无迹可循 | 至少落 `logs/panel_server.log`（该文件存在但 0 字节） |
| N7 | 低 | pentdb/__pycache__/ | 孤儿 .pyc：kb_mcp（无源）、kb（已移子目录）、3.14 产物与 venv 3.13 并存 | 清理 + gitignore |
| N8 | 低 | index.html:153-154 vs app.report.js | 注释契约 "boot() 必须最后加载"，但 index.html 把 app.explore.js 排在 app.report.js 之后——契约已破坏（当前无害，属脆弱隐式顺序耦合） | boot() 移到末尾显式调用，或修注释 |
| N9 | 信息 | 实库核查 | intents/plan_steps/hints 实库 **0 行**——v9-v11 探索血缘层（204 测试覆盖）真实项目尚未启用，生产验证不足 | 下个真实项目启用观察 |
| N10 | 信息 | pdb_core.py:494 | `connect()` 中 `os.makedirs(os.path.dirname(DB_PATH))`：PENTDB_DB 为裸文件名时 dirname='' 直接 FileNotFoundError | 判空 |

---

## 4. 测试基线实测结果

- 命令：`.venv\Scripts\python.exe -m unittest discover -s pentdb/tests -t pentdb -p "test_*.py"`（仓库根）
- **实测：`Ran 204 tests in 19.422s — OK`，204/204 全绿**（2026-10-12 主理人独立复跑，venv Python）。
- 与 `pentdb/tests/_ut_sum.txt` 记录一致；比 2026-10-11 的 193 多 11 个，增量即 test_bugfix_r1r5.py。
- 测试文件实为 **16 个** test_*.py（README 两处写 15 和 12，均过时）。
- 短板：server.py HTTP 层仅 int_param 有单测，do_GET/do_POST 路由无端到端测试（R2 因此长期存活）；kb.py 仅 AST 签名守护。

---

## 5. 文档 vs 实现偏差清单

| # | 文档位置 | 声明 | 实现实况 |
|---|---------|------|---------|
| D1 | README.md:30/:149 | "15 个单测" / "12 个测试文件" | 实际 16 个 test_*.py、204 用例 |
| D2 | README.md:28 | "web/ 七文件…5 个 app.*.js" | 实际 8 文件、**6 个** app.*.js（漏列 explore） |
| D3 | README.md:19-28 目录树 | 未列 pdb_intents.py | pdb_intents.py 存在且是 intent/plan/hint 核心模块 |
| D4 | README.md:48 | "waives 仅允许 confirmed 0→1" | v7 起放行 0→{1,2}（pdb_core.py:195-202） |
| D5 | README.md:48 | "--merge-key 保留兼容但零读写" | --merge-key 仍注册且落库（pdb_assets.py:222,236）——活着的功能 |
| D6 | pentdb.py:15 / pdb_core.py:11 | "写库唯一入口：一切写入必须经本 CLI" | server.py 7 个 POST 直接写库（复用 cmd_*）——字面偏差仍在，实际语义是"唯一实现 + 双入口" |

---

## 6. 总体评价与优先级建议

**总体**：架构分层清晰（core→领域→façade→适配层，单向向下、无加载期循环），审计触发器下沉 DB 层、lint 门禁、豁免三态机等核心纪律有真实强制力且被测试直接验证。2026-10-11 批次（R1-R5）的修复质量高：schema 基线 + v12 迁移双管齐下、cmd_add 改返回值消灭整类竞态，并配真正重现场景的回归测试。204 测试实测全绿，基线记录属实。

**旧报告未修部分全部属实**：R2/R6/R7/R8/R9/R11/R12/R13 逐条复核仍在；R2 有现行实测证据（连接被杀死、无 JSON 错误响应），且面板日志被 DEVNULL 吞掉（N6），线上表现为"面板偶发无响应且无从排查"。

**修复优先级**：
1. **P0（高）R2**：do_GET/do_POST 顶层 try/except → 500 JSON（半天工作量，顺带解决 N6 日志）；面板可用性最大单点。
2. **P1（中）**：N2 backup 撕裂、R6 删文件、R7 stdout 重定向（照抄 server.py:413 pentest 模板直调模式）、N1 waive/draft 返回值。
3. **P2（低）**：N3/N4/N5 面板一致性、R12 probe scope、R13 迁移吞错改"列已存在才跳过"、R9 死表死列清理（v13 迁移或文档明示退役）。
4. **工程 hygiene**：清理孤儿 __pycache__（N7）、修正 README 三处过时计数/清单（D1-D3）。

---

## 附：P0 修复记录（2026-10-12 当日完成）

**commit `fc1ab8a`** `fix(server): 顶层异常兜底 500/400 JSON + 异常落盘日志 (R2/N6)`（本地，未 push）

- **R2 已修复**（server.py，+119/-15）：do_GET/do_POST 改为薄包装，路由体顶层 `except Exception` → `_fail()`；`send_response` 覆写置位 `_responded` 防 double-send（已发响应只记日志不补发）；新增 `_read_json()` 统一处理 7 个 POST 路由的 body 解析（CL 缺失/非数字/负值、非 UTF-8、非 JSON、非对象 → 400 `invalid json`）；/api/void ids、/api/waive/draft id 非数字 → 400；SystemExit（BaseException）不被吞，原有 SystemExit→400 行为不变。
- **N6 已修复**：`log_exception()` 落盘 `pentdb/logs/panel_server.log`（时间戳 + 位置 + 异常摘要 + 完整 traceback，写日志自身失败不影响响应）；log_message 空实现未动。
- **新增回归** `pentdb/tests/test_server_guard.py`（7 用例）：畸形 event_id → 500 且连接存活、异常落盘格式、6 路由畸形/非对象 JSON → 400、两处非数字 id → 400、正常读写 sanity。
- **验证**：工程师自测 + QA 独立验证（临时库起真实服务复现原始 bug 三场景 + 自选边角 10 项：CL=-5/abc/5.5/缺失、半连接、SystemExit 不吞、既有 400/404 语义未变，共 26 项 0 失败）+ 主理人复跑 **211/211 OK**（基线 204 + 7）。`pentdb/tests/_ut_sum.txt` 已刷新为 211 记录。
- **遗留 known issue（QA 判定不阻塞）**：500 body 直接带 `str(exc)` 内部细节；`_read_json` 信任 Content-Length，巨大 CL 半连接会挂住一个 worker 线程（既有行为类）。

**P0 清零。P1 待办**：N2 backup 撕裂、R6 删文件、R7 stdout 重定向、N1 waive/draft 返回值。

---

## 附：评审过程说明

- 架构师（高见远）完成全部实证评审并回传完整报告；其最后一次收尾运行因 429 频率限制失败（未影响已交付内容）。
- 主理人独立复核：测试套件复跑；R2（server.py:89-90）、R6（pdb_tooling.py:133-154）代码抽查与报告一致。
- P0 修复走 BugFix 快捷路径：工程师实现 → QA 独立验证（PASS，26 项 0 失败）→ 主理人复跑确认 211/211。

---

## 附：R9 修复记录（2026-10-14 完成）

**v14 迁移 `_mig_v14_drop_sop_remnants`（schema v13→v14，SCHEMA_VERSION=14）**

- DROP TABLE pending_tests（全库零读写死表）；ALTER DROP COLUMN projects.stages_enabled / raw_events.stage（写入口 INSERT 列清单均不含 stage，历史残留恒空值，无数据损失）
- 幂等语义吸取 R13 教训：仅 "no such column" 跳过，其余异常照常抛出、版本不推进
- SCHEMA 基线同步删除三处（删除死结构例外于"不回改基线"铁律——否则 drop --project 的 executescript(SCHEMA) 会复活死表；新库路径 v2 按历史事实重新加列、v14 再删，链路诚实收敛）
- 配套清理：pdb_findings.py drop 级联列表删 pending_tests；server.py:15 模块级死 DB_PATH 删除；recon.py + 14 个测试文件的 stage="" 噪音 kwarg 全删（cmd_add/cmd_exec 从不读该字段）
- 测试：test_bugfix_r1r5 断言升 v14 + v14 形状断言（表/列不存在）+ 幂等双跑用例；test_intents 版本断言同步
- 验证：全量 238/238 OK（基线链 204→211→225→234→236→238）；真库 data/pentdb.db 迁移后 user_version=14、死表死列消、raw_events 1455 行 / assets 1203 行无损、8 审计触发器全存活；面板 /api/assets、/api/findings、/ 200 正常

**R9 关闭。P2 剩余：N3/N4/N5、R12、R13。**
