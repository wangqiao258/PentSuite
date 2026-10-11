# PentSuite（PentDB）代码级架构评审报告

- 评审日期：2026-10-11
- 评审人：软件公司专家团队 · 架构师（高见远）
- 评审对象：`C:\AI项目\PentSuite`
- 评审口径：**全部结论仅从可执行代码推导**（函数体逻辑、SQL DDL、argparse 注册、HTTP 路由注册、测试 assert 断言）。README/SKILL.md/注释仅用于定位入口，不作为结论依据；发现代码与文档/注释矛盾时以代码为准并单独列出（§9）。
- 经验证据：全量测试套件在本机实跑通过（`Ran 193 tests in 19.201s — OK`，2026-10-11，venv Python 3.13，只读验证，未修改任何源文件）。

---

## 1. 这个项目实际上是什么

从 `if __name__ == "__main__"` 与启动逻辑看，本仓库共有 **4 个可执行入口**，全部围绕同一个 SQLite 数据文件（`pentdb/data/pentdb.db`，路径可由环境变量 `PENTDB_DB` 覆盖，见 `pentdb/pdb_core.py:24`）运转：

### 入口 ①：`pentdb/pentdb.py` —— 主 CLI（写库唯一入口的宿主）
- `pentdb.py:846-851`：`__main__` 块重配置 stdout 为 UTF-8 后调用 `main()`。
- `main()`（`pentdb.py:447-843`）注册 **31 个顶层子命令**（见 §4 完整清单），覆盖：项目生命周期（init/archive/unarchive/drop）、观测写入（add/exec/probe-import）、资产派生（rebuild-assets）、人审（review/pending）、门禁（lint）、豁免（waive）、作废（void）、证据（evidence/evidence-move）、复测（verify/lifecycle）、探索计划（intent/plan/hint）、侦察采集（recon/js）、报告（report/sop）、面板与工具（panel/serve/hook-install/bootstrap）、云经验库（kb）、迁移（migrate）。
- `pentdb.py:40-75` 对 `pdb_core/pdb_assets/pdb_findings/pdb_intents/pdb_report/pdb_tooling` 六个拆分模块做 façade re-export（server 与测试以 `pentdb.xxx` 属性访问），自身保留 journal 对账（`journal_unmatched`，:86-137）、lint 引擎（`lint_report`，:155-343）、报告出口（`cmd_report`/`_report_run`，:371-444）与 `main()`。

### 入口 ②：`pentdb/server.py` —— 本地 Web 面板（只读 + 有限写）
- `server.py:640-648`：argparse 接收 `--port`（默认 8766）与 `--db`（写 `PENTDB_DB` 环境变量）后 `run(port)`。
- `run()`（:633-637）以 `ThreadingHTTPServer` 绑定 **127.0.0.1:8766** 常驻服务；`do_GET` 注册 20 个 GET 路由、`do_POST` 注册 7 个写路由（见 §5）。写操作复用 CLI 的 `cmd_*` 实现（如 `/api/review` → `pdb_assets.apply_review`，`/api/void` → `pentdb.cmd_void`），保证留痕语义一致。

### 入口 ③：`pentdb/hooks/journal.py` —— 宿主 PreToolUse 钩子（执行流水采集）
- `journal.py:50-51`：读 stdin JSON（宿主 Bash/PowerShell 工具的每条命令），`record()`（:22-37）把 `{ts,tool,session,cwd,cmd}` 逐行追加到 `pentdb/data/journal/<日期>.log`；任何异常静默退出 0（:41-46），保证永不阻塞宿主命令。部署方式是 `pentdb.py hook-install` 写入宿主 settings.json（`pdb_tooling.py:85-154`）。

### 入口 ④：`skill/pentest-kb-workflow/scripts/panel.py` —— 面板生命周期工具（skill 随行）
- `panel.py:193-194`：`start/stop/status` 三动作。`cmd_start`（:90-141）优先经 `explorer.exe panel_start.bat` 代理拉起 server.py（脱离 AI 会话进程树、跨会话常驻），失败则退回宿主托管（subprocess 直接拉起并 `proc.wait()`）；`cmd_stop`（:144-165）netstat(GBK) 找 PID → taskkill → socket 复验。`resolve_pt()`（:34-48）按 `home.txt` 或目录层级推断套件根。

非入口模块：`recon.py`、`kb/kb.py`、`pdb_*.py` 均为库（被 pentdb.py 经函数级 import 委托调用），无 `__main__`。

**形态总结**：这是一个 **AI 渗透测试信息收集/证据管理系统**——Python 标准库零依赖 CLI（核心）+ 本地 Web 人审面板 + 宿主命令流水钩子 + Supabase/PostgreSQL 云经验库（可选，依赖 psycopg2/jieba/rank_bm25），落库数据为真实渗透项目（实库 9 项目 / raw_events 4271 行 / evidence 238 条 / changelog 3440 条，2026-10-11 只读核查）。

---

## 2. 模块架构与依赖方向

### 2.1 模块级 import 关系（静态）

| 模块 | 顶层依赖 | 函数级（延迟）依赖 |
|---|---|---|
| `pdb_core.py` | 仅 stdlib | — |
| `pdb_assets.py` | `pdb_core`（:21-23） | `pdb_findings.sync_lifecycle_from_test`（:246，注释明示为避免环） |
| `pdb_findings.py` | `pdb_core` + `pdb_assets`（:23-26） | `pdb_assets.probe_ingest/probe_parse_text`（:302） |
| `pdb_intents.py` | `pdb_core`（:20） | — |
| `pdb_report.py` | `pdb_core`（:15） | — |
| `pdb_tooling.py` | `pdb_core`（:20） | `recon` / `server` / `kb`（:158-186 各命令内 import） |
| `pentdb.py` | 全部 6 个 pdb_* 模块（façade re-export，:41-75） | — |
| `recon.py` | stdlib | `import pentdb as pdb`（`run`:93、`run_js`:158 内） |
| `server.py` | stdlib | `pentdb` / `pdb_assets` / `pdb_findings`（请求处理函数内） |
| `kb/kb.py` | psycopg2 / jieba / rank_bm25（第三方） | — |
| `hooks/journal.py` | 仅 stdlib | — |

### 2.2 分层判断

- **无模块加载期循环**：`pdb_assets → pdb_findings` 的双向关系被刻意拆成"顶层单向（findings→assets）+ 函数级反向（assets→findings）"，import 顺序 `pentdb.py:46→52` 先 assets 后 findings 可正常加载（193 个测试全通过即为证据）。
- 分层清晰度：**core（常量/SCHEMA/迁移/连接/留痕）→ 领域模块（assets/findings/intents/report）→ façade（pentdb.py）→ 适配层（tooling/server/recon/panel.py）**，方向总体单向向下。
- 边界瑕疵（代码证据）：
  1. `server.py:44` 自行复制了一份 `LIFE_CODES` 常量而非引用 `pdb_findings.LIFE_CODES`（`server.py:47-51` 的 `set_lifecycle` 委托 `pentdb.set_lifecycle`，但常量是两份，存在漂移风险）。
  2. `server.py:11` 定义了模块级 `DB_PATH` 但全文件从未使用（实际备份用 `pentdb.DB_PATH`，:369）——死代码。
  3. `recon.py:93/158` 函数级 import `pentdb`，与 façade 形成运行时环（pentdb→pdb_tooling→(延迟)recon→pentdb），靠延迟 import 化解，可运行但依赖关系图上是一个环。
  4. `pdb_findings.py:23` 顶层依赖 `pdb_assets`（为复用 `cmd_add` 写入口），使 assets/findings 两个领域模块互相知晓，是全项目唯一的领域间顶层依赖。

---

## 3. 数据模型

来源：`pdb_core.py:36-222` 的 `SCHEMA` DDL、`pdb_core.py:295-469` 的 11 个迁移函数（`PRAGMA user_version` 驱动，`SCHEMA_VERSION=11`），并与实库 `pentdb/data/pentdb.db`（user_version=11）只读比对。

### 3.1 表清单（本地 SQLite）

| 表 | 主键 | 关键字段 | 代码层面可观察的语义 |
|---|---|---|---|
| `projects` | `name` | `stages_enabled`、`archived`、`created_at` | 归档仅翻标记（`pdb_assets.py:40-63` `_set_archived` 只 UPDATE archived）；**实库额外存在 `profile` 列（默认 'attack-surface'），但 SCHEMA 与 11 个迁移步均不创建它**——schema 漂移，见 §8-R1 |
| `raw_events` | `id` AUTOINCREMENT | `project/kind/value/title/detail/note/parent_ext/status/confidence/severity/scope/source/origin/dedup_key/voided/intent_id/attrs(JSON)/created_at/updated_at` | **append-only 观测流**。状态机 `new→confirmed/rejected`（VALID_STATUS，`pdb_core.py:28`），只有 `apply_review`（`pdb_assets.py:803-827`）改 status；kind 枚举 10 种（:27）；`voided` 墓碑（v8 迁移 :387-395）；`intent_id` 血缘归属（v9 :398-420）；触发器锁死 kind/project/created_at 不可改（:214-221） |
| `evidence` | `id` | `project/event_id/path/sha256/note/etype` | 证据登记；`event_id=0` 表示项目级物料（`pdb_core.py:512-515`）；`etype` 由 note 前缀推导 request/response/file（:555-559）；sha256 落库时现算（:546-549） |
| `pending_tests` | `id` | `project/event_id/term/stage` | **死表**：SCHEMA 建表后全库无任何读写（grep 证据：仅出现在 SCHEMA、v2 迁移加列、drop 级联清表中） |
| `waives` | `id` | `project/event_id/term/reason/confirmed` | 豁免状态机：`confirmed 0=起草 → 1=人工确认 / 2=人工作废`，由 `trg_waives_only_confirm` 触发器在 DB 层强制只允许 0→{1,2} 且其余字段不变（`pdb_core.py:194-201`、v7 迁移 :370-384 重建该触发器放行 0→2）；禁止 DELETE（:202-206） |
| `reviews` | `id` | `event_id/action/reviewer/note/at` | 人审流水，append-only（UPDATE/DELETE 双触发器拒绝，:184-193）；**无 project 列**，drop 时按被删事件 id 集合清理（`pdb_findings.py:730-732`） |
| `changelog` | `id` | `project/action/detail/at/actor` | 全部写操作留痕，append-only 双触发器（:174-183）；`actor` 区分 agent/human/机器采集（v5 迁移 :348-354，`log_change` 默认 agent，`pdb_core.py:499-503`） |
| `assets` | `(project, atype, akey)` 复合主键 | `atype(domain/host/service/endpoint)`、`akey` 规范身份键、`parent_atype/parent_akey`、`attrs(JSON)`、`event_ids(JSON)`、`first_seen/last_seen` | **纯派生表**：`rebuild_assets`（`pdb_assets.py:484-592`）全量 `DELETE FROM assets WHERE project=?` 后重插（:581-588），幂等、不触碰 raw_events；每次资产类 add 后自动触发（`pdb_assets.py:274-276`） |
| `intents` | `id` | `parent_id`(自引用)、`goal/hypothesis/status/note/created_at/closed_at` | 探索意图状态机 `active/done/dead`（`pdb_intents.py:22`）；关闭后拒绝新观测挂接（`pdb_assets.py:229-230`）；父链上溯防环上限 10 层（`pdb_intents.py:84-96`） |
| `plan_steps` | `id` | `seq/depends_on(逗号串)/intent_id/status/note` | 共享 todolist 状态机 `blocked/ready/doing/done/skip`（`pdb_intents.py:23`）；依赖晋升由 `_plan_promote` 循环至不动点（:172-193），晋升写 `plan-ready` 留痕 |
| `hints` | `id` | `text/intent_id/status/created_at/absorbed_at` | 人工判断通道，状态机 `open/absorbed`（:26）；绑定意图的 hint 随 intent close 自动吸收（`pdb_intents.py:148-153`） |

### 3.2 索引与触发器

- 索引 5 个：`idx_events_project`、`idx_events_status`、`idx_intents_project`、`idx_plan_project`、`idx_hints_project`（`pdb_core.py:110-169`）。
- **7 个 P0 防绕过审计触发器**（`pdb_core.py:174-221`，清单 `AUDIT_TRIGGERS` :225-230）：
  1. `trg_changelog_no_update/no_delete` — changelog append-only；
  2. `trg_reviews_no_update/no_delete` — reviews append-only；
  3. `trg_waives_only_confirm` + `trg_waives_no_delete` — 豁免状态机单向；
  4. `trg_events_agent_insert` — `origin='agent' AND status='confirmed'` 且 kind ∉ FACT_KINDS 的 INSERT 直接 ABORT（`--auto` 门禁的 DB 侧兜底）；
  5. `trg_events_no_core_update` — kind/project/created_at 不可改。
  唯一解除通道是 `cmd_drop`：先 `DROP TRIGGER` 再级联删、最后 `executescript(SCHEMA)` 幂等恢复（`pdb_findings.py:726-734`）。

### 3.3 迁移机制（schema 演进）

- `connect()`（`pdb_core.py:482-496`）：每连接必设 `busy_timeout=5000`；journal_mode 非 WAL 才切 WAL（并发基础）；随后 `_migrate`（:472-479）按 `PRAGMA user_version` 逐版本执行 `_MIGRATIONS[ver]`（11 步：v1 建表 → v2 补列 → v3 evidence.etype+回填 → v4 waives.confirmed+存量回填=1 → v5 changelog.actor → v6 dedup_key+存量 finding 回填指纹 → v7 重建 waives 触发器放行 0→2 → v8 voided → v9 intents+intent_id → v10 plan_steps → v11 hints），每步完成即 commit 并推进版本号。
- 派生语义细节：v6 明确"只填列不合并，存量归并由人依 lint warn 裁决"（:357-367）。

### 3.4 云库表（PostgreSQL，`pentdb/kb/schema.sql`）

- `pentest_knowledge`：uuid 主键、`scenario_tags jsonb`（GIN 索引）、状态机 `draft（默认）→approved / rejected→draft（恢复）/ deleted`、`deleted_at` 软删时间；`status` 无 CHECK 约束，状态合法性完全由 `kb.py` 应用层维护（`approve/reject/delete/restore` 各 UPDATE 均带 status 前置条件）。

---

## 4. CLI 命令面

来源：`pentdb.py main()` 的 `add_parser` 注册（:447-841）。共 **31 个顶层命令**，其中 4 个带二级子命令：

| 命令 | 关键参数 | 落点函数 |
|---|---|---|
| `init` | `--project`* | `cmd_init` |
| `archive` / `unarchive` | `--project`* | 翻 `projects.archived` 标记 |
| `panel` | `--project`、`--port`(8766) | 幂等拉起/复用面板子进程并播报待审数 |
| `add` | `--project/--kind/--value/--source`*、`--title/--detail/--detail-file/--note`、`--req/--resp`（报文文件或 `-` stdin）、`--waive-capture`、`--ext-id/--parent-ext/--merge-key`、`--status`(new/confirmed/rejected)、`--confidence/--severity/--code/--tech/--service/--scope`、`--auto`、`--update`（重扫更新）、`--no-dedupe`、`--intent <id>`、`--origin`(agent/human/migrate) | `cmd_add`（统一写入口，含全部写入门禁） |
| `exec` | `--project/--parent-ext/--cmd`*、`--action/--title/--note/--detail/--severity/--confidence`(high)/`--timeout`(120s)、`--probe-parse/--probe-host`、`--intent` | `cmd_exec`：shell 执行→输出落盘→test 事件→证据挂库 |
| `probe-import` | `--project/--file`*、`--host/--source/--parent-ext`、`--format`(auto/json/text)、`--dry-run` | 扫描结果批量入 kind=probe |
| `query` | `--project`*、`--kind/--status` | 只读列表 |
| `pending` | `--project`* | 待审列表 |
| `review` | `--project/--id`*、`--confirm/--reject`（二选一强制）、`--reviewer/--note` | 人审 |
| `lint` | `--project`*、`--no-journal`、`--health` | 门禁扫描，error 时 exit 1 |
| `hook-install` | `--global` | 写宿主 PreToolUse hook 配置 |
| `rebuild-assets` | `--project`* | 幂等重建资产实体层 |
| `migrate` | `--from <目录>`*、`--project`* | 从旧 jsonl（targets/ports/paths/params/findings/tests.jsonl）迁移 |
| `report` | `--project`*、`--out`、`--force`、`--template`(assets/pentest) | 出报告（lint error 默认拒绝） |
| `serve` | `--port`(8766)、`--db` | 直接跑面板（不常驻检查） |
| `sop` | `--project`* | SOP 提示清单（关键词命中参考，非门禁） |
| `waive` | `--project`*、起草：`--id <事件id> --term --reason`；裁决：`--wid <id[,id…]> --confirm / --reject` | 豁免起草/确认/作废（批量支持逗号分隔） |
| `void` | `--project`*、`--id` 或 `--ids <n,m,…>`、`--reason`*（作废必填）、`--undo` | 记录作废/恢复墓碑 |
| `drop` | `--project`*、`--confirm`* | 整项目删除（留 changelog 墓碑） |
| `evidence` | `--project/--event-id`*、`--path/--text/--keep-in-place/--note` | 证据挂库（event_id=0 项目级） |
| `evidence-move` | `--project/--id/--event-id`* | 改挂归属（0=项目级） |
| `verify` | `--project/--id`* | 刷新 verified_at |
| `lifecycle` | `--project/--id/--code`*（open/reproduced/not-reproduced/fixed/reopened）、`--note` | finding 生命周期 |
| `intent` | 子命令 `add`(--goal*/--hypothesis/--parent)、`list`(--all)、`show`(--id*)、`close`(--id*/--status* done\|dead/--note) | 探索意图 |
| `plan` | 子命令 `add`(--title*/--depends/--intent/--note)、`next`、`review`(--note/--refs)、`done`(--id*)、`skip`(--id*)、`list`(--all) | 共享 todolist |
| `hint` | 子命令 `add`(--text*/--intent)、`list`(--all)、`absorb`(--ids*/--note) | 人工判断通道 |
| `recon` | `--project/--domain`*、`--proxy/--timeout`(10)/`--workers`(16)/`--limit`(300)、`--single` | 被动子域枚举+存活探测+落库 |
| `js` | `--project`*、`--proxy/--timeout/--limit`(15) | JS 深挖（endpoint/密钥提取） |
| `kb` | 子命令 ×12：`search`(--keyword*/--tags/--limit)、`add`(--title*/--detail\|--from-file/--tags/--tool-code/--tool-type)、`find-similar`、`list`(--limit/--offset)、`pending`、`approve`(--id*/--confirm*/--merge-with)、`reject`、`delete`、`restore`、`deleted`、`purge`(--days 30)、`get`、`update`(--id*/字段) | 云经验库 |
| `bootstrap` | `--skip-deps`、`--kb-creds <旧凭据文件>` | 新机引导（venv/依赖/凭据迁移） |

---

## 5. Web 面板

### 5.1 后端 API（来源：`server.py` 路由注册代码）

**GET 路由（20 个）**：

| 路由 | 参数 | 行为要点 |
|---|---|---|
| `/`、`/index.html` | — | 返回 `web/index.html`（Cache-Control: no-store） |
| 静态白名单 `/style.css`、`/app.core.js`、`/app.findings.js`、`/app.assets.js`、`/app.queue.js`、`/app.report.js`、`/app.explore.js` | — | 白名单字典直读文件（`server.py:14-22,78-88`） |
| `/api/projects` | — | 项目列表（含 archived 过滤材料）；**查询 `projects.profile` 列——新库无此列，见 §8-R1**（:91-96） |
| `/api/overview` | project | by_kind/by_status 统计 + domain 列表；项目不存在 404（:97-108） |
| `/api/events` | project、kind、ids、kinds、value、status、q | 多条件过滤，`ORDER BY id DESC LIMIT 500`，附 ev_count 证据计数（:109-138） |
| `/api/assets` | project、atype、status、q、code_group | 实体列表；服务端计算 review 聚合态与 stale；code_group 语义组过滤（2xx/3xx/wall/404/5xx/none）（:139-194） |
| `/api/asset-detail` | project、atype、akey | 资产下钻：`findings_for_asset` + `exec_packets_for_asset` + 观测证据（含 exists 磁盘检查）（:195-222） |
| `/api/evidence` | project、event_id、event_ids | 证据列表（LEFT JOIN 事件 kind/title，exists 标记）（:223-239） |
| `/api/evidence/view` | id | int_param 安全转 int（400）；读前 256KB；utf-8→gbk 容错解码；NUL 判二进制（:240-265） |
| `/api/evidence/packet` | id | exec .log → curl 请求/响应报文只读投影；解析失败 `ok=false` 供前端降级（:266-285） |
| `/api/timeline` | project | 最近 100 事件 + 50 条 changelog（:286-294） |
| `/api/findings` | project | finding/osint 列表 + 起草态豁免行内带出 + no_pkt/no_ev 门禁旗标（与 lint F-301/O-301 同口径）（:295-323） |
| `/api/probes` | project、host | probe 观测；host 支持子域聚合 `value LIKE '%.host'`，LIMIT 5000（:324-340） |
| `/api/suggestions` | project | 最新 30 条 suggestion（:341-346） |
| `/api/intents` | project | 意图列表 + 每意图挂接观测数（:347-356） |
| `/api/plan` | project | plan_steps 按 seq（:357-362） |
| `/api/lint` | project | 直接返回 `pentdb.lint_report` 结构化结果（:363-366） |
| `/api/backup` | — | 整库 SQLite 文件下载（:367-378） |
| `/api/pending` | project | 待审队列 + dup_confirmed/dup_rejected 同值历史打标（:379-398） |
| `/api/report` | project、template、force | 先跑 lint：有 error 且非 force=1 → **409 拒绝出报告**；assets 模板经 stdout 重定向复用 `cmd_report`（:399-424） |

**POST 路由（7 个）**：

| 路由 | 请求体 | 行为要点 |
|---|---|---|
| `/api/retest` | finding_id、action、conclusion、source、lifecycle | 面板复测：可改 lifecycle（校验 LIFE_CODES）和/或登记 test 事件（复用 `cmd_add`，origin=human）；parent_ext 自动拼 finding 自身 id + 其数字型 parent（:432-478） |
| `/api/manual-add` | project、kind、value、source、note、scope、severity、update | 手动补录（origin=human、status=confirmed）复用 `cmd_add`（:479-507） |
| `/api/waive/confirm`、`/api/waive/reject` | project、wid 或 wids[] | 豁免批量确认/作废（人的决定，actor=human 留痕；409 语义冲突保护）（:508-549） |
| `/api/waive/draft` | project、id、term、reason | 豁免起草，复用 `cmd_waive` 同一实现（:550-575） |
| `/api/void` | project、ids[]、reason、undo | 复用 `cmd_void`（:576-597） |
| `/api/review` | action、ids[]、note | 人审批量；**批量(>1)必须 note**（:613-614）；统一走 `pdb_assets.apply_review` 单连接单事务（:615-630） |

### 5.2 前端页面结构（来源：`web/index.html` 分区 + 各 app.*.js 的加载/渲染代码）

单页应用，7 个 tab（`index.html:18-26`），`boot()` 在 `app.report.js:50` 尾部触发（该文件必须最后加载），项目下拉切换即整页刷新（`app.core.js:23`）。API 调用统一走 `api()`（`app.core.js:6`）。

1. **目标总览**（overview）：AI 建议卡（`api("suggestions")`，采纳/忽略按钮走 doReview）+ 统计卡（`api("overview")`，可点击深链到资产/待审）+ 子域按主域聚合分组（`app.core.js:57-106`）。
2. **发现·漏洞**（findings，`app.findings.js`）：项目级物料（`api("evidence",{event_id:0})`）、严重度/豁免/人审态筛选、漏洞列表（同指纹×N 打标、生命周期 tag、最近复测摘要）+ 详情工作台四页签 `["packet","复测包"],["timeline","时间轴"],["evid","证据链"],["retest","登记复测"]`（:57）；证据链页对每条证据并发拉 `/api/evidence/packet` 降级到 `/api/evidence/view`；复测提交走 `/api/retest`；豁免确认/作废/起草与记录作废按钮行内化（fetch POST）。
3. **资产明细**（assets，`app.assets.js`）：手动补录表单（POST `/api/manual-add`）+ 资产树（`api("assets",{atype})` 全量缓存，节点锚定子树过滤）+ 实体表（响应码语义组多选 chips 2xx/3xx/wall/404/5xx/none）+ 实体下钻（`api("asset-detail")`：属性卡/关联漏洞/exec 报文/probe 探测观测/原始观测折叠）。
4. **时间线**（timeline，`app.queue.js`）：`api("timeline")` 最近事件表 + changelog 留痕表。
5. **待审队列**（review，`app.queue.js`）：`api("pending")` 按来源分组、批量确认/驳回（批注必填，POST `/api/review`）、同值重复嫌疑置底折叠、行展开判据卡（`api("events",{value})` 拉同值历史）。
6. **探索·计划**（explore，`app.explore.js`）：`api("intents")` + `api("plan")` 两个只读面板（写操作全部走 CLI，页面明示）。
7. **报告·收尾**（report，`app.report.js`）：lint 门禁仪表盘（`api("lint")`，分层渲染阻断/豁免待确认/健康度）+ Markdown 报告（`api("report")`，模板切换、复制、下载 .md、整库备份链接）。

---

## 6. 代码中硬性执行的业务规则

每条给出可执行代码位置（非注释依据）：

**写入门禁（pdb_assets.cmd_add / _add_write）**
1. `source` 必填——空即 `sys.exit`（`pdb_assets.py:80-81`）。
2. AI（origin=agent）不得直接置 confirmed：CLI 校验（:89-92）+ **DB 触发器兜底**（`trg_events_agent_insert`，`pdb_core.py:207-213`，绕过 CLI 手编 SQLite 也被拒）；`--auto` 仅限 `FACT_KINDS = domain/port/path/param/test/probe`（`pdb_core.py:32`）。缺省规则：`--auto`+事实 kind→confirmed，否则 new（`pdb_assets.py:84-88`）。
3. AI 写入必须声明 confidence（:95-96）；severity/scope 枚举校验（:97-100）。
4. test 事件必须带 title/detail/note 至少一项（:102-104）；同 project+source+title+detail 的重复 test 拒绝入库（:116-122）。
5. 非 test 类同 kind+value 重复：无 `--update` 拒绝；有 `--update` 走重扫更新（刷新观测字段，保留状态与人审结论，:123-173）。
6. **finding 必须带真实报文**：缺 `--req/--resp` 且无 `--waive-capture` 直接拒绝（:174-179）；osint 至少 req/resp 任一（:181-186）；豁免起草后 lint 仍报 error 直到人工确认。
7. **finding 同指纹去重**：`dedup_key_for`（端点集规范化排序+title 折叠，SHA1 前 16 位，`pdb_core.py:256-282`）；同指纹已存在时——有新报文转挂主条目 evidence（dedup-merge 留痕，不新建）、无新报文拒写、`--no-dedupe` 强制独立成条（`pdb_assets.py:190-218`）。
8. `--intent` 挂接校验：意图必须存在且 active，已关闭拒绝（:224-230，`pdb_intents.py:39-47`）。

**人审与豁免状态机**
9. review 只认 confirm/reject 二选一（`pdb_assets.py:831-832`）；落库统一走 `apply_review`（CLI 与面板 `/api/review` 共用，:803-827）；幂等跳过不重复留痕（:811-812）。
10. **人审驳回联动**：把挂在该事件上的起草态豁免 confirmed 0→2 终结，避免孤儿豁免（:817-826）。
11. 豁免裁决三态强制：已确认不可作废、已作废不可确认/再翻转（`pdb_findings.py:120-155`）+ DB 触发器兜底；`--wid` 支持逗号批量（:91-98）。
12. 面板批量人审必须批注（`server.py:613-614`）。

**append-only 审计（DB 层强制）**
13. changelog / reviews 禁 UPDATE/DELETE；waives 禁 DELETE、UPDATE 仅 0→{1,2}；raw_events 的 kind/project/created_at 不可改（7 个触发器，`pdb_core.py:174-221`）。

**作废与删除**
14. void 必须写 reason、支持批量与 undo、只翻 voided 墓碑（`pdb_findings.py:44-88`）；作废记录退出 lint 阻断/报告/面板主视图/资产派生（`pentdb.py:181-182`、`pdb_assets.py:486-488` 等查询均带 `voided=0`）。
15. drop 必须 `--confirm`；级联删前临时解除触发器、删后 `executescript(SCHEMA)` 恢复；changelog 留 `__system__` 墓碑（`pdb_findings.py:713-739`）。

**lint 门禁（pentdb.lint_report，规则号即代码常量）**
16. 阻断级：E-101 证据文件丢失、E-102 无溯源、E-103/104 状态/类型非法、E-105 scope 非法、T-201 test 未关联被测对象、F-301 finding 无可重放报文（req+resp 成对）、O-301 osint 无取证材料、F-504→warn 同指纹多登记、**J-601 journal 有探测命令而库内无对应 test 记录（"测了没记"）**（`pentdb.py:155-343`）。
17. journal 对账语义：命令 ⊆ source 恒平账；反向须 source ≥12 字符；pentdb.py 自身命令豁免；cwd 会话隔离（并行会话不误归因）（`pentdb.py:78-137`）。
18. **报告出口门禁**：lint 有 error 拒绝出报告，`--force` 人工解除（CLI `pentdb.py:382-388` sys.exit；面板 `server.py:407-410` 返回 409）；lint 命令 error 时进程 exit 1（`pentdb.py:366`）。

**生命周期联动**
19. test 结论机读词（复现/未复现/已修复/部分修复/仍存在/待复测）→ finding lifecycle 自动映射（复现→reproduced…部分修复·仍存在→reopened，待复测/散文不触发）（`pdb_findings.py:30-41, 659-692`）；add 与 exec 两通道都经 cmd_add 天然全覆盖（`pdb_assets.py:242-249`）；同值幂等不重复写。
20. lifecycle CLI 只对 finding 生效（`pdb_findings.py:704-705`）。

**探索计划纪律**
21. 意图关闭（done/dead）后拒绝新观测挂接（`pdb_assets.py:229-230`）；父意图须 active（`pdb_intents.py:56-60`）。
22. plan 依赖放行：blocked 步骤前置全部 done/skip 才晋升 ready，晋升写 `plan-ready` changelog，循环至不动点（`pdb_intents.py:172-193`）；终态步骤不可重复关闭（:261-262）。
23. `plan review --note` 必须 `--refs` 引用**本项目中存在**的观测 id，裸判断拒绝落库（:452-459）；复盘检查点（events/hints/open_intents 计数）写入 changelog 作下次比对基准（:466-469）。

**证据与资产**
24. 证据落库统一 `attach_evidence`：文件复制进套件 evidence/ 目录（重名自增 _1/_2 后缀）、--text 直存（uuid 防覆盖）、keep-in-place 只存指针、sha256 现算、etype 按 note 前缀推导（`pdb_core.py:512-562`）。
25. 资产归并规则：domain akey=小写 FQDN 去尾点、port 拆 host:port、service akey=host:port、endpoint 一律归 host（parent 指向 service 的上溯剥端口）、param 并入 endpoint attrs.params、IP 误录 domain 按 host 归并（`pdb_assets.py:429-571`）；rebuild 幂等 DELETE+INSERT。
26. 资产级人审聚合：任一 new→pending，否则任一 confirmed→confirmed，全 rejected→rejected（`asset_review_state`，:722-729）；last_seen 超 30 天 stale（`pdb_core.py:34`、`asset_is_stale`，:732-743）。
27. probe 观测：纯观测不参与资产归并（不在 ASSET_KINDS），同 (host, attrs 全量) 重复跳过、状态/长度变化视为新观测（`probe_ingest`，:369-392）。
28. exec 单通道：输出强制落盘 `.log`（`$ 命令\nexit=码\n\n输出` 格式，`pdb_findings.py:268-274`）+ test 事件 + 证据自动挂库；超时仍落盘并在 note 前缀标注（:263-266, 276-277）。
29. exec .log → 报文投影降级原则：任何意外返回 None 绝不抛异常（`parse_exec_packet`，:395-404；`parse_exec_log_file`，:407-416）；不确定性记 flags（inferred_method/has_variables/unbalanced_quote/data_from_file/truncated/no_host 等）而非猜测（:553-597）。

**经验库（kb）**
30. add 一律 draft + 写入前脱敏校验（IP/域名/邮箱/凭据/云 Key/JWT/私钥/手机号正则命中即拒写，白名单域名与特殊 IP 放行）（`kb.py:148-180, 285-292`）。
31. approve 必须显式 `--confirm`（`pdb_tooling.py:209-211`）；`update_experience` 不暴露 status 参数（审批门禁不可绕过，`kb.py:556-599`，且有 AST 测试守护 `test_guards.py:331-340`）。
32. BM25 检索缓存：任何写操作后 `_invalidate_bm25_cache()`（lru_cache 清空，`kb.py:244-245`）；自定义 `_BM25Okapi` 修正负 IDF（:204-210）。

**并发基础**
33. 每连接 `busy_timeout=5000` + 库文件级 WAL（`pdb_core.py:488-494`），支撑 ThreadingHTTPServer 每请求新建连接 × CLI 并发写。

---

## 7. 测试实际验证了什么

15 个 unittest 文件、**193 个测试，实跑全部通过**（`Ran 193 tests in 19.201s — OK`）。测试用 `PENTDB_DB` 指向临时目录隔离库（如 `test_guards.py:20`），从 assert 断言归纳实际验证面：

- **test_guards.py**：DB 触发器语义——agent+confirmed 推断 kind 被 IntegrityError 拒绝、事实 kind 放行（:57-86）；raw_events kind/project/created_at UPDATE 拒绝、观测列放行（:105-134）；changelog/reviews UPDATE/DELETE 全拒（:139-188）；waives 0→1/0→2 放行、重复确认/改字段/倒退/DELETE 拒绝（:219-267）；drop 后触发器全部恢复且守卫立即生效、`__system__` 墓碑存在（:271-295）；`--auto` 缺省状态规则（事实→confirmed、推断→new、显式优先）（:315-328）；`kb.update_experience` 函数签名无 status 参数（AST 解析源码断言，:332-340）。
- **test_journal.py**：`probe_like` 启发式（URL/工具词命中、普通命令/pentdb 自身命令不命中）；`journal_unmatched` 平账语义——exec source 包含命令平账、极短 source（'s'）不得平账、完全一致恒平账、非探测/损坏行容忍、计数聚合、**其他会话 cwd 过滤**（:98-103）。
- **test_exec.py**：exec 通道落库形态——source=完整命令、title=exec 前缀、status=confirmed、origin=agent、confidence=high、detail 含 exit=、证据 etype=file 且磁盘存在、文件含 `$ 命令/exit=`、超时 note 标注、parent-ext/--cmd 缺失拒绝。
- **test_exec_packet.py**：curl 报文重建——显式/推断 method（POST/HEAD）、Content-Type 推断标记 inferred_header、Host 补齐、Basic 认证 base64、`$TOKEN` 原样保留 + has_variables、`@file` data 标记、多 URL truncated、no_host、响应提取（有无 -i 的 response_inferred 区分）、进度噪音行剥离、空输出 empty 标记、各种退化输入（随机文本/缺 exit/无 URL/二进制/None/bytes）返回 None 不抛、未闭合引号记 flag；façade re-export 同一性。
- **test_assets.py**：`_norm_domain`（大小写/尾点/co.uk 二级后缀/非法输入）、`_split_hostport`；rebuild_assets 幂等（两次重建 assets 计数不变、raw_events 不动）；IP 误录 domain 归 host；`asset_review_state` 聚合；stale 判定。
- **test_asset_detail.py**：`_match_asset` host 级归因四规则（host 精确/service 剥端口/endpoint 取首段/domain 子域后缀）；两跳 path 上溯；未知 id / host:port 直传；结果按 id 倒序；空资产返回空列表。
- **test_asset_packets.py**：`tests_for_asset` 归属变体（域名聚合、多 id、数字 id、跨主机）；`exec_packets_for_asset` 只收解析成功的 curl 日志（python 脚本/已删证据排除）、limit 截断至最近 10 条 test、无归属资产返回空；façade 同一性。
- **test_probe.py**：三种文本格式+JSON 解析（小写化、URL 拆 host/path、端口剥除、location 提取）；probe_ingest 去重计数；probe 落库 status=confirmed、parent_ext 透传；probe 不进 ASSET_KINDS 但在 VALID_KINDS/FACT_KINDS。
- **test_audit.py**：lifecycle CLI/自动联动（含幂等不重复写、多 finding、非 finding 跳过、changelog tag 区分来源）；lint 全链路——E-101 文件丢失、T-503 零留痕、T-504 结论词、F-301 报文门禁（豁免起草→确认放行/作废恢复阻断/批量确认清零）、O-301 osint 取证、dedup-merge 报文转挂主条目不新建、`--no-dedupe` 独立成条、同指纹 warn、test 缺 parent_ext 的 T-201。
- **test_plan.py**：suggestion 计划 lint（S-201 空计划、S-503 缺【下一步】、R-501 复盘裸判断）；渗透测试报告结构（复测计划引用最新 suggestion、"## 5 附录"顺延编号、发现标题入文）。
- **test_intents.py**：schema v11（intents/plan_steps/hints 表 + raw_events.intent_id 列）；意图挂接/已关闭拒绝/父意图校验；`exec --intent` 透传到 test 事件；**计划串行链不错序**（步骤1 ready、2/3 blocked → 1 done 后 2 晋升而 3 仍 blocked → 2 skip 后 3 才 ready）；终态保护；`--depends` 只认数字 id 且须存在。
- **test_review.py**：plan review 检查点（首次复盘触发、新增观测/hints 触发、无变化跳过）；`--note` 无 `--refs` 拒绝；结论落库 kind=note value=plan-review 且含【依据】#id；changelog 含 events=/open_intents= 基准；R-501 只 warn 不阻断。
- **test_hints.py**：hint 注入/列表/吸收全留痕；**绑定意图的 hint 随意图关闭自动吸收、项目级 hint 不被连带吸收**；重复吸收幂等提示。
- **test_server_param.py**：`int_param` 边界（正常/负数/非数字/小数/None/空列表/缺省值/参数名不匹配）。
- **test_sop.py**：`_term_in` 多候选拆词；hints 菜单扁平化（同术语多 when 各自成项）；sop_report 状态计数守恒（done+missing=total）、done 必带 #id、missing ev 为 None。

**测试面评价**：断言密度高、直击门禁与状态机不变量（触发器、豁免三态、依赖晋升、归因规则、报文重建降级），且大量断言**端到端行为**（add→lint→waive→report 链路）而非实现细节；未覆盖面主要是 server.py 的 HTTP 层（仅 int_param 有单测）与 kb.py（云端依赖，仅签名 AST 测试）。

---

## 8. 代码级风险发现

按严重度排列，逐条给证据：

**R1（高）schema 漂移：新装环境面板首屏即崩。**
`server.py:95` `/api/projects` 执行 `SELECT name, profile, archived FROM projects`，但 `pdb_core.SCHEMA`（:37-42）与全部 11 个迁移步都不创建 `profile` 列。实库（user_version=11）确有该列（PRAGMA 实测：name/created_at/profile/stages_enabled/archived），系历史上手工或外部脚本加列。**已实测复现**：用 `PENTDB_DB` 指向临时目录新建库后执行同款 SQL，报 `sqlite3.OperationalError: no such column: profile`；新建库 projects 列仅为 `[name, stages_enabled, archived, created_at]`。后果链：`do_GET` 对该路由无 try/except（仅 `finally: c.close()`，`server.py:89-90,427-428`），异常逃逸到 BaseHTTPRequestHandler → 连接被重置无响应；前端 `boot()` 第一步 `api("projects")`（`app.core.js:9`）即抛错 → **新机器全新建库后面板整个不可用**。

**R2（高）server.py 异常处理整体缺失。**
`do_GET` 主体（:65-428）除 `/api/report` 的 lint 调用（:403-406）外没有任何 try/except；`do_POST`（:430-630）对 `json.loads`（:434/481/512/554/580/601）与 `int()` 强转（如 `/api/evidence` 的 `event_id`/`event_ids`，:229-233）均未捕获——畸形 JSON 或非数字参数直接杀死该请求线程且客户端无 JSON 错误响应。与 `/api/evidence/view` 用 `int_param`+400（:241-243）的处理形成对照，属明显的处理不一致。面板以 `stdout=DEVNULL` 拉起（`pdb_tooling.py:55-57`），异常日志也被吞。

**R3（高）`cmd_drop` 级联删除不完整：intents/plan_steps/hints 成为孤儿。**
`pdb_findings.py:728-729` 级联清理的表仅有 `("raw_events","assets","pending_tests","waives","evidence")` + reviews（按事件 id，:730-732）+ projects（:733）；v9/v10/v11 引入的 `intents`、`plan_steps`、`hints` 三表不在清理清单。删除项目后这三表数据残留（面板按 project 过滤不可见，但占用库且 `intent add` 校验 `--project 一致` 时可能与同 id 新项目数据串扰）。

**R4（中）lint 修复指引引用不存在的 CLI 命令。**
`pentdb.py:288`（R-501 fix："update --id 本条补【依据】段…"）与 `pentdb.py:310`（F-503 fix："update --id 本条 --parent-ext 资产id"）指示用户执行 `update` 命令，但 argparse 全部注册（§4）中**不存在顶层 `update` 命令**（只有 `add --update` 重扫标志与 `kb update` 子命令）。照指引操作必然报错。

**R5（中）"取最后插入 id"跨连接竞态。**
`_exec_run`（`pdb_findings.py:293-295`）、面板 `/api/retest`（`server.py:473-476`）与 `/api/manual-add`（:500-505）均在 `cmd_add`（内部自开自关连接并 commit）**之后**另开连接执行 `SELECT id … ORDER BY id DESC LIMIT 1` 推断刚写入的事件 id。ThreadingHTTPServer 并发下（或 CLI 与面板并发写时）可能取到他人刚插入的事件，导致证据挂错事件、返回错 id。应使用同连接的 `lastrowid`（`attach_evidence` 已返回但未被利用，`pdb_core.py:562`）。

**R6（中）`cmd_hook_install --global` 可能误删项目级 settings.json 的其他配置。**
`pdb_tooling.py:140-152`：读项目级 `.codebuddy/settings.json` 后，仅检查 `hooks.PreToolUse` 里非 journal 条目（`rest`）；`rest` 为空即 `os.remove(proj_cfg)` **整文件删除**——若该文件还含 `hooks` 之外的任何其他配置键（如模型设置），将一并丢失（代码从未检查 pc 的其他顶层键）。

**R7（中）`/api/report` assets 模板的全局 stdout 重定向非线程安全。**
`server.py:415-423` 通过 `sys.stdout = buf` 全局替换复用 `cmd_report`。ThreadingHTTPServer 并发两个报告请求会互相践踏 `sys.stdout`，输出串流/丢失。应改用 `_report_run` 直调或线程局部重定向。

**R8（低）面板无鉴权（仅靠 127.0.0.1 绑定）。**
`server.py:634` 绑定 127.0.0.1，但 7 个 POST 写端点（review/waive/void/retest/manual-add）无任何 token；本机任意进程可冒"人的决定"确认/驳回/写库（且 origin=human 自动 confirmed，绕过 agent 门禁属设计使然，但通道本身无防护）。单用户工作站场景可接受，多用户/远程端口转发场景是越权面。

**R9（低）死 schema / 死代码。**
- `pending_tests` 表：全库无读写（仅 SCHEMA 建表、v2 加列、drop 清理时出现）。
- `projects.stages_enabled`、`raw_events.stage` 列：无任何业务读写（grep 全仓仅出现在 DDL、迁移与测试 Namespace 的占位 `stage=""`）。
- `server.py:11` 的模块级 `DB_PATH` 从未使用。
- `pentdb.py:41-45` façade re-export 的 `decode_text_compat/read_text_compat` 等符号部分仅供 server 使用，属接口面偏宽（轻微）。

**R10（低）exec 通道 `shell=True` 直执行原始命令串。**
`pdb_findings.py:260`：`subprocess.run(cmd_str, shell=True, …)`。这是产品核心设计（AI 的执行落库单通道），但意味着任何注入到 `--cmd` 的内容（含 prompt injection 诱导）都会原样执行；`--timeout`（默认 120s）超时后仍落盘留痕（:263-266）算是补偿。风险登记为"信任模型已知项"。

**R11（低）资源管理瑕疵。**
- `recon.run`/`run_js` 打开的连接 `c` 无 finally close（`recon.py:97/141/162/246`）；每 host 一次 `cmd_add` 各自 connect/close（:129-137），大批量子域时连接开销大（功能正确）。
- `journal.py:36` 直接 `open(path,"a")` 追加，无文件锁——宿主并发工具调用时理论上可交错（Windows 小写入基本原子，实际影响低）；journal 按日累积全量读入 lint（`pentdb.py:93-115`），长期项目 lint 会越来越慢。

**R12（低）probe 观测硬编码 scope="in"。**
`pdb_assets.py:387` probe_ingest INSERT 固定 `scope="in"`——即便探测目标实际在授权范围外，也会被标为 in-scope 且 lint E-105 不可能命中；scope 语义在 probe 通道失真。

**R13（低）迁移的静默吞错。**
`_mig_v2_columns`（`pdb_core.py:317-320`）等对所有 `ALTER` 捕获 OperationalError 后 `pass`——"列已存在"的幂等语义与"真失败"（磁盘/权限）不可区分，失败后版本号照样推进，留下永久 schema 漂移（R1 的 profile 问题若经此路径将无法察觉）。

**R14（信息）server.py 的 set_lifecycle 包装与常量复制。**
`server.py:44-51` 复制 `LIFE_CODES` 并包装 `set_lifecycle`（补 note 默认值）——委托实现尚一致，但常量双份，`pdb_findings.LIFE_CODES` 扩展时面板校验会滞后。

---

## 9. 代码 vs 文档/注释的矛盾点

逐条列出（本节"文档/注释"仅用于对照，结论均以代码实测为准）：

1. **`/api/projects` 的 `profile` 列 vs SCHEMA 自称完整基线**：`pdb_core.py:296` 注释称 v1 迁移"首次建表（SCHEMA 幂等，含全部基线列）"，但实际运行库的 `projects.profile` 列不在 SCHEMA 中也无迁移步创建——代码（server.py:95）依赖了一个基线之外的列。已实测：新库执行该 SQL 崩溃。**以实库为准可用、以 SCHEMA 为准新装必崩**，两套"事实"互相矛盾（详见 §8-R1）。
2. **lint fix 指引 vs argparse 实际注册**：`pentdb.py:288/310` 的修复指引让用户执行 `update --id …` 命令，CLI 中不存在该命令（仅 `add --update` / `kb update`）。指引与可执行面不符（§8-R4）。
3. **bootstrap 输出的回归命令错误**：`pdb_tooling.py:288` 打印 `回归: cd pentdb && python -m unittest test_sop`——测试实际位于 `pentdb/tests/` 包内（含 `tests/__init__.py`），从 `pentdb/` 目录执行 `python -m unittest test_sop` 找不到模块；正确命令应为 `python -m unittest discover -s pentdb/tests -t pentdb -p "test_*.py"`（本报告实测使用后者）。打印输出（程序行为的一部分）与目录结构不符。
4. **cmd_exec docstring 与 CLI 参数形态不符**：`pdb_findings.py:238` docstring 写"用法：… exec --project P --parent-ext N -- <命令…>（-- 后接实际命令）"，而实际 argparse 注册的是 `--cmd` 必填参数（`pentdb.py:512-513`），并无 `--` 透传形态。
5. **waives.confirmed 列注释滞后于触发器实现**：`pdb_core.py:93` SCHEMA 内联注释只写"0=起草…1=人工确认生效"，遗漏 2=人工作废态；而 v7 迁移（:370-384）与触发器 `trg_waives_only_confirm` 实际实现了 0→2。注释与 DDL 行为不一致（行为以触发器为准）。
6. **"写库唯一入口：一切写入必须经本 CLI"（pentdb.py:15 docstring）vs 面板写通道**：server.py 的 7 个 POST 端点同样直接写库（虽复用 cmd_* 实现，但入口不是 CLI）；同时 `cmd_drop` 本身就是经 CLI 的大批量 DELETE 通道（临时解除 append-only 触发器）。"唯一入口"的实际语义是"唯一实现（cmd_*）+ 双入口（CLI/面板）+ 一个人工豁免通道（drop --confirm）"，与字面表述有出入。

除上述外，主链路（add 门禁、lint 规则、报告门禁、豁免状态机、资产重建、exec 落库）注释声称的行为与代码实测一致，未发现其他矛盾。

---

## 附：评审方法与可复现性

- CLI 面：grep `add_parser` 全量枚举（31 顶层 + 4 组子命令）。
- 数据模型：grep `CREATE TABLE`/`ALTER TABLE` + 实库 `sqlite_master`/`PRAGMA table_info`/行数只读核查（user_version=11，9 项目/4271 事件/238 证据/3440 changelog/1509 assets）。
- API 面：server.py do_GET/do_POST 路由逐条核对；前端页面按 index.html 分区 + 各 JS 的 fetch/api 调用归纳。
- 测试：全量实跑（venv Python，193 tests OK，19.2s），断言语义按文件归纳。
- 关键风险实证：R1 以临时新库复现 `no such column: profile`；R3/R4/R6 由静态代码证据定位。
- 全程只读：未修改任何源文件；仅新增本报告文件。
