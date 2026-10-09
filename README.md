# PentSuite — AI 渗透测试信息收集套件

AI 落库与聚合、人看面板与审核的渗透测试**单一项目**。三层各司其职、一体分发、便携部署：

| 层 | 载体 | 职责 |
|----|------|------|
| 事实层 | `pentdb/pentdb.py` 等 | PentDB CLI（写库唯一入口）+ 零依赖面板 + SOP 引擎 + SQLite 事实库 |
| 经验层 | `pentdb/kb/`（CLI `kb-*` 子命令） | pentest-kb 经验沉淀/检索，存你自己的 Supabase 云端（强制脱敏） |
| 方法论层 | `skill/` | 标准 SKILL.md 格式的方法论，按所用客户端的技能方式安装（路径由 skill 目录 home.txt 自配置） |
| 引导 | `pentdb.py bootstrap` | 可选：建 .venv/装 kb 依赖/迁移经验库凭据 |

事实层与经验层**共用一个 CLI 入口和一个套件运行时**：代码全部在 `pentdb/`，venv 只有根目录一个 `.venv`（PentDB 零依赖不使用它，仅供 kb-* 子命令），仓库内不携带任何环境。

## 目录结构

```
PentSuite/
├─ pentdb/                 套件运行时（内部全部 __file__ 相对寻址，可整体搬移）
│  ├─ pentdb.py            CLI 入口 + main() 子命令注册 + journal 对账/lint 门禁（JOURNAL_DIR 留守保测试补丁语义）
│  │                       并以 façade 形式 re-export 全部符号——server.py 与 5 个测试文件 `import pentdb` 零感知
│  ├─ pdb_core.py          共享内核：BASE/DB_PATH/SCHEMA/常量、now/connect/log_change/require_project/attach_evidence
│  ├─ pdb_assets.py        资产域：init/add/域名归并/rebuild-assets/query/pending/review
│  ├─ pdb_findings.py      漏洞域：waive/evidence/verify/exec/lifecycle/drop/migrate
│  ├─ pdb_report.py        报告/SOP 域：pentest 报告装配、sop 提示
│  ├─ pdb_tooling.py       工具域：panel/hook-install/recon/js/kb/bootstrap
│  ├─ recon.py             采集器：被动子域枚举 + 存活探测（--single / --proxy 可移植）
│  ├─ server.py + web/     零依赖面板（stdlib，端口 8766；六视图全交互联动）
│  │                       web/ 七文件：index.html + style.css + 5 个 app.*.js（core/findings/assets/queue/report，按视图域拆分；boot() 在 app.report.js 尾部触发；server.py 白名单静态路由）
│  ├─ sop/default.json     SOP 提示清单（扁平 hints：when 触发语义 + check 提示术语，AI 查漏补缺用，无阶段）
│  ├─ tests/               12 个单测（stdlib unittest，unittest discover 全跑）：核心/资产/实体下钻/exec/报文解析/审计门禁/journal/probe/面板参数/审计触发器(guards)/决策链(plan)/sop 提示
│  ├─ hooks/journal.py     PreToolUse hook：宿主命令流水落盘（hook-install 部署）
│  ├─ kb/                  经验层单元（pentest-kb，Supabase 云端，强制脱敏）
│  │  ├─ kb.py             经验库逻辑（CLI kb-* 子命令的实现）
│  │  ├─ schema.sql        经验库建表 DDL（自建 Supabase 时执行）
│  │  ├─ dict.txt          经验检索词典
│  │  ├─ requirements.txt  经验层依赖清单（psycopg2/jieba/rank-bm25）
│  │  └─ creds_tpl.json    经验库云凭据模板（随仓库分发；拷贝为同目录 creds.json 后填值，creds.json 已 gitignore 不入库）
│  └─ data/pentdb.db       SQLite 事实库（init 生成，仅存本机）
├─ skill/pentest-kb-workflow/SKILL.md   方法论 skill（纯 SKILL.md，直接装入）
├─ .venv/                  套件唯一运行时（bootstrap 创建）
└─ README.md               本文件
```

## 数据模型与状态机

- `raw_events`（append-only 观测流）：kind: domain/port/path/param/finding/osint/note/test/suggestion/probe；source 必填；AI（origin=agent）必须带 confidence；confirmed 仅限机器事实 kind（domain/port/path/param/test/probe）加 `--auto`，且此时**缺省即 confirmed**（机器事实零接触入库，显式 `--status new` 可留待审），推断类一律 new 进待审
- `assets`（纯派生实体层）：观测流之上的归并层，对齐成熟 ASM 产品的"观测→实体→展示"三层。按规范 akey 归并为四类实体——domain（小写 FQDN，parent=注册域）、host（IP/主机名，从 port 观测提取）、service（host:port，parent=host）、endpoint（host+path，**已拍板：一律归 host**（parent_atype=host，不经 service），接受 akey 无 scheme/端口、同 host 的 http/https 同路径归并一行的副作用；param 并入 attrs.params 不再单独成行）；attrs 聚合端口/技术栈/服务/参数/状态码/scope；first_seen/last_seen 由 created_at/updated_at 派生。`rebuild-assets` 幂等全量重建（add/recon 后自动触发），人审聚合与生命周期（last_seen 超 30 天=stale）在面板侧实时计算，不落库
- `pending_tests`（legacy 空表，阶段制退役后不再写入；同退役的还有 `raw_events.stage` / `projects.stages_enabled` 列与 `--merge-key` 参数——库中保留兼容但零读写）/ `waives` / `reviews` / `changelog`（留痕含 actor：agent=AI 经 CLI / human=人审动作，面板时间线可辨操作者）：append-only 由 P0 审计触发器在 DB 层强制——changelog/reviews 禁 UPDATE/DELETE，waives 仅允许 confirmed 0→1，raw_events 的 kind/project/created_at 禁改；任何写路径（含手编 SQLite）均被数据库本身拒绝，唯一解除通道=`drop --confirm`
- 状态机 `new →(人审)→ confirmed/rejected`；报告与攻击建议只引用 confirmed；实体的"有待审/已确认/已驳回"是其观测的人审聚合，与生命周期互相独立（对应成熟产品的归属态/人审态分离）
- finding detail 七段约定：`【描述】【请求】【payload】【判据】【原因】【手工验证】【修复】`——【请求】是**测试用例（构造物）**，未实测须标"待验证"；**事实数据包 = evidence 的 request/response 对**（`add --kind finding --req/--resp` **写入口强制**，无报文直接拒绝；豁免走 `--waive-capture` 起草 + 人工 `waive --wid N --confirm` 确认；lint 兜底：漏洞无 req/resp 证据=error）。【判据】=基线 vs 复现的判定标准。test 事件 **value=动作、note=结论**，结论后用「｜ 依据：<输出关键证据>」补判断依据（两段式；机读结论但缺依据=lint warn——决策链在面板可复核）。批次收尾计划走 `--kind suggestion`：detail 按【已做】/【结论】/【下一步】三段（缺【下一步】=lint warn），报告「复测计划」节自动引用最新一条
- 物料归属三层：**项目级**（凭据表/报告/访问说明，`evidence --event-id 0`）｜**finding 级**（该漏洞自己的 req/resp 证据）｜**实体级**（资产实体层聚合观测）。归属判定=复测时必须用到；认证依赖禁止虚构
- `evidence`：证据随库走——文件默认复制进 `data/evidence/<project>/`（--keep-in-place 只存指针；`--text` 直存请求/响应原文），库内存路径+SHA256+**etype**（request/response/file，按 note 前缀自动落，面板按类型渲染）；详情页可查看，报告自动附证据清单
- `intents` / `plan_steps`（v9/v10 探索血缘层，借鉴 ARTEX 双图+共享 todolist 的本地化落地）：`intents` 一条=一条带假设的推进方向（goal+hypothesis，parent_id 连父链，status: active/done/dead），观测经 `raw_events.intent_id` 挂接成方向→观测血缘链（挂接校验：意图须同项目且未关闭）；`plan_steps` 共享 todolist（seq 顺序、depends_on 前置、status: blocked/ready/doing/done/skip），`plan next` 只放行前置已满足的步骤（自动晋升留痕）——串行攻击链在"每轮全新会话"下仍稳定推进。两表为普通可变状态表（不受 append-only 触发器约束），全部状态推进走 CLI 留痕 changelog

## 命令速查（CLI = `python pentdb/pentdb.py`）

| 动作 | 命令 |
|------|------|
| 建档 | `init --project P` |
| 归档 | `archive --project P` / `unarchive --project P`（面板下拉默认隐藏已归档项目，「含归档」开关可见；数据/证据全部保留可查；**真删除仍走 drop --confirm，仅限人显式指令**） |
| 开面板（幂等托管） | `panel --project P`（活着复用/没起拉起/被占报 PID；输出 url+pending 数；**AI 会话内禁用本命令**——detached 子进程必死） |
| 面板启停（AI 走这里） | skill 随行脚本 `skill/pentest-kb-workflow/scripts/panel.py start\|stop\|status`：start 须 `run_in_background=true` 后台跑（内部=端口预检+explorer 代理经 panel_start.bat 静默拉起 pythonw server.py，脱离会话进程树、跨会话常驻，会话结束不回收；explorer 不可用自动退回宿主托管并在输出标注；已运行幂等跳过）；**只拉不停**——AI 任务收尾不停面板，stop 仅限人工排障/重启前使用（netstat(GBK) 查 PID+taskkill+socket 复验关闭）。规范见 SKILL「面板生命周期」 |
| 落资产 | `add --project P --kind domain\|port\|path\|param\|finding\|osint --value V --source "命令/URL" [--code][--tech][--service][--scope][--severity]`；`--auto`（机器事实 kind）缺省自动 confirmed，推断类缺省 new 进待审 |
| 重扫更新 | 同 kind+value 重复时 `add --update`：刷新观测字段并更新 last_seen（updated_at），状态与人审结论保留 |
| 重建实体层 | `rebuild-assets --project P`（幂等；add/recon 资产类写入后自动触发，一般无需手跑） |
| 登记测试 | `add --kind test --value "动作" --note "结论 ｜ 依据：输出关键证据" --parent-ext <id>[,id2] --source "命令" --auto --status confirmed --confidence high`（value=动作、note=「结论 ｜ 依据」两段式） |
| 批次计划 | `add --kind suggestion --title "批次计划" --detail "【已做】…【结论】…【下一步】…"`（三段式，【下一步】具体到目标/命令；面板待审页+报告「复测计划」节可见） |
| 执行落库单通道 | `exec --project P --parent-ext N --cmd '<完整命令>' [--action][--note 结论][--timeout S]`——命令输出自动落盘 + test 事件自动入库 + 原始输出自动挂证据（note=output，etype=file），探测/测试类命令一律走此通道，防"测了没记"；`[--probe-parse --probe-host H]`：目录扫描输出逐路径解析入库 kind=probe（Burp 式全录） |
| 探测观测入库 | `probe-import --project P --file <json\|log> [--host H][--source S][--parent-ext N][--format auto\|json\|text][--dry-run]`——扫描结果（JSON 行列表或 dirscan/gobuster/ffuf 文本）批量入库 kind=probe：逐条 HTTP 探测观测（host/path/status/len/ctype 入 attrs），append-only（同 host+全量 attrs 重复跳过，状态变化=新观测）；**不参与资产归并**——endpoint 准入门槛不变，防 404 灌爆资产树；面板资产页 host/domain 详情「探测观测」页签可查可过滤（domain 节点聚合其全部子域） |
| 结论同步 | `lifecycle --project P --id <finding> --code open\|reproduced\|not-reproduced\|fixed\|reopened [--note]`——复测结论机读化（test note 以机读词开头：复现/未复现/已修复/部分修复/仍存在/待复测）；**test 事件入库（add/exec）即自动联动**：note 机读词映射 parent finding 生命周期（复现→reproduced、未复现→not-reproduced、已修复→fixed、部分修复/仍存在→reopened；待复测与散文 note 不触发），parent_ext 逗号分隔多 finding 全部联动、非 finding 跳过，已同值不重复写；留痕 tag=（test#N 自动）与手动 CLI 的（CLI）可区分 |
| 登记漏洞 | `add --kind finding --req <请求原文\|-> --resp <响应原文\|-> ...`——**写入口强制：无 req/resp 直接拒绝**，自动挂 evidence（note=request/response）并在面板展示；报文确实已丢的加 `--waive-capture '原因'` 起草豁免（待人确认，确认前 lint 仍报 error） |
| 漏洞去重 | finding 写入即算指纹（规范化端点集+title 的 sha1 前缀）：同指纹已有记录→**报文自动转挂主条目**（dedup-merge 留痕）不新建待审条目，无报文拒写；确属不同漏洞加 `--no-dedupe` 强制独立成条；存量同指纹组由 lint warn 提示人工归并 |
| 登记情报 | `add --kind osint` 必带 `--resp <文件\|->` 或 `--req` 任一（事实取证：API 响应/页面原文/工具输出，写入口强制，不强制成对）；材料取不回的走 `--waive-capture '原因'` 起草豁免（待人确认，确认前 lint 仍报 error） |
| 证据 | `evidence --project P --event-id N --path F`（默认复制进套件；`--text` 直存文本；`--event-id 0`=项目级物料）；`evidence-move --id N --event-id M` 改挂归属 |
| AI 推断 | `add ... --confidence high\|medium\|low`（推断类禁止 confirmed，一律 new 进待审） |
| 查询 | `query --project P [--kind][--status]` |
| SOP 提示 | `sop --project P`（扁平提示清单：when 触发语义 + check 提示术语 + 状态参考，AI 语义判断命中后对照自查；**提示层非门禁、非义务，不设豁免**，覆盖度由 AI 显式申报、人背书；无阶段概念） |
| 豁免 | `waive --project P --id N --term T --reason R`（只作用于具体事件：报文豁免挂 finding、归因豁免挂 test；起草态不生效，人工 `waive --wid M --confirm` 确认后生效、`--wid M --reject` 作废终结（留痕、阻断恢复），均 AI 不得代行；`--wid 34,35,36` 逗号分隔批量） |
| 记录作废 | `void --project P --id N --reason R`（或 `--ids N,M,…` 批量；**人的决定**：冗余/误录数据清理通道，区别于豁免——作废记录退出 lint 阻断/报告/面板主视图/资产派生；`--undo` 恢复误作废；均留痕 actor=human） |
| 门禁 | `lint --project P [--health]`（收尾 0 阻断；两分类：**阻断**=证据文件丢失/缺报文·取证/测试未归因/命令流水未落库/溯源缺失；**健康度**=格式类提示（零留痕/结论词/分节/计划三段式等）不阻断，CLI 缺省只报条数 `--health` 看明细，面板常驻；含执行流水对账：journal 探测类命令无对应 test 事件=阻断（测了没记），`--no-journal` 开发场景跳过） |
| hook 部署 | `hook-install`（生成 PreToolUse journal hook；默认项目级仅本工作区生效，**`--global` 写用户级全工作区生效——渗透发生在目标工作目录，推荐**；CLI 终端版需 `/hooks` 面板审查，桌面版实测动态加载即生效，验证=新会话跑命令查 journal） |
| 人审 | `review --project P --id N --confirm\|--reject`（面板支持按来源分组多选批量，批量强制批注） |
| 探索意图（血缘） | `intent add --project P --goal '<方向>' [--hypothesis 假设][--parent 父意图id]`；观测落库带 `--intent N`（add/exec 均可）挂到意图 → 形成方向→观测血缘链（回答"这个方向为什么测、产出了什么"）；`intent list/show/close`（close --status done\|dead；**关闭后拒绝新挂接**；已关闭意图的重扫更新补挂也拒绝）。面板「探索·计划」页只读展示 |
| 共享计划（todolist） | `plan add --project P --title '<本步做什么>' [--depends 前置id,前置id][--intent N]`（有未满足前置→blocked，否则 ready）；`plan next`（**只放行前置已全部 done/skip 的步骤**，blocked 步骤依赖满足时自动晋升 ready 留痕；AI 粗筛循环的领取通道）；`plan done/skip --id N [--note]`（写回后自动解锁下游）；`plan list [--all]`。串行攻击链（注入点→凭据→横向）按依赖逐步派发，不错序、不重复 |
| 报告 | `report --project P [--template pentest] [--out F]`（pentest=描述/复现包/原因/手工验证/修复+证据清单+**复测计划（最新 suggestion）**；**出口门禁：lint 有 error 拒绝出报告**，`--force` 仅限人工解除） |
| 采集 | `recon --project P --domain D [--single][--proxy]`；`js --project P` |
| 经验库 | `kb search --keyword K`；`kb add --title T --from-file F`（一律 draft）；`kb find-similar`；`kb pending`；`kb approve --id N --confirm`（人的决定）；`kb update`（仅内容字段，状态翻转只走 approve/reject）；`kb get/list/deleted/...` |

## 面板七视图（全交互联动）

目标总览（卡片点击跳转筛选）｜发现·漏洞（级别过滤+状态筛选；详情=复测工作台：目标跳资产、复测包页签=事实报文成对查看器（request/response 页签切换+复制为 curl）+复测用例（【请求】/【payload】一键复制/复制为 curl）+概要七节、证据链页签只放附件物料（查看）、复测时间轴、登记本轮手工复测）｜资产明细（实体分列：domain/host/service/endpoint，属性芯片+首末见+生命周期，点行下钻原始观测，手动补录）｜时间线｜待审队列（按来源分组+多选批量）｜探索·计划（意图血缘链+共享 todolist 只读看板，写走 CLI intent/plan）｜报告·收尾（assets/pentest 模板+lint 门禁+整库备份）。SOP 提示已退役为 AI-only（CLI `sop`），面板不再展示

AI 播报约定：**仅批次产生新待审项时**播报（链接+新增数+待审数+重点）；纯 --auto 批次不打扰。

## 执行流水对账（journal，堵"测了没记"）

AI 拥有裸 shell，exec 是建议走的门而非唯一的门。宿主工具链拦截补上这一层：`hook-install --global` 部署 PreToolUse hook（matcher `Bash|PowerShell`，用户级全工作区生效），宿主执行任何命令前先落一行流水到 `pentdb/data/journal/<日期>.log`；`lint` 收尾对账——journal 里探测类命令（含 URL 或 curl/nmap/sqlmap 等工具词）在 test 事件中找不到对应记录 = **error**（`pentdb.py` 自身调用是记账/自录通道天然豁免；exec 落库 source=完整命令，天然平账）。强制力在宿主 harness 而非 AI 自觉：沙箱内命令必经 Bash/PowerShell 工具，绕过在结构上不存在。生效方式：CLI 终端版经 `/hooks` 面板审查（配置外部修改需人工确认，AI 无法代批或静默篡改）；桌面版实测免审动态生效（验证=新会话跑任意命令后查 journal）。

## 快速开始

```bash
python pentdb/pentdb.py init --project <目标>
python pentdb/pentdb.py panel --project <目标>
python pentdb/pentdb.py recon --project <目标> --domain example.com
python pentdb/pentdb.py sop --project <目标>
python pentdb/pentdb.py lint --project <目标>
python pentdb/pentdb.py report --project <目标> --template pentest --out report.md
```

## 安装（新机器 / GitHub clone 后）

前置：PentDB CLI/面板零依赖；经验库需要 Python 3.10+（bootstrap 建 venv）。

1. **装 skill**：把 `skill/pentest-kb-workflow/` 按所用客户端的技能方式装入（WorkBuddy：拖拽；Claude Code：复制到其 skills 目录；其他客户端：让 AI 直接读该文件亦可）。首次使用时 AI 会询问"PentSuite 克隆在哪个目录？"并把路径写入 skill 目录的 `home.txt`——一次配置，长期有效。
2. **（可选）经验库**：`python pentdb/pentdb.py bootstrap`（建套件 .venv、装 kb 依赖）→ 注册 Supabase 免费实例 → SQL Editor 执行 `pentdb/kb/schema.sql` → 拷贝凭据模板 `pentdb/kb/creds_tpl.json` 为同目录 `creds.json`（已被 .gitignore 排除，不会入库），填入 host / user / password 三项即用。不用经验库可全部跳过——PentDB 事实层全套零依赖照常可用。

   三个值都在 Supabase 控制台 **Project Settings → Database**：
   - **host** = Connection pooler 的主机名（形如 `xxx.pooler.supabase.com`）
   - **user** = `postgres.<项目ref>`（连接串里 `@` 前面那段）
   - **password** = 建项目时设置的数据库密码（忘了可在同页 Reset 重置）
   - port / dbname 已预填 `5432` / `postgres`，无需改动

   填好的 `creds.json` 实例样式（占位值示意，以旧 pentest-kb-mcp 配置模板同款格式为例；**模板本体保持空值，拷贝后替换成真实值**——占位值原样留着会让 kb 误以为已配置而报连接错误）：

   ```json
   {
     "host": "your-supabase-host.pooler.supabase.com",
     "port": "5432",
     "dbname": "postgres",
     "user": "postgres.your-project-ref",
     "password": "your-database-password"
   }
   ```

   也可以不走文件、直接设环境变量（键名与旧 mcp.json 一致，优先级高于 creds.json）：

   ```bash
   set PENTEST_KB_DB_HOST=your-supabase-host.pooler.supabase.com
   set PENTEST_KB_DB_USER=postgres.your-project-ref
   set PENTEST_KB_DB_PASSWORD=your-database-password
   ```
3. **验证**：

```bash
python pentdb/pentdb.py init --project demo
python pentdb/pentdb.py panel --project demo      # 浏览器打开输出的 URL
python pentdb/pentdb.py kb search --keyword 测试   # 未配凭据时返回友好提示
.venv/Scripts/python.exe -m unittest discover -s pentdb/tests -t pentdb -p "test_*.py"   # 全量回归（仓库根执行，12 个测试文件，含 probe 观测层/审计触发器/决策链用例）
```

- 数据存放：事实库 `pentdb/data/pentdb.db` 为本地文件，clone 后不存在、init 按需生成；凭据模板 `pentdb/kb/creds_tpl.json` 随仓库自带（空值），拷贝为 `creds.json` 填入真实值后仅存本机（已被 .gitignore 排除）、套件不会自动上传任何内容
- 旧机器迁移经验库凭据：`pentdb.py bootstrap --kb-creds <creds.json>`
- 自用迁移（多机器带数据）：手工压缩整个目录（含 pentdb/data/），自行保管，与 GitHub 互不干扰
