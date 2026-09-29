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
│  ├─ pentdb.py            CLI：init/panel/add/exec/lifecycle/query/review/lint/rebuild-assets/sop/waive/
│  │                       migrate/report/drop/evidence/verify/stages/recon/js/serve
│  ├─ recon.py             采集器：被动子域枚举 + 存活探测（--single / --proxy 可移植）
│  ├─ server.py + web/     零依赖面板（stdlib，端口 8766；七视图全交互联动）
│  │                       web/ 三文件：index.html + style.css + app.js（server.py 白名单静态路由）
│  ├─ sop/default.json     SOP 提示清单（stage_hints：when 触发语义 + check 提示术语，AI 查漏补缺用）+ 7 阶段
│  ├─ test_sop.py          核心逻辑单测（stdlib unittest）
│  ├─ test_assets.py       资产实体层单测（key 规范化/归并/聚合语义）
│  ├─ kb/                  经验层单元（pentest-kb，Supabase 云端，强制脱敏）
│  │  ├─ kb.py             经验库逻辑（CLI kb-* 子命令的实现）
│  │  ├─ schema.sql        经验库建表 DDL（自建 Supabase 时执行）
│  │  ├─ dict.txt          经验检索词典
│  │  ├─ requirements.txt  经验层依赖清单（psycopg2/jieba/rank-bm25）
│  │  └─ creds.json        经验库云凭据（空模板随仓库自带，填值即用）
│  └─ data/pentdb.db       SQLite 事实库（init 生成，仅存本机）
├─ skill/pentest-kb-workflow/SKILL.md   方法论 skill（纯 SKILL.md，直接装入）
├─ .venv/                  套件唯一运行时（bootstrap 创建）
└─ README.md               本文件
```

## 数据模型与状态机

- `raw_events`（append-only 观测流）：kind: domain/port/path/param/finding/osint/note/test/suggestion；source 必填；AI（origin=agent）必须带 confidence 且不得置 confirmed（--auto 仅限机器事实 domain/port/path/param/test）
- `assets`（纯派生实体层）：观测流之上的归并层，对齐成熟 ASM 产品的"观测→实体→展示"三层。按规范 akey 归并为四类实体——domain（小写 FQDN，parent=注册域）、host（IP/主机名，从 port 观测提取）、service（host:port，parent=host）、endpoint（host+path，param 并入 attrs.params 不再单独成行）；attrs 聚合端口/技术栈/服务/参数/状态码/scope；first_seen/last_seen 由 created_at/updated_at 派生。`rebuild-assets` 幂等全量重建（add/recon 后自动触发），人审聚合与生命周期（last_seen 超 30 天=stale）在面板侧实时计算，不落库
- `pending_tests`（带 stage）/ `waives` / `reviews` / `changelog`：只追加留痕
- 状态机 `new →(人审)→ confirmed/rejected`；报告与攻击建议只引用 confirmed；实体的"有待审/已确认/已驳回"是其观测的人审聚合，与生命周期互相独立（对应成熟产品的归属态/人审态分离）
- finding detail 七段约定：`【描述】【请求】【payload】【判据】【原因】【手工验证】【修复】`——【请求】是**测试用例（构造物）**，未实测须标"待验证"；**事实数据包 = evidence 的 request/response 对**（`add --kind finding --req/--resp` **写入口强制**，无报文直接拒绝；豁免走 `--waive-capture` 起草 + 人工 `waive --wid N --confirm` 确认；lint 兜底：漏洞无 req/resp 证据=error）。【判据】=基线 vs 复现的判定标准。test 事件 **value=动作、note=结论**
- 物料归属三层：**项目级**（凭据表/报告/访问说明，`evidence --event-id 0`）｜**finding 级**（该漏洞自己的 req/resp 证据）｜**实体级**（资产实体层聚合观测）。归属判定=复测时必须用到；认证依赖禁止虚构
- `evidence`：证据随库走——文件默认复制进 `data/evidence/<project>/`（--keep-in-place 只存指针；`--text` 直存请求/响应原文），库内存路径+SHA256+**etype**（request/response/file，按 note 前缀自动落，面板按类型渲染）；详情页可查看，报告自动附证据清单

## 命令速查（CLI = `python pentdb/pentdb.py`）

| 动作 | 命令 |
|------|------|
| 建档 | `init --project P` |
| 开面板（幂等托管） | `panel --project P`（活着复用/没起拉起/被占报 PID；输出 url+pending 数） |
| 落资产 | `add --project P --kind domain\|port\|path\|param\|finding\|osint --value V --source "命令/URL" [--code][--tech][--service][--scope][--severity]` |
| 重扫更新 | 同 kind+value 重复时 `add --update`：刷新观测字段并更新 last_seen（updated_at），状态与人审结论保留 |
| 重建实体层 | `rebuild-assets --project P`（幂等；add/recon 资产类写入后自动触发，一般无需手跑） |
| 登记测试 | `add --kind test --value "动作" --note "结论" --parent-ext <id>[,id2] --stage <阶段名> --source "命令" --auto --status confirmed --confidence high`（**--stage 必带**；value=动作、note=结论） |
| 执行落库单通道 | `exec --project P --parent-ext N --cmd '<完整命令>' [--stage][--action][--note 结论][--timeout S]`——命令输出自动落盘 + test 事件自动入库 + 原始输出自动挂证据（etype=output/file），探测/测试类命令一律走此通道，防"测了没记" |
| 结论同步 | `lifecycle --project P --id <finding> --code open\|reproduced\|not-reproduced\|fixed\|reopened [--note]`——复测结论机读化（test note 以机读词开头：复现/未复现/已修复/部分修复/仍存在/待复测） |
| 登记漏洞 | `add --kind finding --req <请求原文\|-> --resp <响应原文\|-> ...`——**写入口强制：无 req/resp 直接拒绝**，自动挂 evidence（note=request/response）并在面板展示；报文确实已丢的加 `--waive-capture '原因'` 起草豁免（待人确认，确认前 lint 仍报 error） |
| 证据 | `evidence --project P --event-id N --path F`（默认复制进套件；`--text` 直存文本；`--event-id 0`=项目级物料）；`evidence-move --id N --event-id M` 改挂归属 |
| AI 推断 | `add ... --confidence high\|medium\|low`（推断类禁止 confirmed，一律 new 进待审） |
| 查询 | `query --project P [--kind][--status]` |
| SOP 提示 | `sop --project P`（查漏补缺提示清单：when 触发语义 + check 提示术语，AI 语义判断命中后对照自查；**提示层非门禁、非义务，不设豁免**，覆盖度由 AI 显式申报、人背书） |
| 豁免 | `waive --project P --id N --term T --reason R`（只作用于具体事件：报文豁免挂 finding、归因豁免挂 test；起草态不生效，人工 `waive --wid M --confirm` 确认后才生效，AI 不得代批） |
| 门禁 | `lint --project P`（收尾 0 error；含对账：证据文件丢失=error、test 零证据输出/结论无机读词=warn） |
| 人审 | `review --project P --id N --confirm\|--reject`（面板支持按来源分组多选批量，批量强制批注） |
| 报告 | `report --project P [--template pentest] [--out F]`（pentest=描述/复现包/原因/手工验证/修复+证据清单；**出口门禁：lint 有 error 拒绝出报告**，`--force` 仅限人工解除） |
| 采集 | `recon --project P --domain D [--single][--proxy]`；`js --project P` |
| 经验库 | `kb search --keyword K`；`kb add --title T --from-file F`（一律 draft）；`kb find-similar`；`kb pending`；`kb approve --id N --confirm`（人的决定）；`kb get/list/deleted/...` |

## 面板七视图（全交互联动）

目标总览（卡片点击跳转筛选）｜SOP 提示（提示清单=when×check、状态卡过滤、lint 门禁）｜发现·漏洞（级别过滤+状态筛选；详情=复测工作台：目标跳资产、复测包页签=事实报文成对查看器（request/response 页签切换+复制为 curl）+复测用例（【请求】/【payload】一键复制/复制为 curl）+概要七节、证据链页签只放附件物料（查看）、复测时间轴、登记本轮手工复测）｜资产明细（实体分列：domain/host/service/endpoint，属性芯片+首末见+生命周期，点行下钻原始观测，手动补录）｜时间线｜待审队列（按来源分组+多选批量）｜报告（assets/pentest 模板+整库备份）

AI 播报约定：**仅批次产生新待审项时**播报（链接+新增数+待审数+重点）；纯 --auto 批次不打扰。

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
2. **（可选）经验库**：`python pentdb/pentdb.py bootstrap`（建套件 .venv、装 kb 依赖）→ 注册 Supabase 免费实例 → SQL Editor 执行 `pentdb/kb/schema.sql` → 凭据模板 `pentdb/kb/creds.json` 已随仓库自带，填入 host / user / password 三项即用。若你打算把自己的副本推到别的仓库，先 `git update-index --skip-worktree pentdb/kb/creds.json` 让 git 停止跟踪它。不用经验库可全部跳过——PentDB 事实层全套零依赖照常可用。

   三个值都在 Supabase 控制台 **Project Settings → Database**：
   - **host** = Connection pooler 的主机名（形如 `xxx.pooler.supabase.com`）
   - **user** = `postgres.<项目ref>`（连接串里 `@` 前面那段）
   - **password** = 建项目时设置的数据库密码（忘了可在同页 Reset 重置）
   - port / dbname 已预填 `5432` / `postgres`，无需改动
3. **验证**：

```bash
python pentdb/pentdb.py init --project demo
python pentdb/pentdb.py panel --project demo      # 浏览器打开输出的 URL
python pentdb/pentdb.py kb search --keyword 测试   # 未配凭据时返回友好提示
cd pentdb && python -m unittest test_sop test_assets   # 25 用例回归
```

- 数据存放：事实库 `pentdb/data/pentdb.db` 为本地文件，clone 后不存在、init 按需生成；凭据模板 `pentdb/kb/creds.json` 随仓库自带（空值），填入真实值后仅存本机、套件不会自动上传任何内容
- 旧机器迁移经验库凭据：`pentdb.py bootstrap --kb-creds <creds.json>`
- 自用迁移（多机器带数据）：手工压缩整个目录（含 pentdb/data/），自行保管，与 GitHub 互不干扰
