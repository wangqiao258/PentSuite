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
│  ├─ pentdb.py            CLI：init/panel/add/query/review/lint/sop/waive/migrate/
│  │                       report/drop/evidence/verify/stages/recon/js/serve
│  ├─ recon.py             采集器：被动子域枚举 + 存活探测（--single / --proxy 可移植）
│  ├─ server.py + web/     零依赖面板（stdlib，端口 8766；七视图全交互联动）
│  ├─ sop/default.json     SOP 必测规则（R1-R7 带 stage）+ 7 阶段 stage_required 菜单
│  ├─ test_sop.py          核心逻辑单测（stdlib unittest，15 用例）
│  ├─ kb/                  经验层单元（pentest-kb，Supabase 云端，强制脱敏）
│  │  ├─ kb.py             经验库逻辑（CLI kb-* 子命令的实现）
│  │  ├─ schema.sql        经验库建表 DDL（自建 Supabase 时执行）
│  │  ├─ dict.txt          经验检索词典
│  │  ├─ requirements.txt  经验层依赖清单（psycopg2/jieba/rank-bm25）
│  │  └─ creds.json        云库凭据（gitignore，绝不入 git）
│  └─ data/pentdb.db       SQLite 事实库（真实数据，**不入 git 不入发行包**）
├─ skill/pentest-kb-workflow/SKILL.md   方法论 skill（纯 SKILL.md，直接装入）
├─ .venv/                  套件唯一运行时（bootstrap 创建，gitignore）
└─ README.md               本文件
```

## 数据模型与状态机

- `raw_events`（append-only）：kind: domain/port/path/param/finding/osint/note/test/suggestion；source 必填；AI（origin=agent）必须带 confidence 且不得置 confirmed（--auto 仅限机器事实 domain/port/path/param/test）
- `pending_tests`（带 stage）/ `waives` / `reviews` / `changelog`：只追加留痕
- 状态机 `new →(人审)→ confirmed/rejected`；报告与攻击建议只引用 confirmed
- finding detail 四段约定：`【描述】【原因】【手工验证】【修复】`，手工验证三步 = 构造请求/观察点/影响确认

## 命令速查（CLI = `python pentdb/pentdb.py`）

| 动作 | 命令 |
|------|------|
| 建档 | `init --project P` |
| 开面板（幂等托管） | `panel --project P`（活着复用/没起拉起/被占报 PID；输出 url+pending 数） |
| 落资产 | `add --project P --kind domain\|port\|path\|param\|finding\|osint --value V --source "命令/URL" [--code][--tech][--service][--scope][--severity]` |
| 重扫更新 | 同 kind+value 重复时 `add --update`：刷新观测字段，状态与人审结论保留 |
| 登记测试 | `add --kind test --value "动作" --parent-ext <id>[,id2] --stage <阶段名> --source "命令" --auto --status confirmed --confidence high`（**--stage 必带**） |
| AI 推断 | `add ... --confidence high\|medium\|low`（推断类禁止 confirmed，一律 new 进待审） |
| 查询 | `query --project P [--kind][--status]` |
| SOP | `sop --project P [--apply]`；豁免 `waive --project P --id N --term T --reason R` |
| 门禁 | `lint --project P`（收尾 0 error） |
| 人审 | `review --project P --id N --confirm\|--reject`（面板支持按来源分组多选批量，批量强制批注） |
| 报告 | `report --project P [--template pentest] [--out F]`（pentest=描述/原因/手工验证/修复） |
| 采集 | `recon --project P --domain D [--single][--proxy]`；`js --project P` |
| 经验库 | `kb search --keyword K`；`kb add --title T --from-file F`（一律 draft）；`kb find-similar`；`kb pending`；`kb approve --id N --confirm`（人的决定）；`kb get/list/deleted/...` |

## 面板七视图（全交互联动）

目标总览（卡片点击跳转筛选）｜SOP 覆盖（阶段视图=计划菜单×执行流水、状态卡过滤、lint 门禁）｜发现·漏洞（级别过滤+状态筛选）｜资产明细（手动补录）｜时间线｜待审队列（按来源分组+多选批量）｜报告（assets/pentest 模板+整库备份）

AI 播报约定：**仅批次产生新待审项时**播报（链接+新增数+待审数+重点）；纯 --auto 批次不打扰。

## 快速开始

```bash
python pentdb/pentdb.py init --project <目标>
python pentdb/pentdb.py panel --project <目标>
python pentdb/pentdb.py recon --project <目标> --domain example.com
python pentdb/pentdb.py sop --project <目标> --apply
python pentdb/pentdb.py lint --project <目标>
python pentdb/pentdb.py report --project <目标> --template pentest --out report.md
```

## 安装（新机器 / GitHub clone 后）

前置：PentDB CLI/面板零依赖；经验库需要 Python 3.10+（bootstrap 建 venv）。

1. **装 skill**：把 `skill/pentest-kb-workflow/` 按所用客户端的技能方式装入（WorkBuddy：拖拽；Claude Code：复制到其 skills 目录；其他客户端：让 AI 直接读该文件亦可）。首次使用时 AI 会询问"PentSuite 克隆在哪个目录？"并把路径写入 skill 目录的 `home.txt`——一次配置，长期有效。
2. **（可选）经验库**：`python pentdb/pentdb.py bootstrap`（建套件 .venv、装 kb 依赖）→ 注册 Supabase 免费实例 → SQL Editor 执行 `pentdb/kb/schema.sql` → 创建 `pentdb/kb/creds.json`（host/port/dbname/user/password）。不用经验库可全部跳过——PentDB 事实层全套零依赖照常可用。
3. **验证**：

```bash
python pentdb/pentdb.py init --project demo
python pentdb/pentdb.py panel --project demo      # 浏览器打开输出的 URL
python pentdb/pentdb.py kb search --keyword 测试   # 未配凭据时返回友好提示
cd pentdb && python -m unittest test_sop          # 15 用例回归
```

- 数据边界：仓库不含真实数据与凭据（`data/`、`kb/creds.json`、`.venv/` 均 gitignore）；经验库凭据存 `pentdb/kb/creds.json`，绝不入 git
- 旧机器迁移经验库凭据：`pentdb.py bootstrap --kb-creds <creds.json>`
- 自用迁移（多机器带数据）：手工压缩整个目录（含 pentdb/data/），自行保管，与 GitHub 互不干扰
