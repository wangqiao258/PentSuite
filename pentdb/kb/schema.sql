-- pentest-kb 经验库表结构初始化脚本
-- 幂等：可重复执行
-- 在 PostgreSQL（如 Supabase）的 SQL 编辑器中执行本文件即可

CREATE TABLE IF NOT EXISTS pentest_knowledge (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at timestamptz DEFAULT now(),
    title text,
    scenario_tags jsonb DEFAULT '[]'::jsonb,   -- 场景标签数组，如 ["WAF绕过","SQL注入"]
    experience_detail text,
    tool_code text,                             -- 利用/工具代码
    tool_type text,                             -- 工具类型，如 sqlmap、burp
    status text DEFAULT 'draft'              -- approved（已审批）/ draft（待审批草稿，默认）/ rejected（被拒，软删）/ deleted（软删）
    ,deleted_at timestamptz                     -- 软删除时间（status 为 rejected/deleted 时记录）
);

-- 软删除支持：已存在表补充 deleted_at 列（幂等）
ALTER TABLE pentest_knowledge ADD COLUMN IF NOT EXISTS deleted_at timestamptz;

-- 草稿优先：add_experience 默认 status='draft'，DB 层默认值保持一致（幂等，兼容已建表）
ALTER TABLE pentest_knowledge ALTER COLUMN status SET DEFAULT 'draft';

-- 场景标签过滤索引：支持 search_experience 的 tags_filter 参数（scenario_tags @> 数组）
CREATE INDEX IF NOT EXISTS pentest_knowledge_tags_idx
  ON pentest_knowledge USING GIN (scenario_tags);

-- 可选：语义检索列（当前代码未使用，预留）
-- 如需接入向量语义检索，取消注释并执行以下语句：
-- CREATE EXTENSION IF NOT EXISTS vector;
-- ALTER TABLE pentest_knowledge ADD COLUMN IF NOT EXISTS embedding vector(1536);
-- CREATE INDEX IF NOT EXISTS pentest_knowledge_embedding_idx
--   ON pentest_knowledge USING ivfflat (embedding vector_cosine_ops) WITH (lists = '100');
