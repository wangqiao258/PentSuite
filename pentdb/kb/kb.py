"""pentest-kb 经验库核心逻辑（原 MCP 服务内核，2026-09-28 CLI 化）。

供 pentdb.py 的 kb-* 子命令调用；凭据从环境变量 PENTEST_KB_DB_* 或
同目录 creds.json（随仓库分发的空模板，填值即用）读取。
存储在用户自建的 Supabase 云库（pentest_knowledge 表，见 schema.sql）。
"""

import os
import re
import math
import json
import traceback
import ipaddress
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from functools import lru_cache, wraps

import jieba
import psycopg2
from psycopg2.extras import Json
from psycopg2.pool import ThreadedConnectionPool
from rank_bm25 import BM25Okapi

# ===== 数据库连接参数：环境变量优先，其次同目录 creds.json（空模板随仓库分发，真实值仅存本机）=====
_CREDS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "creds.json")

REQUIRED_KEYS = ("host", "user", "password")


def _load_config():
    cfg = {
        "host": os.environ.get("PENTEST_KB_DB_HOST"),
        "port": os.environ.get("PENTEST_KB_DB_PORT", "5432"),
        "dbname": os.environ.get("PENTEST_KB_DB_NAME", "postgres"),
        "user": os.environ.get("PENTEST_KB_DB_USER"),
        "password": os.environ.get("PENTEST_KB_DB_PASSWORD"),
    }
    if not all(cfg.get(k) for k in REQUIRED_KEYS) and os.path.exists(_CREDS_FILE):
        try:
            local = json.load(open(_CREDS_FILE, encoding="utf-8"))
            for k in ("host", "port", "dbname", "user", "password"):
                if not cfg.get(k):
                    cfg[k] = local.get(k)
        except Exception:
            pass
    return cfg


# ===== 连接池：复用连接，避免每次调用新建/销毁连接 =====
_MAXCONN = int(os.environ.get("PENTEST_KB_DB_MAXCONN", "10"))
_pool = None


def _get_pool() -> ThreadedConnectionPool:
    global _pool
    if _pool is None:
        cfg = _load_config()
        missing = [k for k in REQUIRED_KEYS if not cfg.get(k)]
        if missing:
            raise RuntimeError(
                "经验库未配置（缺 %s）。运行 pentdb.py bootstrap --kb-creds <旧mcp.json>，"
                "或设置环境变量 PENTEST_KB_DB_HOST / PENTEST_KB_DB_USER / PENTEST_KB_DB_PASSWORD。"
                "未配置不影响 PentDB 其余功能。" % "/".join(missing)
            )
        _pool = ThreadedConnectionPool(1, _MAXCONN, **cfg)
    return _pool


@contextmanager
def _db():
    """从连接池取连接，正常提交、异常回滚、最终归还连接池（防泄漏）。"""
    pool = _get_pool()
    conn = pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)


def _safe(func):
    """包装 CLI 可调用入口：捕获异常返回友好提示，避免向用户抛裸堆栈。"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except psycopg2.Error as e:
            traceback.print_exc()
            return f"[x] 数据库错误: {e}"
        except Exception as e:
            traceback.print_exc()
            return f"[x] 操作失败: {e}"
    return wrapper


# ===== 脱敏校验：防止真实目标/凭据写入知识库 =====
_ALLOWED_DOMAINS = {
    "example.com", "example.org", "example.net", "example.edu",
    "test.com", "test.org", "test.net", "localhost", "local",
}

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
_CRED_RE = re.compile(
    r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|token|session|auth"
    r"|密码|口令|密钥|账号|用户名)\s*[=:：]\s*\S+"
)
_AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_ALIYUN_KEY_RE = re.compile(r"\bLTAI[0-9A-Za-z]{12,}\b")
_TENCENT_KEY_RE = re.compile(r"\bAKID[0-9A-Za-z]{13,}\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_PRIVKEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")
_PHONE_RE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")


def _is_allowed_domain(domain: str) -> bool:
    if domain in _ALLOWED_DOMAINS:
        return True
    return any(domain.endswith("." + allowed) for allowed in _ALLOWED_DOMAINS)


def _is_special_ip(ip_str: str) -> bool:
    """判断是否为特殊用途 IP（回环/私网/链路本地等）。这类 IP 不是真实目标，允许入库。"""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def check_sensitive(text: str) -> list:
    """检查文本中的疑似敏感信息，返回命中列表（空列表表示安全）。"""
    hits = []
    if not text:
        return hits
    for m in _IP_RE.finditer(text):
        ip = m.group(0)
        if _is_special_ip(ip):
            continue
        hits.append(f"IP地址: {ip}")
    email_spans = [m.span() for m in _EMAIL_RE.finditer(text)]
    for m in _EMAIL_RE.finditer(text):
        hits.append(f"邮箱: {m.group(0)}")
    for m in _CRED_RE.finditer(text):
        hits.append(f"疑似凭据: {m.group(0)}")
    for m in _DOMAIN_RE.finditer(text):
        domain = m.group(0).lower()
        if _is_allowed_domain(domain):
            continue
        if any(s <= m.start() and m.end() <= e for s, e in email_spans):
            continue  # 该域名是邮箱的一部分，避免重复上报
        hits.append(f"域名: {m.group(0)}")
    for label, regex in (
        ("云厂商AccessKey", _AWS_KEY_RE),
        ("云厂商AccessKey", _ALIYUN_KEY_RE),
        ("云厂商AccessKey", _TENCENT_KEY_RE),
        ("JWT令牌", _JWT_RE),
        ("私钥", _PRIVKEY_RE),
        ("手机号", _PHONE_RE),
    ):
        for m in regex.finditer(text):
            hits.append(f"{label}: {m.group(0)}")
    return hits


# ===== 领域分词词典：提升渗透专有名词切分准确率 =====
import logging
jieba.setLogLevel(logging.WARNING)  # 压掉 jieba 的 Building prefix dict stderr 噪音
_DICT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dict.txt")
if os.path.exists(_DICT_PATH):
    jieba.load_userdict(_DICT_PATH)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _tokenize(text: str) -> list:
    """jieba 分词，并保护 CVE 编号不被切碎。"""
    tokens = []
    for piece in re.split(r"(CVE-\d{4}-\d{4,7})", text, flags=re.IGNORECASE):
        if _CVE_RE.fullmatch(piece):
            tokens.append(piece.upper())
        else:
            tokens.extend(jieba.lcut(piece))
    return tokens


class _BM25Okapi(BM25Okapi):
    """非负 IDF 的 BM25Okapi：rank_bm25 原版在词频超语料一半时得负分，会被 score>0 误过滤。"""

    def _calc_idf(self, nd):
        for word, freq in nd.items():
            self.idf[word] = math.log(1 + (self.corpus_size - freq + 0.5) / (freq + 0.5))
        self.average_idf = sum(self.idf.values()) / len(self.idf)


# ===== 内部辅助：BM25 检索（供搜索和查重复用）=====
@lru_cache(maxsize=8)
def _bm25_index(status: str, tags: frozenset):
    """构建并缓存指定状态语料的 BM25 索引。任何写操作后须调用 _invalidate_bm25_cache()。"""
    with _db() as conn:
        cur = conn.cursor()
        sql = (
            "SELECT id, title, experience_detail, scenario_tags "
            "FROM pentest_knowledge WHERE status = %s"
        )
        params = [status]
        if tags:
            sql += " AND scenario_tags @> %s"
            params.append(Json(list(tags)))
        cur.execute(sql, params)
        rows = cur.fetchall()
        cur.close()

    if not rows:
        return (), None

    corpus = []
    for _id, title, detail, tags_ in rows:
        text = " ".join(filter(None, [title, detail]))
        if tags_:
            text += " " + " ".join(tags_)
        corpus.append(_tokenize(text))

    return tuple(rows), _BM25Okapi(corpus)


def _invalidate_bm25_cache():
    _bm25_index.cache_clear()


def _bm25_search(keyword: str, status: str = "approved", limit: int = 10, tags: list = None):
    """按 BM25 相关性检索指定状态的经验，返回 [(row, score), ...]。"""
    rows, bm25 = _bm25_index(status, frozenset(tags or []))
    if not rows:
        return []

    query_tokens = _tokenize(keyword)
    scores = bm25.get_scores(query_tokens)

    ranked = [(row, score) for row, score in zip(rows, scores) if score > 0]
    ranked.sort(key=lambda x: x[1], reverse=True)
    return ranked[:limit]


@_safe
def search_experience(keyword: str, tags_filter: list = None, limit: int = 5) -> str:
    """检索经验库（仅已审批）。紧凑输出：完整详情用 get_experience(experience_id)。"""
    ranked = _bm25_search(keyword, status="approved", limit=max(1, min(int(limit), 20)),
                          tags=tags_filter)
    if not ranked:
        return f"未找到与 '{keyword}' 相关的经验记录。"

    results = []
    for (_id, title, detail, _tags), score in ranked:
        brief = (detail or "").replace("\n", " ")[:160]
        results.append(f"# (相关度 {score:.2f}) [{_id}] {title}\n  {brief}...")
    return "检索结果（已审批；完整详情用 kb-get）:\n" + "\n".join(results)


@_safe
def add_experience(
    title: str,
    detail: str,
    scenario_tags: list = None,
    tool_code: str = None,
    tool_type: str = None,
) -> str:
    """新增经验，**一律写为 draft 草稿**（门禁：人审批后才 approved）。写入前强制脱敏校验。"""
    combined = " ".join(filter(None, [title, detail, tool_code or ""]))
    hits = check_sensitive(combined)
    if hits:
        return (
            "[x] 检测到疑似敏感信息，已拒绝写入。请将真实目标/凭据替换为占位符"
            "（如 <目标URL>、<目标域名>）后重试。\n命中项:\n- " + "\n- ".join(hits)
        )

    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO pentest_knowledge
                (title, experience_detail, scenario_tags, tool_code, tool_type, status)
            VALUES (%s, %s, %s, %s, %s, 'draft')
            """,
            (title, detail, Json(scenario_tags or []), tool_code, tool_type),
        )
        cur.close()
    _invalidate_bm25_cache()
    return f"[ok] 已写入草稿（待人审批）: {title}"


@_safe
def list_all_experiences(limit: int = 50, offset: int = 0) -> str:
    """分页列出经验库中所有已审批记录的标题。"""
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))

    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT count(*) FROM pentest_knowledge WHERE status = 'approved'"
        )
        total = cur.fetchone()[0]
        cur.execute(
            "SELECT id, title FROM pentest_knowledge WHERE status = 'approved' "
            "ORDER BY title LIMIT %s OFFSET %s",
            (limit, offset),
        )
        rows = cur.fetchall()
        cur.close()

    if not rows:
        return "经验库当前为空。"

    results = []
    for rid, title in rows:
        results.append(f"- [{rid}] {title}")
    end = offset + len(rows)
    return f"共 {total} 条记录（显示第 {offset + 1}-{end} 条）:\n" + "\n".join(results)


@_safe
def find_similar(title: str, detail: str = None) -> str:
    """查重：查找与给定标题/详情相似的已入库经验，用于避免重复录入。"""
    query = " ".join(filter(None, [title, detail or ""]))
    ranked = _bm25_search(query, status="approved", limit=5)
    if not ranked:
        return "未找到相似记录。"

    results = []
    for i, ((_id, t, _d, _tags), score) in enumerate(ranked, 1):
        results.append(f"#{i} (相关度 {score:.3f}) [{_id}]\n标题: {t}")
    return "可能重复的记录:\n" + "\n\n".join(results)


@_safe
def list_pending_experiences() -> str:
    """列出待审批的经验草稿，并提示每条草稿可能重复的已入库记录。"""
    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, title, experience_detail, scenario_tags, tool_code, tool_type "
            "FROM pentest_knowledge WHERE status = 'draft' ORDER BY created_at"
        )
        rows = cur.fetchall()
        cur.close()

    if not rows:
        return "当前没有待审批的草稿。"

    results = []
    for rid, title, detail, _tags, _code, _type in rows:
        preview = (detail or "")[:100]
        results.append(f"[{rid}] {title}\n  详情: {preview}...")
        sim = _bm25_search(" ".join(filter(None, [title, detail])), status="approved", limit=2)
        if sim:
            sim_titles = "、".join(t for (_id, t, _d, _tg), _s in sim)
            results.append(f"  [!] 可能重复: {sim_titles}")
    return "待审批草稿:\n" + "\n\n".join(results)


@_safe
def approve_experience(experience_id: str, merge_with_id: str = None) -> str:
    """审批通过一条待审批草稿。merge_with_id 提供时合并进目标记录后删除草稿。"""
    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, title, experience_detail, scenario_tags, tool_code, tool_type "
            "FROM pentest_knowledge WHERE id = %s AND status = 'draft'",
            (experience_id,),
        )
        draft = cur.fetchone()
        if not draft:
            return f"[x] 未找到待审批草稿: {experience_id}"
        did, dtitle, ddetail, dtags, dcode, dtype = draft

        if merge_with_id:
            cur.execute(
                "SELECT id, title, experience_detail, scenario_tags, tool_code, tool_type "
                "FROM pentest_knowledge WHERE id = %s",
                (merge_with_id,),
            )
            target = cur.fetchone()
            if not target:
                return f"[x] 未找到要合并的目标记录: {merge_with_id}"
            tid, ttitle, tdetail, ttags, tcode, ttype = target

            if ddetail and ddetail not in (tdetail or ""):
                new_detail = (tdetail or "") + "\n\n" + ddetail
            else:
                new_detail = tdetail
            new_tags = list(dict.fromkeys(list(ttags or []) + list(dtags or [])))
            new_code = tcode or dcode
            new_type = ttype or dtype

            cur.execute(
                "UPDATE pentest_knowledge SET experience_detail=%s, scenario_tags=%s, "
                "tool_code=%s, tool_type=%s WHERE id=%s",
                (new_detail, Json(new_tags), new_code, new_type, merge_with_id),
            )
            cur.execute("DELETE FROM pentest_knowledge WHERE id = %s", (experience_id,))
            _invalidate_bm25_cache()
            return f"[ok] 已合并草稿《{dtitle}》到《{ttitle}》，草稿已删除。"
        else:
            cur.execute(
                "UPDATE pentest_knowledge SET status = 'approved' WHERE id = %s",
                (experience_id,),
            )
            _invalidate_bm25_cache()
            return f"[ok] 已审批通过: {dtitle}"


@_safe
def reject_experience(experience_id: str) -> str:
    """拒绝一条待审批草稿（软删除：记录保留，状态置为 rejected，可恢复）。"""
    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE pentest_knowledge SET status = 'rejected', deleted_at = now() "
            "WHERE id = %s AND status = 'draft'",
            (experience_id,),
        )
        updated = cur.rowcount
        cur.close()
    if updated:
        _invalidate_bm25_cache()
        return f"[ok] 已拒绝草稿（软删除，可恢复）: {experience_id}"
    return f"[x] 未找到待审批草稿: {experience_id}"


@_safe
def delete_experience(experience_id: str) -> str:
    """软删除一条已审批经验（状态置为 deleted，不参与检索，可恢复）。"""
    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE pentest_knowledge SET status = 'deleted', deleted_at = now() "
            "WHERE id = %s AND status = 'approved'",
            (experience_id,),
        )
        updated = cur.rowcount
        cur.close()
    if updated:
        _invalidate_bm25_cache()
        return f"[ok] 已软删除经验（可恢复）: {experience_id}"
    return f"[x] 未找到已审批经验: {experience_id}"


@_safe
def restore_experience(experience_id: str) -> str:
    """恢复一条软删除的记录：被拒绝的草稿恢复为 draft，被删除的经验恢复为 approved。"""
    with _db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT status FROM pentest_knowledge WHERE id = %s", (experience_id,))
        row = cur.fetchone()
        if not row:
            return f"[x] 未找到记录: {experience_id}"
        status = row[0]
        if status not in ("rejected", "deleted"):
            return f"[x] 该记录状态为 {status}，不是软删除状态，无需恢复。"
        new_status = "draft" if status == "rejected" else "approved"
        cur.execute(
            "UPDATE pentest_knowledge SET status = %s, deleted_at = NULL WHERE id = %s",
            (new_status, experience_id),
        )
        cur.close()
    _invalidate_bm25_cache()
    return f"[ok] 已恢复为 {new_status}: {experience_id}"


@_safe
def list_deleted_experiences() -> str:
    """列出所有软删除的记录（被拒绝的草稿 + 被删除的经验），便于恢复或彻底清理。"""
    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, title, status, deleted_at FROM pentest_knowledge "
            "WHERE status IN ('rejected', 'deleted') ORDER BY deleted_at"
        )
        rows = cur.fetchall()
        cur.close()
    if not rows:
        return "当前没有软删除的记录。"
    results = []
    for rid, title, status, deleted_at in rows:
        label = "被拒绝草稿" if status == "rejected" else "被删除经验"
        results.append(f"[{rid}] {label}: {title}（{deleted_at}）")
    return f"共 {len(rows)} 条软删除记录:\n" + "\n".join(results)


@_safe
def purge_experiences(days: int = 30) -> str:
    """彻底删除软删除超过指定天数的记录（物理删除，不可恢复，请谨慎）。"""
    days = max(0, int(days))
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM pentest_knowledge "
            "WHERE status IN ('rejected', 'deleted') AND deleted_at < %s",
            (cutoff,),
        )
        deleted = cur.rowcount
        cur.close()
    if deleted:
        _invalidate_bm25_cache()
    return f"[ok] 已彻底删除 {deleted} 条超过 {days} 天的软删除记录。"


@_safe
def get_experience(experience_id: str) -> str:
    """按 id 获取一条经验的完整内容（标题、详情、标签、工具代码、状态等）。"""
    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, title, experience_detail, scenario_tags, tool_code, tool_type, "
            "status, created_at, deleted_at FROM pentest_knowledge WHERE id = %s",
            (experience_id,),
        )
        row = cur.fetchone()
        cur.close()
    if not row:
        return f"[x] 未找到记录: {experience_id}"
    rid, title, detail, tags, code, ttype, status, created_at, deleted_at = row
    parts = [f"ID: {rid}", f"标题: {title}", f"状态: {status}", f"创建时间: {created_at}"]
    if tags:
        parts.append(f"标签: {', '.join(tags)}")
    if ttype:
        parts.append(f"工具类型: {ttype}")
    if detail:
        parts.append(f"详情:\n{detail}")
    if code:
        parts.append(f"工具代码:\n{code}")
    if deleted_at:
        parts.append(f"软删除时间: {deleted_at}")
    return "\n".join(parts)


@_safe
def update_experience(
    experience_id: str,
    title: str = None,
    detail: str = None,
    scenario_tags: list = None,
    tool_code: str = None,
    tool_type: str = None,
) -> str:
    """更新一条经验的字段（只更新传入的字段，未传字段保持不变）。修改前自动做脱敏校验。
    注意：不提供 status 参数——状态翻转（审批/驳回）只能走 approve/reject 通道，
    approve 的 --confirm 人审门不允许经 update 绕过（2026-10-02 P0 防绕过）。"""
    combined = " ".join(filter(None, [title or "", detail or "", tool_code or ""]))
    hits = check_sensitive(combined)
    if hits:
        return (
            "[x] 检测到疑似敏感信息，已拒绝更新。请将真实目标/凭据替换为占位符后重试。\n命中项:\n- "
            + "\n- ".join(hits)
        )

    fields, params = [], []
    if title is not None:
        fields.append("title = %s")
        params.append(title)
    if detail is not None:
        fields.append("experience_detail = %s")
        params.append(detail)
    if scenario_tags is not None:
        fields.append("scenario_tags = %s")
        params.append(Json(scenario_tags))
    if tool_code is not None:
        fields.append("tool_code = %s")
        params.append(tool_code)
    if tool_type is not None:
        fields.append("tool_type = %s")
        params.append(tool_type)
    if not fields:
        return "[x] 未提供任何要更新的字段。"

    with _db() as conn:
        cur = conn.cursor()
        params.append(experience_id)
        cur.execute(
            f"UPDATE pentest_knowledge SET {', '.join(fields)} WHERE id = %s", params
        )
        updated = cur.rowcount
        cur.close()
    if not updated:
        return f"[x] 未找到记录: {experience_id}"
    _invalidate_bm25_cache()
    return f"[ok] 已更新记录: {experience_id}"
