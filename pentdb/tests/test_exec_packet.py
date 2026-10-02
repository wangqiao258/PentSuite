#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PentDB exec .log 报文解析器单测（stdlib unittest，零依赖，纯函数无写库）。
运行：python -m unittest test_exec_packet -v

覆盖：
  1. 标准 curl（-X POST + -H 双引号 + --data-raw）→ request 完整还原
  2. 无 -X 有 -d → POST 推断（inferred_method）；补 Content-Type（inferred_header）
  3. -i/-I 输出 → response 原样含状态行；无 -i → response_inferred
  4. ``\\`` 与 ``^`` 行续接；多 -d 用 & 连接；-u → Authorization: Basic
  5. $TOKEN 变量原样保留 + has_variables；@file data 引用照抄 + data_from_file
  6. 降级：非 curl 命令 / 首行非 "$ " / 缺 exit= / 空串 / 乱码 → None 且不抛
  7. Windows curl 进度噪音剥离（真实形态样本）；空输出 empty；多 URL truncated
"""
import os
import tempfile
import unittest

# 必须在 import pentdb 前设置；setdefault 保证多模块同跑时与 import 顺序无关
_TMPDIR = tempfile.mkdtemp(prefix="pentdb-packet-test-")
os.environ.setdefault("PENTDB_DB", os.path.join(_TMPDIR, "test.db"))
import pentdb  # noqa: E402
import pdb_findings  # noqa: E402

parse = pentdb.parse_exec_packet


def log(cmd, out="", code=0):
    """按 cmd_exec 落盘格式拼 .log 全文。"""
    return "$ %s\nexit=%s\n\n%s" % (cmd, code, out)


class TestExecPacketRequest(unittest.TestCase):
    """命令串 → request 报文。"""

    def test_full_post_restored(self):
        t = parse(log('curl.exe -sk -X POST "https://api.example.com/v1/login?x=1" '
                      '-H "Content-Type: application/json" -H "Cookie: sid=abc" '
                      "-d '{\"user\":\"a\"}'"))
        self.assertIsNotNone(t)
        self.assertEqual(t["request"],
                         "POST /v1/login?x=1 HTTP/1.1\n"
                         "Host: api.example.com\n"
                         "Content-Type: application/json\n"
                         "Cookie: sid=abc\n"
                         "\n"
                         '{"user":"a"}')
        self.assertFalse(t["flags"]["inferred_method"])
        self.assertFalse(t["flags"]["inferred_header"])

    def test_inferred_method_and_header(self):
        t = parse(log('curl -sk https://h.example.com/p -d "a=1"'))
        self.assertIsNotNone(t)
        self.assertTrue(t["request"].startswith("POST /p HTTP/1.1"))
        self.assertTrue(t["flags"]["inferred_method"])
        self.assertIn("Content-Type: application/x-www-form-urlencoded", t["request"])
        self.assertTrue(t["flags"]["inferred_header"])

    def test_get_default_no_data(self):
        t = parse(log("curl https://h.example.com/a/b?q=2"))
        self.assertTrue(t["request"].startswith("GET /a/b?q=2 HTTP/1.1\nHost: h.example.com"))
        self.assertFalse(t["flags"]["inferred_method"])
        self.assertNotIn("Content-Type:", t["request"])

    def test_multi_data_joined_with_amp(self):
        t = parse(log('curl https://h/p -d "a=1" -d "b=2"'))
        self.assertTrue(t["request"].endswith("\n\na=1&b=2"))

    def test_basic_auth(self):
        import base64
        t = parse(log('curl -u admin:pw https://h/p'))
        self.assertIn("Authorization: Basic "
                      + base64.b64encode(b"admin:pw").decode("ascii"), t["request"])
        self.assertFalse(t["flags"]["has_variables"])

    def test_continuation_backslash(self):
        t = parse(log('curl -sk \\\n  -X GET "https://h/p"'))
        self.assertIsNotNone(t)
        self.assertTrue(t["request"].startswith("GET /p HTTP/1.1"))

    def test_continuation_caret(self):
        t = parse(log('curl.exe -sk ^\n  -d a=1 "https://h/p"'))
        self.assertIsNotNone(t)
        self.assertTrue(t["request"].startswith("POST /p HTTP/1.1"))
        self.assertTrue(t["flags"]["inferred_method"])

    def test_variables_kept_verbatim(self):
        t = parse(log('curl -sk -H "Authorization: Bearer $TOKEN" https://h/p'))
        self.assertIn("Authorization: Bearer $TOKEN", t["request"])
        self.assertTrue(t["flags"]["has_variables"])

    def test_data_from_file_ref_kept(self):
        t = parse(log("curl -s https://h/p -d @C:/tmp/sqli.json"))
        self.assertTrue(t["request"].endswith("\n\n@C:/tmp/sqli.json"))
        self.assertTrue(t["flags"]["data_from_file"])

    def test_multi_url_truncated(self):
        t = parse(log("curl -sk https://h/one https://h/two"))
        self.assertTrue(t["request"].startswith("GET /one HTTP/1.1"))
        self.assertTrue(t["flags"]["truncated"])

    def test_head_via_short_I(self):
        t = parse(log("curl -sI https://demo.owasp-juice.shop/"))
        self.assertTrue(t["request"].startswith("HEAD / HTTP/1.1"))
        self.assertTrue(t["flags"]["inferred_method"])

    def test_url_without_scheme_flagged(self):
        t = parse(log("curl -sk h/p"))
        self.assertIsNotNone(t)
        self.assertTrue(t["flags"]["no_host"])
        self.assertIn("GET h/p HTTP/1.1", t["request"])


class TestExecPacketResponse(unittest.TestCase):
    """输出 → response 报文。"""

    def test_include_response_verbatim(self):
        out = "HTTP/1.1 403 Forbidden\ncontent-type: application/json\n\n{\"result\":\"error\"}"
        t = parse(log('curl.exe -is "https://api.kdrive.infomaniak.com/2/drive"', out))
        self.assertEqual(t["response"], out)
        self.assertFalse(t["flags"]["response_inferred"])
        self.assertFalse(t["flags"]["empty"])

    def test_no_include_inferred(self):
        out = '{"authentication":{"token":"eyJ..."}}'
        t = parse(log("curl -s https://h/rest", out))
        self.assertEqual(t["response"], out)
        self.assertTrue(t["flags"]["response_inferred"])

    def test_progress_noise_stripped(self):
        out = ("  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\r\n"
               "                                 Dload  Upload   Total   Spent    Left  Speed\r\n"
               "  100   925  100   925    0     0    925      0  0:00:01 --:--:-- --:--:--   925\r\n"
               '{"ok":true}')
        t = parse(log("curl -s https://h/p", out))
        self.assertEqual(t["response"], '{"ok":true}')

    def test_empty_output_flagged(self):
        t = parse(log("curl -sk -o /dev/null https://h/p", ""))
        self.assertEqual(t["response"], "")
        self.assertTrue(t["flags"]["empty"])

    def test_proxy_connect_line_preserved(self):
        # 实测样本：走代理时 -i 输出含 200 Connection Established，原样保留不清洗
        out = "HTTP/1.1 200 Connection Established\n\nHTTP/1.1 200 OK\nserver: Apache"
        t = parse(log('curl.exe -is "https://api.kdrive.infomaniak.com/2/drive"', out))
        self.assertEqual(t["response"], out)


class TestExecPacketDegradation(unittest.TestCase):
    """降级路径：解析不出一律 None，绝不抛异常。"""

    def test_non_curl_command(self):
        self.assertIsNone(parse(log(
            r"C:\AI项目\PentSuite\.venv\Scripts\python.exe C:\tmp\probe_hosts.py",
            "[probe] 25/165")))

    def test_first_line_not_dollar(self):
        self.assertIsNone(parse("some random content\nexit=0\n\noutput"))

    def test_missing_exit_line(self):
        self.assertIsNone(parse("$ curl https://h/p\n\nbody without exit"))

    def test_curl_without_url(self):
        self.assertIsNone(parse("$ curl -sk --version\nexit=0\n\n"))

    def test_empty_string(self):
        self.assertIsNone(parse(""))

    def test_binary_garbage(self):
        self.assertIsNone(parse("\x00\x01\x02garbage\xff\xfe"))
        self.assertIsNone(parse(None))
        self.assertIsNone(parse(b"\x00\x01"))  # bytes 也不抛

    def test_unmatched_quote_still_flagged_not_crash(self):
        t = parse("$ curl -sk \"https://h/p\nexit=0\n\n")
        self.assertIsNotNone(t)  # 引号未闭合记 flag 而非崩
        self.assertTrue(t["flags"]["unbalanced_quote"])

    def test_facade_reexport(self):
        self.assertIs(pentdb.parse_exec_packet, pdb_findings.parse_exec_packet)


if __name__ == "__main__":
    unittest.main()
