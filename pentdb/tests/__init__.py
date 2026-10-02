# -*- coding: utf-8 -*-
"""PentDB 单测包：全部 test_*.py 外置于此目录，与运行时代码分离。

权威跑法（在仓库根 PentSuite/ 下执行，一条命令全量回归）：

    .venv/Scripts/python.exe -m unittest discover -s pentdb/tests -t pentdb -p "test_*.py"

本包被导入时把 pentdb/ 目录插入 sys.path 头部：测试内既有的裸导入
（import pentdb / pdb_assets / pdb_findings / pdb_core / server）在任意
cwd 下均可解析，pdb_* 源码零改动。
"""
import os
import sys

_PENTDB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PENTDB_DIR not in sys.path:
    sys.path.insert(0, _PENTDB_DIR)
