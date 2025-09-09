#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WSGI入口点 - 用于Gunicorn生产环境部署
解决Flask开发服务器的CONNECTION_RESET问题
"""

import sys
from pathlib import Path

# 确保可以导入web模块
sys.path.insert(0, str(Path(__file__).parent))

from web.app_simple import app

# Gunicorn会查找名为application的WSGI应用对象
application = app

if __name__ == '__main__':
    # 如果直接运行此文件，使用Flask开发服务器（仅用于调试）
    app.run(host='0.0.0.0', port=5000, debug=False)
