#!/bin/bash
# 一层扫描报告生成脚本

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# 运行Python脚本，传递所有参数
python3 "$SCRIPT_DIR/scripts/report/generate_layer1_report.py" "$@"