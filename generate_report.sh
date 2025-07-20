#!/bin/bash
# 多层扫描报告生成脚本 - 支持所有层级扫描结果展示

set -e

# 设置项目根目录
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

# 默认参数
TARGET_DOMAIN=""
OUTPUT_FILE=""
OPEN_BROWSER=false

# 显示帮助信息
show_help() {
    echo "🎯 生成多层扫描HTML报告"
    echo ""
    echo "用法:"
    echo "  ./generate_report.sh [域名] [选项]"
    echo ""
    echo "选项:"
    echo "  -o, --output FILE    指定输出文件路径"
    echo "  --open              生成后自动打开浏览器"
    echo "  -h, --help          显示帮助信息"
    echo ""
    echo "示例:"
    echo "  ./generate_report.sh                     # 自动检测域名"
    echo "  ./generate_report.sh vtmarkets.com       # 指定域名"
    echo "  ./generate_report.sh vtmarkets.com --open # 生成后打开浏览器"
    echo "  ./generate_report.sh -o /tmp/report.html  # 指定输出文件"
    echo ""
    echo "说明:"
    echo "  多层报告包含所有扫描层级的结果（Layer 1, 2, 3+）"
    echo "  自动解析标题信息、安全扫描结果、层级关系等"
}

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --open)
            OPEN_BROWSER=true
            shift
            ;;
        -*)
            echo "❌ 未知选项: $1"
            echo "使用 -h 或 --help 查看帮助"
            exit 1
            ;;
        *)
            if [ -z "$TARGET_DOMAIN" ]; then
                TARGET_DOMAIN="$1"
            fi
            shift
            ;;
    esac
done

echo "🚀 开始生成扫描报告..."

# 构建Python命令 - 使用树形报告生成器
PYTHON_CMD="python3 scripts/report/generate_tree_report.py"

if [ -n "$TARGET_DOMAIN" ]; then
    PYTHON_CMD="$PYTHON_CMD $TARGET_DOMAIN"
fi

if [ -n "$OUTPUT_FILE" ]; then
    PYTHON_CMD="$PYTHON_CMD -o $OUTPUT_FILE"
fi

if [ "$OPEN_BROWSER" = true ]; then
    PYTHON_CMD="$PYTHON_CMD --open"
fi

# 执行Python脚本
$PYTHON_CMD