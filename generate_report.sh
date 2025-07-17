#!/bin/bash
# 生成扫描结果HTML报告的便捷脚本

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

# 构建Python命令
PYTHON_CMD="python3 scripts/report/generate_scan_report.py"

if [ -n "$TARGET_DOMAIN" ]; then
    PYTHON_CMD="$PYTHON_CMD $TARGET_DOMAIN"
fi

if [ -n "$OUTPUT_FILE" ]; then
    PYTHON_CMD="$PYTHON_CMD -o $OUTPUT_FILE"
fi

# 执行Python脚本
$PYTHON_CMD

# 获取生成的报告文件路径
if [ -n "$OUTPUT_FILE" ]; then
    REPORT_FILE="$OUTPUT_FILE"
else
    # 自动检测域名
    if [ -z "$TARGET_DOMAIN" ]; then
        if [ -d "output" ]; then
            TARGET_DOMAIN=$(find output -maxdepth 1 -type d -name "*.*" | head -1 | xargs basename)
        fi
    fi
    
    if [ -n "$TARGET_DOMAIN" ]; then
        REPORT_FILE="output/$TARGET_DOMAIN/scan_report_$TARGET_DOMAIN.html"
    else
        echo "❌ 无法确定报告文件路径"
        exit 1
    fi
fi

# 检查报告文件是否存在
if [ ! -f "$REPORT_FILE" ]; then
    echo "❌ 报告文件不存在: $REPORT_FILE"
    exit 1
fi

echo ""
echo "✅ 报告生成完成！"
echo "📁 报告文件: $REPORT_FILE"
echo "🌐 浏览器访问: file://$(realpath "$REPORT_FILE")"

# 如果指定了打开浏览器
if [ "$OPEN_BROWSER" = true ]; then
    echo "🔄 正在打开浏览器..."
    
    # 尝试不同的浏览器命令
    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$REPORT_FILE" 2>/dev/null &
    elif command -v open >/dev/null 2>&1; then
        open "$REPORT_FILE" 2>/dev/null &
    elif command -v firefox >/dev/null 2>&1; then
        firefox "$REPORT_FILE" 2>/dev/null &
    elif command -v chrome >/dev/null 2>&1; then
        chrome "$REPORT_FILE" 2>/dev/null &
    elif command -v chromium >/dev/null 2>&1; then
        chromium "$REPORT_FILE" 2>/dev/null &
    else
        echo "⚠️  无法自动打开浏览器，请手动访问报告文件"
    fi
fi

echo ""
echo "🎉 完成！"