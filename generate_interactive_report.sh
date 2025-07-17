#!/bin/bash
# 生成交互式多层扫描报告

set -e

# 设置项目根目录
SCAN_PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$SCAN_PROJECT_ROOT"

# 函数：显示帮助信息
show_help() {
    cat << EOF
🎯 交互式扫描报告生成器

使用方法:
    $0 [域名] [选项]

选项:
    --open          生成后自动在浏览器中打开报告
    --output-dir    指定输出目录 (默认: output)
    --help          显示此帮助信息

示例:
    $0 example.com
    $0 example.com --open
    $0 example.com --output-dir /path/to/output --open

如果不指定域名，将尝试自动检测。
EOF
}

# 默认参数
TARGET_DOMAIN=""
OUTPUT_DIR="output"
OPEN_BROWSER=false

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --open)
            OPEN_BROWSER=true
            shift
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        *)
            if [ -z "$TARGET_DOMAIN" ]; then
                TARGET_DOMAIN="$1"
            fi
            shift
            ;;
    esac
done

# 自动检测域名函数
auto_detect_domain() {
    # 检查data/input/url文件
    if [ -f "data/input/url" ]; then
        local domain=$(cat data/input/url | head -1 | tr -d '\n' | tr -d '\r')
        if [ -n "$domain" ]; then
            echo "$domain"
            return 0
        fi
    fi
    
    # 检查output目录下的域名目录
    if [ -d "$OUTPUT_DIR" ]; then
        local domain_dirs=$(find "$OUTPUT_DIR" -maxdepth 1 -type d -name "*.*" | head -1)
        if [ -n "$domain_dirs" ]; then
            local domain=$(basename "$domain_dirs")
            if [ "$domain" != "output" ]; then
                echo "$domain"
                return 0
            fi
        fi
    fi
    
    return 1
}

# 如果没有指定域名，尝试自动检测
if [ -z "$TARGET_DOMAIN" ]; then
    if TARGET_DOMAIN=$(auto_detect_domain); then
        echo "✅ 自动检测到域名: $TARGET_DOMAIN"
    else
        echo "❌ 错误: 未指定域名，且无法自动检测"
        echo "请使用: $0 <域名> 或确保 data/input/url 文件存在"
        exit 1
    fi
fi

echo "🚀 开始生成交互式扫描报告..."
echo "🔍 目标域名: $TARGET_DOMAIN"
echo "📂 输出目录: $OUTPUT_DIR"

# 检查目标域名的扫描数据是否存在
TARGET_OUTPUT_DIR="$OUTPUT_DIR/$TARGET_DOMAIN"
if [ ! -d "$TARGET_OUTPUT_DIR" ]; then
    echo "❌ 错误: 未找到域名 $TARGET_DOMAIN 的扫描数据"
    echo "   查找目录: $TARGET_OUTPUT_DIR"
    exit 1
fi

echo "📊 收集 $TARGET_DOMAIN 的扫描数据..."

# 检测扫描层数
LAYER_COUNT=1
if [ -d "$TARGET_OUTPUT_DIR/expansion/report" ]; then
    ((LAYER_COUNT++))
fi

# 检查更高层数
for layer_num in {3..10}; do
    if [ -d "$TARGET_OUTPUT_DIR/expansion/layer$layer_num" ]; then
        LAYER_COUNT=$layer_num
    else
        break
    fi
done

echo "✅ 发现 $LAYER_COUNT 层扫描数据"

# 生成报告
OUTPUT_FILE="$TARGET_OUTPUT_DIR/interactive_scan_report_$TARGET_DOMAIN.html"

echo "📝 生成交互式HTML报告..."
python3 scripts/report/generate_interactive_report.py "$TARGET_DOMAIN" --output-dir "$OUTPUT_DIR" --output-file "$OUTPUT_FILE"

if [ $? -eq 0 ]; then
    echo "✅ 交互式报告已生成: $OUTPUT_FILE"
    
    # 显示文件信息
    if [ -f "$OUTPUT_FILE" ]; then
        FILE_SIZE=$(du -h "$OUTPUT_FILE" | cut -f1)
        echo "📁 报告文件大小: $FILE_SIZE"
    fi
    
    # 显示访问URL
    FULL_PATH=$(realpath "$OUTPUT_FILE")
    echo "🌐 浏览器访问: file://$FULL_PATH"
    
    # 如果指定了打开浏览器
    if [ "$OPEN_BROWSER" = true ]; then
        echo "🚀 正在打开浏览器..."
        
        # 尝试多种浏览器
        if command -v firefox >/dev/null 2>&1; then
            firefox "file://$FULL_PATH" >/dev/null 2>&1 &
            echo "✅ 已在 Firefox 中打开报告"
        elif command -v google-chrome >/dev/null 2>&1; then
            google-chrome "file://$FULL_PATH" >/dev/null 2>&1 &
            echo "✅ 已在 Chrome 中打开报告"
        elif command -v chromium-browser >/dev/null 2>&1; then
            chromium-browser "file://$FULL_PATH" >/dev/null 2>&1 &
            echo "✅ 已在 Chromium 中打开报告"
        else
            echo "⚠️ 未找到支持的浏览器，请手动打开上述链接"
        fi
    fi
    
    echo ""
    echo "🎉 完成！"
    echo "📁 报告文件: $OUTPUT_FILE"
    echo "🌐 浏览器访问: file://$FULL_PATH"
    
else
    echo "❌ 报告生成失败"
    exit 1
fi