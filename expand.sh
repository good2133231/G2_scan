#!/bin/bash
# 简化的二层扩展扫描脚本
# 基于一层扫描结果进行扩展扫描

set -e

# 设置项目根目录环境变量
export SCAN_PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"

# 自动识别域名函数
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
    if [ -d "output" ]; then
        local domain_dirs=$(find output -maxdepth 1 -type d -name "*.*" | head -1 | basename)
        if [ -n "$domain_dirs" ] && [ "$domain_dirs" != "output" ]; then
            echo "$domain_dirs"
            return 0
        fi
    fi
    
    # 默认域名
    echo "example.com"
    return 1
}

# 参数处理
TARGET_DOMAIN=""
ACTION="generate"
USE_TEST_MODE=false

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --test|-test)
            USE_TEST_MODE=true
            shift
            ;;
        run)
            ACTION="run"
            shift
            ;;
        generate)
            ACTION="generate"
            shift
            ;;
        *)
            if [ -z "$TARGET_DOMAIN" ]; then
                TARGET_DOMAIN="$1"
            fi
            shift
            ;;
    esac
done

# 如果没有指定域名，自动识别
if [ -z "$TARGET_DOMAIN" ]; then
    TARGET_DOMAIN=$(auto_detect_domain)
    if [ $? -ne 0 ]; then
        echo "⚠️ 警告: 使用默认域名 $TARGET_DOMAIN"
        echo "建议: 手动指定域名或确保 data/input/url 文件存在"
    else
        echo "✅ 自动识别域名: $TARGET_DOMAIN"
    fi
fi

# 显示模式
if [ "$USE_TEST_MODE" = true ]; then
    echo "🧪 二层扫描测试模式"
else
    echo "🔥 二层扫描生产模式"
fi

echo "[*] 目标域名: $TARGET_DOMAIN"
echo "[*] 操作: $ACTION"

# 检查一层扫描结果是否存在
SCAN_DIR="output/$TARGET_DOMAIN/tuozhan/all_tuozhan"
if [ ! -d "$SCAN_DIR" ]; then
    echo "❌ 错误: 未找到一层扫描结果 $SCAN_DIR"
    echo "请先运行一层扫描: ./scan.sh"
    exit 1
fi

# 检查是否有扩展数据
if [ ! -f "$SCAN_DIR/ip.txt" ] && [ ! -f "$SCAN_DIR/urls.txt" ] && [ ! -f "$SCAN_DIR/root_domains.txt" ]; then
    echo "❌ 错误: 未找到扩展数据文件"
    echo "请确保已完成一层扫描并生成了扩展结果"
    exit 1
fi

echo "[*] 开始二层扩展扫描..."

# 生成扩展任务
if [ "$USE_TEST_MODE" = true ]; then
    python3 scripts/management/expansion_processor.py "$TARGET_DOMAIN" --test
else
    python3 scripts/management/expansion_processor.py "$TARGET_DOMAIN"
fi

if [ $? -ne 0 ]; then
    echo "❌ 生成扩展任务失败"
    exit 1
fi

# 获取最新生成的任务目录
EXPANSION_DIR=$(find output/$TARGET_DOMAIN/expansion/tasks -name "expansion_*" -type d | sort | tail -1)

if [ -z "$EXPANSION_DIR" ]; then
    echo "❌ 错误: 未找到生成的任务目录"
    exit 1
fi

echo "[✓] 扩展任务已生成: $EXPANSION_DIR"

# 显示任务信息
echo ""
echo "📊 扩展任务详情:"
if [ -f "$EXPANSION_DIR/expansion_summary.txt" ]; then
    # 提取关键信息
    IP_COUNT=$(grep "IP目标:" "$EXPANSION_DIR/expansion_summary.txt" | grep -o "[0-9]\+" | head -1)
    URL_COUNT=$(grep "URL目标:" "$EXPANSION_DIR/expansion_summary.txt" | grep -o "[0-9]\+" | head -1)
    DOMAIN_COUNT=$(grep "根域名目标:" "$EXPANSION_DIR/expansion_summary.txt" | grep -o "[0-9]\+" | head -1)
    
    echo "   🎯 IP目标: ${IP_COUNT:-0} 个 (fscan端口扫描)"
    echo "   🌐 URL目标: ${URL_COUNT:-0} 个 (httpx探测扫描)"  
    echo "   🔍 根域名目标: ${DOMAIN_COUNT:-0} 个 (完整扫描流程)"
fi

# 根据操作执行相应任务
if [ "$ACTION" = "run" ]; then
    echo ""
    echo "🚀 开始执行二层扩展任务..."
    cd "$EXPANSION_DIR"
    
    if [ -f "run_all_expansions.sh" ]; then
        ./run_all_expansions.sh
        echo ""
        echo "✅ 二层扩展任务执行完成！"
        echo "📂 查看结果: ls -la output/$TARGET_DOMAIN/expansion/report/expansion_*/"
        echo "📊 最终报告: output/$TARGET_DOMAIN/expansion/report/"
    else
        echo "❌ 未找到执行脚本"
        exit 1
    fi
else
    echo ""
    echo "🚀 使用方法:"
    echo "   查看详细摘要: cat $EXPANSION_DIR/expansion_summary.txt"
    echo "   执行所有任务: cd $EXPANSION_DIR && ./run_all_expansions.sh"
    echo "   快捷执行命令: ./expand.sh $TARGET_DOMAIN run"
    if [ "$USE_TEST_MODE" = true ]; then
        echo "   测试模式执行: ./expand.sh $TARGET_DOMAIN run --test"
    fi
fi

echo ""
echo "🎉 二层扫描操作完成！"