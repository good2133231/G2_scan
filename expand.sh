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
SCAN_LAYER=2  # 默认二层扫描

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --test|-test)
            USE_TEST_MODE=true
            shift
            ;;
        --layer|-l)
            SCAN_LAYER="$2"
            shift 2
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
    echo "🧪 第${SCAN_LAYER}层扫描测试模式"
else
    echo "🔥 第${SCAN_LAYER}层扫描生产模式"
fi

echo "[*] 目标域名: $TARGET_DOMAIN"
echo "[*] 扫描层数: $SCAN_LAYER"
echo "[*] 操作: $ACTION"

# 根据扫描层数确定输入目录
if [ "$SCAN_LAYER" -eq 2 ]; then
    # 二层扫描：使用一层的扩展结果
    SCAN_DIR="output/$TARGET_DOMAIN/tuozhan/all_tuozhan"
    ERROR_MSG="未找到一层扫描结果，请先运行: ./scan.sh"
    
    # 检查扫描结果是否存在
    if [ ! -d "$SCAN_DIR" ]; then
        echo "❌ 错误: $ERROR_MSG"
        echo "   查找目录: $SCAN_DIR"
        exit 1
    fi
    
    # 检查是否有扩展数据
    if [ ! -f "$SCAN_DIR/ip.txt" ] && [ ! -f "$SCAN_DIR/urls.txt" ] && [ ! -f "$SCAN_DIR/root_domains.txt" ]; then
        echo "❌ 错误: 未找到扩展数据文件"
        echo "请确保已完成上一层扫描并生成了扩展结果"
        exit 1
    fi
else
    # 三层及以上：特殊处理，需要遍历上一层的所有域名结果
    echo "[*] 第${SCAN_LAYER}层扫描：收集上一层所有域名的扩展结果..."
    
    # 创建临时目录存储收集的目标
    TEMP_TARGETS="temp/layer${SCAN_LAYER}_targets_$$"
    mkdir -p "$TEMP_TARGETS"
    touch "$TEMP_TARGETS/ip.txt" "$TEMP_TARGETS/urls.txt" "$TEMP_TARGETS/root_domains.txt"
    
    # 根据层数确定上一层的结果目录
    if [ "$SCAN_LAYER" -eq 3 ]; then
        # 三层：从二层的domain_scan_results收集
        PREV_LAYER_DIR="output/$TARGET_DOMAIN/expansion/report/domain_scan_results"
    else
        # 四层及以上：从上一层的report收集
        PREV_LAYER=$((SCAN_LAYER - 1))
        PREV_LAYER_DIR="output/$TARGET_DOMAIN/expansion/layer${PREV_LAYER}/report/domain_scan_results"
    fi
    
    # 收集所有域名的扩展结果
    if [ -d "$PREV_LAYER_DIR" ]; then
        echo "[*] 从目录收集: $PREV_LAYER_DIR"
        for domain_dir in "$PREV_LAYER_DIR"/*; do
            if [ -d "$domain_dir" ]; then
                domain_name=$(basename "$domain_dir")
                tuozhan_dir="$domain_dir/$domain_name/tuozhan/all_tuozhan"
                
                if [ -d "$tuozhan_dir" ]; then
                    echo "   - 收集 $domain_name 的扩展结果"
                    
                    # 收集IP
                    if [ -f "$tuozhan_dir/ip.txt" ]; then
                        grep -v "^#" "$tuozhan_dir/ip.txt" 2>/dev/null >> "$TEMP_TARGETS/ip.txt" || true
                    fi
                    
                    # 收集URL
                    if [ -f "$tuozhan_dir/urls.txt" ]; then
                        grep -v "^#" "$tuozhan_dir/urls.txt" 2>/dev/null >> "$TEMP_TARGETS/urls.txt" || true
                    fi
                    
                    # 收集域名
                    if [ -f "$tuozhan_dir/root_domains.txt" ]; then
                        grep -v "^#" "$tuozhan_dir/root_domains.txt" 2>/dev/null >> "$TEMP_TARGETS/root_domains.txt" || true
                    fi
                fi
            fi
        done
        
        # 去重
        sort -u "$TEMP_TARGETS/ip.txt" -o "$TEMP_TARGETS/ip.txt"
        sort -u "$TEMP_TARGETS/urls.txt" -o "$TEMP_TARGETS/urls.txt"
        sort -u "$TEMP_TARGETS/root_domains.txt" -o "$TEMP_TARGETS/root_domains.txt"
        
        # 统计
        IP_COUNT=$(grep -v "^$" "$TEMP_TARGETS/ip.txt" | wc -l)
        URL_COUNT=$(grep -v "^$" "$TEMP_TARGETS/urls.txt" | wc -l)
        DOMAIN_COUNT=$(grep -v "^$" "$TEMP_TARGETS/root_domains.txt" | wc -l)
        
        echo "[*] 收集完成:"
        echo "    - IP目标: $IP_COUNT 个"
        echo "    - URL目标: $URL_COUNT 个"
        echo "    - 域名目标: $DOMAIN_COUNT 个"
        
        if [ $IP_COUNT -eq 0 ] && [ $URL_COUNT -eq 0 ] && [ $DOMAIN_COUNT -eq 0 ]; then
            echo "❌ 错误: 上一层扫描未发现任何扩展目标"
            rm -rf "$TEMP_TARGETS"
            exit 1
        fi
        
        SCAN_DIR="$TEMP_TARGETS"
    else
        echo "❌ 错误: 未找到第$((SCAN_LAYER-1))层扫描结果"
        echo "   查找目录: $PREV_LAYER_DIR"
        exit 1
    fi
fi

echo "[*] 开始第${SCAN_LAYER}层扩展扫描..."
echo "[*] 输入目录: $SCAN_DIR"

# 生成扩展任务
if [ "$USE_TEST_MODE" = true ]; then
    python3 scripts/management/expansion_processor.py "$TARGET_DOMAIN" --test --layer "$SCAN_LAYER" --input-dir "$SCAN_DIR"
else
    python3 scripts/management/expansion_processor.py "$TARGET_DOMAIN" --layer "$SCAN_LAYER" --input-dir "$SCAN_DIR"
fi

if [ $? -ne 0 ]; then
    echo "❌ 生成扩展任务失败"
    exit 1
fi

# 获取任务目录（根据层数）
if [ "$SCAN_LAYER" -eq 2 ]; then
    EXPANSION_DIR="output/$TARGET_DOMAIN/expansion/tasks"
else
    EXPANSION_DIR="output/$TARGET_DOMAIN/expansion/layer${SCAN_LAYER}/tasks"
fi

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
    echo "🚀 开始执行第${SCAN_LAYER}层扩展任务..."
    cd "$EXPANSION_DIR"
    
    if [ -f "run_all_expansions.sh" ]; then
        ./run_all_expansions.sh
        echo ""
        echo "✅ 第${SCAN_LAYER}层扩展任务执行完成！"
        echo "📂 查看结果: ls -la output/$TARGET_DOMAIN/expansion/report/"
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
echo "🎉 第${SCAN_LAYER}层扫描操作完成！"

# 清理临时目录
if [ -d "$TEMP_TARGETS" ]; then
    rm -rf "$TEMP_TARGETS"
fi