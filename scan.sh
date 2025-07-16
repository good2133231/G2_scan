#!/bin/bash
# 简化的主扫描脚本 - 回到核心流程
# 流程：data/input/url -> 子域名扫描 -> httpx -> start.py -> afrog + fscan

set -e

# 解析参数
USE_TEST_MODE=false
if [[ "$1" == "--test" ||  "$1" == "-test" ]]; then
    USE_TEST_MODE=true
    echo "🧪 测试模式：使用精简参数"
else
    echo "🔥 生产模式：使用完整参数"
fi

# 执行日志函数
LOG_FILE=""
log_command() {
    local cmd="$1"
    local description="$2"
    echo "========================================" >> "$LOG_FILE"
    echo "时间: $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
    echo "步骤: $description" >> "$LOG_FILE"
    echo "命令: $cmd" >> "$LOG_FILE"
    echo "========================================" >> "$LOG_FILE"
    echo "📝 执行: $description"
    echo "   命令: $cmd"
}

# 检查文件函数
check_file_result() {
    local file_path="$1"
    local step_name="$2"
    local line_count=0
    
    if [ -f "$file_path" ]; then
        line_count=$(wc -l < "$file_path" 2>/dev/null || echo "0")
    fi
    
    echo "   结果: $line_count 条记录" | tee -a "$LOG_FILE"
    
    if [ "$line_count" -eq 0 ]; then
        echo "⚠️  警告: $step_name 结果为空，请检查上一步骤" | tee -a "$LOG_FILE"
        echo "   文件: $file_path" | tee -a "$LOG_FILE"
        return 1
    fi
    
    return 0
}

# 项目路径
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$PROJECT_ROOT/tools/scanner"
CONFIG_DIR="$PROJECT_ROOT/config"
DATA_DIR="$PROJECT_ROOT/data"
OUTPUT_DIR="$PROJECT_ROOT/output"
SCRIPTS_DIR="$PROJECT_ROOT/scripts"
TEMP_DIR="$PROJECT_ROOT/temp"

# 确保目录存在
mkdir -p "$OUTPUT_DIR" "$TEMP_DIR"

# 检查目标文件
TARGET_FILE="$DATA_DIR/input/url"
if [ ! -f "$TARGET_FILE" ]; then
    echo "❌ 错误: 未找到目标文件 $TARGET_FILE"
    echo "请创建该文件并填入目标域名"
    exit 1
fi

TARGET_DOMAIN=$(cat "$TARGET_FILE" | head -1 | xargs)
if [ -z "$TARGET_DOMAIN" ]; then
    echo "❌ 错误: 目标文件为空"
    exit 1
fi

echo "🎯 目标域名: $TARGET_DOMAIN"

# 创建执行日志
START_TIME=$(date +%s)
# 创建日志目录
mkdir -p temp/log
LOG_FILE="temp/log/scan_log_${TARGET_DOMAIN}_$(date +%Y%m%d_%H%M%S).log"
echo "📝 执行日志: $LOG_FILE"
echo "扫描开始时间: $(date)" > "$LOG_FILE"
echo "目标域名: $TARGET_DOMAIN" >> "$LOG_FILE"
echo "扫描模式: $([ "$USE_TEST_MODE" = true ] && echo "测试模式" || echo "生产模式")" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

# 检查工具
for tool in subfinder puredns httpx; do
    if [ ! -f "$TOOLS_DIR/$tool" ]; then
        echo "❌ 错误: 工具 $tool 不存在"
        exit 1
    fi
done

echo "🚀 开始一层扫描流程..."

# 1. 子域名收集
echo "📡 步骤1: 子域名收集..."
if [ "$USE_TEST_MODE" = true ]; then
    CMD="$TOOLS_DIR/subfinder -dL $TARGET_FILE -all -t 20 -o $TEMP_DIR/passive.txt"
    log_command "$CMD" "子域名被动收集(测试模式)"
    $TOOLS_DIR/subfinder -dL "$TARGET_FILE" -all -t 20 -o "$TEMP_DIR/passive.txt" 2>&1 | tee -a "$LOG_FILE"
else
    CMD="$TOOLS_DIR/subfinder -dL $TARGET_FILE -all -t 200 -o $TEMP_DIR/passive.txt"
    log_command "$CMD" "子域名被动收集(生产模式)"
    $TOOLS_DIR/subfinder -dL "$TARGET_FILE" -all -t 200 -o "$TEMP_DIR/passive.txt" 2>&1 | tee -a "$LOG_FILE"
fi

# 检查结果
if ! check_file_result "$TEMP_DIR/passive.txt" "子域名收集"; then
    echo "❌ 子域名收集失败，请检查网络连接和目标域名" | tee -a "$LOG_FILE"
    if [ "$USE_TEST_MODE" != true ]; then
        exit 1
    fi
fi

# 2. 子域名爆破
echo "💥 步骤2: 子域名爆破..."
if [ "$USE_TEST_MODE" = true ]; then
    # 测试模式：只使用前100行字典
    head -100 "$CONFIG_DIR/subdomains.txt" > "$TEMP_DIR/test_subdomains.txt"
    CMD="$TOOLS_DIR/puredns bruteforce $TEMP_DIR/test_subdomains.txt -d $TARGET_DOMAIN -r $CONFIG_DIR/resolvers.txt -q -w $TEMP_DIR/brute.txt"
    log_command "$CMD" "子域名爆破(测试模式-100行字典)"
    $TOOLS_DIR/puredns bruteforce "$TEMP_DIR/test_subdomains.txt" \
        -d "$TARGET_DOMAIN" \
        -r "$CONFIG_DIR/resolvers.txt" \
        -q -w "$TEMP_DIR/brute.txt" 2>&1 | tee -a "$LOG_FILE"
else
    # 生产模式：使用完整字典
    CMD="$TOOLS_DIR/puredns bruteforce $CONFIG_DIR/subdomains.txt -d $TARGET_DOMAIN -r $CONFIG_DIR/resolvers.txt -q -w $TEMP_DIR/brute.txt"
    log_command "$CMD" "子域名爆破(生产模式-完整字典)"
    $TOOLS_DIR/puredns bruteforce "$CONFIG_DIR/subdomains.txt" \
        -d "$TARGET_DOMAIN" \
        -r "$CONFIG_DIR/resolvers.txt" \
        -q -w "$TEMP_DIR/brute.txt" 2>&1 | tee -a "$LOG_FILE"
fi

# 检查结果  
if ! check_file_result "$TEMP_DIR/brute.txt" "子域名爆破"; then
    echo "⚠️  子域名爆破结果为空，可能字典无匹配或DNS问题" | tee -a "$LOG_FILE"
    # 爆破为空不算错误，继续执行
else
    echo "✅ 子域名爆破成功，发现新的子域名" | tee -a "$LOG_FILE"
fi

# 3. 合并去重
echo "🔗 步骤3: 合并去重..."
CMD="cat $TEMP_DIR/passive.txt $TEMP_DIR/brute.txt | sort -u > $TEMP_DIR/domain_life"
log_command "$CMD" "合并去重子域名"
cat "$TEMP_DIR/passive.txt" "$TEMP_DIR/brute.txt" 2>/dev/null | sort -u > "$TEMP_DIR/domain_life"

# 检查合并结果
if ! check_file_result "$TEMP_DIR/domain_life" "合并去重"; then
    echo "❌ 合并去重失败，没有发现任何子域名" | tee -a "$LOG_FILE"
    exit 1
fi

# 4. 域名解析验证
echo "🔍 步骤4: 域名解析验证..."
CMD="$TOOLS_DIR/puredns resolve $TEMP_DIR/domain_life -r $CONFIG_DIR/resolvers.txt --wildcard-tests 50 --wildcard-batch 1000000 -q -w $TEMP_DIR/httpx_url"
log_command "$CMD" "域名解析验证"
$TOOLS_DIR/puredns resolve "$TEMP_DIR/domain_life" \
    -r "$CONFIG_DIR/resolvers.txt" \
    --wildcard-tests 50 --wildcard-batch 1000000 \
    -q -w "$TEMP_DIR/httpx_url" 2>&1 | tee -a "$LOG_FILE"

# 检查解析结果
if ! check_file_result "$TEMP_DIR/httpx_url" "域名解析验证"; then
    echo "⚠️  puredns验证结果为空，使用备用方案" | tee -a "$LOG_FILE"
    echo "备用方案：直接使用domain_life文件（subfinder收集的域名）" | tee -a "$LOG_FILE"
    cp "$TEMP_DIR/domain_life" "$TEMP_DIR/httpx_url"
    echo "   备用方案执行完成，继续HTTP探测" | tee -a "$LOG_FILE"
else
    echo "✅ puredns验证成功，使用验证后的域名列表" | tee -a "$LOG_FILE"
fi

# 5. HTTP探测
echo "🌐 步骤5: HTTP探测..."
if [ "$USE_TEST_MODE" = true ]; then
    CMD="$TOOLS_DIR/httpx -l $TEMP_DIR/httpx_url -mc 200,301,302,403,404 -timeout 2 -favicon -hash md5,mmh3 -retries 1 -t 50 -rl 1000 -resume -extract-fqdn -tls-grab -json -o $TEMP_DIR/result_all.json"
    log_command "$CMD" "HTTP探测(测试模式-50线程)"
    $TOOLS_DIR/httpx -l "$TEMP_DIR/httpx_url" \
        -mc 200,301,302,403,404 -timeout 2 \
        -favicon -hash md5,mmh3 -retries 1 -t 50 -rl 1000 \
        -resume -extract-fqdn -tls-grab -json \
        -o "$TEMP_DIR/result_all.json" 2>&1 | tee -a "$LOG_FILE"
else
    CMD="$TOOLS_DIR/httpx -l $TEMP_DIR/httpx_url -mc 200,301,302,403,404 -timeout 2 -favicon -hash md5,mmh3 -retries 1 -t 300 -rl 1000000 -resume -extract-fqdn -tls-grab -json -o $TEMP_DIR/result_all.json"
    log_command "$CMD" "HTTP探测(生产模式-300线程)"
    $TOOLS_DIR/httpx -l "$TEMP_DIR/httpx_url" \
        -mc 200,301,302,403,404 -timeout 2 \
        -favicon -hash md5,mmh3 -retries 1 -t 300 -rl 1000000 \
        -resume -extract-fqdn -tls-grab -json \
        -o "$TEMP_DIR/result_all.json" 2>&1 | tee -a "$LOG_FILE"
fi

# 检查HTTP探测结果
if ! check_file_result "$TEMP_DIR/result_all.json" "HTTP探测"; then
    echo "❌ HTTP探测失败，没有发现HTTP服务" | tee -a "$LOG_FILE"
    if [ "$USE_TEST_MODE" != true ]; then
        exit 1
    fi
fi

# 6. 数据处理和漏洞扫描
echo "📊 步骤6: 数据处理和漏洞扫描..."
cd "$PROJECT_ROOT"

if [ "$USE_TEST_MODE" = true ]; then
    # 测试模式：传递-test参数给start.py
    CMD="python3 $SCRIPTS_DIR/core/start.py -test"
    log_command "$CMD" "数据处理和漏洞扫描(测试模式)"
    python3 "$SCRIPTS_DIR/core/start.py" -test 2>&1 | tee -a "$LOG_FILE"
else
    # 生产模式：正常运行
    CMD="python3 $SCRIPTS_DIR/core/start.py"
    log_command "$CMD" "数据处理和漏洞扫描(生产模式)"
    python3 "$SCRIPTS_DIR/core/start.py" 2>&1 | tee -a "$LOG_FILE"
fi

# 检查扫描结果目录
RESULT_DIR="$OUTPUT_DIR/$TARGET_DOMAIN"
if [ -d "$RESULT_DIR" ]; then
    echo "✅ 数据处理完成，结果已生成" | tee -a "$LOG_FILE"
    ls -la "$RESULT_DIR" | tee -a "$LOG_FILE"
else
    echo "⚠️  警告: 未生成结果目录，请检查start.py执行情况" | tee -a "$LOG_FILE"
fi

# 7. 清理临时文件
echo "🧹 清理临时文件..."
find "$TEMP_DIR" -name "*.txt" -delete 2>/dev/null || true
find "$TEMP_DIR" -name "*.json" -delete 2>/dev/null || true

echo "✅ 一层扫描完成！" | tee -a "$LOG_FILE"
echo "📂 查看结果: ls -la $OUTPUT_DIR/$TARGET_DOMAIN/"
echo "📝 详细日志: $LOG_FILE"

# 检查是否有扩展目标
echo "🔍 检查扩展目标..." | tee -a "$LOG_FILE"
TUOZHAN_DIR="$OUTPUT_DIR/$TARGET_DOMAIN/tuozhan/all_tuozhan"
if [ -d "$TUOZHAN_DIR" ]; then
    IP_COUNT=0
    URL_COUNT=0
    DOMAIN_COUNT=0
    
    # 记录扩展目标检查过程
    echo "检查扩展目标文件:" >> "$LOG_FILE"
    echo "   目录: $TUOZHAN_DIR" >> "$LOG_FILE"
    
    # 检查IP目标
    if [ -f "$TUOZHAN_DIR/ip.txt" ]; then
        IP_COUNT=$(wc -l < "$TUOZHAN_DIR/ip.txt" 2>/dev/null || echo "0")
        echo "   IP文件: $IP_COUNT 个目标" >> "$LOG_FILE"
    else
        echo "   IP文件: 不存在" >> "$LOG_FILE"
    fi
    
    # 检查URL目标
    if [ -f "$TUOZHAN_DIR/urls.txt" ]; then
        URL_COUNT=$(wc -l < "$TUOZHAN_DIR/urls.txt" 2>/dev/null || echo "0")
        echo "   URL文件: $URL_COUNT 个目标" >> "$LOG_FILE"
    else
        echo "   URL文件: 不存在" >> "$LOG_FILE"
    fi
    
    # 检查域名目标
    if [ -f "$TUOZHAN_DIR/root_domains.txt" ]; then
        DOMAIN_COUNT=$(wc -l < "$TUOZHAN_DIR/root_domains.txt" 2>/dev/null || echo "0")
        echo "   域名文件: $DOMAIN_COUNT 个目标" >> "$LOG_FILE"
    else
        echo "   域名文件: 不存在" >> "$LOG_FILE"
    fi
    
    # 统计总扩展目标
    TOTAL_EXPANSION_TARGETS=$((IP_COUNT + URL_COUNT + DOMAIN_COUNT))
    echo "   总扩展目标: $TOTAL_EXPANSION_TARGETS 个" >> "$LOG_FILE"
    
    if [ $TOTAL_EXPANSION_TARGETS -gt 0 ]; then
        echo ""
        echo "🔄 发现扩展目标:"
        echo "   IP目标: $IP_COUNT 个"
        echo "   URL目标: $URL_COUNT 个" 
        echo "   域名目标: $DOMAIN_COUNT 个"
        echo ""
        echo "💡 执行二层扫描: ./expand.sh $TARGET_DOMAIN run"
        if [ "$USE_TEST_MODE" = true ]; then
            echo "💡 测试模式二层: ./expand.sh $TARGET_DOMAIN run --test"
        fi
        
        # 记录扩展建议到日志
        echo "扩展目标统计:" >> "$LOG_FILE"
        echo "   IP目标: $IP_COUNT 个 (fscan端口扫描)" >> "$LOG_FILE"
        echo "   URL目标: $URL_COUNT 个 (httpx探测)" >> "$LOG_FILE"
        echo "   域名目标: $DOMAIN_COUNT 个 (完整扫描流程)" >> "$LOG_FILE"
        echo "建议执行命令: ./expand.sh $TARGET_DOMAIN run$([ \"$USE_TEST_MODE\" = true ] && echo ' --test')" >> "$LOG_FILE"
    else
        echo "ℹ️  未发现扩展目标，一层扫描已完成" | tee -a "$LOG_FILE"
    fi
else
    echo "⚠️  警告: 未找到扩展目标目录 $TUOZHAN_DIR" | tee -a "$LOG_FILE"
    echo "这可能是因为start.py执行过程中出现问题" | tee -a "$LOG_FILE"
fi

# 记录扫描完成信息
echo "" >> "$LOG_FILE"
echo "========================================" >> "$LOG_FILE"
echo "扫描结束时间: $(date)" >> "$LOG_FILE"
echo "总耗时: $(($(date +%s) - START_TIME))秒" >> "$LOG_FILE"
echo "扫描模式: $([ "$USE_TEST_MODE" = true ] && echo "测试模式" || echo "生产模式")" >> "$LOG_FILE"
echo "目标域名: $TARGET_DOMAIN" >> "$LOG_FILE"
echo "输出目录: $OUTPUT_DIR/$TARGET_DOMAIN" >> "$LOG_FILE"
echo "日志文件: $LOG_FILE" >> "$LOG_FILE"
echo "========================================" >> "$LOG_FILE"

echo "🎉 扫描流程完成！"
echo "📝 完整日志已保存至: $LOG_FILE"