#!/bin/bash
# 简化的扫描脚本 - 新架构版本
# scan -s 1: 主域名扫描 + 扩展资产快速扫描
# scan -s 2: 主域名扫描 + 扩展域名独立扫描

set -e

# 解析参数
USE_TEST_MODE=false
SCAN_MODE=1  # 默认模式1

while [[ $# -gt 0 ]]; do
    case $1 in
        --test|-test)
            USE_TEST_MODE=true
            shift
            ;;
        -s|--scan-mode)
            SCAN_MODE="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

# 项目根目录（scan.sh所在目录）
PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
TOOLS_DIR="$PROJECT_ROOT/tools/scanner"
CONFIG_DIR="$PROJECT_ROOT/config"
DATA_DIR="$PROJECT_ROOT/data"
OUTPUT_DIR="$PROJECT_ROOT/output"
SCRIPTS_DIR="$PROJECT_ROOT/scripts"
TEMP_DIR="$PROJECT_ROOT/temp"

# 确保目录存在
mkdir -p "$OUTPUT_DIR" "$TEMP_DIR" "$TEMP_DIR/log"

# 检查目标文件
TARGET_FILE="$DATA_DIR/input/url"
if [ ! -f "$TARGET_FILE" ]; then
    echo "❌ 错误: 未找到目标文件 $TARGET_FILE"
    exit 1
fi

TARGET_DOMAIN=$(cat "$TARGET_FILE" | head -1 | xargs)
if [ -z "$TARGET_DOMAIN" ]; then
    echo "❌ 错误: 目标文件为空"
    exit 1
fi

echo "🎯 目标域名: $TARGET_DOMAIN"
echo "🔧 扫描模式: $SCAN_MODE"
echo "🧪 测试模式: $USE_TEST_MODE"

# 创建日志
LOG_FILE="$TEMP_DIR/log/scan_${TARGET_DOMAIN}_$(date +%Y%m%d_%H%M%S).log"
echo "📝 执行日志: $LOG_FILE"

# 记录命令函数
log_command() {
    echo "📌 执行命令: $1" | tee -a "$LOG_FILE"
    echo "📋 说明: $2" | tee -a "$LOG_FILE"
}

# 检查文件结果函数
check_file_result() {
    local file=$1
    local desc=$2
    if [ -f "$file" ] && [ -s "$file" ]; then
        local count=$(wc -l < "$file")
        echo "✅ $desc 完成，发现 $count 条记录" | tee -a "$LOG_FILE"
        return 0
    else
        echo "⚠️  $desc 结果为空" | tee -a "$LOG_FILE"
        return 1
    fi
}

# 主域名扫描函数
scan_domain() {
    local domain=$1
    local domain_dir="$OUTPUT_DIR/$domain"
    
    echo "🚀 开始扫描域名: $domain" | tee -a "$LOG_FILE"
    
    # 如果域名已扫描过，跳过
    if [ -f "$domain_dir/finish.txt" ]; then
        echo "✅ 域名 $domain 已扫描过，跳过" | tee -a "$LOG_FILE"
        return 0
    fi
    
    # 创建域名目录
    mkdir -p "$domain_dir"
    
    # 初始化扫描状态
    "$SCRIPTS_DIR/utils/update_scan_status.sh" "$domain" "subdomain_discovery" "pending"
    
    # 1. 子域名收集
    echo "📡 步骤1: 子域名收集..."
    "$SCRIPTS_DIR/utils/update_scan_status.sh" "$domain" "subdomain_discovery" "in_progress" "10" "开始收集子域名"
    echo "$domain" > "$TEMP_DIR/single_domain.txt"
    
    if [ "$USE_TEST_MODE" = true ]; then
        $TOOLS_DIR/subfinder -dL "$TEMP_DIR/single_domain.txt" -t 20 -o "$TEMP_DIR/passive_$domain.txt" 2>&1 | tee -a "$LOG_FILE"
    else
        $TOOLS_DIR/subfinder -dL "$TEMP_DIR/single_domain.txt" -all -t 200 -o "$TEMP_DIR/passive_$domain.txt" 2>&1 | tee -a "$LOG_FILE"
    fi
    
    # 2. 子域名爆破（生产模式）
    if [ "$USE_TEST_MODE" = true ]; then
        touch "$TEMP_DIR/brute_$domain.txt"
    else
        echo "💥 步骤2: 子域名爆破..."
        $TOOLS_DIR/puredns bruteforce "$CONFIG_DIR/subdomains.txt" \
            "$domain" \
            -r "$CONFIG_DIR/resolvers.txt" \
            -q -w "$TEMP_DIR/brute_$domain.txt" 2>&1 | tee -a "$LOG_FILE"
    fi
    
    # 3. 合并和验证
    echo "🔄 步骤3: 合并和验证子域名..."
    cat "$TEMP_DIR/passive_$domain.txt" "$TEMP_DIR/brute_$domain.txt" 2>/dev/null | sort -u > "$TEMP_DIR/all_$domain.txt"
    "$SCRIPTS_DIR/utils/update_scan_status.sh" "$domain" "subdomain_discovery" "completed" "100" "子域名收集完成"
    
    if [ "$USE_TEST_MODE" = true ]; then
        cp "$TEMP_DIR/all_$domain.txt" "$TEMP_DIR/resolved_$domain.txt"
    else
        $TOOLS_DIR/puredns resolve "$TEMP_DIR/all_$domain.txt" \
            -r "$CONFIG_DIR/resolvers.txt" \
            --write "$TEMP_DIR/resolved_$domain.txt" 2>&1 | tee -a "$LOG_FILE"
    fi
    
    # 4. httpx扫描
    echo "🌐 步骤4: HTTP/HTTPS探测..."
    "$SCRIPTS_DIR/utils/update_scan_status.sh" "$domain" "http_probe" "in_progress" "10" "开始HTTP服务探测"
    if [ "$USE_TEST_MODE" = true ]; then
        $TOOLS_DIR/httpx -l "$TEMP_DIR/resolved_$domain.txt" \
            -threads 50 -timeout 10 \
            -o "$TEMP_DIR/result_all_$domain.json" -json \
            -td -fhr -include-response -include-chain 2>&1 | tee -a "$LOG_FILE"
    else
        $TOOLS_DIR/httpx -l "$TEMP_DIR/resolved_$domain.txt" \
            -threads 200 -timeout 30 \
            -o "$TEMP_DIR/result_all_$domain.json" -json \
            -td -fhr -include-response -include-chain 2>&1 | tee -a "$LOG_FILE"
    fi
    
    # 5. start.py处理
    echo "📊 步骤5: 数据处理和分析..."
    "$SCRIPTS_DIR/utils/update_scan_status.sh" "$domain" "http_probe" "completed" "100" "HTTP探测完成"
    "$SCRIPTS_DIR/utils/update_scan_status.sh" "$domain" "expand_scan" "in_progress" "10" "开始数据分析和扩展资产发现"
    cp "$TEMP_DIR/result_all_$domain.json" "$TEMP_DIR/result_all.json"
    
    if [ "$USE_TEST_MODE" = true ]; then
        python3 "$SCRIPTS_DIR/core/start.py" -test -domain "$domain" 2>&1 | tee -a "$LOG_FILE"
    else
        python3 "$SCRIPTS_DIR/core/start.py" -domain "$domain" 2>&1 | tee -a "$LOG_FILE"
    fi
    "$SCRIPTS_DIR/utils/update_scan_status.sh" "$domain" "expand_scan" "completed" "100" "扩展资产发现完成"
    
    # 6. 安全扫描
    if [ "$USE_TEST_MODE" != true ]; then
        echo "🔍 步骤6: 安全扫描..."
        "$SCRIPTS_DIR/utils/update_scan_status.sh" "$domain" "vulnerability_scan" "in_progress" "10" "开始漏洞扫描"
        
        # Afrog扫描
        if [ -f "$domain_dir/input/representative_urls.txt" ]; then
            $TOOLS_DIR/afrog -T "$domain_dir/input/representative_urls.txt" \
                -o "$domain_dir/afrog_report_$domain.json" \
                -disable-poc-update 2>&1 | tee -a "$LOG_FILE"
        fi
        "$SCRIPTS_DIR/utils/update_scan_status.sh" "$domain" "vulnerability_scan" "completed" "100" "漏洞扫描完成"
        
        # Fscan扫描
        "$SCRIPTS_DIR/utils/update_scan_status.sh" "$domain" "port_scan" "in_progress" "10" "开始端口扫描"
        if [ -f "$domain_dir/tuozhan/all_tuozhan/ips.txt" ]; then
            $TOOLS_DIR/fscan -hf "$domain_dir/tuozhan/all_tuozhan/ips.txt" \
                -o "$domain_dir/fscan_result_$domain.txt" 2>&1 | tee -a "$LOG_FILE"
        fi
        "$SCRIPTS_DIR/utils/update_scan_status.sh" "$domain" "port_scan" "completed" "100" "端口扫描完成"
    else
        "$SCRIPTS_DIR/utils/update_scan_status.sh" "$domain" "vulnerability_scan" "completed" "100" "测试模式跳过"
        "$SCRIPTS_DIR/utils/update_scan_status.sh" "$domain" "port_scan" "completed" "100" "测试模式跳过"
    fi
    
    "$SCRIPTS_DIR/utils/update_scan_status.sh" "$domain" "report_generation" "completed" "100" "扫描完成"
    echo "✅ 域名 $domain 扫描完成" | tee -a "$LOG_FILE"
}

# 扩展资产快速扫描函数
scan_expanded_assets() {
    local domain=$1
    local domain_dir="$OUTPUT_DIR/$domain"
    local expand_dir="$domain_dir/expand_quick_scan"
    
    echo "⚡ 开始扩展资产快速扫描..." | tee -a "$LOG_FILE"
    mkdir -p "$expand_dir"
    
    # 扫描扩展IP
    if [ -f "$domain_dir/tuozhan/all_tuozhan/expand_ips.txt" ] && [ -s "$domain_dir/tuozhan/all_tuozhan/expand_ips.txt" ]; then
        echo "🔍 扫描扩展IP..." | tee -a "$LOG_FILE"
        $TOOLS_DIR/fscan -hf "$domain_dir/tuozhan/all_tuozhan/expand_ips.txt" \
            -o "$expand_dir/fscan_ips.txt" 2>&1 | tee -a "$LOG_FILE"
    fi
    
    # 扫描扩展URL
    if [ -f "$domain_dir/tuozhan/all_tuozhan/expand_urls.txt" ] && [ -s "$domain_dir/tuozhan/all_tuozhan/expand_urls.txt" ]; then
        echo "🌐 扫描扩展URL..." | tee -a "$LOG_FILE"
        
        # httpx获取标题
        $TOOLS_DIR/httpx -l "$domain_dir/tuozhan/all_tuozhan/expand_urls.txt" \
            -threads 100 -timeout 20 \
            -o "$expand_dir/httpx_urls.json" -json \
            -td -fhr 2>&1 | tee -a "$LOG_FILE"
        
        # afrog扫描漏洞
        if [ "$USE_TEST_MODE" != true ]; then
            $TOOLS_DIR/afrog -T "$domain_dir/tuozhan/all_tuozhan/expand_urls.txt" \
                -o "$expand_dir/afrog_urls.json" \
                -disable-poc-update 2>&1 | tee -a "$LOG_FILE"
        fi
    fi
    
    echo "✅ 扩展资产快速扫描完成" | tee -a "$LOG_FILE"
}

# 记录关系数据
record_relationships() {
    local parent_domain=$1
    local domain_dir="$OUTPUT_DIR/$parent_domain"
    local relationships_file="$domain_dir/relationships.json"
    
    # 调用Python脚本生成关系数据
    python3 -c "
import json
from pathlib import Path
from datetime import datetime

domain_dir = Path('$domain_dir')
relationships = {
    'domain': '$parent_domain',
    'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    'scan_mode': 's$SCAN_MODE',
    'discovered_by': None,
    'discovered_from': None,
    'discoveries': {
        'domains': [],
        'ips': [],
        'urls': []
    }
}

# 读取扩展域名
expand_domains_file = domain_dir / 'tuozhan/all_tuozhan/root_domains.txt'
if expand_domains_file.exists():
    with open(expand_domains_file, 'r') as f:
        for line in f:
            domain = line.strip()
            if domain and domain != '$parent_domain':
                relationships['discoveries']['domains'].append({
                    'domain': domain,
                    'method': 'expansion',
                    'scanned': False
                })

# 读取扩展IP
expand_ips_file = domain_dir / 'tuozhan/all_tuozhan/expand_ips.txt'
if expand_ips_file.exists():
    with open(expand_ips_file, 'r') as f:
        for line in f:
            ip = line.strip()
            if ip:
                relationships['discoveries']['ips'].append({
                    'ip': ip,
                    'method': 'expansion',
                    'scanned': True
                })

# 读取扩展URL
expand_urls_file = domain_dir / 'tuozhan/all_tuozhan/expand_urls.txt'
if expand_urls_file.exists():
    with open(expand_urls_file, 'r') as f:
        for line in f:
            url = line.strip()
            if url:
                relationships['discoveries']['urls'].append({
                    'url': url,
                    'method': 'expansion',
                    'scanned': True
                })

# 保存关系数据
with open('$relationships_file', 'w') as f:
    json.dump(relationships, f, indent=2, ensure_ascii=False)

print(f'✅ 关系数据已保存到: $relationships_file')
"
}

# 主流程
echo "🎯 开始扫描流程..." | tee -a "$LOG_FILE"

# 1. 扫描主域名
scan_domain "$TARGET_DOMAIN"

# 2. 记录关系数据
record_relationships "$TARGET_DOMAIN"

# 3. 根据扫描模式决定是否扫描扩展资产
if [ "$SCAN_MODE" = "1" ]; then
    # 模式1：只对扩展资产进行快速扫描
    scan_expanded_assets "$TARGET_DOMAIN"
    
elif [ "$SCAN_MODE" = "2" ]; then
    # 模式2：扩展域名作为独立域名扫描
    echo "📌 扫描模式2：对扩展域名进行独立扫描" | tee -a "$LOG_FILE"
    
    # 先进行扩展资产快速扫描
    scan_expanded_assets "$TARGET_DOMAIN"
    
    # 获取扩展域名列表
    EXPAND_DOMAINS_FILE="$OUTPUT_DIR/$TARGET_DOMAIN/tuozhan/all_tuozhan/root_domains.txt"
    if [ -f "$EXPAND_DOMAINS_FILE" ]; then
        while IFS= read -r expand_domain; do
            if [ -n "$expand_domain" ] && [ "$expand_domain" != "$TARGET_DOMAIN" ]; then
                echo "🔄 扫描扩展域名: $expand_domain" | tee -a "$LOG_FILE"
                
                # 对扩展域名进行完整扫描
                scan_domain "$expand_domain"
                
                # 更新扩展域名的关系数据
                python3 -c "
import json
from pathlib import Path

# 更新扩展域名的关系数据
domain_dir = Path('$OUTPUT_DIR/$expand_domain')
relationships_file = domain_dir / 'relationships.json'

if relationships_file.exists():
    with open(relationships_file, 'r') as f:
        data = json.load(f)
    data['discovered_by'] = '$TARGET_DOMAIN'
    data['discovered_from'] = 'expansion'
    with open(relationships_file, 'w') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
else:
    # 创建新的关系数据
    relationships = {
        'domain': '$expand_domain',
        'scan_time': '$(date +%Y-%m-%d\ %H:%M:%S)',
        'scan_mode': 's2',
        'discovered_by': '$TARGET_DOMAIN',
        'discovered_from': 'expansion',
        'discoveries': {'domains': [], 'ips': [], 'urls': []}
    }
    domain_dir.mkdir(parents=True, exist_ok=True)
    with open(relationships_file, 'w') as f:
        json.dump(relationships, f, indent=2, ensure_ascii=False)
"
                
                # 更新主域名的关系数据，标记已扫描
                python3 -c "
import json

relationships_file = '$OUTPUT_DIR/$TARGET_DOMAIN/relationships.json'
with open(relationships_file, 'r') as f:
    data = json.load(f)

for domain_info in data['discoveries']['domains']:
    if domain_info['domain'] == '$expand_domain':
        domain_info['scanned'] = True
        break

with open(relationships_file, 'w') as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
"
            fi
        done < "$EXPAND_DOMAINS_FILE"
    fi
fi

# 记录扫描完成时间
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
echo "⏱️  扫描总耗时: ${DURATION}秒" | tee -a "$LOG_FILE"
echo "✅ 所有扫描任务完成！" | tee -a "$LOG_FILE"

# 生成扫描摘要
echo -e "\n📊 扫描摘要:" | tee -a "$LOG_FILE"
echo "- 目标域名: $TARGET_DOMAIN" | tee -a "$LOG_FILE"
echo "- 扫描模式: $SCAN_MODE" | tee -a "$LOG_FILE"
echo "- 测试模式: $USE_TEST_MODE" | tee -a "$LOG_FILE"
echo "- 日志文件: $LOG_FILE" | tee -a "$LOG_FILE"
echo "- 输出目录: $OUTPUT_DIR/$TARGET_DOMAIN" | tee -a "$LOG_FILE"