#!/bin/bash
# 🎯 IP地址独立端口扫描脚本 - 基于fscan架构
# 专用于IP地址的端口扫描和路径探测，与域名扫描完全分离

set -e

TARGET_IP="$1"
PORTS="$2"
OUTPUT_DIR="$3"

if [ -z "$TARGET_IP" ] || [ -z "$PORTS" ] || [ -z "$OUTPUT_DIR" ]; then
    echo "❌ 用法: $0 <target_ip> <ports> <output_dir>"
    echo "   ports: all(默认)|common|web|database"
    echo "   🎯 推荐: all - 全端口扫描(1-65535)，适合红队渗透测试"
    exit 1
fi

echo "🎯 开始IP端口扫描: $TARGET_IP"
echo "📊 端口范围: $PORTS"
echo "📁 输出目录: $OUTPUT_DIR"
echo "⏰ 开始时间: $(date)"

# 确保输出目录存在
mkdir -p "$OUTPUT_DIR"

# 创建扫描日志文件
SCAN_LOG="$OUTPUT_DIR/scan.log"
exec > >(tee -a "$SCAN_LOG") 2>&1

echo "🚀 IP扫描开始 - $(date)" >> "$SCAN_LOG"

# 获取项目根目录
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
PROJECT_ROOT="$SCRIPT_DIR"
FSCAN_TOOL="$PROJECT_ROOT/tools/scanner/fscan"

# 检查fscan是否存在
if [ ! -f "$FSCAN_TOOL" ]; then
    echo "❌ 错误: fscan工具不存在: $FSCAN_TOOL"
    echo "请确保fscan工具位于 tools/scanner/fscan"
    exit 1
fi

# 检查fscan是否可执行
if [ ! -x "$FSCAN_TOOL" ]; then
    echo "🔧 设置fscan执行权限..."
    chmod +x "$FSCAN_TOOL"
fi

# 创建目标IP文件
TARGET_FILE="$OUTPUT_DIR/target_ip.txt"
echo "$TARGET_IP" > "$TARGET_FILE"

# 根据端口范围设置fscan参数 - 默认全端口扫描
case "$PORTS" in
    "common")
        FSCAN_PORTS="21,22,23,25,53,80,110,139,143,443,993,995,1433,3306,3389,5432,6379,8080,8443,9090,27017"
        PORT_DESC="常用端口"
        TIMEOUT=300
        ;;
    "all"|"full")
        FSCAN_PORTS="all"
        PORT_DESC="全端口扫描 (1-65535)"
        TIMEOUT=1800  # 30分钟
        ;;
    "web")
        FSCAN_PORTS="80,443,8080,8443,8000,8888,9000,3000,9090,8001,8888,8081,8082"
        PORT_DESC="Web服务端口"
        TIMEOUT=180
        ;;
    "database")
        FSCAN_PORTS="1433,3306,5432,1521,27017,6379,11211,9042,5984,7000,7001,9160,9042"
        PORT_DESC="数据库端口"
        TIMEOUT=180
        ;;
    *)
        # 🎯 默认全端口扫描 - 符合红队测试需求
        FSCAN_PORTS="all"
        PORT_DESC="全端口扫描 (默认)"
        TIMEOUT=1800  # 30分钟
        ;;
esac

echo "🔍 fscan扫描配置:"
echo "   目标IP: $TARGET_IP"
echo "   端口范围: $PORT_DESC"
echo "   fscan端口参数: -p $FSCAN_PORTS"
echo "   超时时间: ${TIMEOUT}s"

# 1. 执行fscan扫描
echo ""
echo "📡 步骤1: fscan端口扫描和服务识别"
FSCAN_OUTPUT="$OUTPUT_DIR/fscan_result.txt"
FSCAN_JSON="$OUTPUT_DIR/fscan_result.json"

# fscan命令构建
fscan_cmd="$FSCAN_TOOL -hf $TARGET_FILE -p $FSCAN_PORTS -np -nobr -t $TIMEOUT -o $FSCAN_OUTPUT"
echo "执行命令: $fscan_cmd"

# 执行fscan扫描
echo "========================================" | tee -a "$SCAN_LOG"
echo "时间: $(date)" | tee -a "$SCAN_LOG" 
echo "步骤: fscan端口扫描" | tee -a "$SCAN_LOG"
echo "命令: $fscan_cmd" | tee -a "$SCAN_LOG"
echo "========================================" | tee -a "$SCAN_LOG"

if timeout 1800 $fscan_cmd; then  # 30分钟超时
    echo "✅ fscan扫描完成"
else
    echo "⚠️ fscan扫描超时或失败，继续处理结果"
fi

# 2. 处理fscan结果
echo ""
echo "📊 步骤2: 处理fscan扫描结果"

if [ -f "$FSCAN_OUTPUT" ]; then
    result_lines=$(wc -l < "$FSCAN_OUTPUT" 2>/dev/null || echo "0")
    echo "✅ fscan扫描结果: $result_lines 行记录"
    
    # 解析fscan结果生成JSON格式
    python3 -c "
import sys
import json
import re
from datetime import datetime

fscan_file = '$FSCAN_OUTPUT'
json_file = '$FSCAN_JSON'

results = {
    'target_ip': '$TARGET_IP',
    'scan_time': '$(date)',
    'scan_type': '$PORT_DESC',
    'open_ports': [],
    'services': [],
    'web_services': [],
    'vulnerabilities': [],
    'summary': {}
}

if '$FSCAN_OUTPUT' == '$FSCAN_OUTPUT':
    try:
        with open(fscan_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # 解析fscan输出
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # 端口开放信息 - 格式: 192.168.1.1:80 open
            port_match = re.match(r'($TARGET_IP):(\d+)\s+open', line)
            if port_match:
                port = int(port_match.group(2))
                port_info = {
                    'port': port,
                    'protocol': 'tcp',
                    'state': 'open',
                    'service': 'unknown'
                }
                results['open_ports'].append(port_info)
                continue
            
            # Web服务信息 - 格式: [*] http://192.168.1.1:80 [200] [title]
            web_match = re.search(r'\[.*?\]\s+(https?://$TARGET_IP:(\d+))\s+\[(\d+)\](?:\s+(.*))?', line)
            if web_match:
                url = web_match.group(1)
                port = int(web_match.group(2))
                status = web_match.group(3)
                title = web_match.group(4) if web_match.group(4) else ''
                
                web_info = {
                    'url': url,
                    'port': port,
                    'status_code': int(status),
                    'title': title.strip() if title else '',
                    'service': 'http' if url.startswith('http://') else 'https'
                }
                results['web_services'].append(web_info)
                
                # 更新对应端口的服务信息
                for port_info in results['open_ports']:
                    if port_info['port'] == port:
                        port_info['service'] = web_info['service']
                        break
                continue
            
            # 服务信息 - 格式: [*] NetInfo: 192.168.1.1:22 [ssh] OpenSSH
            service_match = re.search(r'NetInfo:\s+$TARGET_IP:(\d+)\s+\[(.*?)\](?:\s+(.*))?', line)
            if service_match:
                port = int(service_match.group(1))
                service = service_match.group(2)
                banner = service_match.group(3) if service_match.group(3) else ''
                
                service_info = {
                    'port': port,
                    'service': service,
                    'banner': banner.strip() if banner else '',
                    'protocol': 'tcp'
                }
                results['services'].append(service_info)
                
                # 更新对应端口的服务信息
                for port_info in results['open_ports']:
                    if port_info['port'] == port:
                        port_info['service'] = service
                        break
                continue
            
            # 漏洞信息
            if '[+]' in line and ('vuln' in line.lower() or 'poc' in line.lower()):
                vuln_info = {
                    'description': line,
                    'severity': 'unknown',
                    'target': '$TARGET_IP'
                }
                results['vulnerabilities'].append(vuln_info)
        
        # 生成摘要
        results['summary'] = {
            'total_open_ports': len(results['open_ports']),
            'web_services_count': len(results['web_services']),
            'vulnerabilities_count': len(results['vulnerabilities']),
            'common_services': list(set([p.get('service', 'unknown') for p in results['open_ports']]))
        }
        
        # 保存JSON结果
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f'✅ 结果解析完成，发现 {len(results[\"open_ports\"])} 个开放端口')
        print(f'📄 JSON结果保存到: {json_file}')
        
        # 输出简要结果
        if results['open_ports']:
            print('🔓 开放端口:')
            for port in results['open_ports'][:15]:  # 只显示前15个
                service = port.get('service', 'unknown')
                print(f'   {port[\"port\"]}/tcp - {service}')
            
            if len(results['open_ports']) > 15:
                print(f'   ... 还有 {len(results[\"open_ports\"]) - 15} 个端口')
        else:
            print('❌ 未发现开放端口')
        
        # 显示Web服务
        if results['web_services']:
            print(f'🌐 Web服务 ({len(results[\"web_services\"])}个):')
            for web in results['web_services'][:10]:
                title = web.get('title', '')[:50] if web.get('title') else 'No Title'
                print(f'   {web[\"url\"]} [{web[\"status_code\"]}] {title}')
        
        # 显示漏洞
        if results['vulnerabilities']:
            print(f'⚠️ 发现可能的安全问题 ({len(results[\"vulnerabilities\"])}个)')
    
    except Exception as e:
        print(f'❌ 解析fscan结果失败: {e}')
        # 创建基本的失败结果
        results = {
            'target_ip': '$TARGET_IP',
            'scan_time': '$(date)',
            'scan_type': '$PORT_DESC',
            'open_ports': [],
            'services': [],
            'error': str(e)
        }
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
"
else
    echo "❌ fscan扫描结果文件不存在"
    # 创建空结果文件
    echo '{"target_ip":"'$TARGET_IP'","scan_time":"'$(date)'","error":"No fscan results","open_ports":[],"services":[]}' > "$FSCAN_JSON"
fi

# 3. Web路径探测（如果发现了Web服务）
if [ -f "$FSCAN_JSON" ]; then
    WEB_COUNT=$(python3 -c "
import json
try:
    with open('$FSCAN_JSON', 'r') as f:
        data = json.load(f)
    print(len(data.get('web_services', [])))
except:
    print(0)
")

    if [ "$WEB_COUNT" -gt "0" ]; then
        echo ""
        echo "🌐 步骤3: Web路径探测 ($WEB_COUNT 个Web服务)"
        
        WEB_PATHS_FILE="$OUTPUT_DIR/web_paths.txt"
        
        # fscan自动进行一些Web路径探测，结果已包含在原始输出中
        # 这里可以添加额外的路径探测逻辑
        echo "ℹ️ fscan已进行基础Web探测，详细结果请查看 $FSCAN_OUTPUT"
        
        # 提取Web相关信息到单独文件
        grep -E "(http|https|title|path|dir)" "$FSCAN_OUTPUT" > "$WEB_PATHS_FILE" 2>/dev/null || echo "无Web路径信息" > "$WEB_PATHS_FILE"
        
        echo "✅ Web探测信息保存到: $WEB_PATHS_FILE"
    else
        echo "ℹ️ 未发现Web服务，跳过路径探测"
    fi
fi

# 4. 生成最终扫描报告
echo ""
echo "📋 步骤4: 生成扫描报告"
REPORT="$OUTPUT_DIR/scan_report.txt"

{
    echo "🎯 IP端口扫描报告 (基于fscan)"
    echo "=================================="
    echo "目标IP: $TARGET_IP"
    echo "扫描时间: $(date)"
    echo "扫描类型: $PORT_DESC"
    echo "工具: fscan"
    echo ""
    
    if [ -f "$FSCAN_JSON" ]; then
        python3 -c "
import json
try:
    with open('$FSCAN_JSON', 'r') as f:
        data = json.load(f)
    
    open_ports = data.get('open_ports', [])
    web_services = data.get('web_services', [])
    services = data.get('services', [])
    vulnerabilities = data.get('vulnerabilities', [])
    summary = data.get('summary', {})
    
    print('📊 扫描摘要:')
    print(f'   开放端口: {summary.get(\"total_open_ports\", 0)} 个')
    print(f'   Web服务: {summary.get(\"web_services_count\", 0)} 个')
    print(f'   检测到的服务类型: {len(set(summary.get(\"common_services\", [])))} 种')
    
    if vulnerabilities:
        print(f'   ⚠️  潜在安全问题: {len(vulnerabilities)} 个')
    
    print('')
    
    if open_ports:
        print('🔓 开放端口详情:')
        for port in open_ports:
            service = port.get('service', 'unknown')
            print(f'   {port[\"port\"]}/tcp - {service}')
    
    if web_services:
        print('')
        print('🌐 Web服务详情:')
        for web in web_services[:10]:
            title = web.get('title', 'No Title')[:50]
            print(f'   {web[\"url\"]} [{web[\"status_code\"]}] {title}')
    
    if vulnerabilities:
        print('')
        print('⚠️ 安全问题:')
        for vuln in vulnerabilities[:5]:
            print(f'   {vuln[\"description\"]}')
            
except Exception as e:
    print(f'❌ 生成报告失败: {e}')
"
    else
        echo "❌ 扫描结果文件不存在"
    fi
    
    echo ""
    echo "📁 输出文件:"
    echo "   - 扫描日志: $SCAN_LOG"
    echo "   - fscan原始结果: $FSCAN_OUTPUT"  
    echo "   - JSON格式结果: $FSCAN_JSON"
    echo "   - 扫描报告: $REPORT"
    
    if [ -f "$WEB_PATHS_FILE" ]; then
        echo "   - Web路径信息: $WEB_PATHS_FILE"
    fi
    
    echo ""
    echo "⏰ 扫描完成时间: $(date)"
    
} > "$REPORT"

echo ""
echo "✅ IP端口扫描全部完成！"
echo "📋 详细报告: $REPORT"
echo "📊 JSON结果: $FSCAN_JSON"
echo "🔧 使用工具: fscan (专业端口扫描+Web路径探测)"

# 显示报告内容
if [ -f "$REPORT" ]; then
    echo ""
    echo "📄 扫描报告预览:"
    echo "=================="
    cat "$REPORT"
fi

exit 0