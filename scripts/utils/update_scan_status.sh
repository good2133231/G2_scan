#!/bin/bash
# 扫描状态更新脚本

DOMAIN=$1
STAGE=$2
STATUS=$3
PROGRESS=${4:-0}
DETAILS=${5:-""}

# 检查参数
if [ -z "$DOMAIN" ] || [ -z "$STAGE" ] || [ -z "$STATUS" ]; then
    echo "Usage: $0 <domain> <stage> <status> [progress] [details]"
    echo "Stages: subdomain_discovery, http_probe, port_scan, vulnerability_scan, expand_scan, report_generation"
    echo "Status: pending, in_progress, completed, failed"
    exit 1
fi

# 状态文件路径
STATUS_FILE="output/$DOMAIN/scanning_status.json"
mkdir -p "output/$DOMAIN"

# 当前时间
CURRENT_TIME=$(date '+%Y-%m-%d %H:%M:%S')

# 如果状态文件不存在，创建初始状态
if [ ! -f "$STATUS_FILE" ]; then
    cat > "$STATUS_FILE" << EOF
{
  "domain": "$DOMAIN",
  "start_time": "$CURRENT_TIME",
  "current_stage": "$STAGE",
  "progress": 0,
  "scan_stages": {
    "subdomain_discovery": {"status": "pending"},
    "http_probe": {"status": "pending"},
    "port_scan": {"status": "pending"},
    "vulnerability_scan": {"status": "pending"},
    "expand_scan": {"status": "pending"},
    "report_generation": {"status": "pending"}
  },
  "errors": [],
  "last_update": "$CURRENT_TIME"
}
EOF
fi

# 使用Python更新状态
python3 -c "
import json
import sys
from datetime import datetime

status_file = '$STATUS_FILE'
stage = '$STAGE'
status = '$STATUS'
progress = $PROGRESS
details = '$DETAILS'

# 读取现有状态
with open(status_file, 'r') as f:
    data = json.load(f)

# 更新阶段状态
if stage not in data['scan_stages']:
    data['scan_stages'][stage] = {}

data['scan_stages'][stage]['status'] = status

if status == 'in_progress':
    if 'start_time' not in data['scan_stages'][stage]:
        data['scan_stages'][stage]['start_time'] = '$CURRENT_TIME'
    data['scan_stages'][stage]['progress'] = progress
    data['current_stage'] = stage
elif status == 'completed':
    data['scan_stages'][stage]['end_time'] = '$CURRENT_TIME'
    if 'start_time' not in data['scan_stages'][stage]:
        data['scan_stages'][stage]['start_time'] = '$CURRENT_TIME'
elif status == 'failed':
    data['scan_stages'][stage]['end_time'] = '$CURRENT_TIME'
    data['scan_stages'][stage]['error'] = details
    data['errors'].append(f'{stage}: {details}')

# 更新详情
if details:
    data['scan_stages'][stage]['details'] = details

# 计算总进度和更新当前阶段
stage_weights = {
    'subdomain_discovery': 20,
    'http_probe': 20,
    'vulnerability_scan': 20,
    'port_scan': 20,
    'expand_scan': 15,
    'report_generation': 5
}

# 阶段执行顺序（按实际流程）
stage_order = ['subdomain_discovery', 'http_probe', 'vulnerability_scan', 'port_scan', 'expand_scan', 'report_generation']

total_progress = 0
current_stage_found = None

for s, w in stage_weights.items():
    if s in data['scan_stages']:
        if data['scan_stages'][s]['status'] == 'completed':
            total_progress += w
        elif data['scan_stages'][s]['status'] == 'in_progress' and 'progress' in data['scan_stages'][s]:
            total_progress += w * data['scan_stages'][s]['progress'] / 100
            current_stage_found = s

# 如果没有正在进行的阶段，找到下一个待执行的阶段
if not current_stage_found:
    for stage_name in stage_order:
        if stage_name in data['scan_stages'] and data['scan_stages'][stage_name]['status'] == 'pending':
            current_stage_found = stage_name
            break

# 更新当前阶段
if current_stage_found:
    data['current_stage'] = current_stage_found

data['progress'] = int(total_progress)
data['last_update'] = '$CURRENT_TIME'

# 如果所有阶段完成，标记扫描完成
all_completed = all(
    data['scan_stages'].get(s, {}).get('status') == 'completed' 
    for s in stage_weights.keys()
)
if all_completed:
    data['scan_completed'] = True
    data['end_time'] = '$CURRENT_TIME'

# 保存更新后的状态
with open(status_file, 'w') as f:
    json.dump(data, f, indent=2, ensure_ascii=False)

# 如果扫描完成，创建finish.txt文件以确保向后兼容
if all_completed:
    finish_file = f'output/{domain}/finish.txt'
    with open(finish_file, 'w') as f:
        f.write(f'扫描完成时间: {data.get(\"end_time\", \"$CURRENT_TIME\")}\\n')

print(f'状态更新成功: {stage} -> {status} ({progress}%)')
"

# 如果是特定阶段开始，输出提示
case "$STAGE" in
    "subdomain_discovery")
        [ "$STATUS" = "in_progress" ] && echo "[*] 开始子域名发现..."
        ;;
    "http_probe")
        [ "$STATUS" = "in_progress" ] && echo "[*] 开始HTTP服务探测..."
        ;;
    "port_scan")
        [ "$STATUS" = "in_progress" ] && echo "[*] 开始端口扫描..."
        ;;
    "vulnerability_scan")
        [ "$STATUS" = "in_progress" ] && echo "[*] 开始漏洞扫描..."
        ;;
    "expand_scan")
        [ "$STATUS" = "in_progress" ] && echo "[*] 开始扩展资产扫描..."
        ;;
    "report_generation")
        [ "$STATUS" = "in_progress" ] && echo "[*] 开始生成报告..."
        ;;
esac

exit 0