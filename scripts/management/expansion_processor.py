#!/usr/bin/env python3
"""
自动化扩展处理器 (Expansion Processor)
自动读取第一次扫描的输出文件并执行相应的扩展扫描工作
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import argparse
import shutil

class ExpansionProcessor:
    def __init__(self, target_domain, project_root=".", use_test_config=False, scan_layer=2, input_dir=None):
        self.target_domain = target_domain
        self.project_root = Path(project_root)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.use_test_config = use_test_config
        self.scan_layer = scan_layer
        
        # 扫描结果路径（根据层数和输入目录）
        self.scan_output = self.project_root / "output" / target_domain
        if input_dir:
            self.tuozhan_dir = Path(input_dir)
        else:
            # 默认使用一层扫描结果
            self.tuozhan_dir = self.scan_output / "tuozhan" / "all_tuozhan"
        
        # 扩展任务输出目录 - 根据层数决定
        self.expansion_base = self.project_root / "output" / target_domain / "expansion"
        if scan_layer == 2:
            # 二层保持原有结构以兼容
            self.expansion_logs = self.expansion_base / "logs"
            self.expansion_tasks = self.expansion_base / "tasks"
            self.expansion_report = self.expansion_base / "report"
        else:
            # 三层及以上使用新结构
            layer_base = self.expansion_base / f"layer{scan_layer}"
            self.expansion_logs = layer_base / "logs"
            self.expansion_tasks = layer_base / "tasks"
            self.expansion_report = layer_base / "report"
        
        self.expansion_logs.mkdir(parents=True, exist_ok=True)
        self.expansion_tasks.mkdir(parents=True, exist_ok=True)
        self.expansion_report.mkdir(parents=True, exist_ok=True)
        
        # 去重集合
        self.processed_domains = set()
        self.processed_ips = set()
        self.processed_urls = set()
        
        print(f"[*] 初始化扩展处理器: {target_domain}")
        print(f"[*] 扫描层数: 第{scan_layer}层")
        print(f"[*] 输入目录: {self.tuozhan_dir}")
        print(f"[*] 任务目录: {self.expansion_tasks}")
        print(f"[*] 日志目录: {self.expansion_logs}")
        print(f"[*] 结果目录: {self.expansion_report}")

    def load_existing_targets(self):
        """加载已有的目标，用于去重"""
        # 读取原始扫描的域名和IP  
        domains_dir = self.project_root / "output" / self.target_domain
        
        # 原始URLs
        if (domains_dir / "urls.txt").exists():
            with open(domains_dir / "urls.txt", "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.processed_urls.add(line)
        
        # 原始IPs
        if (domains_dir / "a_records.txt").exists():
            with open(domains_dir / "a_records.txt", "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.processed_ips.add(line)
        
        print(f"[*] 加载已有目标: {len(self.processed_urls)} URLs, {len(self.processed_ips)} IPs")

    def read_expansion_files(self):
        """读取扩展文件"""
        ip_targets = []
        url_targets = []
        root_domain_targets = []
        
        # 读取 ip.txt
        ip_file = self.tuozhan_dir / "ip.txt"
        if ip_file.exists():
            current_source = None
            with open(ip_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("# 来源:"):
                        current_source = line.replace("# 来源:", "").strip()
                        continue
                    # 跳过所有注释行
                    if line.startswith("#"):
                        continue
                    # 处理IP:PORT格式，只保留IP部分
                    if ":" in line and not line.startswith("["):  # 排除IPv6格式
                        clean_ip = line.split(":")[0]
                    else:
                        clean_ip = line
                    
                    # 验证IP格式
                    try:
                        import ipaddress
                        ipaddress.ip_address(clean_ip)
                        if clean_ip not in self.processed_ips:
                            ip_targets.append((clean_ip, current_source))
                            self.processed_ips.add(clean_ip)
                    except ValueError:
                        print(f"[!] 跳过无效IP格式: {line}")
                        continue
        
        # 读取 urls.txt
        url_file = self.tuozhan_dir / "urls.txt"
        if url_file.exists():
            with open(url_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and line not in self.processed_urls:
                        url_targets.append(line)
                        self.processed_urls.add(line)
        
        # 读取 root_domains.txt
        root_file = self.tuozhan_dir / "root_domains.txt"
        if root_file.exists():
            with open(root_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and line not in self.processed_domains:
                        # 排除原始目标域名
                        if line != self.target_domain:
                            root_domain_targets.append(line)
                            self.processed_domains.add(line)
        
        print(f"[*] 发现扩展目标:")
        print(f"    - IP目标: {len(ip_targets)}")
        print(f"    - URL目标: {len(url_targets)}")
        print(f"    - 根域名目标: {len(root_domain_targets)}")
        
        return ip_targets, url_targets, root_domain_targets

    def create_ip_scan_tasks(self, ip_targets):
        """创建IP扫描任务 - fscan专用"""
        if not ip_targets:
            return
        
        ip_scan_dir = self.expansion_tasks / "ip_scans"
        ip_scan_dir.mkdir(exist_ok=True)
        
        # 按来源分组IP
        source_groups = defaultdict(list)
        for ip, source in ip_targets:
            source_name = source.split("://")[-1].split("/")[0] if source else "unknown"
            source_groups[source_name].append(ip)
        
        # 为每个来源创建任务
        task_scripts = []
        for source_name, ips in source_groups.items():
            if not ips:
                continue
            
            task_dir = ip_scan_dir / f"task_{source_name.replace('.', '_')}"
            task_dir.mkdir(exist_ok=True)
            
            # 写入IP列表
            ip_list_file = task_dir / "targets.txt"
            with open(ip_list_file, "w") as f:
                f.write(f"# IP扫描任务 - 来源: {source_name}\n")
                f.write(f"# 生成时间: {datetime.now()}\n")
                f.write(f"# 目标数量: {len(ips)}\n\n")
                for ip in ips:
                    f.write(f"{ip}\n")
            
            # 创建扫描脚本
            scan_script = task_dir / "scan_ips.sh"
            with open(scan_script, "w") as f:
                f.write(f"""#!/bin/bash
# IP扫描脚本 - 来源: {source_name}
# 生成时间: {datetime.now()}

set -e

# 设置项目根目录环境变量
export SCAN_PROJECT_ROOT="$(cd "$(dirname "$0")/../../../../../.." && pwd)"

# 创建日志目录并设置日志文件
mkdir -p "$SCAN_PROJECT_ROOT/temp/log"
mkdir -p "$SCAN_PROJECT_ROOT/output/{self.target_domain}/expansion/logs"
LOG_FILE="$SCAN_PROJECT_ROOT/output/{self.target_domain}/expansion/logs/ip_scan_log_{source_name}_$(date +%Y%m%d_%H%M%S).log"

echo "扫描开始时间: $(date)" | tee -a "$LOG_FILE"
echo "任务类型: IP端口扫描" | tee -a "$LOG_FILE"
echo "来源: {source_name}" | tee -a "$LOG_FILE"
echo "目标文件: targets.txt" | tee -a "$LOG_FILE"
echo "扫描IP数量: {len(ips)}" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# 检查工具
if [ ! -f "$SCAN_PROJECT_ROOT/tools/scanner/fscan" ]; then
    echo "❌ 错误: fscan工具不存在" | tee -a "$LOG_FILE"
    exit 1
fi

if [ ! -f "$SCAN_PROJECT_ROOT/scripts/utils/cdn_checker.py" ]; then
    echo "❌ 错误: CDN检查工具不存在" | tee -a "$LOG_FILE"
    exit 1
fi

# CDN过滤
echo "========================================" | tee -a "$LOG_FILE"
echo "时间: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$LOG_FILE"
echo "步骤: CDN过滤" | tee -a "$LOG_FILE"
echo "命令: python3 scripts/utils/cdn_checker.py --input targets.txt --output targets_filtered.txt --verbose" | tee -a "$LOG_FILE"
echo "========================================" | tee -a "$LOG_FILE"

TASK_DIR=$(pwd)
cd "$SCAN_PROJECT_ROOT"
python3 scripts/utils/cdn_checker.py --input "$TASK_DIR/targets.txt" --output "$TASK_DIR/targets_filtered.txt" --verbose 2>&1 | tee -a "$LOG_FILE"
cd - > /dev/null

# 检查过滤后结果
if [ -f targets_filtered.txt ]; then
    filtered_count=$(grep -E "^[0-9]" targets_filtered.txt | wc -l 2>/dev/null || echo "0")
    echo "CDN过滤结果: $filtered_count 个IP" | tee -a "$LOG_FILE"
else
    filtered_count=0
    echo "CDN过滤结果: 0 个IP" | tee -a "$LOG_FILE"
fi

if [ "$filtered_count" -eq 0 ]; then
    echo "[!] 警告: CDN过滤后没有剩余IP，跳过fscan扫描" | tee -a "$LOG_FILE"
    echo "[*] 任务完成时间: $(date)" | tee -a "$LOG_FILE"
    
    # 仍然保存日志
    mkdir -p "$SCAN_PROJECT_ROOT/output/{self.target_domain}/expansion/report/ip_scan_results/$(basename $(pwd))"
    cp "$LOG_FILE" "$SCAN_PROJECT_ROOT/output/{self.target_domain}/expansion/report/ip_scan_results/$(basename $(pwd))/"
    exit 0
fi

# 执行fscan扫描
echo "========================================" | tee -a "$LOG_FILE"
echo "时间: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$LOG_FILE"
echo "步骤: fscan端口扫描" | tee -a "$LOG_FILE"
echo "命令: $SCAN_PROJECT_ROOT/tools/scanner/fscan -hf targets_filtered.txt -p all -np -nobr -t 600 -o fscan_result.txt" | tee -a "$LOG_FILE"
echo "========================================" | tee -a "$LOG_FILE"

"$SCAN_PROJECT_ROOT/tools/scanner/fscan" -hf targets_filtered.txt -p all -np -nobr -t 600 -o fscan_result.txt 2>&1 | tee -a "$LOG_FILE"

# 检查扫描结果
if [ -f fscan_result.txt ]; then
    result_lines=$(wc -l < fscan_result.txt 2>/dev/null || echo "0")
    echo "fscan扫描结果: $result_lines 行记录" | tee -a "$LOG_FILE"
    
    # 检查是否有url.txt文件（fscan发现的URL）
    if [ -f fscan_url.txt ]; then
        url_count=$(wc -l < fscan_url.txt 2>/dev/null || echo "0")
        echo "fscan发现URL: $url_count 个" | tee -a "$LOG_FILE"
    fi
else
    echo "⚠️ 警告: 未生成fscan扫描结果文件" | tee -a "$LOG_FILE"
fi

# 创建统一输出目录
echo "[*] 整理扫描结果..." | tee -a "$LOG_FILE"
mkdir -p "$SCAN_PROJECT_ROOT/output/{self.target_domain}/expansion/report/ip_scan_results/$(basename $(pwd))"
cp fscan_result.txt "$SCAN_PROJECT_ROOT/output/{self.target_domain}/expansion/report/ip_scan_results/$(basename $(pwd))/" 2>/dev/null || true
cp targets_filtered.txt "$SCAN_PROJECT_ROOT/output/{self.target_domain}/expansion/report/ip_scan_results/$(basename $(pwd))/targets_used.txt" 2>/dev/null || true

# 复制fscan发现的URL文件
if [ -f fscan_url.txt ]; then
    cp fscan_url.txt "$SCAN_PROJECT_ROOT/output/{self.target_domain}/expansion/report/ip_scan_results/$(basename $(pwd))/" 2>/dev/null || true
    echo "   已保存fscan发现的URL文件" | tee -a "$LOG_FILE"
fi

cp "$LOG_FILE" "$SCAN_PROJECT_ROOT/output/{self.target_domain}/expansion/report/ip_scan_results/$(basename $(pwd))/"

echo "✅ 结果已保存到: output/{self.target_domain}/expansion/report/ip_scan_results/$(basename $(pwd))/" | tee -a "$LOG_FILE"
echo "[*] 日志文件: $LOG_FILE" | tee -a "$LOG_FILE"
echo "[*] 任务完成时间: $(date)" | tee -a "$LOG_FILE"
""")
            
            scan_script.chmod(0o755)
            task_scripts.append(scan_script)
            print(f"[+] 创建IP扫描任务: {task_dir.name} ({len(ips)} IPs)")
        
        # 创建批量执行脚本
        if task_scripts:
            batch_script = ip_scan_dir / "run_all_ip_scans.sh"
            with open(batch_script, "w") as f:
                f.write(f"""#!/bin/bash
# 批量IP扫描脚本
# 生成时间: {datetime.now()}

set -e

echo "[*] 开始批量IP扫描任务"
echo "[*] 任务数量: {len(task_scripts)}"

""")
                for script in task_scripts:
                    relative_path = script.relative_to(ip_scan_dir)
                    task_dir = relative_path.parent
                    f.write(f"""
echo "========================================"
echo "[*] 执行任务: {task_dir}"
cd {task_dir}
./scan_ips.sh
cd ..
echo "[*] 任务 {task_dir} 完成"
""")
                
                f.write(f"""
echo "========================================"
echo "[*] 所有IP扫描任务完成"
echo "[*] 完成时间: $(date)"
""")
            
            batch_script.chmod(0o755)
            print(f"[+] 创建批量IP扫描脚本: {batch_script}")

    def create_url_scan_tasks(self, url_targets):
        """创建URL扫描任务 - 直接httpx"""
        if not url_targets:
            return
        
        url_scan_dir = self.expansion_tasks / "url_scans"
        url_scan_dir.mkdir(exist_ok=True)
        
        # 写入URL列表
        url_list_file = url_scan_dir / "targets.txt"
        with open(url_list_file, "w") as f:
            f.write(f"# URL扫描任务\n")
            f.write(f"# 生成时间: {datetime.now()}\n")
            f.write(f"# 目标数量: {len(url_targets)}\n\n")
            for url in url_targets:
                # 确保URL有协议前缀
                if not url.startswith(("http://", "https://")):
                    f.write(f"https://{url}\n")
                else:
                    f.write(f"{url}\n")
        
        # 根据测试模式设置参数
        if self.use_test_config:
            httpx_params = "-l targets.txt -mc 200,301,302,403,404 -timeout 2 -favicon -hash md5,mmh3 -retries 1 -t 50 -rl 1000000 -resume -extract-fqdn -tls-grab -json -o httpx_result.json"
            mode_description = "测试模式"
        else:
            httpx_params = "-l targets.txt -mc 200,301,302,403,404 -timeout 2 -favicon -hash md5,mmh3 -retries 1 -t 300 -rl 1000000 -resume -extract-fqdn -tls-grab -json -o httpx_result.json"
            mode_description = "生产模式"

        # 创建扫描脚本
        scan_script = url_scan_dir / "scan_urls.sh"
        with open(scan_script, "w") as f:
            f.write(f"""#!/bin/bash
# URL扫描脚本
# 生成时间: {datetime.now()}
# 扫描模式: {mode_description}

set -e

# 设置项目根目录环境变量
export SCAN_PROJECT_ROOT="$(cd "$(dirname "$0")/../../../../.." && pwd)"

# 创建日志目录并设置日志文件
mkdir -p "$SCAN_PROJECT_ROOT/temp/log"
mkdir -p "$SCAN_PROJECT_ROOT/output/{self.target_domain}/expansion/logs"
LOG_FILE="$SCAN_PROJECT_ROOT/output/{self.target_domain}/expansion/logs/url_scan_log_$(date +%Y%m%d_%H%M%S).log"

echo "扫描开始时间: $(date)" | tee -a "$LOG_FILE"
echo "任务类型: URL扫描" | tee -a "$LOG_FILE"
echo "目标文件: targets.txt" | tee -a "$LOG_FILE"
echo "扫描URL数量: {len(url_targets)}" | tee -a "$LOG_FILE"
echo "扫描模式: {mode_description}" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# 检查工具
if [ ! -f "$SCAN_PROJECT_ROOT/tools/scanner/httpx" ]; then
    echo "❌ 错误: httpx工具不存在" | tee -a "$LOG_FILE"
    echo "工具路径: $SCAN_PROJECT_ROOT/tools/scanner/httpx" | tee -a "$LOG_FILE"
    ls -la "$SCAN_PROJECT_ROOT/tools/scanner/" | tee -a "$LOG_FILE"
    exit 1
fi

# 执行httpx扫描
echo "========================================" | tee -a "$LOG_FILE"
echo "时间: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$LOG_FILE"
echo "步骤: HTTP探测扫描" | tee -a "$LOG_FILE"
echo "命令: $SCAN_PROJECT_ROOT/tools/scanner/httpx {httpx_params}" | tee -a "$LOG_FILE"
echo "========================================" | tee -a "$LOG_FILE"

"$SCAN_PROJECT_ROOT/tools/scanner/httpx" {httpx_params} 2>&1 | tee -a "$LOG_FILE"

# 检查结果
if [ -f "httpx_result.json" ]; then
    result_count=$(wc -l < httpx_result.json 2>/dev/null || echo "0")
    echo "结果: $result_count 条HTTP记录" | tee -a "$LOG_FILE"
else
    echo "⚠️ 警告: 未生成HTTP扫描结果文件" | tee -a "$LOG_FILE"
fi

# 创建统一输出目录
echo "[*] 整理扫描结果..." | tee -a "$LOG_FILE"
mkdir -p "$SCAN_PROJECT_ROOT/output/{self.target_domain}/expansion/report/url_scan_results/"
cp httpx_result.json "$SCAN_PROJECT_ROOT/output/{self.target_domain}/expansion/report/url_scan_results/" 2>/dev/null || true
cp targets.txt "$SCAN_PROJECT_ROOT/output/{self.target_domain}/expansion/report/url_scan_results/targets_used.txt"
cp "$LOG_FILE" "$SCAN_PROJECT_ROOT/output/{self.target_domain}/expansion/report/url_scan_results/"

echo "✅ 结果已保存到: output/{self.target_domain}/expansion/report/url_scan_results/" | tee -a "$LOG_FILE"
echo "[*] 日志文件: $LOG_FILE" | tee -a "$LOG_FILE"
echo "[*] 任务完成时间: $(date)" | tee -a "$LOG_FILE"
""")
        
        scan_script.chmod(0o755)
        print(f"[+] 创建URL扫描任务: {url_scan_dir.name} ({len(url_targets)} URLs)")

    def create_domain_scan_tasks(self, root_domain_targets):
        """创建根域名扫描任务 - 完整流程"""
        if not root_domain_targets:
            return
        
        domain_scan_dir = self.expansion_tasks / "domain_scans"
        domain_scan_dir.mkdir(exist_ok=True)
        
        # 限制域名数量，避免资源浪费
        max_domains = 10
        if len(root_domain_targets) > max_domains:
            print(f"[!] 根域名数量过多({len(root_domain_targets)})，限制为前{max_domains}个")
            root_domain_targets = root_domain_targets[:max_domains]
        
        task_scripts = []
        
        # 为每个根域名创建完整扫描任务
        for i, domain in enumerate(root_domain_targets, 1):
            task_dir = domain_scan_dir / f"task_{i:02d}_{domain.replace('.', '_')}"
            task_dir.mkdir(exist_ok=True)
            
            # 创建目标文件
            data_input_dir = task_dir / "data" / "input"
            data_input_dir.mkdir(parents=True, exist_ok=True)
            target_file = data_input_dir / "url"
            with open(target_file, "w") as f:
                f.write(domain)
            
            # 使用环境变量SCAN_PROJECT_ROOT访问工具和脚本，不需要创建符号链接
            # 所有工具通过$SCAN_PROJECT_ROOT/tools和$SCAN_PROJECT_ROOT/scripts访问
            
            # 根据测试模式设置参数（使用环境变量指向根目录配置）
            if self.use_test_config:
                subfinder_params = "-dL data/input/url -all -t 20 -o temp/passive.txt"
                puredns_bruteforce_params = f"$SCAN_PROJECT_ROOT/config/test_subdomains.txt {domain} -r $SCAN_PROJECT_ROOT/config/resolvers.txt -q -w temp/brute.txt"
                puredns_resolve_params = "temp/domain_life -r $SCAN_PROJECT_ROOT/config/resolvers.txt --wildcard-tests 50 --wildcard-batch 1000000 -q -w temp/httpx_url"
                httpx_params = "-l temp/httpx_url -mc 200,301,302,403,404 -timeout 2 -favicon -hash md5,mmh3 -retries 1 -t 50 -rl 1000000 -resume -extract-fqdn -tls-grab -json -o temp/result_all.json"
                start_py_params = "-small -test"  # 测试模式参数
                mode_description = "测试模式"
            else:
                subfinder_params = "-dL data/input/url -all -t 200 -o temp/passive.txt"
                puredns_bruteforce_params = f"$SCAN_PROJECT_ROOT/config/subdomains.txt {domain} -r $SCAN_PROJECT_ROOT/config/resolvers.txt -q -w temp/brute.txt"
                puredns_resolve_params = "temp/domain_life -r $SCAN_PROJECT_ROOT/config/resolvers.txt --wildcard-tests 50 --wildcard-batch 1000000 -q -w temp/httpx_url"
                httpx_params = "-l temp/httpx_url -mc 200,301,302,403,404 -timeout 2 -favicon -hash md5,mmh3 -retries 1 -t 300 -rl 1000000 -resume -extract-fqdn -tls-grab -json -o temp/result_all.json"
                start_py_params = ""  # 生产模式无额外参数
                mode_description = "生产模式"
            
            # 创建扫描脚本
            scan_script = task_dir / "scan.sh"
            with open(scan_script, "w") as f:
                f.write(f"""#!/bin/bash
# 根域名完整扫描脚本: {domain}
# 生成时间: {datetime.now()}
# 扫描模式: {mode_description}

set -e

# 设置项目根目录环境变量
export SCAN_PROJECT_ROOT="$(cd "$(dirname "$0")/../../../../../.." && pwd)"

# 创建日志目录并设置日志文件
mkdir -p "$SCAN_PROJECT_ROOT/temp/log"
mkdir -p "$SCAN_PROJECT_ROOT/output/{self.target_domain}/expansion/logs"
LOG_FILE="$SCAN_PROJECT_ROOT/output/{self.target_domain}/expansion/logs/scan_log_{domain}_$(date +%Y%m%d_%H%M%S).log"

# 执行日志记录函数
log_command() {{
    local cmd="$1"
    local description="$2"
    echo "========================================" >> "$LOG_FILE"
    echo "时间: $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
    echo "步骤: $description" >> "$LOG_FILE"
    echo "命令: $cmd" >> "$LOG_FILE"
    echo "========================================" >> "$LOG_FILE"
    
    # 同时输出到控制台和日志文件
    echo "[*] $description" | tee -a "$LOG_FILE"
    echo "[*] 执行命令: $cmd" | tee -a "$LOG_FILE"
}}

# 文件结果检查函数
check_file_result() {{
    local file_path="$1"
    local step_name="$2"
    local line_count=0
    
    if [ -f "$file_path" ]; then
        line_count=$(wc -l < "$file_path" 2>/dev/null || echo "0")
    fi
    
    echo "   结果: $line_count 条记录" | tee -a "$LOG_FILE"
    
    if [ "$line_count" -eq 0 ]; then
        echo "⚠️  警告: $step_name 结果为空" | tee -a "$LOG_FILE"
        return 1
    fi
    return 0
}}

# 开始扫描
echo "扫描开始时间: $(date)" | tee -a "$LOG_FILE"
echo "目标域名: {domain}" | tee -a "$LOG_FILE"
echo "扫描模式: {mode_description}" | tee -a "$LOG_FILE"
echo "任务目录: $(pwd)" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# 创建必要目录
mkdir -p temp

# 1. 子域名收集
log_command "$SCAN_PROJECT_ROOT/tools/scanner/subfinder {subfinder_params}" "子域名被动收集({mode_description})"
"$SCAN_PROJECT_ROOT/tools/scanner/subfinder" {subfinder_params} 2>&1 | tee -a "$LOG_FILE"
check_file_result "temp/passive.txt" "子域名收集"

# 2. 子域名爆破（二层扫描跳过）
log_command "echo '⚡ 二层扫描：跳过子域名爆破，创建空文件' && touch temp/brute.txt" "子域名爆破（跳过）"
echo "⚡ 二层扫描：跳过子域名爆破，创建空文件" | tee -a "$LOG_FILE"
touch temp/brute.txt

# 3. 合并去重
log_command "cat temp/passive.txt temp/brute.txt | sort -u > temp/domain_life" "合并去重"
cat temp/passive.txt temp/brute.txt | sort -u > temp/domain_life
check_file_result "temp/domain_life" "合并去重"

# 4. 域名解析验证
log_command "$SCAN_PROJECT_ROOT/tools/scanner/puredns resolve {puredns_resolve_params}" "域名解析验证"
"$SCAN_PROJECT_ROOT/tools/scanner/puredns" resolve {puredns_resolve_params} 2>&1 | tee -a "$LOG_FILE"

# 检查puredns验证结果
if ! check_file_result "temp/httpx_url" "域名解析验证"; then
    echo "⚠️  puredns验证结果为空，使用备用方案" | tee -a "$LOG_FILE"
    echo "备用方案：直接使用domain_life文件（subfinder+爆破结果）" | tee -a "$LOG_FILE"
    cp temp/domain_life temp/httpx_url
    echo "   备用方案执行完成，继续HTTP探测" | tee -a "$LOG_FILE"
else
    echo "✅ puredns验证成功，使用验证后的域名列表" | tee -a "$LOG_FILE"
fi

# 5. HTTP探测
log_command "$SCAN_PROJECT_ROOT/tools/scanner/httpx {httpx_params}" "HTTP探测"
"$SCAN_PROJECT_ROOT/tools/scanner/httpx" {httpx_params} 2>&1 | tee -a "$LOG_FILE"
check_file_result "temp/result_all.json" "HTTP探测"

# 6. 数据处理和分析
log_command "python3 $SCAN_PROJECT_ROOT/scripts/core/start.py {start_py_params}" "数据处理和分析"
python3 "$SCAN_PROJECT_ROOT/scripts/core/start.py" {start_py_params} 2>&1 | tee -a "$LOG_FILE"

echo "扫描完成时间: $(date)" | tee -a "$LOG_FILE"
echo "[*] 扫描完成: {domain}" | tee -a "$LOG_FILE"

# 创建统一输出目录
echo "[*] 整理扫描结果..." | tee -a "$LOG_FILE"
mkdir -p "$SCAN_PROJECT_ROOT/output/{self.target_domain}/expansion/report/domain_scan_results/{domain}/"

# 复制扫描结果文件
if [ -f "temp/result_all.json" ]; then
    cp temp/result_all.json "$SCAN_PROJECT_ROOT/output/{self.target_domain}/expansion/report/domain_scan_results/{domain}/"
fi

if [ -d "output" ]; then
    cp -r output/* "$SCAN_PROJECT_ROOT/output/{self.target_domain}/expansion/report/domain_scan_results/{domain}/"
fi

# 复制日志文件
cp "$LOG_FILE" "$SCAN_PROJECT_ROOT/output/{self.target_domain}/expansion/report/domain_scan_results/{domain}/"

echo "✅ 结果已保存到: output/{self.target_domain}/expansion/report/domain_scan_results/{domain}/" | tee -a "$LOG_FILE"
echo "[*] 日志文件: $LOG_FILE" | tee -a "$LOG_FILE"
echo "[*] 完成时间: $(date)" | tee -a "$LOG_FILE"
""")
            
            scan_script.chmod(0o755)
            task_scripts.append(scan_script)
            print(f"[+] 创建域名扫描任务: {task_dir.name}")
        
        # 创建批量执行脚本
        if task_scripts:
            batch_script = domain_scan_dir / "run_all_domain_scans.sh"
            with open(batch_script, "w") as f:
                f.write(f"""#!/bin/bash
# 批量域名扫描脚本
# 生成时间: {datetime.now()}

set -e

echo "[*] 开始批量域名扫描任务"
echo "[*] 任务数量: {len(task_scripts)}"

""")
                for script in task_scripts:
                    relative_path = script.relative_to(domain_scan_dir)
                    task_dir = relative_path.parent
                    f.write(f"""
echo "========================================"
echo "[*] 执行任务: {task_dir}"
cd {task_dir}
./scan.sh
cd ..
echo "[*] 任务 {task_dir} 完成"
""")
                
                f.write(f"""
echo "========================================"
echo "[*] 所有域名扫描任务完成"
echo "[*] 完成时间: $(date)"
""")
            
            batch_script.chmod(0o755)
            print(f"[+] 创建批量域名扫描脚本: {batch_script}")

    def create_master_script(self):
        """创建主控脚本"""
        master_script = self.expansion_tasks / "run_all_expansions.sh"
        with open(master_script, "w") as f:
            f.write(f"""#!/bin/bash
# 主控扩展扫描脚本
# 目标域名: {self.target_domain}
# 生成时间: {datetime.now()}

set -e

echo "[*] 开始扩展扫描任务: {self.target_domain}"
echo "[*] 工作目录: $(pwd)"

# 1. 执行IP扫描
if [ -d "ip_scans" ]; then
    echo "[*] 执行IP扫描任务..."
    cd ip_scans
    if [ -f "run_all_ip_scans.sh" ]; then
        ./run_all_ip_scans.sh
    fi
    cd ..
fi

# 2. 执行URL扫描
if [ -d "url_scans" ]; then
    echo "[*] 执行URL扫描任务..."
    cd url_scans
    if [ -f "scan_urls.sh" ]; then
        ./scan_urls.sh
    fi
    cd ..
fi

# 3. 执行域名扫描
if [ -d "domain_scans" ]; then
    echo "[*] 执行域名扫描任务..."
    cd domain_scans
    if [ -f "run_all_domain_scans.sh" ]; then
        ./run_all_domain_scans.sh
    fi
    cd ..
fi

echo "[*] 所有扩展扫描任务完成"
echo "[*] 完成时间: $(date)"
""")
        
        master_script.chmod(0o755)
        print(f"[+] 创建主控脚本: {master_script}")

    def generate_summary(self, ip_targets, url_targets, root_domain_targets):
        """生成扩展任务摘要"""
        summary_file = self.expansion_tasks / "expansion_summary.txt"
        with open(summary_file, "w") as f:
            f.write(f"""扩展扫描任务摘要
====================================

目标域名: {self.target_domain}
生成时间: {datetime.now()}
任务目录: {self.expansion_tasks}

扩展目标统计:
- IP目标: {len(ip_targets)} 个
- URL目标: {len(url_targets)} 个  
- 根域名目标: {len(root_domain_targets)} 个

任务类型说明:
1. IP扫描 (ip_scans/):
   - 工具: fscan
   - 用途: 端口扫描和服务发现
   - 执行: cd ip_scans && ./run_all_ip_scans.sh

2. URL扫描 (url_scans/):
   - 工具: httpx
   - 用途: 子域名HTTP探测
   - 执行: cd url_scans && ./scan_urls.sh

3. 域名扫描 (domain_scans/):
   - 工具: subfinder + httpx + start.py
   - 用途: 完整域名扫描流程
   - 执行: cd domain_scans && ./run_all_domain_scans.sh

快速执行:
./run_all_expansions.sh

注意事项:
- 所有任务都已去重，不会与原始扫描重复
- IP扫描已按来源分组，便于溯源
- 域名扫描限制数量避免资源浪费
- 建议根据资源情况分批执行
""")
        
        print(f"[+] 生成任务摘要: {summary_file}")

    def process(self):
        """主处理流程"""
        print(f"\n[*] 开始处理扩展任务...")
        
        # 检查输入文件
        if not self.tuozhan_dir.exists():
            print(f"❌ 错误: 扩展目录不存在 {self.tuozhan_dir}")
            return False
        
        # 加载已有目标
        self.load_existing_targets()
        
        # 读取扩展文件
        ip_targets, url_targets, root_domain_targets = self.read_expansion_files()
        
        if not any([ip_targets, url_targets, root_domain_targets]):
            print("[!] 没有发现新的扩展目标")
            return False
        
        # 创建各类扫描任务
        self.create_ip_scan_tasks(ip_targets)
        self.create_url_scan_tasks(url_targets)
        self.create_domain_scan_tasks(root_domain_targets)
        
        # 创建主控脚本
        self.create_master_script()
        
        # 生成摘要
        self.generate_summary(ip_targets, url_targets, root_domain_targets)
        
        print(f"\n[✓] 扩展任务生成完成!")
        
        # 如果不是二层，合并当前层的所有扫描结果
        if self.scan_layer != 2:
            self.merge_layer_results()
        
        return True
    
    def merge_layer_results(self):
        """合并当前层的所有扫描结果，为下一层准备"""
        print(f"\n[*] 合并第{self.scan_layer}层扫描结果...")
        
        # 创建合并目标目录
        if self.scan_layer == 2:
            merged_dir = self.expansion_base / "layer2" / "merged_targets"
        else:
            merged_dir = self.expansion_base / f"layer{self.scan_layer}" / "merged_targets"
        
        merged_dir.mkdir(parents=True, exist_ok=True)
        
        # 收集所有扫描结果
        all_ips = set()
        all_urls = set()
        all_domains = set()
        
        # 遍历当前层的所有扫描结果
        for result_dir in self.expansion_report.iterdir():
            if result_dir.is_dir():
                # 查找tuozhan/all_tuozhan目录
                tuozhan_path = result_dir / "tuozhan" / "all_tuozhan"
                if tuozhan_path.exists():
                    # 读取IP
                    ip_file = tuozhan_path / "ip.txt"
                    if ip_file.exists():
                        with open(ip_file, 'r') as f:
                            for line in f:
                                line = line.strip()
                                if line and not line.startswith('#'):
                                    all_ips.add(line)
                    
                    # 读取URL
                    url_file = tuozhan_path / "urls.txt"
                    if url_file.exists():
                        with open(url_file, 'r') as f:
                            for line in f:
                                line = line.strip()
                                if line and not line.startswith('#'):
                                    all_urls.add(line)
                    
                    # 读取域名
                    domain_file = tuozhan_path / "root_domains.txt"
                    if domain_file.exists():
                        with open(domain_file, 'r') as f:
                            for line in f:
                                line = line.strip()
                                if line and not line.startswith('#'):
                                    all_domains.add(line)
        
        # 写入合并结果
        with open(merged_dir / "ip.txt", 'w') as f:
            if all_ips:
                f.write(f"# 第{self.scan_layer}层扫描合并IP目标\n")
                for ip in sorted(all_ips):
                    f.write(f"{ip}\n")
            else:
                f.write("# 暂无IP目标\n")
        
        with open(merged_dir / "urls.txt", 'w') as f:
            if all_urls:
                f.write(f"# 第{self.scan_layer}层扫描合并URL目标\n")
                for url in sorted(all_urls):
                    f.write(f"{url}\n")
            else:
                f.write("# 暂无URL目标\n")
        
        with open(merged_dir / "root_domains.txt", 'w') as f:
            if all_domains:
                f.write(f"# 第{self.scan_layer}层扫描合并域名目标\n")
                for domain in sorted(all_domains):
                    f.write(f"{domain}\n")
            else:
                f.write("# 暂无域名目标\n")
        
        print(f"[✓] 合并完成:")
        print(f"   - IP目标: {len(all_ips)} 个")
        print(f"   - URL目标: {len(all_urls)} 个")
        print(f"   - 域名目标: {len(all_domains)} 个")
        print(f"   - 结果目录: {merged_dir}")
        print(f"[✓] 任务目录: {self.expansion_tasks}")
        print(f"[✓] 执行命令: cd {self.expansion_tasks} && ./run_all_expansions.sh")
        
        return True

def auto_discover_targets(project_root):
    """自动发现需要处理的目标域名"""
    output_dir = Path(project_root) / "output"
    
    if not output_dir.exists():
        print(f"[!] 输出目录不存在: {output_dir}")
        return []
    
    targets = []
    for target_dir in output_dir.iterdir():
        if target_dir.is_dir() and not target_dir.name == "expansions":
            tuozhan_dir = target_dir / "tuozhan" / "all_tuozhan"
            if tuozhan_dir.exists():
                # 检查是否有扩展文件
                has_files = any([
                    (tuozhan_dir / "ip.txt").exists(),
                    (tuozhan_dir / "urls.txt").exists(), 
                    (tuozhan_dir / "root_domains.txt").exists()
                ])
                if has_files:
                    targets.append(target_dir.name)
    
    return targets

def main():
    parser = argparse.ArgumentParser(description="自动化扩展处理器")
    parser.add_argument("target_domain", nargs="?", help="目标域名（可选，不提供则自动处理所有目标）")
    parser.add_argument("--project-root", default=".", help="项目根目录")
    parser.add_argument("--batch", action="store_true", help="批量模式，处理所有目标")
    parser.add_argument("--test", action="store_true", help="使用测试配置")
    parser.add_argument("--layer", type=int, default=2, help="扫描层数（默认为2）")
    parser.add_argument("--input-dir", help="输入目录（默认根据层数自动确定）")
    
    args = parser.parse_args()
    
    if args.target_domain:
        # 处理单个目标
        processor = ExpansionProcessor(args.target_domain, args.project_root, args.test, args.layer, args.input_dir)
        success = processor.process()
        sys.exit(0 if success else 1)
    else:
        # 自动发现并处理所有目标
        targets = auto_discover_targets(args.project_root)
        
        if not targets:
            print("[!] 没有发现可处理的目标")
            print("[!] 请先运行主扫描生成扩展数据")
            sys.exit(1)
        
        print(f"[*] 发现 {len(targets)} 个可处理的目标:")
        for i, target in enumerate(targets, 1):
            print(f"    {i}. {target}")
        
        print()
        success_count = 0
        failed_targets = []
        
        for target in targets:
            print(f"\\n{'='*50}")
            print(f"[*] 处理目标: {target}")
            print(f"{'='*50}")
            
            try:
                processor = ExpansionProcessor(target, args.project_root, args.test)
                if processor.process():
                    success_count += 1
                    print(f"[✓] 目标 {target} 处理成功")
                else:
                    failed_targets.append(target)
                    print(f"[✗] 目标 {target} 处理失败")
            except Exception as e:
                failed_targets.append(target)
                print(f"[✗] 目标 {target} 处理异常: {e}")
        
        print(f"\\n{'='*50}")
        print(f"[*] 批量处理完成")
        print(f"[*] 成功: {success_count}/{len(targets)}")
        if failed_targets:
            print(f"[*] 失败目标: {', '.join(failed_targets)}")
        print(f"{'='*50}")
        
        sys.exit(0 if success_count > 0 else 1)

if __name__ == "__main__":
    main()