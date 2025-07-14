#!/usr/bin/env python3
"""
扩展扫描管理器 (Tuozhan Manager)
用于管理和组织扩展扫描结果的结构化工具
"""

import os
import sys
import json
import shutil
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import argparse

class TuozhanManager:
    def __init__(self, base_path=".", target_domain=None):
        self.base_path = Path(base_path)
        self.target_domain = target_domain
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
    def discover_tuozhan_results(self):
        """发现所有tuozhan扩展结果"""
        tuozhan_results = []
        reports_path = self.base_path / "output" / "reports" / "scan"
        
        if not reports_path.exists():
            print("[!] 未找到reports/scan目录")
            return tuozhan_results
            
        for domain_dir in reports_path.iterdir():
            if domain_dir.is_dir():
                tuozhan_dir = domain_dir / "tuozhan" / "all_tuozhan"
                if tuozhan_dir.exists():
                    urls_file = tuozhan_dir / "urls.txt"
                    if urls_file.exists():
                        tuozhan_results.append({
                            'domain': domain_dir.name,
                            'path': tuozhan_dir,
                            'urls_file': urls_file,
                            'size': self._count_urls(urls_file)
                        })
        
        return tuozhan_results
    
    def _count_urls(self, file_path):
        """计算URL文件中的有效URL数量"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                count = 0
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        count += 1
                return count
        except Exception:
            return 0
    
    def create_generation_structure(self, source_domain):
        """创建分代扫描目录结构"""
        gen_base = self.base_path / "generations"
        gen_base.mkdir(exist_ok=True)
        
        # 创建源域名目录
        source_dir = gen_base / source_domain
        source_dir.mkdir(exist_ok=True)
        
        # 查找已有的代数
        existing_gens = [d.name for d in source_dir.iterdir() if d.is_dir() and d.name.startswith('gen_')]
        next_gen = len(existing_gens) + 1
        
        # 创建新代目录
        gen_dir = source_dir / f"gen_{next_gen:02d}_{self.timestamp}"
        gen_dir.mkdir(exist_ok=True)
        
        return gen_dir, next_gen
    
    def prepare_tuozhan_scan(self, source_domain, output_dir=None):
        """准备tuozhan域名的新一轮扫描"""
        print(f"🔍 为 {source_domain} 准备扩展扫描...")
        
        # 查找tuozhan结果
        tuozhan_results = self.discover_tuozhan_results()
        source_result = None
        
        for result in tuozhan_results:
            if result['domain'] == source_domain:
                source_result = result
                break
        
        if not source_result:
            print(f"[!] 未找到 {source_domain} 的tuozhan结果")
            return None
        
        print(f"[+] 发现 {source_result['size']} 个扩展URL")
        
        # 创建分代目录
        if output_dir is None:
            gen_dir, gen_num = self.create_generation_structure(source_domain)
        else:
            gen_dir = Path(output_dir)
            gen_dir.mkdir(parents=True, exist_ok=True)
            gen_num = 1
        
        # 解析并分类tuozhan结果
        categorized_domains = self._parse_tuozhan_urls(source_result['urls_file'])
        
        # 创建扫描结构
        scan_structure = self._create_scan_structure(gen_dir, categorized_domains, source_domain, gen_num)
        
        print(f"✅ 扫描结构创建完成: {gen_dir}")
        return scan_structure
    
    def _parse_tuozhan_urls(self, urls_file):
        """解析tuozhan URL文件，按来源分类"""
        categorized = defaultdict(list)
        current_source = "unknown"
        
        with open(urls_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                if line.startswith('# 来源:'):
                    current_source = line.replace('# 来源:', '').strip()
                    if not current_source:
                        current_source = "unknown"
                elif not line.startswith('#'):
                    # 清理URL/域名
                    domain = self._clean_domain(line)
                    if domain:
                        categorized[current_source].append(domain)
        
        return categorized
    
    def _clean_domain(self, line):
        """清理域名/URL"""
        line = line.strip()
        if not line:
            return None
        
        # 移除协议
        if line.startswith(('http://', 'https://')):
            from urllib.parse import urlparse
            parsed = urlparse(line)
            line = parsed.hostname or line
        
        # 基本验证
        if '.' in line and len(line) > 3:
            return line.lower()
        
        return None
    
    def _create_scan_structure(self, gen_dir, categorized_domains, source_domain, gen_num):
        """创建扫描目录结构"""
        structure = {
            'base_dir': gen_dir,
            'source_domain': source_domain,
            'generation': gen_num,
            'timestamp': self.timestamp,
            'scan_groups': {}
        }
        
        # 创建主要目录
        (gen_dir / "targets").mkdir(exist_ok=True)
        (gen_dir / "scripts").mkdir(exist_ok=True)
        (gen_dir / "results").mkdir(exist_ok=True)
        (gen_dir / "logs").mkdir(exist_ok=True)
        
        # 为每个来源创建目标文件
        total_domains = 0
        for source, domains in categorized_domains.items():
            if not domains:
                continue
            
            # 清理来源名称作为文件名
            safe_source = self._safe_filename(source)
            target_file = gen_dir / "targets" / f"{safe_source}.txt"
            
            with open(target_file, 'w', encoding='utf-8') as f:
                f.write(f"# 来源: {source}\n")
                f.write(f"# 域名数量: {len(domains)}\n")
                f.write(f"# 生成时间: {datetime.now().isoformat()}\n\n")
                
                for domain in sorted(set(domains)):
                    f.write(f"{domain}\n")
            
            structure['scan_groups'][safe_source] = {
                'source': source,
                'target_file': target_file,
                'domain_count': len(domains),
                'domains': domains
            }
            total_domains += len(domains)
        
        # 创建合并的目标文件
        all_targets_file = gen_dir / "targets" / "all_domains.txt"
        with open(all_targets_file, 'w', encoding='utf-8') as f:
            f.write(f"# 所有扩展域名 - 来源: {source_domain}\n")
            f.write(f"# 总域名数量: {total_domains}\n")
            f.write(f"# 生成时间: {datetime.now().isoformat()}\n\n")
            
            all_domains = set()
            for group in structure['scan_groups'].values():
                all_domains.update(group['domains'])
            
            for domain in sorted(all_domains):
                f.write(f"{domain}\n")
        
        structure['all_targets_file'] = all_targets_file
        structure['total_domains'] = total_domains
        
        # 创建扫描脚本
        self._create_scan_scripts(gen_dir, structure)
        
        # 创建README
        self._create_readme(gen_dir, structure)
        
        return structure
    
    def _safe_filename(self, name):
        """创建安全的文件名"""
        import re
        # 只保留字母数字和基本符号
        safe = re.sub(r'[^\w\-_.]', '_', name)
        return safe[:50]  # 限制长度
    
    def _create_scan_scripts(self, gen_dir, structure):
        """创建扫描脚本"""
        scripts_dir = gen_dir / "scripts"
        
        # 创建主扫描脚本
        main_script = scripts_dir / "scan_all.sh"
        with open(main_script, 'w', encoding='utf-8') as f:
            f.write(f"""#!/bin/bash
# 扩展域名扫描脚本
# 来源: {structure['source_domain']}
# 第 {structure['generation']} 代扫描
# 生成时间: {structure['timestamp']}

set -e

BASE_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")/.." && pwd)"
TARGETS_DIR="$BASE_DIR/targets"
RESULTS_DIR="$BASE_DIR/results"
LOGS_DIR="$BASE_DIR/logs"

echo "🚀 开始第 {structure['generation']} 代扩展域名扫描..."
echo "📁 基础目录: $BASE_DIR"
echo "🎯 总域名数: {structure['total_domains']}"

# 创建时间戳目录
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
SCAN_RESULT_DIR="$RESULTS_DIR/scan_$TIMESTAMP"
mkdir -p "$SCAN_RESULT_DIR"

# 扫描所有域名
echo "📋 使用目标文件: $TARGETS_DIR/all_domains.txt"

# 检查主扫描工具路径
SCAN_TOOLS_DIR="{self.base_path.absolute()}"
if [ ! -f "$SCAN_TOOLS_DIR/go.sh" ]; then
    echo "❌ 错误: 未找到主扫描脚本 $SCAN_TOOLS_DIR/go.sh"
    exit 1
fi

# 备份当前url文件
if [ -f "$SCAN_TOOLS_DIR/url" ]; then
    cp "$SCAN_TOOLS_DIR/url" "$SCAN_TOOLS_DIR/url.backup.$(date +%s)"
fi

# 逐个扫描每个来源组
""")
            
            for group_name, group_info in structure['scan_groups'].items():
                f.write(f"""
echo "🔍 扫描组: {group_info['source']} ({group_info['domain_count']} 个域名)"
GROUP_RESULT_DIR="$SCAN_RESULT_DIR/{group_name}"
mkdir -p "$GROUP_RESULT_DIR"

# 逐个域名扫描
while IFS= read -r domain || [ -n "$domain" ]; do
    # 跳过注释行和空行
    [[ "$domain" =~ ^#.*$ ]] && continue
    [[ -z "$domain" ]] && continue
    
    echo "⚡ 扫描域名: $domain"
    
    # 设置目标域名
    echo "$domain" > "$SCAN_TOOLS_DIR/url"
    
    # 执行扫描
    cd "$SCAN_TOOLS_DIR"
    timeout 1800 ./go.sh > "$LOGS_DIR/{group_name}_${{domain}}_scan.log" 2>&1 || {{
        echo "⚠️  域名 $domain 扫描超时或失败"
        continue
    }}
    
    # 移动结果
    if [ -d "reports" ]; then
        mv reports/* "$GROUP_RESULT_DIR/" 2>/dev/null || true
    fi
    if [ -d "domains" ]; then
        mv domains/* "$GROUP_RESULT_DIR/" 2>/dev/null || true
    fi
    
    echo "✅ 域名 $domain 扫描完成"
    sleep 5  # 避免过于频繁的请求
    
done < "$TARGETS_DIR/{group_name}.txt"
""")
            
            f.write(f"""
# 恢复原始url文件
if [ -f "$SCAN_TOOLS_DIR/url.backup."* ]; then
    latest_backup=$(ls -t "$SCAN_TOOLS_DIR/url.backup."* | head -1)
    mv "$latest_backup" "$SCAN_TOOLS_DIR/url"
fi

echo "🎉 第 {structure['generation']} 代扫描完成！"
echo "📊 结果目录: $SCAN_RESULT_DIR"
echo "📋 日志目录: $LOGS_DIR"

# 生成扫描报告
python3 "$SCAN_TOOLS_DIR/tuozhan_manager.py" report "$BASE_DIR" > "$SCAN_RESULT_DIR/scan_summary.txt"
""")
        
        # 设置执行权限
        main_script.chmod(0o755)
        
        # 创建单独的组扫描脚本
        for group_name, group_info in structure['scan_groups'].items():
            group_script = scripts_dir / f"scan_{group_name}.sh"
            with open(group_script, 'w', encoding='utf-8') as f:
                f.write(f"""#!/bin/bash
# 扫描组: {group_info['source']}
# 域名数量: {group_info['domain_count']}

BASE_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")/.." && pwd)"
SCAN_TOOLS_DIR="{self.base_path.absolute()}"

echo "🔍 扫描组: {group_info['source']}"
echo "🎯 域名数量: {group_info['domain_count']}"

# 执行扫描
cd "$SCAN_TOOLS_DIR"
while IFS= read -r domain || [ -n "$domain" ]; do
    [[ "$domain" =~ ^#.*$ ]] && continue
    [[ -z "$domain" ]] && continue
    
    echo "⚡ 扫描: $domain"
    echo "$domain" > url
    timeout 1800 ./go.sh
    sleep 5
done < "$BASE_DIR/targets/{group_name}.txt"
""")
            group_script.chmod(0o755)
    
    def _create_readme(self, gen_dir, structure):
        """创建README文档"""
        readme_file = gen_dir / "README.md"
        with open(readme_file, 'w', encoding='utf-8') as f:
            f.write(f"""# 第 {structure['generation']} 代扩展扫描

## 基本信息
- **源域名**: {structure['source_domain']}
- **生成时间**: {datetime.now().isoformat()}
- **总域名数**: {structure['total_domains']}
- **扫描组数**: {len(structure['scan_groups'])}

## 目录结构
```
{gen_dir.name}/
├── targets/           # 扫描目标文件
├── scripts/           # 扫描脚本
├── results/           # 扫描结果
├── logs/             # 扫描日志
└── README.md         # 说明文档
```

## 扫描组详情
""")
            
            for group_name, group_info in structure['scan_groups'].items():
                f.write(f"""
### {group_info['source']}
- **文件**: `targets/{group_name}.txt`
- **域名数**: {group_info['domain_count']}
- **脚本**: `scripts/scan_{group_name}.sh`
""")
            
            f.write(f"""
## 使用方法

### 1. 扫描所有组
```bash
cd {gen_dir}
./scripts/scan_all.sh
```

### 2. 扫描特定组
```bash
cd {gen_dir}
./scripts/scan_[组名].sh
```

### 3. 手动扫描
```bash
# 切换到主扫描目录
cd {self.base_path.absolute()}

# 设置目标域名
echo "target-domain.com" > url

# 执行扫描
./go.sh
```

## 注意事项
1. 扫描前确保主扫描工具已正确安装
2. 扫描过程可能较长，建议使用 `screen` 或 `tmux`
3. 结果将保存在 `results/` 目录中
4. 日志文件在 `logs/` 目录中

## 扫描状态追踪
- 使用 `tail -f logs/*.log` 查看实时日志
- 检查 `results/` 目录查看已完成的扫描
""")
    
    def generate_report(self, scan_dir):
        """生成扫描报告"""
        scan_path = Path(scan_dir)
        if not scan_path.exists():
            print(f"[!] 扫描目录不存在: {scan_dir}")
            return
        
        print(f"# 扫描报告")
        print(f"**目录**: {scan_path.absolute()}")
        print(f"**生成时间**: {datetime.now().isoformat()}")
        print()
        
        # 统计目标文件
        targets_dir = scan_path / "targets"
        if targets_dir.exists():
            print("## 目标统计")
            for target_file in targets_dir.glob("*.txt"):
                count = self._count_urls(target_file)
                print(f"- **{target_file.stem}**: {count} 个域名")
            print()
        
        # 统计结果
        results_dir = scan_path / "results"
        if results_dir.exists():
            print("## 扫描结果")
            for result_dir in results_dir.iterdir():
                if result_dir.is_dir():
                    file_count = len(list(result_dir.rglob("*")))
                    print(f"- **{result_dir.name}**: {file_count} 个文件")
            print()
        
        # 统计日志
        logs_dir = scan_path / "logs"
        if logs_dir.exists():
            print("## 日志文件")
            for log_file in logs_dir.glob("*.log"):
                size = log_file.stat().st_size
                print(f"- **{log_file.name}**: {size} bytes")

def main():
    parser = argparse.ArgumentParser(description="Tuozhan扫描管理器")
    parser.add_argument("command", choices=["discover", "prepare", "report"], 
                       help="命令: discover(发现), prepare(准备), report(报告)")
    parser.add_argument("target", nargs="?", help="目标域名或目录")
    parser.add_argument("--output", "-o", help="输出目录")
    parser.add_argument("--base", "-b", default=".", help="基础目录")
    
    args = parser.parse_args()
    
    manager = TuozhanManager(base_path=args.base)
    
    if args.command == "discover":
        results = manager.discover_tuozhan_results()
        if results:
            print("🔍 发现的Tuozhan结果:")
            for result in results:
                print(f"  📂 {result['domain']}: {result['size']} 个URL")
        else:
            print("❌ 未发现任何Tuozhan结果")
    
    elif args.command == "prepare":
        if not args.target:
            print("❌ 请指定目标域名")
            sys.exit(1)
        
        structure = manager.prepare_tuozhan_scan(args.target, args.output)
        if structure:
            print(f"✅ 扫描结构已创建: {structure['base_dir']}")
            print(f"📊 总域名数: {structure['total_domains']}")
            print(f"🗂️  扫描组数: {len(structure['scan_groups'])}")
        else:
            print("❌ 准备失败")
            sys.exit(1)
    
    elif args.command == "report":
        if not args.target:
            print("❌ 请指定扫描目录")
            sys.exit(1)
        
        manager.generate_report(args.target)

if __name__ == "__main__":
    main()