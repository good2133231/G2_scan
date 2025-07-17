#!/usr/bin/env python3
"""
合并当前层的扫描结果，为下一层准备
"""

import os
import sys
import argparse
from pathlib import Path
from collections import defaultdict

def merge_layer_results(target_domain, layer, project_root="."):
    """合并指定层的所有扫描结果"""
    print(f"\n[*] 合并第{layer}层扫描结果...")
    
    project_root = Path(project_root)
    expansion_base = project_root / "output" / target_domain / "expansion"
    
    # 确定报告目录和合并目录
    if layer == 2:
        report_dir = expansion_base / "report"
        merged_dir = expansion_base / "layer2" / "merged_targets"
    else:
        report_dir = expansion_base / f"layer{layer}" / "report"
        merged_dir = expansion_base / f"layer{layer}" / "merged_targets"
    
    merged_dir.mkdir(parents=True, exist_ok=True)
    
    # 收集所有扫描结果
    all_ips = set()
    all_urls = set()
    all_domains = set()
    
    # 遍历报告目录下的所有子目录
    if report_dir.exists():
        for subdir in report_dir.iterdir():
            if subdir.is_dir():
                # 域名扫描结果
                if (subdir / "domain_scan_results").exists():
                    for domain_dir in (subdir / "domain_scan_results").iterdir():
                        if domain_dir.is_dir():
                            tuozhan_path = domain_dir / domain_dir.name / "tuozhan" / "all_tuozhan"
                            if tuozhan_path.exists():
                                collect_from_dir(tuozhan_path, all_ips, all_urls, all_domains)
                
                # 直接在report下的域名目录
                else:
                    for domain_dir in subdir.iterdir():
                        if domain_dir.is_dir():
                            tuozhan_path = domain_dir / "tuozhan" / "all_tuozhan"
                            if tuozhan_path.exists():
                                collect_from_dir(tuozhan_path, all_ips, all_urls, all_domains)
    
    # 写入合并结果
    with open(merged_dir / "ip.txt", 'w') as f:
        if all_ips:
            f.write(f"# 第{layer}层扫描合并IP目标\n")
            for ip in sorted(all_ips):
                f.write(f"{ip}\n")
        else:
            f.write("# 暂无IP目标\n")
    
    with open(merged_dir / "urls.txt", 'w') as f:
        if all_urls:
            f.write(f"# 第{layer}层扫描合并URL目标\n")
            for url in sorted(all_urls):
                f.write(f"{url}\n")
        else:
            f.write("# 暂无URL目标\n")
    
    with open(merged_dir / "root_domains.txt", 'w') as f:
        if all_domains:
            f.write(f"# 第{layer}层扫描合并域名目标\n")
            for domain in sorted(all_domains):
                f.write(f"{domain}\n")
        else:
            f.write("# 暂无域名目标\n")
    
    print(f"[✓] 合并完成:")
    print(f"   - IP目标: {len(all_ips)} 个")
    print(f"   - URL目标: {len(all_urls)} 个")
    print(f"   - 域名目标: {len(all_domains)} 个")
    print(f"   - 结果目录: {merged_dir}")
    
    return True

def collect_from_dir(tuozhan_path, all_ips, all_urls, all_domains):
    """从指定目录收集目标"""
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

def main():
    parser = argparse.ArgumentParser(description="合并扫描层结果")
    parser.add_argument("target_domain", help="目标域名")
    parser.add_argument("--layer", type=int, required=True, help="扫描层数")
    parser.add_argument("--project-root", default=".", help="项目根目录")
    
    args = parser.parse_args()
    
    success = merge_layer_results(args.target_domain, args.layer, args.project_root)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()