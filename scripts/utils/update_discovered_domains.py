#!/usr/bin/env python3
"""
实时更新扫描状态中的域名发现信息
"""

import json
import sys
import os
from datetime import datetime
from pathlib import Path

def update_discovered_domains(domain, discovered_domains, source_method=""):
    """
    更新扫描状态文件中的域名发现信息
    
    Args:
        domain: 目标域名
        discovered_domains: 发现的域名列表
        source_method: 发现方法
    """
    status_file = Path(f"output/{domain}/scanning_status.json")
    
    if not status_file.exists():
        return
    
    try:
        # 读取现有状态
        with open(status_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # 初始化discovered_domains字段
        if 'discovered_domains' not in data:
            data['discovered_domains'] = {
                'total': 0,
                'methods': {},
                'domains': [],
                'last_update': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        
        # 更新发现的域名
        existing_domains = set(data['discovered_domains']['domains'])
        new_domains = []
        
        for d in discovered_domains:
            if d and d not in existing_domains:
                new_domains.append(d)
                existing_domains.add(d)
        
        if new_domains:
            # 添加新域名
            data['discovered_domains']['domains'].extend(new_domains)
            data['discovered_domains']['total'] = len(data['discovered_domains']['domains'])
            data['discovered_domains']['last_update'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # 按方法统计
            if source_method:
                if source_method not in data['discovered_domains']['methods']:
                    data['discovered_domains']['methods'][source_method] = 0
                data['discovered_domains']['methods'][source_method] += len(new_domains)
            
            # 更新总状态的最后更新时间
            data['last_update'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # 保存更新后的状态
            with open(status_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            print(f"[+] 更新扫描状态: 新增 {len(new_domains)} 个域名 (方法: {source_method})")
            for d in new_domains[:5]:  # 只显示前5个
                print(f"    - {d}")
            if len(new_domains) > 5:
                print(f"    ... 还有 {len(new_domains) - 5} 个域名")
        
    except Exception as e:
        print(f"[!] 更新域名发现状态失败: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 update_discovered_domains.py <domain> <discovered_domain1> [discovered_domain2] ... [--method=METHOD]")
        sys.exit(1)
    
    target_domain = sys.argv[1]
    discovered_domains = []
    source_method = ""
    
    # 解析参数
    for arg in sys.argv[2:]:
        if arg.startswith('--method='):
            source_method = arg.replace('--method=', '')
        else:
            discovered_domains.append(arg)
    
    update_discovered_domains(target_domain, discovered_domains, source_method)
