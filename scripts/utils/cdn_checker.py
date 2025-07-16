#!/usr/bin/env python3
"""
CDN检查工具 - 独立的CDN判断脚本
从start.py中提取的CDN判断逻辑
"""

import os
import sys
import ipaddress
import socket
import argparse
from pathlib import Path

# CDN IP段文件路径
CDN_LIST_PATH = "config/filters/cdn.txt"
CDN_DYNAMIC_PATH = "config/filters/cdn_动态添加_一年清一次.txt"

# CDN域名关键词
CDN_KEYWORDS = [
    "cloudfront.net", "r.cloudfront.net",
    "cloudflare.com", "cloudflare.net",
    "akamai", "akamaiedge.net", "akamaized.net", "akamaitechnologies.com",
    "fastly.com", "fastlylb.net",
    "amazonaws.com", "awsdns",
    "azure", "azureedge.net", "azurefd.net",
    "cdn", "cdnjs", "jsdelivr", "unpkg",
    "googleusercontent.com", "gstatic.com",
    "chinacache.net", "ccgslb.net",
    "chinanetcenter.com", "wscloudcdn.com",
    "qbox.me", "qiniucdn.com",
    "alicdn.com", "tbcdn.cn", "aliyuncs.com"
]

def load_cdn_ranges(path):
    """载入CDN IP段"""
    ranges = []
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        net = ipaddress.ip_network(line if '/' in line else line + '/32', strict=False)
                        ranges.append(net)
                    except ValueError:
                        print(f"[!] 无效CDN条目: {line}", file=sys.stderr)
    return ranges

def is_cdn_ip(ip, cdn_ranges):
    """判断IP是否属于CDN（基于IP段）"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in cdn_ranges)
    except ValueError:
        return False

def is_cdn_domain(domain):
    """判断域名是否为CDN域名"""
    return any(keyword in domain.lower() for keyword in CDN_KEYWORDS)

def reverse_lookup(ip):
    """IP反向解析"""
    try:
        result = socket.gethostbyaddr(ip)
        return [result[0]] + list(result[1])
    except (socket.herror, socket.gaierror):
        return []

def forward_lookup(domain):
    """域名正向解析"""
    try:
        return [info[4][0] for info in socket.getaddrinfo(domain, None)]
    except (socket.herror, socket.gaierror):
        return []

def is_cdn_ip_advanced(ip):
    """高级CDN判断（基于反向解析）"""
    domains = reverse_lookup(ip)
    
    if not domains:
        return False, "无反向解析"
    
    # 条件1：域名数量过多，直接判定为CDN
    if len(domains) > 45:
        return True, f"域名数量过多({len(domains)})"
    
    # 条件2：域名包含CDN关键词
    for domain in domains:
        if is_cdn_domain(domain):
            return True, f"CDN域名: {domain}"
    
    # 条件3：随机选一个域名做正向解析测试
    if domains:
        test_domain = domains[0]
        try:
            ips = forward_lookup(test_domain)
            if ip not in ips:
                return True, f"IP不在{test_domain}的解析列表中"
            if len(ips) > 4:
                return True, f"{test_domain}解析到{len(ips)}个IP"
        except Exception as e:
            return True, f"解析异常: {e}"
    
    return False, "非CDN"

def check_ip_cdn_status(ip, cdn_ranges, use_advanced=True):
    """综合CDN检查"""
    # 基础IP段检查
    if is_cdn_ip(ip, cdn_ranges):
        return True, "CDN IP段"
    
    # 高级检查
    if use_advanced:
        is_cdn, reason = is_cdn_ip_advanced(ip)
        return is_cdn, reason
    
    return False, "非CDN"

def filter_ips_from_file(input_file, output_file, cdn_ranges, verbose=False):
    """从文件过滤CDN IP"""
    if not os.path.exists(input_file):
        print(f"❌ 输入文件不存在: {input_file}")
        return False
    
    with open(input_file, 'r') as f:
        lines = f.readlines()
    
    filtered_ips = []
    cdn_ips = []
    current_source = None
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        if line.startswith("# 来源:"):
            current_source = line
            filtered_ips.append(line)
            continue
        
        if line.startswith("#"):
            filtered_ips.append(line)
            continue
        
        # 检查IP
        try:
            ipaddress.ip_address(line)  # 验证是否为有效IP
            is_cdn, reason = check_ip_cdn_status(line, cdn_ranges)
            
            if is_cdn:
                cdn_ips.append((line, reason, current_source))
                if verbose:
                    print(f"[-] CDN IP: {line} ({reason})")
            else:
                filtered_ips.append(line)
                if verbose:
                    print(f"[+] 保留IP: {line}")
        except ValueError:
            # 不是有效IP，直接保留
            filtered_ips.append(line)
    
    # 写入过滤后的结果
    with open(output_file, 'w') as f:
        for line in filtered_ips:
            f.write(f"{line}\\n")
    
    print(f"[*] CDN过滤完成:")
    print(f"    输入文件: {input_file}")
    print(f"    输出文件: {output_file}")
    print(f"    过滤掉CDN IP: {len(cdn_ips)}")
    print(f"    保留IP: {len([l for l in filtered_ips if not l.startswith('#')])})")
    
    if cdn_ips and verbose:
        print(f"\\n[*] 被过滤的CDN IP详情:")
        for ip, reason, source in cdn_ips:
            print(f"    {ip}: {reason} (来源: {source})")
    
    return True

def main():
    parser = argparse.ArgumentParser(description="CDN检查工具")
    parser.add_argument("--ip", help="检查单个IP")
    parser.add_argument("--input", help="输入IP文件")
    parser.add_argument("--output", help="输出过滤后的IP文件")
    parser.add_argument("--verbose", "-v", action="store_true", help="详细输出")
    parser.add_argument("--simple", action="store_true", help="只使用基础IP段检查")
    
    args = parser.parse_args()
    
    # 加载CDN IP段
    cdn_ranges = load_cdn_ranges(CDN_LIST_PATH)
    print(f"[*] 加载CDN IP段: {len(cdn_ranges)} 个")
    
    if args.ip:
        # 检查单个IP
        is_cdn, reason = check_ip_cdn_status(args.ip, cdn_ranges, not args.simple)
        print(f"IP: {args.ip}")
        print(f"状态: {'CDN' if is_cdn else '非CDN'}")
        print(f"原因: {reason}")
        sys.exit(0 if not is_cdn else 1)
    
    elif args.input and args.output:
        # 过滤文件中的IP
        success = filter_ips_from_file(args.input, args.output, cdn_ranges, args.verbose)
        sys.exit(0 if success else 1)
    
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()