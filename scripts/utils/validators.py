#!/usr/bin/env python3
"""
输入验证工具集
用于验证域名、IP地址等输入的合法性
"""

import re
import ipaddress


def validate_domain(domain):
    """
    验证域名格式是否合法
    
    Args:
        domain: 待验证的域名
        
    Returns:
        bool: 是否为合法域名
    """
    if not domain or len(domain) > 253:
        return False
        
    # 移除可能的端口号
    if ':' in domain:
        domain = domain.split(':')[0]
        
    # 域名正则表达式
    domain_pattern = re.compile(
        r'^(?=.{1,253}$)'  # 总长度限制
        r'(?!-)'  # 不能以-开头
        r'(?!.*--)'  # 不能包含连续的--
        r'(?!.*-$)'  # 不能以-结尾
        r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'  # 子域名
        r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'  # 顶级域名
    )
    
    return bool(domain_pattern.match(domain))


def validate_ip(ip_str):
    """
    验证IP地址格式是否合法
    
    Args:
        ip_str: 待验证的IP地址字符串
        
    Returns:
        bool: 是否为合法IP地址
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def validate_url(url):
    """
    验证URL格式是否合法
    
    Args:
        url: 待验证的URL
        
    Returns:
        bool: 是否为合法URL
    """
    url_pattern = re.compile(
        r'^https?://'  # 协议
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # 域名
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP地址
        r'(?::\d+)?'  # 端口
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    return bool(url_pattern.match(url))


def sanitize_domain(domain):
    """
    清理和标准化域名
    
    Args:
        domain: 原始域名
        
    Returns:
        str: 清理后的域名，如果无效则返回None
    """
    if not domain:
        return None
        
    # 移除前后空白
    domain = domain.strip()
    
    # 移除协议前缀
    domain = re.sub(r'^https?://', '', domain)
    
    # 移除路径
    domain = domain.split('/')[0]
    
    # 移除端口
    domain = domain.split(':')[0]
    
    # 转换为小写
    domain = domain.lower()
    
    # 验证清理后的域名
    if validate_domain(domain):
        return domain
    
    return None


def is_private_ip(ip_str):
    """
    检查是否为私有IP地址
    
    Args:
        ip_str: IP地址字符串
        
    Returns:
        bool: 是否为私有IP
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False


def is_cdn_ip(ip_str):
    """
    检查是否为已知CDN的IP地址
    
    Args:
        ip_str: IP地址字符串
        
    Returns:
        bool: 是否为CDN IP
    """
    # CDN IP段（示例，实际应从配置文件加载）
    cdn_ranges = [
        '104.16.0.0/12',  # Cloudflare
        '172.64.0.0/13',  # Cloudflare
        '103.21.244.0/22',  # Cloudflare
        '103.22.200.0/22',  # Cloudflare
        '103.31.4.0/22',  # Cloudflare
        '141.101.64.0/18',  # Cloudflare
        '108.162.192.0/18',  # Cloudflare
        '190.93.240.0/20',  # Cloudflare
        '188.114.96.0/20',  # Cloudflare
        '197.234.240.0/22',  # Cloudflare
        '198.41.128.0/17',  # Cloudflare
    ]
    
    try:
        ip = ipaddress.ip_address(ip_str)
        for cdn_range in cdn_ranges:
            if ip in ipaddress.ip_network(cdn_range):
                return True
    except ValueError:
        pass
        
    return False


if __name__ == '__main__':
    # 测试用例
    test_domains = [
        'example.com',
        'sub.example.com',
        'test-domain.co.uk',
        'invalid-.com',
        '-invalid.com',
        'invalid..com',
        'https://example.com',
        'example.com:8080',
        '192.168.1.1',
        ''
    ]
    
    print("域名验证测试:")
    for domain in test_domains:
        print(f"  {domain}: {validate_domain(domain)}")
        
    print("\n域名清理测试:")
    for domain in test_domains:
        cleaned = sanitize_domain(domain)
        print(f"  {domain} -> {cleaned}")