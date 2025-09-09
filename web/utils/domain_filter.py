#!/usr/bin/env python3
"""域名过滤工具"""

import ipaddress
from urllib.parse import urlparse

def is_valid_domain(domain):
    """检查是否是有效的域名（非IP地址）"""
    if not domain:
        return False
    
    # 清理域名
    domain = domain.strip()
    
    # 过滤IP地址
    try:
        ipaddress.ip_address(domain.split(':')[0])
        return False
    except ValueError:
        pass
    
    # 过滤端口号形式
    if ':' in domain and domain.split(':')[-1].isdigit():
        return False
    
    # 过滤纯数字
    if domain.replace('.', '').isdigit():
        return False
    
    # 过滤无效字符
    if any(char in domain for char in ['#', ' ', '\t', '\n']):
        return False
    
    return True

def extract_domain_keywords(domain):
    """提取域名关键字"""
    # 移除常见的前缀和后缀
    domain = domain.lower()
    domain = domain.replace('www.', '')
    domain = domain.replace('portal.', '')
    domain = domain.replace('api.', '')
    domain = domain.replace('admin.', '')
    
    # 提取主要部分
    parts = domain.split('.')
    if len(parts) >= 2:
        # 获取主域名部分（不包括顶级域名）
        main_part = parts[0]
        # 分割连字符
        keywords = main_part.split('-')
        return [kw for kw in keywords if len(kw) > 2]
    return []

def is_related_domain(source_domain, target_domain, threshold=0.3):
    """判断两个域名是否相关"""
    # 处理自引用
    if source_domain == target_domain:
        return True
    
    source_keywords = extract_domain_keywords(source_domain)
    target_keywords = extract_domain_keywords(target_domain)
    
    if not source_keywords or not target_keywords:
        return False
    
    # 特殊处理一些变体情况
    # dlsm -> dls, dlas 等
    source_main = source_keywords[0] if source_keywords else ""
    target_str = ' '.join(target_keywords).lower()
    
    # 检查主关键字或其变体是否存在
    if source_main:
        # 完全匹配
        if source_main in target_keywords:
            return True
        
        # 检查是否包含主关键字
        if source_main in target_str:
            return True
        
        # 检查常见变体（如 dlsm -> dls, dlas）
        if len(source_main) >= 3:
            prefix = source_main[:3]
            if any(tk.startswith(prefix) for tk in target_keywords):
                return True
    
    # 通用匹配逻辑
    matches = 0
    for sk in source_keywords:
        for tk in target_keywords:
            # 更宽松的匹配：只要有3个字符以上的共同前缀就认为相关
            if len(sk) >= 3 and len(tk) >= 3:
                common_len = min(len(sk), len(tk))
                if sk[:3] == tk[:3]:
                    matches += 1
                    break
    
    # 如果有任何匹配，就认为相关
    return matches > 0

def clean_url_to_domain(url):
    """清理URL并提取域名"""
    if not url:
        return None
    
    # 移除协议
    url = url.replace('https://', '').replace('http://', '')
    
    # 分割路径和端口
    domain = url.split('/')[0].split(':')[0]
    
    return domain if is_valid_domain(domain) else None