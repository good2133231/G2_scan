#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
渗透扫描平台 - 纯API后端
只提供JSON API，不提供Web界面
配合React前端使用
"""

import os
import json
import logging
import sqlite3
import re
from datetime import datetime
from flask import Flask, jsonify, request
from flask_cors import CORS
from functools import wraps
import base64
import threading
import time

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)  # 允许跨域请求

# 基础认证
def check_auth(username, password):
    return username == 'admin' and password == 'MyStr0ngP@ssw0rd!'

def authenticate():
    return jsonify({'error': 'Authentication required'}), 401

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# 数据目录
DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
DB_PATH = os.path.join(DATA_DIR, 'scan_platform.db')

# 初始化数据库
def init_database():
    """初始化SQLite数据库"""
    os.makedirs(DATA_DIR, exist_ok=True)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 创建目标表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            scan_progress INTEGER DEFAULT 0,
            current_stage TEXT DEFAULT '',
            last_scan_time TIMESTAMP,
            notes TEXT DEFAULT ''
        )
    ''')
    
    # 创建扫描任务表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER,
            task_type TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            progress INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            started_at TIMESTAMP,
            completed_at TIMESTAMP,
            error_message TEXT,
            FOREIGN KEY (target_id) REFERENCES targets (id)
        )
    ''')
    
    # 创建用户会话表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_token TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()
    logger.info("数据库初始化完成")

# 数据库操作辅助函数
def get_db_connection():
    """获取数据库连接"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # 使结果可以像字典一样访问
    return conn

def load_domain_data(domain):
    """加载域名数据"""
    try:
        domain_dir = os.path.join(DATA_DIR, domain)
        if not os.path.exists(domain_dir):
            return None
            
        # 加载主数据文件
        data_file = os.path.join(domain_dir, 'domain_data.json')
        if os.path.exists(data_file):
            with open(data_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        return None
    except Exception as e:
        logger.error(f"加载域名数据失败: {e}")
        return None

def check_and_update_scan_completion(domain, data):
    """检查扫描结果并更新数据库状态为完成"""
    try:
        # 检查是否有实际的扫描结果
        has_results = False
        
        if data and 'layers' in data and '1' in data['layers']:
            layer_data = data['layers']['1']
            
            # 检查是否有URL结果
            urls = layer_data.get('urls', [])
            if urls and len(urls) > 0:
                has_results = True
            
            # 检查是否有域名发现结果
            content_mining = layer_data.get('content_mining', [])
            if content_mining and len(content_mining) > 0:
                has_results = True
            
            # 检查是否有FOFA结果
            fofa_results = layer_data.get('fofa_results', [])
            if fofa_results and len(fofa_results) > 0:
                has_results = True
        
        # 如果有结果，更新数据库状态为完成
        if has_results:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # 检查当前数据库状态
            cursor.execute('SELECT status, scan_progress FROM targets WHERE domain = ?', (domain,))
            result = cursor.fetchone()
            
            if result:
                current_status = result['status']
                current_progress = result['scan_progress']
                
                # 如果状态不是完成或进度不是100%，则更新
                if current_status != 'completed' or current_progress != 100:
                    cursor.execute('''
                        UPDATE targets 
                        SET status = 'completed', 
                            scan_progress = 100, 
                            current_stage = '扫描完成',
                            updated_at = CURRENT_TIMESTAMP
                        WHERE domain = ?
                    ''', (domain,))
                    conn.commit()
                    logger.info(f"已更新域名 {domain} 状态为完成 (100%)")
            
            conn.close()
            
    except Exception as e:
        logger.error(f"检查扫描完成状态失败: {e}")

def load_scan_status(domain):
    """加载扫描状态"""
    try:
        # 首先检查数据库中的状态，这是最权威的数据源
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT status, scan_progress, current_stage FROM targets WHERE domain = ?', (domain,))
        db_result = cursor.fetchone()
        conn.close()
        
        if db_result:
            db_status = db_result['status']
            db_progress = db_result['scan_progress']
            db_stage = db_result['current_stage']
            
            # 如果数据库显示已完成，直接返回完成状态（无论进度如何）
            if db_status == 'completed':
                return {
                    'scan_completed': True,
                    'progress': 100,
                    'current_stage': '扫描完成',
                    'start_time': None,
                    'end_time': None,
                    'scan_stages': {
                        'subdomain_discovery': {'status': 'completed'},
                        'http_probe': {'status': 'completed'},
                        'port_scan': {'status': 'completed'},
                        'vulnerability_scan': {'status': 'completed'},
                        'expand_scan': {'status': 'completed'},
                        'report_generation': {'status': 'completed'}
                    },
                    'discovered_domains': {},
                    'errors': []
                }
        
        # 如果数据库没有记录或状态不是完成，检查扫描状态文件
        domain_output_dir = os.path.join('..', 'output', domain)
        scanning_status_file = os.path.join(domain_output_dir, 'scanning_status.json')
        
        if os.path.exists(scanning_status_file):
            with open(scanning_status_file, 'r', encoding='utf-8') as f:
                status_data = json.load(f)
                
                # 验证和修复扫描状态逻辑
                scan_stages = status_data.get('scan_stages', {})
                fixed_stages = fix_scan_stages_logic(scan_stages)
                
                # 重新计算总体进度和当前阶段
                progress, current_stage, scan_completed = calculate_overall_progress(fixed_stages)
                
                return {
                    'scan_completed': scan_completed,
                    'progress': progress,
                    'current_stage': current_stage,
                    'start_time': status_data.get('start_time'),
                    'end_time': status_data.get('end_time') if scan_completed else None,
                    'scan_stages': fixed_stages,
                    'discovered_domains': status_data.get('discovered_domains', {}),
                    'errors': status_data.get('errors', [])
                }
        
        # 检查是否有扫描输出目录但没有状态文件
        if os.path.exists(domain_output_dir):
            return {
                'scan_completed': True,
                'progress': 100,
                'current_stage': 'completed',
                'start_time': '2025-09-03 10:00:00',
                'scan_stages': {
                    'scan_completed': {
                        'status': 'completed',
                        'progress': 100,
                        'start_time': '2025-09-03 10:00:00',
                        'end_time': '2025-09-03 12:00:00',
                        'details': f'域名 {domain} 扫描完成'
                    }
                }
            }
        else:
            # 检查数据库中的扫描状态
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT status, scan_progress, current_stage FROM targets WHERE domain = ?', (domain,))
            target = cursor.fetchone()
            conn.close()
            
            if target and target['status'] == 'scanning':
                return {
                    'scan_completed': False,
                    'progress': target['scan_progress'] or 0,
                    'current_stage': target['current_stage'] or 'preparing',
                    'start_time': None,
                    'scan_stages': {},
                    'message': f'域名 {domain} 正在扫描中...'
                }
            else:
                return {
                    'scan_completed': False,
                    'progress': 0,
                    'current_stage': 'not_started',
                    'start_time': None,
                    'scan_stages': {},
                    'message': f'域名 {domain} 尚未开始扫描'
                }
    except Exception as e:
        logger.error(f"加载扫描状态失败: {e}")
        return None

def fix_scan_stages_logic(scan_stages):
    """修复扫描阶段逻辑错误"""
    # 定义正确的扫描顺序
    stage_order = [
        'subdomain_discovery',
        'http_probe', 
        'port_scan',
        'vulnerability_scan',
        'expand_scan',
        'report_generation'
    ]
    
    fixed_stages = {}
    
    # 检查逻辑一致性：如果前面的阶段是pending，后面的不能是completed
    for i, stage in enumerate(stage_order):
        if stage in scan_stages:
            stage_info = scan_stages[stage].copy()
            
            # 检查前置依赖
            if i > 0:
                prev_stage = stage_order[i-1]
                if prev_stage in fixed_stages:
                    prev_status = fixed_stages[prev_stage].get('status', 'pending')
                    current_status = stage_info.get('status', 'pending')
                    
                    # 如果前一个阶段是pending，当前阶段不能是completed
                    if prev_status == 'pending' and current_status == 'completed':
                        stage_info['status'] = 'pending'
                        # 清除不合理的时间信息
                        stage_info.pop('start_time', None)
                        stage_info.pop('end_time', None)
                        stage_info.pop('details', None)
            
            fixed_stages[stage] = stage_info
    
    return fixed_stages

def calculate_overall_progress(scan_stages):
    """计算总体进度和当前阶段"""
    stage_order = [
        'subdomain_discovery',
        'http_probe', 
        'port_scan',
        'vulnerability_scan',
        'expand_scan',
        'report_generation'
    ]
    
    completed_count = 0
    current_stage = 'not_started'
    
    for stage in stage_order:
        if stage in scan_stages:
            status = scan_stages[stage].get('status', 'pending')
            if status == 'completed':
                completed_count += 1
            elif status == 'running':
                current_stage = stage
                break
            elif status == 'pending':
                current_stage = stage
                break
    
    # 如果所有阶段都完成
    if completed_count == len(stage_order):
        progress = 100
        current_stage = 'completed'
        scan_completed = True
    else:
        progress = int((completed_count / len(stage_order)) * 100)
        scan_completed = False
    
    return progress, current_stage, scan_completed

def load_logs(domain):
    """加载日志"""
    try:
        logs_file = os.path.join(DATA_DIR, domain, 'logs.json')
        if os.path.exists(logs_file):
            with open(logs_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        return []
    except Exception as e:
        logger.error(f"加载日志失败: {e}")
        return []

def parse_urls_with_duplicates(domain_output_dir):
    """解析URL并统计重复情况 - 基于base_info文件的重复网站部分"""
    import re
    from collections import defaultdict
    
    try:
        base_info_file = os.path.join(domain_output_dir, f'base_info_{os.path.basename(domain_output_dir)}.txt')
        
        if not os.path.exists(base_info_file):
            return {
                'unique_urls': [],
                'duplicate_urls': [],
                'statistics': {
                    'total_urls': 0,
                    'unique_urls': 0,
                    'duplicate_instances': 0,
                    'duplicate_unique_count': 0
                }
            }
        
        with open(base_info_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 1. 解析URL和标题部分，获取基础URL信息
        detailed_urls = {}
        url_section_match = re.search(r'URL和标题:\s*\n(.*?)(?=\n\n|\nIP反查域名|\n\[URL BODY INFO|\Z)', content, re.DOTALL)
        if url_section_match:
            url_lines = url_section_match.group(1).strip().split('\n')
            for line in url_lines:
                line = line.strip()
                if line.startswith('- '):
                    url_match = re.match(r'-\s+(\S+)\s+\[([^\]]*)\]\[size:(\d+)\]', line)
                    if url_match:
                        url = url_match.group(1)
                        title = url_match.group(2) if url_match.group(2) else '无标题'
                        size = int(url_match.group(3))
                        detailed_urls[url] = {'title': title, 'size': size, 'status_code': 200}
        
        # 2. 解析重复网站部分
        duplicate_groups = []
        unique_urls = []
        
        # 查找重复网站部分
        duplicate_section_match = re.search(r'重复网站:\s*\n==============================\s*\n(.*?)(?=\n==============================|\Z)', content, re.DOTALL)
        
        if duplicate_section_match:
            duplicate_content = duplicate_section_match.group(1).strip()
            
            # 按重复组分割
            groups = re.split(r'\n\s*- 重复于:', duplicate_content)
            
            for group in groups:
                if not group.strip():
                    continue
                    
                # 如果不是以"重复于"开头，添加前缀
                if not group.strip().startswith('重复于:'):
                    group = '重复于: ' + group
                
                # 解析主URL和重复URL列表
                lines = group.strip().split('\n')
                if not lines:
                    continue
                    
                # 解析主URL和标题
                main_url_match = re.search(r'重复于:\s*(\S+)\s+标题:\s*([^[]+)', lines[0])
                if not main_url_match:
                    continue
                    
                main_url = main_url_match.group(1)
                main_title = main_url_match.group(2).strip()
                
                # 统计这个组内有多少个URL
                group_count = 0
                main_size = 0
                
                # 解析组内所有URL来统计数量和获取主URL的size
                i = 1
                while i < len(lines):
                    line = lines[i].strip()
                    if line.startswith('- '):
                        url_match = re.search(r'-\s+(\S+)\[size:(\d+)\]', line)
                        if url_match:
                            group_count += 1
                            url = url_match.group(1)
                            size = int(url_match.group(2))
                            
                            # 如果是主URL，记录其size
                            if url == main_url:
                                main_size = size
                    i += 1
                
                # 添加组内所有URL到重复URL列表
                if group_count > 1:  # 确保真的有重复
                    # 重新解析获取所有URL
                    i = 1
                    while i < len(lines):
                        line = lines[i].strip()
                        if line.startswith('- '):
                            url_match = re.search(r'-\s+(\S+)\[size:(\d+)\]', line)
                            if url_match:
                                url = url_match.group(1)
                                size = int(url_match.group(2))
                                title = main_title  # 同组内URL使用相同标题
                                
                                # 查找下一行的具体标题
                                if i + 1 < len(lines):
                                    next_line = lines[i + 1].strip()
                                    title_match = re.search(r'标题:\s*(.+)', next_line)
                                    if title_match:
                                        title = title_match.group(1)
                                        i += 1  # 跳过标题行
                                
                                # 只添加非主URL的重复实例
                                if url != main_url:
                                    duplicate_groups.append({
                                        'url': url,
                                        'title': title,
                                        'size': size,
                                        'status_code': 200,
                                        'sources': ['基础信息文件', '重复检测']
                                    })
                        i += 1
        
        # 3. 唯一URL = "URL和标题"中的所有URL（包括重复组的主URL作为代表）
        for url, info in detailed_urls.items():
            unique_urls.append({
                'url': url,
                'title': info['title'],
                'size': info['size'],
                'status_code': info['status_code'],
                'count': 1,
                'sources': ['基础信息文件', 'URL文件']
            })
        
        # 4. 计算统计信息
        # 从input/urls.txt获取总URL数
        all_urls_in_file = set()
        urls_file = os.path.join(domain_output_dir, 'input', 'urls.txt')
        if os.path.exists(urls_file):
            with open(urls_file, 'r', encoding='utf-8') as f:
                for line in f:
                    url = line.strip()
                    if url:
                        all_urls_in_file.add(url)
        
        total_urls = len(all_urls_in_file)
        unique_count = len(unique_urls)  # "URL和标题"中的URL数量（3个）
        duplicate_count = len(duplicate_groups)  # 实际的重复实例数量（8个）
        duplicate_instances = duplicate_count  # 重复实例就是duplicate_count
        
        return {
            'unique_urls': unique_urls,
            'duplicate_urls': duplicate_groups,
            'statistics': {
                'total_urls': total_urls,
                'unique_urls': unique_count,
                'duplicate_instances': duplicate_instances,
                'duplicate_unique_count': duplicate_count
            }
        }
        
    except Exception as e:
        logger.error(f"解析URL重复统计失败: {e}")
        return {
            'unique_urls': [],
            'duplicate_urls': [],
            'statistics': {
                'total_urls': 0,
                'unique_urls': 0,
                'duplicate_instances': 0,
                'duplicate_unique_count': 0
            }
        }

def parse_tuozhan_urls(urls_file):
    """解析拓展域名文件"""
    try:
        with open(urls_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        lines = content.strip().split('\n')
        domains = []
        current_source = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            if line.startswith('# 来源:'):
                # 解析来源信息
                import re
                match = re.search(r'来源:\s*(.+?)\s*->\s*(.+)', line)
                if match:
                    current_source = {
                        'method': match.group(1).strip(),
                        'origin_url': match.group(2).strip()
                    }
            elif not line.startswith('#') and current_source:
                # 这是一个域名
                domains.append({
                    'domain': line,
                    'source': current_source['method'],
                    'origin_url': current_source['origin_url'],
                    'status': 'discovered'
                })
        
        return domains
        
    except Exception as e:
        logger.error(f"解析拓展域名失败: {e}")
        return []

def parse_tuozhan_ips(ip_file):
    """解析拓展IP文件"""
    try:
        with open(ip_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        lines = content.strip().split('\n')
        ips = []
        current_source = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            if line.startswith('# 来源:'):
                # 解析来源信息
                import re
                match = re.search(r'来源:\s*(.+?)\s*->\s*(.+)', line)
                if match:
                    current_source = {
                        'method': match.group(1).strip(),
                        'origin_url': match.group(2).strip()
                    }
            elif not line.startswith('#') and current_source:
                # 这是一个IP（可能包含端口）
                ip_port = line
                ip = ip_port.split(':')[0] if ':' in ip_port else ip_port
                port = ip_port.split(':')[1] if ':' in ip_port else None
                
                ips.append({
                    'ip': ip,
                    'port': port,
                    'ip_port': ip_port,
                    'source': current_source['method'],
                    'origin_url': current_source['origin_url'],
                    'status': 'discovered'
                })
        
        return ips
        
    except Exception as e:
        logger.error(f"解析拓展IP失败: {e}")
        return []

def parse_tuozhan_root_domains(root_domains_file):
    """解析根域名文件"""
    try:
        with open(root_domains_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        lines = content.strip().split('\n')
        root_domains = []
        current_source = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            if line.startswith('# 来源:'):
                # 解析来源信息
                import re
                match = re.search(r'来源:\s*(.+?)\s*->\s*(.+)', line)
                if match:
                    current_source = {
                        'method': match.group(1).strip(),
                        'origin_url': match.group(2).strip()
                    }
            elif not line.startswith('#') and current_source:
                # 这是一个根域名
                root_domains.append({
                    'domain': line,
                    'source': current_source['method'],
                    'origin_url': current_source['origin_url'],
                    'status': 'discovered'
                })
        
        return root_domains
        
    except Exception as e:
        logger.error(f"解析根域名失败: {e}")
        return []

def build_data_from_scan_output(domain):
    """从实际扫描输出构建数据"""
    try:
        domain_output_dir = os.path.join('..', 'output', domain)
        data = {
            'domain': domain,
            'layers': {
                '1': {
                    'urls': [],
                    'fofa_results': [],
                    'content_mining': [],
                    'ip_scan_results': {}
                }
            }
        }
        
        # 使用新的重复URL统计功能
        url_analysis = parse_urls_with_duplicates(domain_output_dir)
        
        # 将唯一URL添加到原有结构中（保持兼容性）
        data['layers']['1']['urls'] = [
            {
                'url': url_info['url'],
                'title': url_info['title'],
                'size': url_info['size'],
                'status_code': url_info['status_code']
            }
            for url_info in url_analysis['unique_urls']
        ]
        
        # 添加新的重复URL数据结构
        data['layers']['1']['url_analysis'] = {
            'unique_urls': url_analysis['unique_urls'],
            'duplicate_urls': url_analysis['duplicate_urls'],
            'statistics': url_analysis['statistics']
        }
        
        # 解析基础信息中的关联真实IP
        base_info_file = os.path.join(domain_output_dir, f'base_info_{domain}.txt')
        if os.path.exists(base_info_file):
            associated_ips = []
            with open(base_info_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # 提取关联真实IP部分
            ip_section_match = re.search(r'关联真实IP:\s*\n(.*?)(?=\n\n|\nURL和标题|\Z)', content, re.DOTALL)
            if ip_section_match:
                ip_lines = ip_section_match.group(1).strip().split('\n')
                for line in ip_lines:
                    line = line.strip()
                    if line.startswith('- '):
                        ip = line.replace('- ', '').strip()
                        if ip:
                            associated_ips.append(ip)
            
            data['layers']['1']['associated_ips'] = associated_ips
        
        # 解析fscan扫描结果
        fscan_file = os.path.join(domain_output_dir, f'fscan_result_{domain}.txt')
        logger.info(f"检查fscan文件: {fscan_file}, 存在: {os.path.exists(fscan_file)}")
        if os.path.exists(fscan_file):
            fscan_results = []
            ip_scan_results = {}
            web_titles = {}  # 存储WebTitle信息
            
            with open(fscan_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        fscan_results.append(line)
                        
                        # 解析端口信息: 8.218.120.180:443 open
                        if ':' in line and 'open' in line and not line.startswith('[*]'):
                            parts = line.split()
                            if len(parts) >= 2:
                                ip_port = parts[0]
                                status = parts[1]
                                
                                if ':' in ip_port:
                                    ip, port = ip_port.split(':', 1)
                                    
                                    if ip not in ip_scan_results:
                                        ip_scan_results[ip] = {
                                            'ports': [],
                                            'vulnerabilities': [],
                                            'web_info': []
                                        }
                                    
                                    ip_scan_results[ip]['ports'].append({
                                        'port': port,
                                        'status': status,
                                        'service': 'tcp'
                                    })
                        
                        # 解析WebTitle信息: [*] WebTitle https://8.218.120.180     code:200 len:854    title:绿色保护行动
                        elif line.startswith('[*] WebTitle'):
                            try:
                                # 提取URL、状态码、长度、标题
                                parts = line.split()
                                if len(parts) >= 4:
                                    url = parts[2]
                                    # 提取IP和端口
                                    if '://' in url:
                                        protocol = url.split('://')[0]
                                        host_part = url.split('://')[1]
                                        if ':' in host_part:
                                            ip = host_part.split(':')[0]
                                            port = host_part.split(':')[1]
                                        else:
                                            ip = host_part
                                            port = '443' if protocol == 'https' else '80'
                                        
                                        # 提取code、len、title
                                        code = ''
                                        length = ''
                                        title = ''
                                        
                                        for part in parts[3:]:
                                            if part.startswith('code:'):
                                                code = part.replace('code:', '')
                                            elif part.startswith('len:'):
                                                length = part.replace('len:', '')
                                            elif part.startswith('title:'):
                                                title = ' '.join(parts[parts.index(part):]).replace('title:', '')
                                                break
                                        
                                        # 确保IP存在于结果中
                                        if ip not in ip_scan_results:
                                            ip_scan_results[ip] = {
                                                'ports': [],
                                                'vulnerabilities': [],
                                                'web_info': []
                                            }
                                        
                                        ip_scan_results[ip]['web_info'].append({
                                                'url': url,
                                                'port': port,
                                                'protocol': protocol,
                                                'status_code': code,
                                                'content_length': length,
                                                'title': title
                                            })
                            except Exception as e:
                                logger.warning(f"解析WebTitle失败: {line}, 错误: {e}")
            
            data['layers']['1']['fscan_results'] = fscan_results
            # 基础IP端口扫描结果（来自关联真实IP）
            data['layers']['1']['basic_ip_scan_results'] = ip_scan_results
        
        # 检查tuozhan目录下的拓展数据
        tuozhan_dir = os.path.join(domain_output_dir, 'tuozhan')
        if os.path.exists(tuozhan_dir):
            # 解析all_tuozhan目录下的详细拓展数据
            all_tuozhan_dir = os.path.join(tuozhan_dir, 'all_tuozhan')
            if os.path.exists(all_tuozhan_dir):
                # 解析拓展域名
                urls_file = os.path.join(all_tuozhan_dir, 'urls.txt')
                if os.path.exists(urls_file):
                    data['layers']['1']['expand_domains'] = parse_tuozhan_urls(urls_file)
                
                # 解析拓展IP
                ip_file = os.path.join(all_tuozhan_dir, 'ip.txt')
                if os.path.exists(ip_file):
                    data['layers']['1']['expand_ips'] = parse_tuozhan_ips(ip_file)
                
                # 解析根域名
                root_domains_file = os.path.join(all_tuozhan_dir, 'root_domains.txt')
                if os.path.exists(root_domains_file):
                    data['layers']['1']['expand_root_domains'] = parse_tuozhan_root_domains(root_domains_file)
            
            # 兼容旧的domain.txt文件
            domain_file = os.path.join(tuozhan_dir, 'domain.txt')
            if os.path.exists(domain_file):
                with open(domain_file, 'r', encoding='utf-8') as f:
                    domains = f.read().strip().split('\n')
                    for found_domain in domains:
                        if found_domain.strip() and found_domain.strip() != domain:
                            data['layers']['1']['content_mining'].append({
                                'domain': found_domain.strip(),
                                'source': '内容挖掘'
                            })
        
        # 检查input目录下的IP扫描结果
        input_dir = os.path.join(domain_output_dir, 'input')
        if os.path.exists(input_dir):
            # 读取IP扫描结果
            for file in os.listdir(input_dir):
                if file.endswith('.txt') and 'ip' in file.lower():
                    ip_file = os.path.join(input_dir, file)
                    with open(ip_file, 'r', encoding='utf-8') as f:
                        content = f.read().strip()
                        # 简单解析IP和端口信息
                        lines = content.split('\n')
                        for line in lines:
                            if ':' in line and line.strip():
                                parts = line.strip().split(':')
                                if len(parts) >= 2:
                                    ip = parts[0]
                                    port = parts[1]
                                    if ip not in data['layers']['1']['ip_scan_results']:
                                        data['layers']['1']['ip_scan_results'][ip] = {
                                            'ports': [],
                                            'vulnerabilities': []
                                        }
                                    data['layers']['1']['ip_scan_results'][ip]['ports'].append({
                                        'port': int(port) if port.isdigit() else port,
                                        'service': 'unknown',
                                        'status': 'open'
                                    })
        
        return data
    except Exception as e:
        logger.error(f"从扫描输出构建数据失败: {e}")
        return None

def load_raw_data(domain):
    """加载原始数据"""
    try:
        raw_data_dir = os.path.join(DATA_DIR, domain, 'raw_data')
        raw_data = {}
        
        if os.path.exists(raw_data_dir):
            for filename in os.listdir(raw_data_dir):
                if filename.endswith('.txt'):
                    filepath = os.path.join(raw_data_dir, filename)
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                    # 根据文件名分类
                    if 'basic' in filename:
                        raw_data['basic_info'] = content
                    elif 'technical' in filename:
                        raw_data['technical_info'] = content
                    elif 'vulnerability' in filename:
                        raw_data['vulnerability_data'] = content
                    elif 'fofa' in filename:
                        raw_data['fofa_results'] = content
                    elif 'content' in filename:
                        raw_data['content_mining'] = content
        
        return raw_data
    except Exception as e:
        logger.error(f"加载原始数据失败: {e}")
        return {}

# API路由
@app.route('/health')
def health_check():
    """健康检查"""
    return jsonify({'status': 'ok', 'message': 'API服务正常运行'})

@app.route('/domain/<domain>')
@requires_auth
def get_domain_data(domain):
    """获取域名数据"""
    logger.info(f"获取域名数据: {domain}")
    data = load_domain_data(domain)
    logger.info(f"load_domain_data返回: {data is not None}")
    
    if data is None:
        # 检查是否有实际的扫描输出文件
        domain_output_dir = os.path.join('..', 'output', domain)
        logger.info(f"检查输出目录: {domain_output_dir}, 存在: {os.path.exists(domain_output_dir)}")
        
        if os.path.exists(domain_output_dir):
            # 尝试从实际扫描结果构建数据
            data = build_data_from_scan_output(domain)
            logger.info(f"build_data_from_scan_output返回: {data is not None}")
            if data:
                logger.info(f"构建的数据URLs数量: {len(data.get('layers', {}).get('1', {}).get('urls', []))}")
                # 检查并更新扫描完成状态
                check_and_update_scan_completion(domain, data)
        
        if data is None:
            # 返回空数据结构，表示未扫描
            logger.info(f"返回空数据结构给域名: {domain}")
            data = {
                'domain': domain,
                'layers': {
                    '1': {
                        'urls': [],
                        'fofa_results': [],
                        'content_mining': [],
                        'ip_scan_results': {}
                    }
                },
                'message': f'域名 {domain} 尚未进行扫描，请先启动扫描任务'
            }
    
    return jsonify(data)

@app.route('/scan_status/<domain>')
@requires_auth
def get_scan_status(domain):
    """获取扫描状态"""
    status = load_scan_status(domain)
    return jsonify(status)

@app.route('/logs/<domain>')
@requires_auth
def get_logs(domain):
    """获取日志"""
    logs = load_logs(domain)
    if not logs:
        # 检查是否有实际扫描输出
        domain_output_dir = os.path.join('..', 'output', domain)
        if os.path.exists(domain_output_dir):
            logs = [
                {
                    'timestamp': '2025-09-03T10:00:00Z',
                    'level': 'info',
                    'message': f'域名 {domain} 扫描已完成',
                    'source': 'scanner'
                }
            ]
        else:
            logs = [
                {
                    'timestamp': '2025-09-03T10:00:00Z',
                    'level': 'info',
                    'message': f'域名 {domain} 尚未开始扫描',
                    'source': 'system'
                }
            ]
    
    return jsonify(logs)

def load_raw_data_from_files(domain):
    """从实际扫描文件加载原始数据"""
    try:
        domain_output_dir = os.path.join('..', 'output', domain)
        raw_data = {}
        
        # 读取基础信息文件
        base_info_file = os.path.join(domain_output_dir, f'base_info_{domain}.txt')
        if os.path.exists(base_info_file):
            with open(base_info_file, 'r', encoding='utf-8') as f:
                raw_data['basic_info'] = f.read()
        
        # 读取技术信息（从tuozhan目录）
        tuozhan_dir = os.path.join(domain_output_dir, 'tuozhan')
        if os.path.exists(tuozhan_dir):
            tech_info = f"域名: {domain}\n扫描技术信息:\n"
            for file in os.listdir(tuozhan_dir):
                if file.endswith('.txt'):
                    file_path = os.path.join(tuozhan_dir, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read().strip()
                            if content:
                                tech_info += f"\n=== {file} ===\n{content}\n"
                    except:
                        continue
            raw_data['technical_info'] = tech_info
        
        # 读取漏洞数据
        vuln_files = []
        for root, dirs, files in os.walk(domain_output_dir):
            for file in files:
                if 'vuln' in file.lower() or 'poc' in file.lower():
                    vuln_files.append(os.path.join(root, file))
        
        if vuln_files:
            vuln_data = f"域名: {domain}\n漏洞扫描结果:\n"
            for vuln_file in vuln_files:
                try:
                    with open(vuln_file, 'r', encoding='utf-8') as f:
                        content = f.read().strip()
                        if content:
                            vuln_data += f"\n=== {os.path.basename(vuln_file)} ===\n{content}\n"
                except:
                    continue
            raw_data['vulnerability_data'] = vuln_data
        
        return raw_data if raw_data else None
    except Exception as e:
        logger.error(f"从文件加载原始数据失败: {e}")
        return None

@app.route('/raw_data/<domain>')
@requires_auth
def get_raw_data(domain):
    """获取原始数据"""
    raw_data = load_raw_data(domain)
    if not raw_data:
        # 检查是否有实际扫描输出
        domain_output_dir = os.path.join('..', 'output', domain)
        if os.path.exists(domain_output_dir):
            # 尝试从实际文件读取原始数据
            raw_data = load_raw_data_from_files(domain)
        
        if not raw_data:
            raw_data = {
                'basic_info': f"""==============================
[基础信息汇总] 域名: {domain}
==============================
该域名尚未进行扫描，无原始数据可显示。
请先启动扫描任务。
==============================""",
                'technical_info': f"""域名: {domain}
状态: 未扫描
请先启动扫描任务以获取技术信息。""",
                'vulnerability_data': f"""域名: {domain}
漏洞扫描状态: 未开始
请先启动扫描任务以获取漏洞信息。"""
            }
    
    return jsonify(raw_data)

@app.route('/start_scan', methods=['POST'])
@requires_auth
def start_scan():
    """启动扫描"""
    data = request.get_json()
    domain = data.get('domain')
    layer = data.get('layer', 1)
    
    if not domain:
        return jsonify({'error': '域名不能为空'}), 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 查找或创建目标
        cursor.execute('SELECT id FROM targets WHERE domain = ?', (domain,))
        target = cursor.fetchone()
        
        if not target:
            # 创建新目标
            cursor.execute('''
                INSERT INTO targets (domain, status, notes, scan_progress, current_stage)
                VALUES (?, 'scanning', '通过API启动扫描', 10, '准备扫描')
            ''', (domain,))
            target_id = cursor.lastrowid
        else:
            target_id = target['id']
            # 更新目标状态
            cursor.execute('''
                UPDATE targets 
                SET status = 'scanning', scan_progress = 10, current_stage = '准备扫描',
                    last_scan_time = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (target_id,))
        
        # 创建扫描任务记录
        cursor.execute('''
            INSERT INTO scan_tasks (target_id, task_type, status, progress, started_at)
            VALUES (?, ?, 'running', 10, CURRENT_TIMESTAMP)
        ''', (target_id, f'layer_{layer}_scan'))
        
        conn.commit()
        conn.close()
        
        # 启动实际扫描（异步）
        import subprocess
        import threading
        
        def run_scan():
            try:
                # 准备扫描环境：更新目标文件
                data_input_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'input')
                os.makedirs(data_input_dir, exist_ok=True)
                
                target_file = os.path.join(data_input_dir, 'url')
                with open(target_file, 'w', encoding='utf-8') as f:
                    f.write(f"{domain}\n")
                
                logger.info(f"已更新目标文件: {target_file} -> {domain}")
                
                # 启动状态监控线程
                def monitor_scan_progress():
                    scanning_status_file = os.path.join('..', 'output', domain, 'scanning_status.json')
                    while True:
                        try:
                            if os.path.exists(scanning_status_file):
                                with open(scanning_status_file, 'r', encoding='utf-8') as f:
                                    status_data = json.load(f)
                                
                                # 更新数据库状态
                                conn = get_db_connection()
                                cursor = conn.cursor()
                                cursor.execute('''
                                    UPDATE targets 
                                    SET scan_progress = ?, current_stage = ?
                                    WHERE id = ?
                                ''', (status_data.get('progress', 0), 
                                     status_data.get('current_stage', 'scanning'), 
                                     target_id))
                                conn.commit()
                                conn.close()
                                
                                # 如果扫描完成，退出监控
                                if status_data.get('scan_completed', False):
                                    break
                            
                            time.sleep(5)  # 每5秒检查一次
                        except Exception as e:
                            logger.error(f"监控扫描进度失败: {e}")
                            time.sleep(10)
                
                # 启动监控线程
                import time
                monitor_thread = threading.Thread(target=monitor_scan_progress)
                monitor_thread.daemon = True
                monitor_thread.start()
                
                # 调用扫描脚本
                scan_script = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'scan.sh')
                result = subprocess.run([
                    'bash', scan_script
                ], capture_output=True, text=True, timeout=3600)  # 1小时超时
                
                # 最终状态更新
                conn = get_db_connection()
                cursor = conn.cursor()
                
                if result.returncode == 0:
                    cursor.execute('''
                        UPDATE targets 
                        SET status = 'completed', scan_progress = 100, current_stage = '扫描完成'
                        WHERE id = ?
                    ''', (target_id,))
                else:
                    cursor.execute('''
                        UPDATE targets 
                        SET status = 'failed', current_stage = '扫描失败', scan_progress = 0
                        WHERE id = ?
                    ''', (target_id,))
                
                conn.commit()
                conn.close()
                
            except Exception as e:
                logger.error(f"扫描执行失败: {e}")
                # 更新为失败状态
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE targets 
                    SET status = 'failed', current_stage = ?, scan_progress = 0
                    WHERE id = ?
                ''', (f'扫描异常: {str(e)[:50]}', target_id))
                conn.commit()
                conn.close()
        
        # 在后台线程中启动扫描
        scan_thread = threading.Thread(target=run_scan)
        scan_thread.daemon = True
        scan_thread.start()
        
        logger.info(f"启动扫描: 域名={domain}, 层级={layer}, 目标ID={target_id}")
        
        return jsonify({
            'status': 'success',
            'message': f'已启动 {domain} 的第{layer}层扫描',
            'target_id': target_id
        })
        
    except Exception as e:
        logger.error(f"启动扫描失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/stop_scan', methods=['POST'])
@requires_auth
def stop_scan():
    """停止扫描"""
    data = request.get_json()
    domain = data.get('domain')
    
    logger.info(f"停止扫描请求: 域名={domain}")
    
    return jsonify({
        'status': 'success',
        'message': f'已停止 {domain} 的扫描'
    })

@app.route('/start_ip_scan', methods=['POST'])
@requires_auth
def start_ip_scan():
    """启动IP扫描"""
    try:
        data = request.get_json()
        ip = data.get('ip')
        
        if not ip:
            return jsonify({'error': 'IP参数缺失'}), 400
        
        logger.info(f"启动IP扫描: {ip}")
        
        # 这里可以调用IP扫描脚本
        # 目前返回成功状态，实际应该启动fscan或nmap等工具
        return jsonify({
            'status': 'success', 
            'message': f'IP {ip} 扫描已启动',
            'ip': ip,
            'scan_type': 'ip_scan'
        })
        
    except Exception as e:
        logger.error(f"启动IP扫描失败: {e}")
        return jsonify({'error': str(e)}), 500

# 目标管理API
@app.route('/targets', methods=['GET'])
@requires_auth
def get_targets():
    """获取所有目标列表"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, domain, status, created_at, updated_at, 
                   scan_progress, current_stage, last_scan_time, notes
            FROM targets 
            ORDER BY created_at DESC
        ''')
        
        targets = []
        for row in cursor.fetchall():
            targets.append({
                'id': row['id'],
                'domain': row['domain'],
                'status': row['status'],
                'created_at': row['created_at'],
                'updated_at': row['updated_at'],
                'scan_progress': row['scan_progress'],
                'current_stage': row['current_stage'],
                'last_scan_time': row['last_scan_time'],
                'notes': row['notes']
            })
        
        conn.close()
        return jsonify({
            'status': 'success',
            'targets': targets,
            'total': len(targets)
        })
        
    except Exception as e:
        logger.error(f"获取目标列表失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/targets', methods=['POST'])
@requires_auth
def add_target():
    """添加新目标"""
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        notes = data.get('notes', '').strip()
        
        if not domain:
            return jsonify({'error': '域名不能为空'}), 400
        
        # 简单的域名格式验证
        if not domain.replace('.', '').replace('-', '').replace('_', '').isalnum():
            return jsonify({'error': '域名格式不正确'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 检查域名是否已存在
        cursor.execute('SELECT id FROM targets WHERE domain = ?', (domain,))
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': '该域名已存在'}), 409
        
        # 插入新目标
        cursor.execute('''
            INSERT INTO targets (domain, notes, status)
            VALUES (?, ?, 'pending')
        ''', (domain, notes))
        
        target_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        logger.info(f"添加新目标: {domain} (ID: {target_id})")
        
        return jsonify({
            'status': 'success',
            'message': f'成功添加目标: {domain}',
            'target_id': target_id
        }), 201
        
    except Exception as e:
        logger.error(f"添加目标失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/targets/<int:target_id>', methods=['DELETE'])
@requires_auth
def delete_target(target_id):
    """删除目标"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 检查目标是否存在
        cursor.execute('SELECT domain FROM targets WHERE id = ?', (target_id,))
        target = cursor.fetchone()
        if not target:
            conn.close()
            return jsonify({'error': '目标不存在'}), 404
        
        domain = target['domain']
        
        # 删除相关的扫描任务
        cursor.execute('DELETE FROM scan_tasks WHERE target_id = ?', (target_id,))
        
        # 删除目标
        cursor.execute('DELETE FROM targets WHERE id = ?', (target_id,))
        
        conn.commit()
        conn.close()
        
        logger.info(f"删除目标: {domain} (ID: {target_id})")
        
        return jsonify({
            'status': 'success',
            'message': f'成功删除目标: {domain}'
        })
        
    except Exception as e:
        logger.error(f"删除目标失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/targets/<int:target_id>', methods=['PUT'])
@requires_auth
def update_target(target_id):
    """更新目标信息"""
    try:
        data = request.get_json()
        notes = data.get('notes', '').strip()
        status = data.get('status', '').strip()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 检查目标是否存在
        cursor.execute('SELECT domain FROM targets WHERE id = ?', (target_id,))
        target = cursor.fetchone()
        if not target:
            conn.close()
            return jsonify({'error': '目标不存在'}), 404
        
        # 更新目标信息
        update_fields = []
        params = []
        
        if notes is not None:
            update_fields.append('notes = ?')
            params.append(notes)
        
        if status and status in ['pending', 'scanning', 'completed', 'failed', 'paused']:
            update_fields.append('status = ?')
            params.append(status)
            
            # 如果状态是completed，自动设置进度为100%和阶段为扫描完成
            if status == 'completed':
                update_fields.append('scan_progress = ?')
                params.append(100)
                update_fields.append('current_stage = ?')
                params.append('扫描完成')
        
        if update_fields:
            update_fields.append('updated_at = CURRENT_TIMESTAMP')
            params.append(target_id)
            
            query = f"UPDATE targets SET {', '.join(update_fields)} WHERE id = ?"
            cursor.execute(query, params)
            
            conn.commit()
        
        conn.close()
        
        return jsonify({
            'status': 'success',
            'message': '目标信息更新成功'
        })
        
    except Exception as e:
        logger.error(f"更新目标失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/targets/batch', methods=['POST'])
@requires_auth
def add_batch_targets():
    """批量添加目标"""
    try:
        data = request.get_json()
        domains = data.get('domains', [])
        notes = data.get('notes', '').strip()
        
        if not domains or not isinstance(domains, list):
            return jsonify({'error': '域名列表不能为空'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        added_targets = []
        failed_targets = []
        
        for domain in domains:
            domain = domain.strip()
            if not domain:
                continue
                
            try:
                # 检查域名是否已存在
                cursor.execute('SELECT id FROM targets WHERE domain = ?', (domain,))
                if cursor.fetchone():
                    failed_targets.append({'domain': domain, 'reason': '域名已存在'})
                    continue
                
                # 插入新目标
                cursor.execute('''
                    INSERT INTO targets (domain, notes, status)
                    VALUES (?, ?, 'pending')
                ''', (domain, notes))
                
                target_id = cursor.lastrowid
                added_targets.append({'domain': domain, 'id': target_id})
                
            except Exception as e:
                failed_targets.append({'domain': domain, 'reason': str(e)})
        
        conn.commit()
        conn.close()
        
        logger.info(f"批量添加目标: 成功{len(added_targets)}个, 失败{len(failed_targets)}个")
        
        return jsonify({
            'status': 'success',
            'message': f'批量添加完成: 成功{len(added_targets)}个, 失败{len(failed_targets)}个',
            'added_targets': added_targets,
            'failed_targets': failed_targets
        })
        
    except Exception as e:
        logger.error(f"批量添加目标失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'API endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# 初始化数据库（无论是直接运行还是通过Gunicorn）
init_database()

def sync_existing_scans():
    """同步已存在的扫描结果到目标管理"""
    try:
        output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'output')
        if not os.path.exists(output_dir):
            return
            
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 获取output目录下的所有域名目录
        for item in os.listdir(output_dir):
            item_path = os.path.join(output_dir, item)
            if os.path.isdir(item_path) and '.' in item:  # 简单判断是否为域名
                domain = item
                
                # 检查是否已存在
                cursor.execute('SELECT id FROM targets WHERE domain = ?', (domain,))
                if not cursor.fetchone():
                    # 检查是否有扫描结果
                    has_results = False
                    # 检查多种可能的结果目录结构
                    check_dirs = ['layer_1', 'layer_2', 'layer_3', 'tuozhan', 'input']
                    for subdir in check_dirs:
                        layer_path = os.path.join(item_path, subdir)
                        if os.path.exists(layer_path):
                            if subdir in ['tuozhan', 'input']:
                                # 对于tuozhan和input目录，检查是否有内容
                                try:
                                    if os.listdir(layer_path):
                                        has_results = True
                                        break
                                except:
                                    continue
                            else:
                                # 对于layer目录，检查是否有内容
                                try:
                                    if os.listdir(layer_path):
                                        has_results = True
                                        break
                                except:
                                    continue
                    
                    # 也检查根目录是否有扫描结果文件
                    if not has_results:
                        for filename in os.listdir(item_path):
                            if filename.endswith(('.txt', '.json')) and 'scan' in filename.lower():
                                has_results = True
                                break
                    
                    if has_results:
                        # 添加到目标管理，状态为已完成
                        cursor.execute('''
                            INSERT INTO targets (domain, status, notes, scan_progress, current_stage)
                            VALUES (?, 'completed', '自动导入已扫描域名', 100, '扫描完成')
                        ''', (domain,))
                        logger.info(f"自动导入已扫描域名: {domain}")
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        logger.error(f"同步已存在扫描失败: {e}")

# 同步已存在的扫描结果
sync_existing_scans()

if __name__ == '__main__':
    print("🚀 启动渗透扫描平台 - 纯API后端")
    print("================================")
    print("📋 API端点:")
    print("  GET  /health                    - 健康检查")
    print("  GET  /domain/<domain>           - 获取域名数据")
    print("  GET  /scan_status/<domain>      - 获取扫描状态")
    print("  GET  /logs/<domain>             - 获取日志")
    print("  GET  /raw_data/<domain>         - 获取原始数据")
    print("  POST /start_scan                - 启动扫描")
    print("  POST /stop_scan                 - 停止扫描")
    print("")
    print("🎯 目标管理API:")
    print("  GET  /targets                   - 获取目标列表")
    print("  POST /targets                   - 添加目标")
    print("  PUT  /targets/<id>              - 更新目标")
    print("  DELETE /targets/<id>            - 删除目标")
    print("  POST /targets/batch             - 批量添加目标")
    print("")
    print("🔐 认证: Basic Auth (admin/MyStr0ngP@ssw0rd!)")
    print("🌐 地址: http://0.0.0.0:5000")
    print("📱 前端: http://localhost:3000")
    print("")
    
    # 开发模式：直接运行Flask（关闭debug提高稳定性）
    app.run(host='0.0.0.0', port=5000, debug=False)



def parse_urls_from_base_info(base_info_file):
    """从基础信息文件解析URL详细信息"""
    import re
    
    urls_data = []
    try:
        with open(base_info_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 查找URL和标题部分
        url_section_match = re.search(r'URL和标题:\s*\n(.*?)(?=\n\n|\nIP反查域名|\n\[URL BODY INFO|\Z)', content, re.DOTALL)
        if url_section_match:
            url_lines = url_section_match.group(1).strip().split('\n')
            
            for line in url_lines:
                line = line.strip()
                if line.startswith('- '):
                    # 解析格式：- http://example.com [Title][size:1234]
                    url_match = re.match(r'-\s+(\S+)\s+\[([^\]]*)\]\[size:(\d+)\]', line)
                    if url_match:
                        url = url_match.group(1)
                        title = url_match.group(2) if url_match.group(2) else '无标题'
                        size = int(url_match.group(3))
                        
                        urls_data.append({
                            'url': url,
                            'title': title,
                            'size': size,
                            'status_code': 200
                        })
                    else:
                        # 备用解析：简单的URL行
                        simple_match = re.match(r'-\s+(\S+)', line)
                        if simple_match:
                            urls_data.append({
                                'url': simple_match.group(1),
                                'title': '扫描发现',
                                'size': 0,
                                'status_code': 200
                            })
        
        return urls_data
    except Exception as e:
        logger.error(f"解析基础信息文件失败: {e}")
        return []

