#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
基于配置文件的Web报告服务器
支持YAML配置文件管理所有设置
"""

from flask import Flask, render_template, jsonify, request, send_from_directory, redirect
from flask_cors import CORS
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
import json
import os
import sys
import yaml
import ipaddress
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import datetime
import re
import time
from collections import defaultdict
from web.utils.domain_filter import is_valid_domain, is_related_domain, clean_url_to_domain

# 导入Web调试日志系统
try:
    from web_debug_logger import web_logger
    WEB_DEBUG_ENABLED = True
    print("✅ Web调试日志系统已启用")
except ImportError:
    WEB_DEBUG_ENABLED = False
    print("⚠️  Web调试日志系统未启用")

# 加载配置文件
CONFIG_FILE = Path("config/web_config.yaml")
if not CONFIG_FILE.exists():
    print(f"❌ 配置文件不存在: {CONFIG_FILE}")
    print("请确保 config/web_config.yaml 文件存在")
    sys.exit(1)

with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
    config = yaml.safe_load(f)

app = Flask(__name__, 
           template_folder='templates',
           static_folder='static')
CORS(app)

# 配置日志
if config['logging']['enabled']:
    log_dir = Path(config['logging']['file']).parent
    log_dir.mkdir(exist_ok=True)
    
    # 解析文件大小
    max_size_str = config['logging']['max_size']
    if max_size_str.endswith('MB'):
        max_bytes = int(max_size_str[:-2]) * 1024 * 1024
    elif max_size_str.endswith('KB'):
        max_bytes = int(max_size_str[:-2]) * 1024
    else:
        max_bytes = int(max_size_str)
    
    file_handler = RotatingFileHandler(
        config['logging']['file'],
        maxBytes=max_bytes,
        backupCount=config['logging']['backup_count']
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(getattr(logging, config['logging']['level']))
    app.logger.addHandler(file_handler)
    app.logger.setLevel(getattr(logging, config['logging']['level']))
    app.logger.info('Web报告服务启动')

# 基础认证
auth = HTTPBasicAuth()

# 用户配置
if config['auth']['enabled']:
    users = {
        config['auth']['username']: generate_password_hash(config['auth']['password'])
    }
    
    @auth.verify_password
    def verify_password(username, password):
        if username in users and check_password_hash(users.get(username), password):
            app.logger.info(f'用户 {username} 登录成功')
            return username
        app.logger.warning(f'登录失败: {username}')
        return None
else:
    # 如果不启用认证，创建一个空的装饰器
    auth.login_required = lambda f: f

# 安全配置
app.config['SECRET_KEY'] = config['security']['secret_key']
app.config['SESSION_COOKIE_SECURE'] = config['security']['session_cookie_secure']
app.config['SESSION_COOKIE_HTTPONLY'] = config['security']['session_cookie_httponly']
app.config['SESSION_COOKIE_SAMESITE'] = config['security']['session_cookie_samesite']

# IP白名单检查
def check_ip_whitelist():
    """检查访问IP是否在白名单中"""
    whitelist = config.get('ip_whitelist', [])
    if not whitelist:  # 如果没有设置白名单，允许所有
        return True
    
    client_ip = request.remote_addr
    # 处理代理情况
    if request.headers.get('X-Forwarded-For'):
        client_ip = request.headers['X-Forwarded-For'].split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        client_ip = request.headers['X-Real-IP']
    
    client_addr = ipaddress.ip_address(client_ip)
    
    # 检查每个白名单项
    for allowed in whitelist:
        try:
            # 尝试作为单个IP解析
            if client_addr == ipaddress.ip_address(allowed):
                return True
        except ValueError:
            # 尝试作为CIDR网段解析
            try:
                if client_addr in ipaddress.ip_network(allowed, strict=False):
                    return True
            except ValueError:
                app.logger.error(f'无效的IP白名单配置: {allowed}')
    
    app.logger.warning(f'IP {client_ip} 不在白名单中')
    return False

@app.before_request
def before_request():
    """请求前检查"""
    # IP白名单检查
    if not check_ip_whitelist():
        return jsonify({'error': 'Forbidden', 'message': 'Your IP is not allowed'}), 403
    
    # 记录访问日志
    if config['logging']['enabled']:
        app.logger.info(f'{request.remote_addr} - {request.method} {request.path}')

# 配置
OUTPUT_DIR = Path(config['data']['output_dir'])
PROJECT_ROOT = Path(__file__).parent.parent  # 指向项目根目录，不是web目录

# 简单的数据收集器类
class SimpleDataCollector:
    def __init__(self, output_dir):
        self.output_dir = Path(output_dir)
        
    def get_all_domains(self):
        """获取所有域名列表"""
        domains = []
        if not self.output_dir.exists():
            return domains
            
        for domain_dir in self.output_dir.iterdir():
            if domain_dir.is_dir() and domain_dir.name and domain_dir.name != 'undefined':
                # 检查扫描状态
                scanning_status_file = domain_dir / "scanning_status.json"
                finish_file = domain_dir / "finish.txt"
                
                status = 'unknown'
                scan_time = '未知'
                layers = 1
                
                if scanning_status_file.exists():
                    try:
                        with open(scanning_status_file, 'r', encoding='utf-8') as f:
                            scan_status = json.load(f)
                        
                        if scan_status.get('scan_completed', False) or finish_file.exists():
                            status = 'completed'
                        else:
                            status = 'scanning'
                        
                        scan_time = scan_status.get('start_time', '未知')
                        layers = scan_status.get('layers', 1)
                    except:
                        status = 'unknown'
                elif finish_file.exists():
                    status = 'completed'
                    scan_time = datetime.fromtimestamp(finish_file.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                
                domains.append({
                    'name': domain_dir.name,
                    'status': status,
                    'layers': layers,
                    'scan_time': scan_time
                })
        
        return sorted(domains, key=lambda x: x.get('scan_time', ''), reverse=True)
    
    def get_domain_summary(self, domain):
        """获取域名摘要"""
        domain_dir = self.output_dir / domain
        if not domain_dir.exists():
            return None
            
        summary = {
            'domain': domain,
            'total_urls': 0,
            'total_ips': 0,
            'total_domains': 0,
            'vulnerabilities': 0,
            'layers': 1
        }
        
        # 统计所有发现的URL
        urls = set()
        
        # 1. 基础URL文件
        urls_file = domain_dir / "input" / "urls.txt"
        if urls_file.exists():
            try:
                content = urls_file.read_text(encoding='utf-8')
                for line in content.split('\n'):
                    line = line.strip()
                    if line and line.startswith('http'):
                        urls.add(line)
            except:
                pass
        
        # 2. FOFA证书发现的URL
        fofa_dir = domain_dir / "tuozhan" / "fofa"
        if fofa_dir.exists():
            for cert_file in fofa_dir.glob("cert_*.txt"):
                try:
                    content = cert_file.read_text(encoding='utf-8')
                    for line in content.split('\n'):
                        line = line.strip()
                        if line and line.startswith('http') and not line.startswith('#'):
                            urls.add(line)
                except:
                    pass
        
        summary['total_urls'] = len(urls)
        
        # 统计IP数量
        ips = set()
        a_records_file = domain_dir / "input" / "all_a_records.txt"
        if a_records_file.exists():
            try:
                content = a_records_file.read_text(encoding='utf-8')
                for line in content.split('\n'):
                    line = line.strip()
                    if line and re.match(r'^\d+\.\d+\.\d+\.\d+', line):
                        ip = line.split()[0]
                        ips.add(ip)
            except:
                pass
        
        summary['total_ips'] = len(ips)
        
        # 统计发现的域名数量
        scanning_status_file = domain_dir / "scanning_status.json" 
        if scanning_status_file.exists():
            try:
                with open(scanning_status_file, 'r', encoding='utf-8') as f:
                    scan_status = json.load(f)
                    
                summary['layers'] = scan_status.get('layers', 1)
                
                # 统计发现的域名
                discovered_domains = scan_status.get('discovered_domains', {})
                summary['total_domains'] = discovered_domains.get('total', 0)
            except:
                pass
        
        return summary
    
    def get_domain_detail(self, domain):
        """获取域名详细数据"""
        domain_dir = self.output_dir / domain
        if not domain_dir.exists():
            return None
            
        detail = {
            'domain': domain,
            'layers': {}
        }
        
        urls = []
        ips = []
        domains = []
        
        # 1. 读取基础URL文件
        urls_file = domain_dir / "input" / "urls.txt"
        if urls_file.exists():
            try:
                content = urls_file.read_text(encoding='utf-8')
                for line in content.split('\n'):
                    line = line.strip()
                    if line and line.startswith('http'):
                        urls.append({
                            'url': line,
                            'title': '基础扫描发现',
                            'size': '-'
                        })
            except Exception as e:
                app.logger.warning(f'读取URLs文件失败: {e}')
        
        # 2. 读取FOFA发现的URL
        fofa_dir = domain_dir / "tuozhan" / "fofa"
        if fofa_dir.exists():
            for cert_file in fofa_dir.glob("cert_*.txt"):
                try:
                    content = cert_file.read_text(encoding='utf-8')
                    for line in content.split('\n'):
                        line = line.strip()
                        if line and line.startswith('http') and not line.startswith('#'):
                            # 检查是否已存在
                            if not any(u['url'] == line for u in urls):
                                urls.append({
                                    'url': line,
                                    'title': 'FOFA证书发现',
                                    'size': '-'
                                })
                except Exception as e:
                    app.logger.warning(f'读取FOFA证书文件失败: {e}')
        
        # 3. 读取A记录IP
        a_records_file = domain_dir / "input" / "all_a_records.txt"
        if a_records_file.exists():
            try:
                content = a_records_file.read_text(encoding='utf-8')
                for line in content.split('\n'):
                    line = line.strip()
                    if line and re.match(r'^\d+\.\d+\.\d+\.\d+', line):
                        ip = line.split()[0]
                        if not any(i.get('ip') == ip for i in ips):
                            ips.append({'ip': ip})
            except Exception as e:
                app.logger.warning(f'读取A记录文件失败: {e}')
        
        # 4. 从扫描状态文件读取发现的域名
        scanning_status_file = domain_dir / "scanning_status.json"
        if scanning_status_file.exists():
            try:
                with open(scanning_status_file, 'r', encoding='utf-8') as f:
                    scan_status = json.load(f)
                
                discovered_domains = scan_status.get('discovered_domains', {}).get('domains', [])
                for discovered_domain in discovered_domains:
                    if not discovered_domain.startswith('http'):
                        domains.append({
                            'domain': discovered_domain,
                            'method': '扫描发现'
                        })
            except Exception as e:
                app.logger.warning(f'读取扫描状态失败: {e}')
        
        detail['layers']['1'] = {
            'urls': urls,
            'ips': ips,
            'domains': domains,
            'vulnerabilities': []
        }
        
        return detail

# 创建数据收集器实例
data_collector = SimpleDataCollector(OUTPUT_DIR)

class ScanDataCollector:
    """扫描数据收集器"""
    
    def __init__(self, output_dir):
        self.output_dir = Path(output_dir)
        self._cache = {}  # 简单内存缓存
        self._cache_timeout = 300  # 5分钟缓存超时
    
    def get_all_domains(self):
        """获取所有已扫描的域名（带缓存）"""
        cache_key = 'all_domains'
        cached = self._get_from_cache(cache_key)
        if cached:
            # 确保返回正确的数据格式
            if isinstance(cached, tuple) and len(cached) == 2:
                return cached[1]  # 返回数据部分
            elif isinstance(cached, list):
                return cached  # 直接是数据列表
            else:
                app.logger.warning(f"缓存数据格式异常: {type(cached)}")
                # 清除异常缓存
                if cache_key in self._cache:
                    del self._cache[cache_key]
            
        domains = []
        if self.output_dir.exists():
            for domain_dir in self.output_dir.iterdir():
                # 严格验证域名目录名
                if (domain_dir.is_dir() and 
                    domain_dir.name and 
                    isinstance(domain_dir.name, str) and 
                    '.' in domain_dir.name and 
                    domain_dir.name != 'undefined' and
                    domain_dir.name.strip() != ''):
                    finish_file = domain_dir / "finish.txt"
                    scanning_status_file = domain_dir / "scanning_status.json"
                    
                    # 优先检查scanning_status.json中的scan_completed字段
                    scan_completed = False
                    scan_status_data = None
                    
                    if scanning_status_file.exists():
                        try:
                            with open(scanning_status_file, 'r', encoding='utf-8') as f:
                                scan_status_data = json.load(f)
                                scan_completed = scan_status_data.get('scan_completed', False)
                        except Exception:
                            pass
                    
                    if scan_completed or finish_file.exists():
                        # 已完成扫描的域名
                    if finish_file.exists():
                            scan_time = datetime.fromtimestamp(finish_file.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                        elif scan_status_data and scan_status_data.get('end_time'):
                            scan_time = scan_status_data.get('end_time', '未知')
                        else:
                            scan_time = datetime.fromtimestamp(scanning_status_file.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                            
                        # 再次验证域名有效性
                        domain_name = domain_dir.name.strip() if domain_dir.name else ''
                        if domain_name and domain_name != 'undefined':
                        domains.append({
                                'name': domain_name,
                                'scan_time': scan_time,
                                'layers': self._count_layers(domain_dir),
                                'status': 'completed'
                            })
                    elif scanning_status_file.exists():
                        # 正在扫描或未完成的域名
                        try:
                            with open(scanning_status_file, 'r', encoding='utf-8') as f:
                                scan_status = json.load(f)
                            
                            # 检查是否真的在扫描中
                            is_scanning = not scan_status.get('scan_completed', False)
                            status = 'scanning' if is_scanning else 'failed'
                            
                            # 验证域名有效性
                            domain_name = domain_dir.name.strip() if domain_dir.name else ''
                            if domain_name and domain_name != 'undefined':
                                domains.append({
                                    'name': domain_name,
                                    'scan_time': scan_status.get('start_time', 'Unknown'),
                                    'layers': 1,  # 扫描中默认为1层
                                    'status': status,
                                    'progress': scan_status.get('progress', 0),
                                    'current_stage': scan_status.get('current_stage', 'Unknown')
                                })
                        except Exception as e:
                            # 如果读取状态文件失败，仍然显示域名但标记为错误
                            domain_name = domain_dir.name.strip() if domain_dir.name else ''
                            if domain_name and domain_name != 'undefined':
                                domains.append({
                                    'name': domain_name,
                                    'scan_time': datetime.fromtimestamp(domain_dir.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                                    'layers': 1,
                                    'status': 'error'
                                })
        
        result = sorted(domains, key=lambda x: (x.get('status') == 'scanning', x['scan_time']), reverse=True)
        self._set_cache(cache_key, result)
        return result
    
    def _count_layers(self, domain_dir):
        """统计扫描层数"""
        layers = 1  # 默认有第一层
        expansion_dir = domain_dir / "expansion"
        if expansion_dir.exists():
            # 检查是否有第二层
            report_dir = expansion_dir / "report"
            if report_dir.exists() and any(report_dir.iterdir()):
                layers = 2
                # 检查是否有第三层
                layer3_dir = expansion_dir / "layer3" / "report"
                if layer3_dir.exists() and any(layer3_dir.iterdir()):
                    layers = 3
        return layers
    
    def _get_from_cache(self, key, max_age=None):
        """从缓存获取数据"""
        if key in self._cache:
            cache_time, data = self._cache[key]
            timeout = max_age if max_age is not None else self._cache_timeout
            if time.time() - cache_time < timeout:
                return (cache_time, data)
            else:
                # 过期了，删除缓存
                del self._cache[key]
        return None
    
    def _set_cache(self, key, data):
        """设置缓存"""
        self._cache[key] = (time.time(), data)
    
    def clear_cache(self):
        """清空缓存"""
        self._cache.clear()
    
    def _parse_base_info_comprehensive(self, base_info_file):
        """解析base_info文件中的URL、标题和IP信息"""
        urls = []
        ips = []
        
        try:
            content = base_info_file.read_text(encoding='utf-8')
            lines = content.splitlines()
            
            # 状态标记
            in_url_section = False
            in_ip_section = False
            
            for line in lines:
                line_stripped = line.strip()
                
                # 检查URL和标题部分
                if 'URL和标题:' in line:
                    in_url_section = True
                    in_ip_section = False
                    continue
                elif '关联真实IP:' in line or 'IP地址:' in line:
                    in_ip_section = True
                    in_url_section = False
                    continue
                elif line_stripped == '':
                    in_url_section = False
                    in_ip_section = False
                    continue
                
                # 解析URL部分
                if in_url_section and line_stripped.startswith('- '):
                    # 解析URL行，格式: - URL [标题][size:xxx]
                    line_content = line_stripped[2:]  # 去掉 "- "
                    
                    # URL是第一个空格之前的内容
                    space_idx = line_content.find(' ')
                    if space_idx > 0:
                        url = line_content[:space_idx]
                        rest = line_content[space_idx+1:]
                    else:
                        url = line_content
                        rest = ''
                    
                    title = ''
                    size = 0
                    
                    if rest:
                        # 提取标题和大小
                        # 处理格式: [标题][size:xxx]
                        brackets = re.findall(r'\[([^\]]*)\]', rest)
                        
                        if len(brackets) >= 2:
                            # 第一个是标题，第二个是size
                            title = brackets[0]
                            # 提取size数值
                            size_match = re.search(r'size:(\d+)', brackets[1])
                            if size_match:
                                size = int(size_match.group(1))
                        elif len(brackets) == 1:
                            # 只有一个方括号，可能是标题或size
                            if 'size:' in brackets[0]:
                                size_match = re.search(r'size:(\d+)', brackets[0])
                                if size_match:
                                    size = int(size_match.group(1))
                            else:
                                title = brackets[0]
                    
                    urls.append({
                        'url': url,
                        'title': title,
                        'size': size
                    })
                
                # 解析IP部分
                elif in_ip_section and line_stripped.startswith('- '):
                    # 解析IP行，格式: - IP地址
                    ip = line_stripped[2:].strip()  # 去掉 "- "
                    if ip and self._is_valid_ip(ip):
                        ips.append(ip)
                        
        except Exception as e:
            app.logger.error(f"解析base_info文件失败: {e}")
        
        return urls, ips
    
    def _is_valid_ip(self, ip):
        """验证IP地址格式是否正确"""
        try:
            import ipaddress
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def get_domain_summary(self, domain):
        """获取域名扫描摘要（健壮缓存版本）"""
        cache_key = f'domain_summary_{domain}'
        
        # 检查缓存是否过期（60秒）
        cached = self._get_from_cache(cache_key, max_age=60)
        
        # 如果数据文件比缓存更新，强制刷新缓存
        domain_dir = self.output_dir / domain
        if cached and domain_dir.exists():
            try:
                # 检查关键文件的修改时间
                key_files = [
                    domain_dir / f"base_info_{domain}.txt",
                    domain_dir / "input" / "urls.txt", 
                    domain_dir / "input" / "a_records.txt",
                    domain_dir / "scanning_status.json"
                ]
                
                latest_mtime = 0
                for file_path in key_files:
                    if file_path.exists():
                        latest_mtime = max(latest_mtime, file_path.stat().st_mtime)
                
                # 如果文件比缓存更新，清除缓存
                if isinstance(cached, tuple) and len(cached) == 2:
                    cache_time, cached_data = cached
                    if latest_mtime > cache_time:
                        if WEB_DEBUG_ENABLED:
                            web_logger.log_debug("数据文件更新，清除缓存", {
                                'domain': domain,
                                'latest_mtime': latest_mtime,
                                'cache_time': cache_time
                            })
                        cached = None
                    else:
                        cached = cached_data  # 使用缓存的数据
                else:
                    # 缓存格式不正确，清除
                    cached = None
            except Exception as e:
                app.logger.warning(f"检查缓存时间失败 {domain}: {e}")
                cached = None
        elif cached and isinstance(cached, tuple):
            # 直接提取数据部分
            cached = cached[1] if len(cached) == 2 else None
        
        if cached:
            return cached
            
        domain_dir = self.output_dir / domain
        
        # 检查域名目录是否存在
        if not domain_dir.exists():
            return None
            
        summary = {
            'domain': domain,
            'layers': {},
            'total_urls': 0,
            'total_ips': 0,
            'total_domains': 0,
            'vulnerabilities': 0,
            'ports': 0,
            'subdomains_total': 0,
            'subdomains_alive': 0
        }
        
        # 第一层数据
        layer1_data = self._collect_layer_data(domain_dir, 1)
        if layer1_data is None:
            return None
        if layer1_data:
            summary['layers'][1] = layer1_data
            # 统计基础URL和扩展URL（不包含未扫描的扩展URL）
            summary['total_urls'] += len(layer1_data.get('urls', []))
            summary['total_urls'] += len(layer1_data.get('expand_scanned_urls', []))
            # summary['total_urls'] += len(layer1_data.get('expand_urls', [])) # 已隐藏，不统计
            
            summary['total_ips'] += len(layer1_data.get('ips', []))
            summary['total_domains'] += len(layer1_data.get('domains', []))
            summary['total_domains'] += len(layer1_data.get('expand_domains', []))
            summary['vulnerabilities'] += len(layer1_data.get('vulnerabilities', []))
            
            # 扩展资产的漏洞
            if layer1_data.get('expand_quick_scan') and layer1_data['expand_quick_scan'].get('afrog_urls'):
                summary['vulnerabilities'] += len(layer1_data['expand_quick_scan']['afrog_urls'])
            
            summary['ports'] += len(layer1_data.get('fscan_results', []))
        
        # 统计子域名信息
        try:
            # 1. 从result_all.json提取所有input域名作为总子域名数
            result_file = domain_dir / 'result_all.json'
            if result_file.exists():
                import json
                unique_inputs = set()
                for line in result_file.read_text().splitlines():
                    if line.strip():
                        try:
                            data = json.loads(line)
                            if 'input' in data:
                                unique_inputs.add(data['input'])
                        except:
                            continue
                summary['subdomains_total'] = len(unique_inputs)
            
            # 2. 统计存活子域名数量（从input/urls.txt文件）
            urls_file = domain_dir / 'input' / 'urls.txt'
            if urls_file.exists():
                urls_content = urls_file.read_text().strip()
                if urls_content:
                    # 从URL中提取域名部分统计
                    alive_domains = set()
                    for line in urls_content.splitlines():
                        if line.strip():
                            try:
                                from urllib.parse import urlparse
                                domain_part = urlparse(line.strip()).netloc
                                if domain_part:
                                    alive_domains.add(domain_part)
                            except:
                                continue
                    summary['subdomains_alive'] = len(alive_domains)
                    
            # 如果没有result_all.json但有存活的，则总数等于存活数
            if summary['subdomains_total'] == 0 and summary['subdomains_alive'] > 0:
                summary['subdomains_total'] = summary['subdomains_alive']
                
        except Exception as e:
            app.logger.warning(f"读取子域名统计信息失败 {domain}: {e}")
        
        # 缓存结果
        self._set_cache(cache_key, summary)
        return summary
    
    def _collect_layer_data(self, base_dir, layer_num):
        """收集特定层的数据（健壮版本）"""
        # 如果基础目录不存在，直接返回None
        if not base_dir.exists():
            app.logger.warning(f"域名目录不存在: {base_dir}")
            return None
            
        data = {
            'urls': [],
            'ips': [],
            'domains': [],
            'expand_domains': [],
            'expand_ips': [],
            'expand_urls': [],
            'vulnerabilities': [],
            'fscan_results': [],
            'relationships': {},
            'expand_quick_scan': {}
        }
        
        # 读取base_info文件获取URL、标题和IP信息（单一数据源）
        base_info_file = base_dir / f"base_info_{base_dir.name}.txt"
        if base_info_file.exists():
            try:
                url_data, ip_data = self._parse_base_info_comprehensive(base_info_file)
                data['urls'] = url_data or []
                data['ips'] = ip_data or []
                
                if WEB_DEBUG_ENABLED:
                    web_logger.log_debug(f"从base_info解析数据", {
                        'domain': base_dir.name,
                        'urls_count': len(data['urls']),
                        'ips_count': len(data['ips']),
                        'file_size': base_info_file.stat().st_size
                    })
                    
                    # 如果IP为空，记录分析信息但不修改数据
                    if not data['ips']:
                        web_logger.log_debug(f"base_info文件IP为空", {
                            'domain': base_dir.name,
                            'base_info_exists': True,
                            'file_size': base_info_file.stat().st_size,
                            'possible_cause': 'domain_resolution_failed_during_scan'
                        })
                        
            except Exception as e:
                app.logger.error(f"解析base_info失败 {base_dir.name}: {e}")
        else:
            # 如果没有base_info文件，尝试使用urls.txt作为备选
            urls_file = base_dir / "input" / "urls.txt"
            if urls_file.exists():
                try:
                    content = urls_file.read_text().strip()
                    if content:
                data['urls'] = [{'url': line.strip(), 'title': '', 'size': 0} 
                                       for line in content.splitlines() if line.strip()]
                        if WEB_DEBUG_ENABLED:
                            web_logger.log_debug(f"使用urls.txt作为备选数据源", {
                                'domain': base_dir.name,
                                'urls_count': len(data['urls']),
                                'reason': 'base_info_file_missing'
                            })
                except Exception as e:
                    app.logger.warning(f"读取URLs文件失败 {urls_file}: {e}")
        
        # 读取域名发现关系
        relationships_file = base_dir / "domain_discovery_relationships.json"
        if relationships_file.exists():
            try:
                import json
                data['relationships'] = json.loads(relationships_file.read_text())
            except:
                pass
        
        # 读取漏洞信息
        afrog_file = base_dir / f"afrog_report_{base_dir.name}.json"
        if afrog_file.exists():
            data['vulnerabilities'] = self._parse_afrog_results(afrog_file)
        
        # 读取fscan结果
        fscan_file = base_dir / f"fscan_result_{base_dir.name}.txt"
        if fscan_file.exists():
            data['fscan_results'] = self._parse_fscan_results(fscan_file)
        
        # 读取扩展资产
        tuozhan_dir = base_dir / "tuozhan" / "all_tuozhan"
        if tuozhan_dir.exists():
            # 读取扩展域名
            expand_domains_file = tuozhan_dir / "root_domains.txt"
            if expand_domains_file.exists():
                data['expand_domains'] = [line.strip() for line in expand_domains_file.read_text().splitlines() if line.strip()]
            
            # 读取扩展IP
            expand_ips_file = tuozhan_dir / "ips.txt"
        if expand_ips_file.exists():
                data['expand_ips'] = [line.strip() for line in expand_ips_file.read_text().splitlines() if line.strip()]
        
            # 读取扩展URL
            expand_urls_file = tuozhan_dir / "urls.txt"
        if expand_urls_file.exists():
                data['expand_urls'] = [line.strip() for line in expand_urls_file.read_text().splitlines() if line.strip()]
        
        return data



    def _parse_afrog_results(self, afrog_file):
        """解析afrog漏洞扫描结果"""
        vulnerabilities = []
        try:
            import json
            content = afrog_file.read_text()
            for line in content.splitlines():
                            if line.strip():
                    try:
                        vuln = json.loads(line)
                        vulnerabilities.append(vuln)
                    except:
                        continue
                except:
                    pass
        return vulnerabilities

    def _parse_fscan_results(self, fscan_file):
        """解析fscan扫描结果"""
        results = []
        try:
            content = fscan_file.read_text()
            for line in content.splitlines():
                if line.strip():
                    results.append(line.strip())
                except:
                    pass
        return results

# 初始化数据收集器
collector = ScanDataCollector(OUTPUT_DIR)

# ==================== 路由定义 ====================

@app.route('/')
@auth.login_required
def index():
    """首页"""
    return render_template('index.html')

@app.route('/domain/<domain>')
@auth.login_required
def domain_detail(domain):
    """域名详情页面"""
    # 验证域名参数
    if not domain or domain == 'undefined' or domain == 'None' or domain.strip() == '':
        app.logger.warning(f'访问域名详情页时域名参数无效: {domain}')
        # 重定向到首页而不是显示错误页面
        from flask import redirect, url_for, flash
        flash('域名参数无效，已重定向到首页', 'warning')
        return redirect(url_for('index'))
    
    # 清理域名参数
    clean_domain = domain.strip()
    app.logger.info(f'访问域名详情页: {clean_domain}')
    
    return render_template('domain.html', domain=clean_domain)

@app.route('/graph')
@auth.login_required
def graph():
    """关系图谱页面"""
    return render_template('graph.html')

# ==================== API路由 ====================

# 重复的API路由已删除

@app.route('/api/domain/<domain>/summary')
@auth.login_required
def api_domain_summary(domain):
    """获取域名扫描摘要"""
    try:
    summary = collector.get_domain_summary(domain)
        if summary is None:
            return jsonify({
                'status': 'error',
                'message': '域名不存在'
            }), 404
        
        return jsonify({
            'status': 'success',
            'data': summary
        })
    except Exception as e:
        app.logger.error(f'获取域名摘要失败: {e}')
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/domain/<domain>/detail')
@auth.login_required
def api_domain_detail(domain):
    """获取域名详细扫描数据"""
    start_time = time.time()
    user = auth.current_user()
    
    if WEB_DEBUG_ENABLED:
        web_logger.log_debug(f"API请求: 获取域名详细数据", {'domain': domain, 'user': user})
    
    try:
        domain_dir = OUTPUT_DIR / domain
        
        if not domain_dir.exists():
        return jsonify({
                'status': 'error',
                'message': '域名不存在'
            }), 404
        
        # 获取基本摘要信息
        summary = collector.get_domain_summary(domain)
        if summary is None:
            return jsonify({
                'status': 'error',
                'message': '域名数据不存在'
            }), 404
        
        # 扩展详细信息
        detail = {
            'domain': domain,
            'summary': summary,
            'layers': {},
            'scan_status': 'completed',
            'scan_progress': 100
        }
        
        # 检查扫描状态
        scanning_status_file = domain_dir / "scanning_status.json"
        finish_file = domain_dir / "finish.txt"
        
        if scanning_status_file.exists() and not finish_file.exists():
            try:
                with open(scanning_status_file, 'r', encoding='utf-8') as f:
                    scan_status = json.load(f)
                detail['scan_status'] = 'scanning' if not scan_status.get('scan_completed', False) else 'failed'
                detail['scan_progress'] = scan_status.get('progress', 0)
                detail['current_stage'] = scan_status.get('current_stage', 'Unknown')
            except Exception as e:
                app.logger.warning(f'读取扫描状态失败: {e}')
        
        # 获取层级详细数据
        for layer_num, layer_data in summary.get('layers', {}).items():
            detail['layers'][layer_num] = layer_data
        
        response_data = {
            'status': 'success',
            'data': detail
        }
        
        # 记录API调用日志
        if WEB_DEBUG_ENABLED:
            duration = time.time() - start_time
            web_logger.log_api_request(
                method='GET',
                endpoint=f'/api/domain/{domain}/detail',
                user=user,
                status_code=200,
                duration=duration,
                extra_data={
                    'domain': domain,
                    'scan_status': detail['scan_status'],
                    'scan_progress': detail['scan_progress'],
                    'layers_count': len(detail['layers'])
                }
            )
        
        return jsonify(response_data)
    except Exception as e:
        app.logger.error(f'获取域名详情失败: {e}')
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/domain/<domain>/logs')
@auth.login_required
def api_domain_logs(domain):
    """获取域名扫描日志"""
    try:
        domain_dir = OUTPUT_DIR / domain
        logs = []
        
        # 如果域名目录不存在，返回提示日志
        if not domain_dir.exists():
            logs.extend([
                {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'level': 'INFO',
                    'stage': 'init',
                    'message': f'域名 {domain} 尚未开始扫描或数据已被清理',
                    'content': f'域名 {domain} 尚未开始扫描或数据已被清理',
                    'details': {}
                },
                {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'level': 'INFO', 
                    'stage': 'info',
                    'message': '可以在首页点击"开始扫描"来启动新的扫描任务',
                    'content': '可以在首页点击"开始扫描"来启动新的扫描任务',
                    'details': {}
                },
                {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'level': 'INFO',
                    'stage': 'tip',
                    'message': '扫描完成后，将在此处显示详细的终端日志信息',
                    'content': '扫描完成后，将在此处显示详细的终端日志信息',
                    'details': {}
                }
            ])
            return jsonify({
                'status': 'success',
                'data': logs
            })
        
        # 读取扫描状态日志
        scanning_status_file = domain_dir / "scanning_status.json"
        if scanning_status_file.exists():
            try:
                with open(scanning_status_file, 'r', encoding='utf-8') as f:
                    scan_status = json.load(f)
                
                # 添加扫描开始日志
                logs.append({
                    'timestamp': scan_status.get('start_time', ''),
                    'level': 'INFO',
                    'stage': 'init',
                    'message': f'开始扫描域名 {domain}',
                    'content': f'开始扫描域名 {domain}，模式: {scan_status.get("mode", "未知")}',
                    'details': {'mode': scan_status.get('mode', '未知')}
                })
                
                # 从状态文件中提取日志信息
                if 'scan_stages' in scan_status:
                    for stage_name, stage_info in scan_status['scan_stages'].items():
                        status = stage_info.get('status', 'pending')
                        if status != 'pending':  # 只显示已开始的阶段
                            stage_label = {
                                'subdomain_discovery': '子域名发现',
                                'http_probe': 'HTTP探测', 
                                'vulnerability_scan': '漏洞扫描',
                                'port_scan': '端口扫描',
                                'report_generation': '报告生成'
                            }.get(stage_name, stage_name)
                            
                            status_text = {
                                'completed': '已完成',
                                'running': '运行中',
                                'failed': '失败'
                            }.get(status, status)
                            
                            log_entry = {
                                'timestamp': stage_info.get('start_time', ''),
                                'level': 'SUCCESS' if status == 'completed' else 'INFO',
                                'stage': stage_name,
                                'message': f"{stage_label} 阶段{status_text}",
                                'content': f"[{stage_info.get('start_time', '')}] {stage_label} 阶段{status_text}",
                                'details': stage_info
                            }
                            logs.append(log_entry)
                
                # 添加总体扫描信息
                if scan_status.get('scan_completed'):
                    logs.append({
                        'timestamp': scan_status.get('end_time', ''),
                        'level': 'SUCCESS',
                        'stage': 'scan_completed', 
                        'message': f"域名 {domain} 扫描完成",
                        'content': f"✅ 域名 {domain} 扫描已完成！总耗时: {scan_status.get('total_time', '未知')}",
                        'details': {
                            'total_time': scan_status.get('total_time', ''),
                            'progress': scan_status.get('progress', 100)
                        }
                    })
                
            except Exception as e:
                app.logger.warning(f'解析扫描状态日志失败: {e}')
        
        # 读取基础信息文件作为日志
        base_info_file = domain_dir / f"base_info_{domain}.txt"
        if base_info_file.exists():
            try:
                content = base_info_file.read_text(encoding='utf-8')
                preview = content[:200] + '...' if len(content) > 200 else content
                logs.append({
                    'timestamp': datetime.fromtimestamp(base_info_file.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                    'level': 'INFO',
                    'stage': 'data_collection',
                    'message': '数据收集完成',
                    'content': f'📋 数据收集完成，基础信息预览: {preview}',
                    'details': content[:500] + '...' if len(content) > 500 else content
                })
            except Exception as e:
                app.logger.warning(f'读取基础信息日志失败: {e}')
        
        # 按时间戳排序
        logs.sort(key=lambda x: x.get('timestamp', ''))
        
        return jsonify({
            'status': 'success',
            'data': logs
        })
    except Exception as e:
        app.logger.error(f'获取域名日志失败: {e}')
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/scan/status/<domain>')
@auth.login_required
def api_scan_status(domain):
    """获取域名扫描状态"""
    try:
        domain_dir = OUTPUT_DIR / domain
        
        # 如果域名目录不存在，返回未开始状态
        if not domain_dir.exists():
            return jsonify({
                'status': 'success',
                'data': {
                    'domain': domain,
                    'scan_status': 'not_started',
                    'message': '扫描尚未开始或数据已被清理'
                }
            })
        
        # 读取扫描状态文件
        scanning_status_file = domain_dir / "scanning_status.json"
        finish_file = domain_dir / "finish.txt"
        
        # 检查是否有完成标记
        scan_completed = finish_file.exists()
        
        if scanning_status_file.exists():
            try:
                with open(scanning_status_file, 'r', encoding='utf-8') as f:
                    scan_status = json.load(f)
                
                # 如果状态文件中明确标记已完成，使用状态文件的数据
                if scan_status.get('scan_completed', False):
                    scan_completed = True
    
    return jsonify({
        'status': 'success',
                    'data': {
                        'domain': domain,
                        'scan_status': 'completed' if scan_completed else 'scanning',
                        'start_time': scan_status.get('start_time', '未知'),
                        'end_time': scan_status.get('end_time', ''),
                        'progress': 100 if scan_completed else scan_status.get('progress', 0),
                        'current_stage': 'completed' if scan_completed else scan_status.get('current_stage', 'unknown'),
                        'scan_completed': scan_completed,
                        'scan_stages': scan_status.get('scan_stages', {})
                    }
                })
            except Exception as e:
                app.logger.error(f'读取扫描状态文件失败: {e}')
        
        # 如果有finish.txt文件但没有状态文件，表示已完成
        if finish_file.exists():
            return jsonify({
                'status': 'success',
                'data': {
                    'domain': domain,
                    'scan_status': 'completed',
                    'progress': 100,
                    'current_stage': 'completed',
                    'scan_completed': True,
                    'end_time': datetime.fromtimestamp(finish_file.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                }
            })
        
        # 默认返回未知状态
        return jsonify({
            'status': 'success',
            'data': {
                'domain': domain,
                'scan_status': 'unknown',
                'message': '无法确定扫描状态'
            }
        })
        
    except Exception as e:
        app.logger.error(f'获取扫描状态失败: {e}')
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/stats')
@auth.login_required
def api_stats():
    """获取总体统计信息"""
    try:
        domains = collector.get_all_domains()
        
        # 过滤和验证域名数据，统计完成扫描的域名
        valid_domains = []
        for d in domains:
            if isinstance(d, dict) and 'status' in d and 'name' in d:
                valid_domains.append(d)
            else:
                app.logger.warning(f'跳过无效域名数据: {type(d)} - {d}')
        
        completed_domains = [d for d in valid_domains if d['status'] == 'completed']
        
        total_stats = {
            'total_domains': len(completed_domains),
        'total_urls': 0,
        'total_ips': 0,
        'total_vulnerabilities': 0,
            'scanning_domains': len([d for d in valid_domains if d['status'] == 'scanning']),
            'failed_domains': len([d for d in valid_domains if d['status'] in ['failed', 'error']])
        }
        
        # 累计各域名统计
        for domain_info in completed_domains:
            try:
        summary = collector.get_domain_summary(domain_info['name'])
                if summary and isinstance(summary, dict):
                    total_stats['total_urls'] += summary.get('total_urls', 0)
                    total_stats['total_ips'] += summary.get('total_ips', 0)
                    total_stats['total_vulnerabilities'] += summary.get('vulnerabilities', 0)
                else:
                    app.logger.warning(f'域名 {domain_info["name"]} summary数据格式异常: {type(summary)}')
            except Exception as e:
                app.logger.warning(f'获取域名 {domain_info["name"]} 统计失败: {e}')
    
    return jsonify({
        'status': 'success',
            'data': total_stats
        })
    except Exception as e:
        app.logger.error(f'获取统计信息失败: {e}')
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/scan', methods=['POST'])
@auth.login_required
def api_start_scan():
    """启动新扫描任务"""
    start_time = time.time()
    user = auth.current_user()
    
    # 清除缓存确保数据一致性
    collector.clear_cache()
    
    try:
        data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({
                'status': 'error',
                'message': '请提供要扫描的域名'
            }), 400
        
        domain = data['domain'].strip().lower()
        mode = data.get('mode', '1')  # 默认快速扫描
        
        # 验证域名格式 - 与前端保持一致
        import re
        domain_pattern = r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$'
        if not re.match(domain_pattern, domain):
            return jsonify({
                'status': 'error',
                'message': f'域名格式不正确: {domain}'
            }), 400
        
        # 检查域名是否已在扫描中
        domain_dir = OUTPUT_DIR / domain
        scanning_status_file = domain_dir / "scanning_status.json"
        
        if scanning_status_file.exists():
            try:
                with open(scanning_status_file, 'r', encoding='utf-8') as f:
                    scan_status = json.load(f)
                if not scan_status.get('scan_completed', False):
                    return jsonify({
                        'status': 'error',
                        'message': f'域名 {domain} 正在扫描中，请勿重复提交'
                    }), 409
            except Exception as e:
                app.logger.warning(f'读取扫描状态失败: {e}')
        
        # 启动扫描任务（异步）
        import subprocess
        import threading
        
        def run_scan():
            try:
                # 写入目标域名到文件
                target_file = PROJECT_ROOT / 'data' / 'input' / 'url'
                target_file.parent.mkdir(parents=True, exist_ok=True)
                with open(target_file, 'w') as f:
                    f.write(domain)
                
                # 构建扫描命令
                scan_cmd = [str(PROJECT_ROOT / 'scan.sh')]
                if mode == '1':
                    scan_cmd.append('--test')  # 快速扫描模式
                elif mode == '2':
                    scan_cmd.extend(['-s', '2'])  # 深度扫描模式
                
                # 执行扫描
                result = subprocess.run(
                    scan_cmd,
                    cwd=str(PROJECT_ROOT),
                    capture_output=True,
                    text=True,
                    timeout=3600  # 1小时超时
                )
                
                app.logger.info(f'域名 {domain} 扫描完成，返回码: {result.returncode}')
                if result.returncode != 0:
                    app.logger.error(f'扫描失败: {result.stderr}')
                
            except Exception as e:
                app.logger.error(f'扫描任务执行失败: {e}')
        
        # 在单独线程中运行扫描
        scan_thread = threading.Thread(target=run_scan)
        scan_thread.daemon = True
        scan_thread.start()
        
        # 清除缓存确保及时更新
        collector.clear_cache()
        
        # 记录扫描启动日志
        if WEB_DEBUG_ENABLED:
            duration = time.time() - start_time
            web_logger.log_api_request(
                method='POST',
                endpoint='/api/scan',
                user=user,
                status_code=200,
                duration=duration,
                extra_data={
                    'domain': domain,
                    'mode': mode,
                    'action': 'scan_started'
                }
            )
            web_logger.log_scan_status(
                domain=domain,
                action='scan_initiated',
                status='starting',
                progress=0,
                stage='initialization',
                details={'mode': mode, 'user': user}
            )
        
        return jsonify({
            'status': 'success',
            'message': f'域名 {domain} 的扫描任务已启动'
        })
        
    except Exception as e:
        app.logger.error(f'启动扫描失败: {e}')
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/domain/<domain>', methods=['DELETE'])
@auth.login_required
def api_delete_domain(domain):
    """删除域名扫描数据"""
    try:
        import shutil
        domain_dir = OUTPUT_DIR / domain
        
        if not domain_dir.exists():
            return jsonify({
                'status': 'error',
                'message': '域名数据不存在'
            }), 404
        
        # 删除域名目录
        shutil.rmtree(domain_dir)
        
        # 清除缓存
        collector.clear_cache()
        
        app.logger.info(f'已删除域名 {domain} 的扫描数据')
        
        return jsonify({
            'status': 'success',
            'message': f'已删除域名 {domain} 的扫描数据'
        })
        
    except Exception as e:
        app.logger.error(f'删除域名数据失败: {e}')
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/cache/clear', methods=['POST'])
@auth.login_required
def api_clear_cache():
    """清除缓存"""
    try:
        collector.clear_cache()
        return jsonify({
            'status': 'success',
            'message': '缓存已清除'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/debug/status')
@auth.login_required  
def api_debug_status():
    """获取Web调试状态"""
    try:
        if not WEB_DEBUG_ENABLED:
            return jsonify({
                'status': 'error',
                'message': 'Web调试系统未启用'
            }), 503
        
        # 获取调试报告
        report = web_logger.generate_debug_report()
        
        return jsonify({
            'status': 'success',
            'data': report
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/debug/domain/<domain>')
@auth.login_required
def api_debug_domain(domain):
    """获取特定域名的调试信息"""
    try:
        if not WEB_DEBUG_ENABLED:
            return jsonify({
                'status': 'error',
                'message': 'Web调试系统未启用'
            }), 503
        
        # 分析域名扫描问题
        analysis = web_logger.analyze_scan_progress_issue(domain)
        
        # 获取域名扫描日志
        logs = web_logger.get_domain_scan_logs(domain, 30)
        
        # 检查域名状态文件
        status_info = web_logger.check_domain_status_file(domain)
        
        return jsonify({
            'status': 'success',
            'data': {
                'domain': domain,
                'analysis': analysis,
                'recent_logs': logs,
                'status_file_info': status_info
            }
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# ==================== API 路由 ====================

@app.route('/api/domains')
@auth.login_required
def api_domains():
    """获取所有域名列表"""
    try:
        domains = data_collector.get_all_domains()
        return jsonify({'status': 'success', 'data': domains})
    except Exception as e:
        app.logger.error(f'获取域名列表失败: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/stats')
@auth.login_required
def api_stats():
    """获取统计信息"""
    try:
        domains = data_collector.get_all_domains()
        # 过滤有效域名数据
        valid_domains = [d for d in domains if isinstance(d, dict) and 'status' in d and 'name' in d]
        completed_domains = [d for d in valid_domains if d['status'] == 'completed']
        
        total_stats = {
            'total_domains': len(completed_domains),
            'total_urls': 0,
            'total_ips': 0,
            'total_vulnerabilities': 0,
            'scanning_domains': len([d for d in valid_domains if d['status'] == 'scanning']),
            'failed_domains': len([d for d in valid_domains if d['status'] in ['failed', 'error']])
        }
        
        # 累计统计
        for domain_info in completed_domains:
            try:
                summary = data_collector.get_domain_summary(domain_info['name'])
                if summary and isinstance(summary, dict):
                    total_stats['total_urls'] += summary.get('total_urls', 0)
                    total_stats['total_ips'] += summary.get('total_ips', 0)
                    total_stats['total_vulnerabilities'] += summary.get('vulnerabilities', 0)
            except Exception as e:
                app.logger.warning(f'获取域名 {domain_info["name"]} 统计失败: {e}')
        
        return jsonify({'status': 'success', 'data': total_stats})
    except Exception as e:
        app.logger.error(f'获取统计信息失败: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/domain/<domain>/summary')
@auth.login_required
def api_domain_summary(domain):
    """获取域名摘要"""
    try:
        summary = data_collector.get_domain_summary(domain)
        if summary is None:
            return jsonify({'status': 'error', 'message': '域名数据不存在'}), 404
        return jsonify({'status': 'success', 'data': summary})
    except Exception as e:
        app.logger.error(f'获取域名摘要失败: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/domain/<domain>/detail')
@auth.login_required
def api_domain_detail(domain):
    """获取域名详细数据"""
    try:
        detail = data_collector.get_domain_detail(domain)
        if detail is None:
            return jsonify({'status': 'error', 'message': '域名数据不存在'}), 404
        return jsonify({'status': 'success', 'data': detail})
    except Exception as e:
        app.logger.error(f'获取域名详情失败: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/domain/<domain>/logs')
@auth.login_required
def api_domain_logs(domain):
    """获取域名扫描日志"""
    try:
        # 简化日志返回 - 从扫描状态文件读取
        domain_dir = OUTPUT_DIR / domain
        logs = []
        
        if not domain_dir.exists():
            logs.append({
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'level': 'INFO',
                'stage': 'init',
                'message': f'域名 {domain} 尚未开始扫描或数据已被清理',
                'content': f'域名 {domain} 尚未开始扫描或数据已被清理'
            })
        else:
            # 读取扫描状态文件生成日志
            scanning_status_file = domain_dir / "scanning_status.json"
            if scanning_status_file.exists():
                try:
                    with open(scanning_status_file, 'r', encoding='utf-8') as f:
                        scan_status = json.load(f)
                    
                    logs.append({
                        'timestamp': scan_status.get('start_time', ''),
                        'level': 'INFO',
                        'stage': 'start',
                        'message': f'开始扫描域名 {domain}',
                        'content': f'开始扫描域名 {domain}'
                    })
                    
                    # 添加各阶段日志
                    if 'scan_stages' in scan_status:
                        for stage_name, stage_info in scan_status['scan_stages'].items():
                            if stage_info.get('status') != 'pending':
                                logs.append({
                                    'timestamp': stage_info.get('start_time', ''),
                                    'level': 'SUCCESS' if stage_info.get('status') == 'completed' else 'INFO',
                                    'stage': stage_name,
                                    'message': f'{stage_name} 阶段{stage_info.get("status", "")}',
                                    'content': f'{stage_name} 阶段{stage_info.get("status", "")}'
                                })
                except Exception as e:
                    app.logger.warning(f'读取扫描状态失败: {e}')
        
        return jsonify({'status': 'success', 'data': logs})
    except Exception as e:
        app.logger.error(f'获取域名日志失败: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/scan', methods=['POST'])
@auth.login_required
def api_start_scan():
    """启动扫描任务"""
    try:
    data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({'status': 'error', 'message': '请提供域名参数'}), 400
        
        domain = data['domain'].strip().lower()
        mode = data.get('mode', '1')
        
        # 解析扫描模式
        is_test_mode = mode.endswith('_test')
        actual_mode = mode.replace('_test', '') if is_test_mode else mode
        mode_desc = '快速扫描 (测试模式)' if is_test_mode else '快速扫描 (正式模式)'
        
        # 验证域名格式
        domain_pattern = r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$'
        if not re.match(domain_pattern, domain):
            return jsonify({'status': 'error', 'message': f'域名格式不正确: {domain}'}), 400
        
        app.logger.info(f'启动扫描: 域名={domain}, 模式={mode_desc}')
        
        # 检查是否已在扫描中
    domain_dir = OUTPUT_DIR / domain
        scanning_status_file = domain_dir / "scanning_status.json"
        
        if scanning_status_file.exists():
            try:
                with open(scanning_status_file, 'r') as f:
                    status = json.load(f)
                    if not status.get('scan_completed', False):
        return jsonify({
                            'status': 'error', 
                            'message': f'域名 {domain} 正在扫描中，请稍后再试'
        }), 409
            except Exception as e:
                app.logger.warning(f'读取扫描状态失败: {e}')
        
        # 准备扫描命令
        cmd = ['bash', str(PROJECT_ROOT / 'scan.sh'), domain, actual_mode]
        env = os.environ.copy()
        if is_test_mode:
            env['TEST_MODE'] = '1'
        
        # 调试模式记录
        debug_enabled = config.get('debug', {}).get('enabled', False)
        if debug_enabled and config.get('debug', {}).get('show_command_paths', False):
            app.logger.info(f'🔧 调试模式 - 扫描命令: {" ".join(cmd)}')
            app.logger.info(f'🔧 调试模式 - 工作目录: {PROJECT_ROOT}')
            app.logger.info(f'🔧 调试模式 - 环境变量: TEST_MODE={env.get("TEST_MODE", "未设置")}')
        
        # 启动扫描进程
        import subprocess
        import threading
        
        def run_scan():
            try:
                if debug_enabled:
                    app.logger.info(f'🔧 调试模式 - 开始执行扫描命令')
                
                result = subprocess.run(
                    cmd, 
                    env=env, 
                    capture_output=True, 
                    text=True, 
                    timeout=1800,
                    cwd=PROJECT_ROOT  # 明确设置工作目录
                )
                
                if debug_enabled:
                    app.logger.info(f'🔧 调试模式 - 扫描命令执行完毕，返回码: {result.returncode}')
                    if result.stdout:
                        app.logger.info(f'🔧 调试模式 - 标准输出: {result.stdout[:500]}...')
                    if result.stderr:
                        app.logger.warning(f'🔧 调试模式 - 错误输出: {result.stderr[:500]}...')
                
                if result.returncode != 0:
                    app.logger.error(f'扫描失败: {result.stderr}')
            except Exception as e:
                app.logger.error(f'扫描异常: {e}')
                if debug_enabled:
                    import traceback
                    app.logger.error(f'🔧 调试模式 - 异常详情: {traceback.format_exc()}')
        
        # 在后台线程中运行扫描
        scan_thread = threading.Thread(target=run_scan, daemon=True)
        scan_thread.start()
        
        return jsonify({
            'status': 'success',
            'message': f'域名 {domain} 扫描已启动 ({mode_desc})',
            'data': {'domain': domain, 'mode': mode_desc}
        })
        
    except Exception as e:
        app.logger.error(f'启动扫描失败: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/scan/status/<domain>')
@auth.login_required
def api_scan_status(domain):
    """获取扫描状态"""
    try:
    domain_dir = OUTPUT_DIR / domain
    
    if not domain_dir.exists():
        return jsonify({
                'status': 'success',
                'data': {
                    'domain': domain,
                    'scan_status': 'not_started',
                    'message': '扫描尚未开始或数据已被清理'
                }
            })
        
        # 读取扫描状态文件
        scanning_status_file = domain_dir / "scanning_status.json"
        finish_file = domain_dir / "finish.txt"
        
        scan_completed = finish_file.exists()
        
        if scanning_status_file.exists():
            try:
                with open(scanning_status_file, 'r', encoding='utf-8') as f:
                scan_status = json.load(f)
            
                if scan_status.get('scan_completed', False):
                    scan_completed = True
            
            return jsonify({
                'status': 'success',
                    'data': {
                        'domain': domain,
                        'scan_status': 'completed' if scan_completed else 'scanning',
                        'start_time': scan_status.get('start_time', '未知'),
                        'end_time': scan_status.get('end_time', ''),
                        'progress': 100 if scan_completed else scan_status.get('progress', 0),
                        'current_stage': 'completed' if scan_completed else scan_status.get('current_stage', 'unknown'),
                        'scan_completed': scan_completed,
                        'scan_stages': scan_status.get('scan_stages', {})
                    }
            })
        except Exception as e:
                app.logger.error(f'读取扫描状态文件失败: {e}')
        
        # 如果有finish.txt但没有状态文件
        if finish_file.exists():
        return jsonify({
                'status': 'success',
                'data': {
                    'domain': domain,
                    'scan_status': 'completed',
                    'progress': 100,
                    'current_stage': 'completed',
                    'scan_completed': True,
                    'end_time': datetime.fromtimestamp(finish_file.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                }
            })
        
        return jsonify({
            'status': 'success',
            'data': {
                'domain': domain,
                'scan_status': 'unknown',
                'message': '无法确定扫描状态'
            }
        })
        
    except Exception as e:
        app.logger.error(f'获取扫描状态失败: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/domain/<domain>/delete', methods=['DELETE'])
@auth.login_required
def api_delete_domain(domain):
    """删除域名数据"""
    try:
        domain_dir = OUTPUT_DIR / domain
        if domain_dir.exists():
    import shutil
            shutil.rmtree(domain_dir)
            app.logger.info(f'已删除域名数据: {domain}')
        
        return jsonify({'status': 'success', 'message': f'域名 {domain} 数据已删除'})
    except Exception as e:
        app.logger.error(f'删除域名数据失败: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ==================== Web 页面路由 ====================

@app.route('/')
@auth.login_required
def index():
    """主页"""
    return render_template('index.html')

@app.route('/domain/<domain>')
@auth.login_required
def domain_detail(domain):
    """域名详情页"""
    # 验证域名参数
    if not domain or domain == 'undefined' or domain == 'None' or domain.strip() == '':
        app.logger.warning(f'访问域名详情页时域名参数无效: {domain}')
        return redirect('/')
    
    clean_domain = domain.strip()
    app.logger.info(f'访问域名详情页: {clean_domain}')
    
    return render_template('domain.html', domain=clean_domain)

# 静态文件路由
@app.route('/static/<path:filename>')
def static_files(filename):
    """静态文件服务"""
    return send_from_directory(PROJECT_ROOT / 'web' / 'static', filename)

if __name__ == '__main__':
    # 创建必要的目录
    web_dir = PROJECT_ROOT / 'web'
    template_dir = web_dir / 'templates'
    static_dir = web_dir / 'static'
    template_dir.mkdir(parents=True, exist_ok=True)
    static_dir.mkdir(parents=True, exist_ok=True)
    
    # 获取公网IP
    try:
        import urllib.request
        public_ip = urllib.request.urlopen('https://ifconfig.me').read().decode('utf-8').strip()
    except:
        public_ip = '未知'
    
    print(f"""
    ╔══════════════════════════════════════════════════╗
    ║     🎯 渗透测试扫描结果Web展示系统 🎯            ║
    ║         基于配置文件的版本                       ║
    ╚══════════════════════════════════════════════════╝
    
    📋 配置文件: {CONFIG_FILE}
    🚀 服务地址: http://{config['server']['host']}:{config['server']['port']}
    🌐 公网地址: http://{public_ip}:{config['server']['port']}
    🔐 认证状态: {'已启用' if config['auth']['enabled'] else '已禁用'}
    📁 数据目录: {OUTPUT_DIR}
    📝 日志文件: {config['logging']['file'] if config['logging']['enabled'] else '未启用'}
    
    ⚠️  提示:
    1. 请修改 config/web_config.yaml 中的默认密码
    2. 生产环境建议启用HTTPS (使用nginx反向代理)
    3. 根据需要配置IP白名单增强安全性
    
    """)
    
    app.run(
        host=config['server']['host'],
        port=config['server']['port'],
        debug=config['server']['debug']
    )