#!/usr/bin/env python3
"""
统一的扫描报告生成器
合并所有报告功能，提供一致的数据处理和展示
"""

import json
import os
import sys
import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import argparse
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

class UnifiedReportGenerator:
    """统一报告生成器"""
    
    def __init__(self, domain, output_dir=None):
        self.domain = domain
        self.project_root = Path(__file__).parent.parent.parent
        self.domain_path = self.project_root / 'output' / domain
        self.output_dir = Path(output_dir) if output_dir else self.project_root / 'reports'
        self.output_dir.mkdir(exist_ok=True)
        
        # 数据存储
        self.layer1_data = {}
        self.expansion_data = {}
        
    def parse_base_info(self, base_info_path):
        """解析base_info文件，提取URL标题和大小信息"""
        url_info_map = {}
        ips = []
        domains = []
        
        if not base_info_path.exists():
            logger.warning(f"base_info文件不存在: {base_info_path}")
            return url_info_map, ips, domains
            
        try:
            with open(base_info_path, 'r', encoding='utf-8') as f:
                current_section = None
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                        
                    if line.startswith('【URL发现】') or line.startswith('URL和标题:'):
                        current_section = 'url'
                    elif line.startswith('【IP发现】') or line.startswith('关联真实IP:'):
                        current_section = 'ip'
                    elif line.startswith('【反查域名】') or line.startswith('IP反查域名:'):
                        current_section = 'domain'
                    elif current_section == 'url' and '- https://' in line:
                        # 解析URL行：  - https://xxx [title][size:123]
                        # 注意：空标题时格式为 [][size:123]
                        match = re.match(r'^\s*-\s*(https?://[^\s]+)\s*\[([^\]]*)\]\[size:(\d+)\]', line)
                        if match:
                            url, title, size = match.groups()
                            url_info_map[url] = {
                                'url': url,
                                'title': title if title else '无标题',
                                'content_length': int(size),
                                'status_code': 200  # 默认值
                            }
                    elif current_section == 'ip' and line.strip().startswith('-'):
                        ip = line.replace('-', '').strip()
                        ips.append(ip)
                    elif current_section == 'domain' and line.startswith('-'):
                        # 解析域名反查行
                        parts = line.replace('-', '').strip().split('->')
                        if len(parts) == 2:
                            ip = parts[0].strip()
                            domain_list = parts[1].strip().split(',')
                            for d in domain_list:
                                domains.append(d.strip())
                                
        except Exception as e:
            logger.error(f"解析base_info失败: {e}")
            
        return url_info_map, ips, domains
        
    def parse_fscan_result(self, fscan_path):
        """解析fscan扫描结果"""
        if not fscan_path.exists():
            return []
            
        results = []
        try:
            with open(fscan_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # 解析开放端口
                port_pattern = r'(\d+\.\d+\.\d+\.\d+):(\d+)\s+open'
                for match in re.finditer(port_pattern, content):
                    ip, port = match.groups()
                    results.append({
                        'type': 'port',
                        'ip': ip,
                        'port': port,
                        'status': 'open'
                    })
                
                # 解析HTTP服务
                http_pattern = r'\[.\]\s+(\d+\.\d+\.\d+\.\d+)\s+(https?://[^\s]+)\s+\[(\d+)\]\s+\[([^\]]*)\]'
                for match in re.finditer(http_pattern, content):
                    ip, url, code, title = match.groups()
                    results.append({
                        'type': 'http',
                        'ip': ip,
                        'url': url,
                        'status_code': code,
                        'title': title
                    })
                    
                # 解析其他服务
                service_patterns = [
                    (r'\[.\]\s+mysql\s+([^:]+):(\d+):(\w+)\s+password\s+is\s+(\w+)', 'mysql'),
                    (r'\[.\]\s+SSH\s+([^:]+):(\d+)\s+banner:\s+(.+)', 'ssh'),
                ]
                
                for pattern, service_type in service_patterns:
                    for match in re.finditer(pattern, content):
                        results.append({
                            'type': service_type,
                            'raw': match.group(0)
                        })
                        
        except Exception as e:
            logger.error(f"解析fscan结果失败: {e}")
            
        return results
        
    def parse_afrog_result(self, afrog_path):
        """解析afrog扫描结果"""
        if not afrog_path.exists():
            return []
            
        vulns = []
        try:
            with open(afrog_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        vuln = {
                            'name': item.get('PocInfo', {}).get('Name', 'Unknown'),
                            'severity': item.get('PocInfo', {}).get('Severity', 'unknown'),
                            'cve': item.get('PocInfo', {}).get('Id', ''),
                            'target': item.get('Target', ''),
                            'full_target': item.get('FullTarget', ''),
                            'description': item.get('PocInfo', {}).get('Description', '')
                        }
                        vulns.append(vuln)
        except Exception as e:
            logger.error(f"解析afrog结果失败: {e}")
            
        return vulns
        
    def load_layer1_data(self):
        """加载第一层扫描数据"""
        logger.info(f"加载一层扫描数据: {self.domain_path}")
        
        # 解析base_info
        base_info_path = self.domain_path / f'base_info_{self.domain}.txt'
        url_info_map, ips, domains = self.parse_base_info(base_info_path)
        
        # 补充representative_urls.txt中的URL
        rep_urls_path = self.domain_path / 'input' / 'representative_urls.txt'
        if rep_urls_path.exists():
            with open(rep_urls_path, 'r') as f:
                for line in f:
                    url = line.strip()
                    if url and url not in url_info_map:
                        url_info_map[url] = {
                            'url': url,
                            'title': '无标题',
                            'content_length': 0,
                            'status_code': 200
                        }
        
        # 解析安全扫描结果
        fscan_results = []
        afrog_vulns = []
        
        for file in self.domain_path.glob('fscan_result_*.txt'):
            fscan_results.extend(self.parse_fscan_result(file))
            
        for file in self.domain_path.glob('afrog_report_*.json'):
            afrog_vulns.extend(self.parse_afrog_result(file))
            
        # 读取扩展目标统计
        tuozhan_stats = self.load_tuozhan_stats(self.domain_path / 'tuozhan' / 'all_tuozhan')
        
        self.layer1_data = {
            'urls': list(url_info_map.values()),
            'ips': ips,
            'domains': domains,
            'fscan': fscan_results,
            'afrog': afrog_vulns,
            'tuozhan': tuozhan_stats
        }
        
        return self.layer1_data
        
    def load_tuozhan_stats(self, tuozhan_path):
        """加载拓展目标统计"""
        stats = {
            'ips': 0,
            'urls': 0,
            'domains': 0,
            'details': {}
        }
        
        if not tuozhan_path.exists():
            return stats
            
        # 统计各文件
        files = {
            'ip.txt': 'ips',
            'urls.txt': 'urls',
            'root_domains.txt': 'domains'
        }
        
        for filename, key in files.items():
            file_path = tuozhan_path / filename
            if file_path.exists():
                with open(file_path, 'r') as f:
                    count = sum(1 for line in f if line.strip() and not line.startswith('#'))
                    stats[key] = count
                    
        return stats
        
    def load_expansion_data(self):
        """加载扩展层扫描数据"""
        logger.info("加载扩展层扫描数据")
        
        # 扩展扫描结果路径
        expansion_base = self.domain_path / 'expansion' / 'report' / 'domain_scan_results'
        
        if not expansion_base.exists():
            logger.info("未找到扩展扫描结果")
            return {}
            
        for domain_dir in expansion_base.iterdir():
            if domain_dir.is_dir():
                domain_name = domain_dir.name
                # 实际数据在 域名/域名/ 下
                actual_path = domain_dir / domain_name
                
                if actual_path.exists():
                    logger.info(f"处理扩展域名: {domain_name}")
                    
                    # 解析该域名的数据
                    domain_data = {
                        'domain': domain_name,
                        'urls': [],
                        'fscan': [],
                        'afrog': []
                    }
                    
                    # 解析base_info
                    base_info_path = actual_path / f'base_info_{domain_name}.txt'
                    if base_info_path.exists():
                        url_info_map, _, _ = self.parse_base_info(base_info_path)
                        domain_data['urls'] = list(url_info_map.values())
                    
                    # 解析安全扫描结果
                    for file in actual_path.glob('fscan_result_*.txt'):
                        domain_data['fscan'].extend(self.parse_fscan_result(file))
                        
                    for file in actual_path.glob('afrog_report_*.json'):
                        domain_data['afrog'].extend(self.parse_afrog_result(file))
                        
                    self.expansion_data[domain_name] = domain_data
                    
        return self.expansion_data
        
    def get_severity_badge(self, severity):
        """获取严重程度的徽章样式"""
        severity = severity.lower()
        colors = {
            'critical': ('#e74c3c', 'white'),
            'high': ('#e67e22', 'white'),
            'medium': ('#f39c12', 'white'),
            'low': ('#f1c40f', 'black'),
            'info': ('#3498db', 'white')
        }
        bg_color, text_color = colors.get(severity, ('#95a5a6', 'white'))
        return f'background-color: {bg_color}; color: {text_color};'
        
    def make_urls_clickable(self, text):
        """将文本中的URL转换为可点击的链接"""
        url_pattern = r'(https?://[^\s<>"]+)'
        return re.sub(url_pattern, r'<a href="\1" target="_blank" class="url-link">\1</a>', text)
        
    def generate_html(self):
        """生成HTML报告"""
        # 加载数据
        self.load_layer1_data()
        self.load_expansion_data()
        
        # 统计数据
        total_urls = len(self.layer1_data.get('urls', []))
        total_vulns = len(self.layer1_data.get('afrog', []))
        expansion_domains = len(self.expansion_data)
        
        # 扩展层统计
        expansion_urls = sum(len(d.get('urls', [])) for d in self.expansion_data.values())
        expansion_vulns = sum(len(d.get('afrog', [])) for d in self.expansion_data.values())
        
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.domain} - 渗透测试扫描报告</title>
    <style>
        :root {{
            --primary-color: #3498db;
            --success-color: #2ecc71;
            --warning-color: #f39c12;
            --danger-color: #e74c3c;
            --dark-bg: #2c3e50;
            --light-bg: #ecf0f1;
            --text-color: #34495e;
            --border-color: #bdc3c7;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
            background-color: #f5f7fa;
            color: var(--text-color);
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 0;
            text-align: center;
            margin-bottom: 40px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            border-radius: 10px;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        
        .summary-card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}
        
        .summary-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }}
        
        .summary-card h3 {{
            color: #666;
            font-size: 0.9em;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .summary-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            color: var(--primary-color);
            margin: 10px 0;
        }}
        
        .summary-card.danger .number {{
            color: var(--danger-color);
        }}
        
        .summary-card.success .number {{
            color: var(--success-color);
        }}
        
        .section {{
            background: white;
            padding: 30px;
            margin-bottom: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .section h2 {{
            color: var(--dark-bg);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--light-bg);
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .layer-indicator {{
            background: var(--primary-color);
            color: white;
            padding: 4px 12px;
            border-radius: 15px;
            font-size: 0.8em;
            font-weight: normal;
        }}
        
        .data-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        
        .data-table th,
        .data-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        
        .data-table th {{
            background-color: var(--light-bg);
            font-weight: 600;
            color: var(--dark-bg);
        }}
        
        .data-table tr:hover {{
            background-color: #f8f9fa;
        }}
        
        .url-link {{
            color: var(--primary-color);
            text-decoration: none;
        }}
        
        .url-link:hover {{
            text-decoration: underline;
        }}
        
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: 600;
        }}
        
        .port-badge {{
            background-color: #e8f4f8;
            color: #2c7a7b;
            font-family: monospace;
        }}
        
        .expansion-domain {{
            background: #f8f9fa;
            padding: 20px;
            margin: 15px 0;
            border-radius: 8px;
            border-left: 4px solid var(--primary-color);
        }}
        
        .expansion-domain h3 {{
            color: var(--primary-color);
            margin-bottom: 15px;
        }}
        
        .stats-row {{
            display: flex;
            gap: 30px;
            margin: 10px 0;
            color: #666;
            font-size: 0.9em;
        }}
        
        .empty-state {{
            text-align: center;
            color: #999;
            padding: 40px;
            font-style: italic;
        }}
        
        .vuln-item {{
            border-left: 3px solid var(--border-color);
            padding-left: 15px;
            margin: 15px 0;
        }}
        
        .vuln-item.critical {{
            border-color: var(--danger-color);
        }}
        
        .vuln-item.high {{
            border-color: #e67e22;
        }}
        
        .vuln-item.medium {{
            border-color: var(--warning-color);
        }}
        
        .footer {{
            text-align: center;
            padding: 30px 0;
            color: #666;
            font-size: 0.9em;
        }}
        
        .expand-btn {{
            background: var(--primary-color);
            color: white;
            border: none;
            padding: 6px 15px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.9em;
            transition: background 0.3s ease;
        }}
        
        .expand-btn:hover {{
            background: #2980b9;
        }}
        
        .expansion-domain-detail {{
            background: #f8f9fa;
            padding: 25px;
            margin: 20px 0;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }}
        
        .expansion-domain-detail h3 {{
            color: var(--primary-color);
            margin-bottom: 20px;
        }}
        
        .expansion-domain-detail h4 {{
            color: var(--dark-bg);
            margin-top: 25px;
            margin-bottom: 15px;
        }}
        
        .badge.danger {{
            background-color: var(--danger-color);
            color: white;
        }}
        
        .badge.success {{
            background-color: var(--success-color);
            color: white;
        }}
        
        @media (max-width: 768px) {{
            .summary-grid {{
                grid-template-columns: 1fr;
            }}
            
            .stats-row {{
                flex-direction: column;
                gap: 10px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 {self.domain}</h1>
            <p>渗透测试扫描报告 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card">
                <h3>一层扫描URL</h3>
                <div class="number">{total_urls}</div>
            </div>
            <div class="summary-card {'danger' if total_vulns > 0 else 'success'}">
                <h3>一层安全漏洞</h3>
                <div class="number">{total_vulns}</div>
            </div>
            <div class="summary-card">
                <h3>扩展域名</h3>
                <div class="number">{expansion_domains}</div>
            </div>
            <div class="summary-card {'danger' if expansion_vulns > 0 else 'success'}">
                <h3>扩展层漏洞</h3>
                <div class="number">{expansion_vulns}</div>
            </div>
        </div>
        
        <!-- 一层扫描结果 -->
        <div class="section">
            <h2>📊 一层扫描结果 <span class="layer-indicator">Layer 1</span></h2>
            
            <h3>🌐 发现的URL ({len(self.layer1_data.get('urls', []))})</h3>
            {self._generate_url_table(self.layer1_data.get('urls', [])[:50])}
            
            <h3 style="margin-top: 30px;">🔍 端口扫描结果</h3>
            {self._generate_fscan_results(self.layer1_data.get('fscan', []))}
            
            {self._generate_vuln_section(self.layer1_data.get('afrog', []), '一层')}
        </div>
        
        <!-- 扩展目标统计 -->
        <div class="section">
            <h2>🎯 扩展目标统计</h2>
            <div class="stats-row">
                <div>🖥️ IP目标: <strong>{self.layer1_data.get('tuozhan', {}).get('ips', 0)}</strong> 个</div>
                <div>🌐 URL目标: <strong>{self.layer1_data.get('tuozhan', {}).get('urls', 0)}</strong> 个</div>
                <div>🏢 域名目标: <strong>{self.layer1_data.get('tuozhan', {}).get('domains', 0)}</strong> 个</div>
            </div>
        </div>
        
        <!-- 扩展层扫描结果 -->
        {self._generate_expansion_section()}
        
        <div class="footer">
            <p>Generated by 渗透测试扫描平台 - 统一报告生成器</p>
        </div>
    </div>
</body>
</html>"""
        
        return html
        
    def _generate_url_table(self, urls):
        """生成URL表格"""
        if not urls:
            return '<div class="empty-state">暂无URL数据</div>'
            
        rows = []
        for url_info in urls:
            url = url_info.get('url', '')
            title = url_info.get('title', '无标题')
            size = url_info.get('content_length', 0)
            rows.append(f'''
                <tr>
                    <td><a href="{url}" target="_blank" class="url-link">{url}</a></td>
                    <td>{title}</td>
                    <td>{size:,} bytes</td>
                </tr>
            ''')
            
        return f'''
            <table class="data-table">
                <thead>
                    <tr>
                        <th>URL</th>
                        <th>标题</th>
                        <th>大小</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        '''
        
    def _generate_fscan_results(self, fscan_data):
        """生成fscan扫描结果"""
        if not fscan_data:
            return '<div class="empty-state">暂无端口扫描数据</div>'
            
        # 按类型分组
        ports = []
        services = []
        
        for item in fscan_data:
            if item['type'] == 'port':
                ports.append(f"{item['ip']}:<span class='port-badge'>{item['port']}</span>")
            elif item['type'] == 'http':
                services.append(f"[{item['status_code']}] {self.make_urls_clickable(item['url'])} - {item['title']}")
            else:
                services.append(self.make_urls_clickable(item.get('raw', str(item))))
                
        html = '<div style="margin: 20px 0;">'
        if ports:
            html += f'<p><strong>开放端口:</strong> {", ".join(ports[:20])}'
            if len(ports) > 20:
                html += f' ... (共{len(ports)}个)'
            html += '</p>'
            
        if services:
            html += '<p style="margin-top: 15px;"><strong>发现的服务:</strong></p>'
            html += '<ul style="margin-left: 20px;">'
            for service in services[:20]:
                html += f'<li>{service}</li>'
            if len(services) > 20:
                html += f'<li>... 还有{len(services)-20}个服务</li>'
            html += '</ul>'
            
        html += '</div>'
        return html
        
    def _generate_vuln_section(self, vulns, layer_name=''):
        """生成漏洞section"""
        if not vulns:
            return ''
            
        # 按严重程度分组
        by_severity = defaultdict(list)
        for vuln in vulns:
            by_severity[vuln['severity']].append(vuln)
            
        html = f'<h3 style="margin-top: 30px;">🛡️ {layer_name}安全漏洞 ({len(vulns)})</h3>'
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            if severity in by_severity:
                for vuln in by_severity[severity]:
                    html += f'''
                    <div class="vuln-item {severity}">
                        <div style="margin-bottom: 5px;">
                            <span class="badge" style="{self.get_severity_badge(severity)}">{severity.upper()}</span>
                            <strong>{vuln['name']}</strong>
                            {f'({vuln["cve"]})' if vuln["cve"] else ''}
                        </div>
                        <div style="color: #666; font-size: 0.9em;">
                            目标: {self.make_urls_clickable(vuln['full_target'])}
                        </div>
                        {f'<div style="color: #666; font-size: 0.9em; margin-top: 5px;">{vuln["description"]}</div>' if vuln["description"] else ''}
                    </div>
                    '''
                    
        return html
        
    def _generate_expansion_section(self):
        """生成扩展层section"""
        if not self.expansion_data:
            return '''
            <div class="section">
                <h2>🔄 扩展层扫描结果 <span class="layer-indicator">Layer 2</span></h2>
                <div class="empty-state">暂无扩展层扫描数据</div>
            </div>
            '''
            
        # 生成域名摘要表格
        html = '''
        <div class="section">
            <h2>🔄 扩展层扫描结果 <span class="layer-indicator">Layer 2</span></h2>
            <p style="margin-bottom: 20px;">发现 <strong>{}</strong> 个扩展域名，点击域名查看详细信息：</p>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>域名</th>
                        <th>URL数量</th>
                        <th>开放端口</th>
                        <th>安全漏洞</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
        '''.format(len(self.expansion_data))
        
        for domain_name, data in self.expansion_data.items():
            url_count = len(data.get('urls', []))
            vuln_count = len(data.get('afrog', []))
            port_count = len([x for x in data.get('fscan', []) if x['type'] == 'port'])
            
            vuln_class = 'danger' if vuln_count > 0 else 'success'
            
            html += f'''
                <tr>
                    <td><strong>{domain_name}</strong></td>
                    <td>{url_count}</td>
                    <td>{port_count}</td>
                    <td><span class="badge {vuln_class}">{vuln_count}</span></td>
                    <td><button class="expand-btn" onclick="toggleDomainDetail('{domain_name}')">查看详情</button></td>
                </tr>
            '''
            
        html += '''
                </tbody>
            </table>
        '''
        
        # 生成每个域名的详细信息（默认隐藏）
        for domain_name, data in self.expansion_data.items():
            html += f'''
            <div class="expansion-domain-detail" id="detail-{domain_name}" style="display: none;">
                <h3>🌐 {domain_name} - 详细信息</h3>
                
                <h4>📄 发现的URL ({len(data.get('urls', []))})</h4>
                {self._generate_url_table(data.get('urls', []))}
                
                <h4 style="margin-top: 30px;">🔍 端口扫描结果</h4>
                {self._generate_fscan_results(data.get('fscan', []))}
                
                {self._generate_vuln_section(data.get('afrog', []), '')}
            </div>
            '''
            
        html += '</div>'
        
        # 添加JavaScript控制显示/隐藏
        html += '''
        <script>
        function toggleDomainDetail(domain) {
            var detail = document.getElementById('detail-' + domain);
            if (detail.style.display === 'none') {
                detail.style.display = 'block';
            } else {
                detail.style.display = 'none';
            }
        }
        </script>
        '''
        
        return html
        
    def save_report(self):
        """保存报告"""
        html = self.generate_html()
        output_path = self.output_dir / f'{self.domain}_unified_report.html'
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
            
        logger.info(f"报告已生成: {output_path}")
        return output_path
        

def main():
    parser = argparse.ArgumentParser(description='生成统一的扫描报告')
    parser.add_argument('domain', nargs='?', help='目标域名')
    parser.add_argument('-o', '--output', help='输出文件路径')
    parser.add_argument('--open', action='store_true', help='生成后自动打开浏览器')
    
    args = parser.parse_args()
    
    # 获取项目根目录
    project_root = Path(__file__).parent.parent.parent
    output_dir = project_root / 'output'
    
    # 如果没有指定域名，尝试自动检测
    if not args.domain:
        domains = [d.name for d in output_dir.iterdir() 
                  if d.is_dir() and not d.name.endswith('_finish') and not d.name.endswith('_vul')]
        if not domains:
            print("[!] 未找到任何扫描结果")
            sys.exit(1)
        elif len(domains) == 1:
            args.domain = domains[0]
            print(f"[*] 自动检测到域名: {args.domain}")
        else:
            print("[*] 发现多个域名，请选择:")
            for i, domain in enumerate(domains, 1):
                print(f"    {i}. {domain}")
            choice = input("请输入序号: ")
            try:
                args.domain = domains[int(choice) - 1]
            except:
                print("[!] 无效的选择")
                sys.exit(1)
    
    # 生成报告
    generator = UnifiedReportGenerator(args.domain, args.output)
    output_path = generator.save_report()
    
    print(f"[✓] 报告已生成: {output_path}")
    
    # 打开浏览器
    if args.open:
        import webbrowser
        webbrowser.open(f'file://{output_path.absolute()}')
        print("[✓] 已在浏览器中打开报告")


if __name__ == '__main__':
    main()