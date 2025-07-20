#!/usr/bin/env python3
"""
树形结构的多层扫描报告生成器
以域名为节点，展示完整的扫描树形结构
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import re


class TreeReportGenerator:
    def __init__(self, root_domain, output_dir="output"):
        self.root_domain = root_domain
        self.output_dir = Path(output_dir)
        self.domain_tree = {}
        self.processed_domains = set()
        
    def build_domain_tree(self):
        """构建域名扫描树"""
        # 从根域名开始构建
        self.domain_tree[self.root_domain] = self.analyze_domain(self.root_domain)
        self._build_tree_recursive(self.root_domain, self.domain_tree[self.root_domain])
        
    def _build_tree_recursive(self, parent_domain, parent_data, depth=1, max_depth=10):
        """递归构建域名树"""
        if depth > max_depth:
            return
            
        # 获取该域名的扩展域名
        expansion_domains = parent_data.get('expansion', {}).get('domains', [])
        
        for child_domain in expansion_domains:
            if child_domain in self.processed_domains:
                continue
                
            # 检查是否有该域名的扫描结果
            child_data = self.find_domain_scan_result(child_domain, parent_domain)
            if child_data:
                parent_data['children'] = parent_data.get('children', {})
                parent_data['children'][child_domain] = child_data
                self.processed_domains.add(child_domain)
                
                # 递归处理子域名
                self._build_tree_recursive(child_domain, child_data, depth + 1, max_depth)
                
    def find_domain_scan_result(self, domain, parent_domain):
        """查找域名的扫描结果"""
        # 可能的位置：
        # 1. 直接在output下（如果是第一层扫描）
        # 2. 在父域名的expansion/report/domain_scan_results下
        
        # 检查直接路径
        direct_path = self.output_dir / domain
        if direct_path.exists() and (direct_path / 'finish.txt').exists():
            return self.analyze_domain(domain, direct_path)
            
        # 检查在父域名的扩展结果中
        parent_path = self.output_dir / parent_domain
        expansion_path = parent_path / 'expansion' / 'report' / 'domain_scan_results' / domain / domain
        if expansion_path.exists():
            return self.analyze_domain(domain, expansion_path)
            
        # 检查多层扩展结果
        for layer_dir in parent_path.glob('expansion/layer*/report/domain_scan_results'):
            domain_path = layer_dir / domain / domain
            if domain_path.exists():
                return self.analyze_domain(domain, domain_path)
                
        return None
        
    def analyze_domain(self, domain, domain_path=None):
        """分析单个域名的扫描结果"""
        if domain_path is None:
            domain_path = self.output_dir / domain
            
        domain_data = {
            'domain': domain,
            'path': str(domain_path),
            'stats': {},
            'results': {},
            'expansion': {},
            'vulnerabilities': [],
            'children': {},
            'url_titles': {}  # 存储URL和标题的映射
        }
        
        # 读取基础信息并解析URL标题
        base_info_file = domain_path / f'base_info_{domain}.txt'
        if base_info_file.exists():
            with open(base_info_file, 'r', encoding='utf-8') as f:
                content = f.read()
                domain_data['base_info'] = content
                
                # 解析URL和标题
                in_url_section = False
                for line in content.split('\n'):
                    if 'URL和标题:' in line:
                        in_url_section = True
                        continue
                    elif in_url_section and line.strip() and not line.startswith(' '):
                        in_url_section = False
                    elif in_url_section and line.strip().startswith('- '):
                        # 解析格式: - URL [标题][size:大小]
                        parts = line.strip()[2:].split(' ', 1)
                        if len(parts) >= 2:
                            url = parts[0]
                            title_part = parts[1]
                            # 提取标题
                            if '[' in title_part:
                                title = title_part.split('[')[1].split(']')[0]
                                domain_data['url_titles'][url] = title
                
        # 读取fscan结果
        fscan_file = domain_path / f'fscan_{domain}.txt'
        if fscan_file.exists():
            with open(fscan_file, 'r', encoding='utf-8') as f:
                fscan_content = f.read()
                # 将URL转换为可点击的链接
                import re
                fscan_content = re.sub(
                    r'(https?://[^\s<>"{}|\\^`\[\]]+)',
                    r'<a href="\1" target="_blank">\1</a>',
                    fscan_content
                )
                domain_data['fscan_results'] = fscan_content
        else:
            # 尝试在父目录查找
            fscan_file = domain_path.parent / f'fscan_{domain}.txt'
            if fscan_file.exists():
                with open(fscan_file, 'r', encoding='utf-8') as f:
                    fscan_content = f.read()
                    fscan_content = re.sub(
                        r'(https?://[^\s<>"{}|\\^`\[\]]+)',
                        r'<a href="\1" target="_blank">\1</a>',
                        fscan_content
                    )
                    domain_data['fscan_results'] = fscan_content
                
        # 统计信息
        input_dir = domain_path / 'input'
        if input_dir.exists():
            # A记录（IP）
            a_records_file = input_dir / 'a_records.txt'
            if a_records_file.exists():
                with open(a_records_file, 'r') as f:
                    ips = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    domain_data['stats']['ips'] = len(ips)
                    domain_data['results']['ips'] = ips
                    
            # 使用representative_urls.txt作为主要URL来源（已去重）
            rep_urls_file = input_dir / 'representative_urls.txt'
            if rep_urls_file.exists():
                with open(rep_urls_file, 'r') as f:
                    urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    domain_data['stats']['urls'] = len(urls)
                    domain_data['results']['urls'] = urls
                    
        # 扩展目标
        tuozhan_dir = domain_path / 'tuozhan' / 'all_tuozhan'
        if tuozhan_dir.exists():
            # 扩展IP
            ip_file = tuozhan_dir / 'ip.txt'
            if ip_file.exists():
                with open(ip_file, 'r') as f:
                    expansion_ips = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    domain_data['expansion']['ips'] = expansion_ips
                    domain_data['stats']['expansion_ips'] = len(expansion_ips)
                    
            # 扩展域名
            domains_file = tuozhan_dir / 'root_domains.txt'
            if domains_file.exists():
                with open(domains_file, 'r') as f:
                    expansion_domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    domain_data['expansion']['domains'] = expansion_domains
                    domain_data['stats']['expansion_domains'] = len(expansion_domains)
                    
            # 扩展URL（urls.txt存储的域名转换为URL）
            urls_file = tuozhan_dir / 'urls.txt'
            if urls_file.exists():
                with open(urls_file, 'r') as f:
                    expansion_urls = []
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # 将域名转换为https URL
                            if not line.startswith('http'):
                                expansion_urls.append(f'https://{line}')
                            else:
                                expansion_urls.append(line)
                    domain_data['expansion']['urls'] = expansion_urls
                    domain_data['stats']['expansion_urls'] = len(expansion_urls)
                    
            # 读取扩展扫描结果
            scan_results_dir = tuozhan_dir / 'scan_results'
            
            # 读取httpx扫描结果获取URL标题
            httpx_urls_file = scan_results_dir / 'httpx_urls_results.json'
            if httpx_urls_file.exists():
                expansion_url_titles = {}
                try:
                    with open(httpx_urls_file, 'r', encoding='utf-8') as f:
                        for line in f:
                            if line.strip():
                                try:
                                    data = json.loads(line)
                                    url = data.get('url', '')
                                    title = data.get('title', '')
                                    if url and title:
                                        expansion_url_titles[url] = title
                                except:
                                    continue
                    domain_data['expansion_url_titles'] = expansion_url_titles
                except Exception as e:
                    print(f"[!] 解析httpx文件失败 {httpx_urls_file}: {e}")
            
            # 读取urls.txt的afrog扫描结果
            afrog_urls_file = scan_results_dir / 'afrog_urls_results.json'
            if afrog_urls_file.exists():
                domain_data['expansion_afrog_results'] = self.parse_afrog_results(afrog_urls_file)
                
            # 读取ip.txt的fscan扫描结果
            fscan_ips_file = scan_results_dir / 'fscan_ips_results.txt'
            if fscan_ips_file.exists():
                with open(fscan_ips_file, 'r', encoding='utf-8') as f:
                    fscan_ips_content = f.read()
                    # 将URL转换为可点击的链接
                    import re
                    fscan_ips_content = re.sub(
                        r'(https?://[^\s<>"{}|\\^`\[\]]+)',
                        r'<a href="\1" target="_blank">\1</a>',
                        fscan_ips_content
                    )
                    domain_data['expansion_fscan_results'] = fscan_ips_content
                    
        # 漏洞发现
        vuln_file = domain_path / '发现漏洞.txt'
        if vuln_file.exists():
            with open(vuln_file, 'r', encoding='utf-8') as f:
                vulns = [v.strip() for v in f.read().strip().split('\n') if v.strip()]
                domain_data['vulnerabilities'].extend(vulns)
                
        # 解析afrog结果
        afrog_patterns = [
            domain_path / f'afrog_report_{domain}.json',
            domain_path.parent / f'afrog_report_{domain}.json',
            self.output_dir / domain / f'afrog_report_{domain}.json'
        ]
        
        for afrog_file in afrog_patterns:
            if afrog_file.exists():
                afrog_data = self.parse_afrog_results(afrog_file)
                domain_data['afrog_results'] = afrog_data
                domain_data['stats']['afrog_vulns'] = len(afrog_data)
                break
                
        return domain_data
        
    def parse_afrog_results(self, afrog_file):
        """解析afrog扫描结果"""
        afrog_data = []
        try:
            with open(afrog_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if not content:
                    return afrog_data
                    
                # 尝试解析为JSON数组
                try:
                    vulns = json.loads(content)
                    if isinstance(vulns, list):
                        for vuln in vulns:
                            if vuln.get('isvul'):
                                afrog_data.append({
                                    'target': vuln.get('fulltarget', vuln.get('target', '')),
                                    'poc_name': vuln.get('pocinfo', {}).get('infoname', ''),
                                    'poc_id': vuln.get('pocinfo', {}).get('id', ''),
                                    'severity': vuln.get('pocinfo', {}).get('infoseg', 'info'),
                                    'author': vuln.get('pocinfo', {}).get('infoauthor', ''),
                                    'detail': '',  # afrog格式中没有详细描述
                                    'created_at': '',  # afrog格式中没有时间
                                    'full_data': vuln
                                })
                except json.JSONDecodeError:
                    # 尝试逐行解析
                    for line in content.split('\n'):
                        if line.strip():
                            try:
                                vuln = json.loads(line)
                                if isinstance(vuln, dict) and vuln.get('isvul'):
                                    afrog_data.append({
                                        'target': vuln.get('fulltarget', vuln.get('target', '')),
                                        'poc_name': vuln.get('pocinfo', {}).get('infoname', ''),
                                        'poc_id': vuln.get('pocinfo', {}).get('id', ''),
                                        'severity': vuln.get('pocinfo', {}).get('infoseg', 'info'),
                                        'author': vuln.get('pocinfo', {}).get('infoauthor', ''),
                                        'detail': '',
                                        'created_at': '',
                                        'full_data': vuln
                                    })
                            except:
                                continue
                                
        except Exception as e:
            print(f"[!] 解析afrog文件失败 {afrog_file}: {e}")
            
        return afrog_data
        
    def generate_html_report(self):
        """生成HTML报告"""
        html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.root_domain} - 渗透测试扫描报告</title>
    <style>
        * {{
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .tree-container {{
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .domain-node {{
            margin: 10px 0;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
            border: 1px solid #e9ecef;
            transition: all 0.3s;
        }}
        
        .domain-node:hover {{
            background: #e9ecef;
            transform: translateX(5px);
        }}
        
        .domain-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            cursor: pointer;
            user-select: none;
        }}
        
        .domain-name {{
            font-size: 1.2em;
            font-weight: bold;
            color: #495057;
        }}
        
        .domain-stats {{
            display: flex;
            gap: 15px;
            font-size: 0.9em;
            color: #6c757d;
        }}
        
        .stat-badge {{
            background: #e9ecef;
            padding: 2px 8px;
            border-radius: 12px;
        }}
        
        .expand-icon {{
            font-size: 1.2em;
            transition: transform 0.3s;
        }}
        
        .expanded .expand-icon {{
            transform: rotate(90deg);
        }}
        
        /* 域名内容容器 - 初始隐藏 */
        .domain-node .domain-content {{
            display: none;
            margin-top: 15px;
        }}
        
        /* 展开状态下显示内容 - 移除，由JS控制 */
        /* .domain-node.expanded .domain-content {{
            display: block;
        }} */
        
        .info-section {{
            margin: 15px 0;
            padding: 15px;
            background: white;
            border-radius: 8px;
            border: 1px solid #dee2e6;
        }}
        
        .info-title {{
            font-weight: bold;
            color: #495057;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        
        .url-list, .ip-list, .domain-list {{
            max-height: 300px;
            overflow-y: auto;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 5px;
        }}
        
        .url-item, .ip-item, .domain-item {{
            padding: 5px 10px;
            margin: 3px 0;
            background: white;
            border-radius: 4px;
            border: 1px solid #e9ecef;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            word-break: break-all;
            transition: background 0.2s;
        }}
        
        .url-item:hover, .ip-item:hover, .domain-item:hover {{
            background: #e9ecef;
        }}
        
        .url-item a {{
            color: #667eea;
            text-decoration: none;
        }}
        
        .url-item a:hover {{
            text-decoration: underline;
        }}
        
        .vuln-section {{
            margin: 15px 0;
        }}
        
        .vuln-item {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 10px 0;
            border-radius: 0 5px 5px 0;
        }}
        
        .vuln-critical {{
            background: #f8d7da;
            border-left-color: #dc3545;
        }}
        
        .vuln-high {{
            background: #fff3cd;
            border-left-color: #fd7e14;
        }}
        
        .vuln-medium {{
            background: #fff3cd;
            border-left-color: #ffc107;
        }}
        
        .vuln-low {{
            background: #d4edda;
            border-left-color: #28a745;
        }}
        
        .vuln-info {{
            background: #d1ecf1;
            border-left-color: #17a2b8;
        }}
        
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        
        .vuln-title {{
            font-weight: bold;
            color: #495057;
        }}
        
        .severity-badge {{
            padding: 2px 8px;
            border-radius: 3px;
            color: white;
            font-size: 0.8em;
            font-weight: bold;
        }}
        
        .severity-critical {{ background: #dc3545; }}
        .severity-high {{ background: #fd7e14; }}
        .severity-medium {{ background: #ffc107; color: #333; }}
        .severity-low {{ background: #28a745; }}
        .severity-info {{ background: #17a2b8; }}
        
        .children-container {{
            margin-left: 30px;
            padding-left: 20px;
            border-left: 2px solid #dee2e6;
        }}
        
        .base-info-content {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            white-space: pre-wrap;
            word-wrap: break-word;
            max-height: 400px;
            overflow-y: auto;
        }}
        
        .tabs {{
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
            border-bottom: 2px solid #dee2e6;
        }}
        
        .tab {{
            padding: 10px 20px;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.3s;
        }}
        
        .tab:hover {{
            background: #f8f9fa;
        }}
        
        .tab.active {{
            border-bottom-color: #667eea;
            color: #667eea;
            font-weight: bold;
        }}
        
        .tab-content {{
            display: none;
        }}
        
        .tab-content.active {{
            display: block;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #e9ecef;
            text-align: center;
        }}
        
        .summary-value {{
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }}
        
        .summary-label {{
            color: #6c757d;
            font-size: 0.9em;
            margin-top: 5px;
        }}
        
        .search-box {{
            margin-bottom: 20px;
            position: relative;
        }}
        
        .search-input {{
            width: 100%;
            padding: 12px 40px 12px 15px;
            border: 1px solid #ced4da;
            border-radius: 5px;
            font-size: 1em;
        }}
        
        .search-icon {{
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
            color: #6c757d;
        }}
        
        .highlight {{
            background: yellow;
            font-weight: bold;
        }}
        
        /* 滚动条样式 */
        ::-webkit-scrollbar {{
            width: 8px;
            height: 8px;
        }}
        
        ::-webkit-scrollbar-track {{
            background: #f1f1f1;
            border-radius: 4px;
        }}
        
        ::-webkit-scrollbar-thumb {{
            background: #888;
            border-radius: 4px;
        }}
        
        ::-webkit-scrollbar-thumb:hover {{
            background: #555;
        }}
        
        @media (max-width: 768px) {{
            .container {{
                padding: 10px;
            }}
            
            .domain-stats {{
                flex-wrap: wrap;
                gap: 5px;
            }}
            
            .children-container {{
                margin-left: 15px;
                padding-left: 10px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{self.root_domain} - 渗透测试扫描报告</h1>
            <div style="opacity: 0.9;">生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </div>
        
        <div class="search-box">
            <input type="text" class="search-input" id="searchInput" placeholder="搜索域名、IP、URL...">
            <span class="search-icon">🔍</span>
        </div>
        
        <div class="tree-container">
            <h2>域名扫描树形结构</h2>
"""
        
        # 生成域名树
        for domain, data in self.domain_tree.items():
            html_content += self.generate_domain_node(domain, data)
            
        html_content += """
        </div>
    </div>
    
    <script>
        // 展开/折叠功能
        function toggleDomain(domainId) {
            console.log('toggleDomain called with:', domainId);
            const node = document.getElementById(domainId);
            if (!node) {
                console.error('Cannot find node with ID:', domainId);
                return;
            }
            
            // 获取domain-content元素
            const content = node.querySelector('.domain-content');
            const expandIcon = node.querySelector('.expand-icon');
            
            if (!content) {
                console.error('Cannot find domain-content for:', domainId);
                return;
            }
            
            // 切换显示状态
            const isExpanded = node.classList.contains('expanded');
            
            if (isExpanded) {
                // 折叠
                node.classList.remove('expanded');
                content.style.display = 'none';
                if (expandIcon) expandIcon.style.transform = 'rotate(0deg)';
            } else {
                // 展开
                node.classList.add('expanded');
                content.style.display = 'block';
                if (expandIcon) expandIcon.style.transform = 'rotate(90deg)';
            }
            
            console.log('Toggle complete - expanded:', !isExpanded);
        }
        
        // 展开/折叠扩展树
        function toggleExpansionTree(event) {
            const container = event.currentTarget.parentElement;
            const icon = container.querySelector('.expansion-tree-icon');
            const content = container.querySelector('.expansion-tree-content');
            
            if (content.style.display === 'none') {
                content.style.display = 'block';
                icon.style.transform = 'rotate(90deg)';
            } else {
                content.style.display = 'none';
                icon.style.transform = 'rotate(0deg)';
            }
        }
        
        // 标签切换功能
        function switchTab(domainId, tabName) {
            const tabs = document.querySelectorAll(`#${domainId} .tab`);
            const contents = document.querySelectorAll(`#${domainId} .tab-content`);
            
            tabs.forEach(tab => {
                if (tab.dataset.tab === tabName) {
                    tab.classList.add('active');
                } else {
                    tab.classList.remove('active');
                }
            });
            
            contents.forEach(content => {
                if (content.dataset.content === tabName) {
                    content.classList.add('active');
                } else {
                    content.classList.remove('active');
                }
            });
        }
        
        // 搜索功能
        document.getElementById('searchInput').addEventListener('input', function(e) {
            const searchTerm = e.target.value.toLowerCase();
            const allNodes = document.querySelectorAll('.domain-node');
            
            if (searchTerm === '') {
                // 清除高亮
                document.querySelectorAll('.highlight').forEach(el => {
                    el.classList.remove('highlight');
                });
                allNodes.forEach(node => {
                    node.style.display = 'block';
                });
                return;
            }
            
            allNodes.forEach(node => {
                const text = node.textContent.toLowerCase();
                if (text.includes(searchTerm)) {
                    node.style.display = 'block';
                    // 自动展开包含搜索词的节点
                    if (!node.classList.contains('expanded')) {
                        node.classList.add('expanded');
                    }
                    // 高亮搜索词
                    highlightText(node, searchTerm);
                } else {
                    node.style.display = 'none';
                }
            });
        });
        
        function highlightText(node, searchTerm) {
            // 简单的高亮实现
            const walker = document.createTreeWalker(
                node,
                NodeFilter.SHOW_TEXT,
                null,
                false
            );
            
            let textNode;
            while (textNode = walker.nextNode()) {
                const text = textNode.nodeValue;
                const regex = new RegExp(searchTerm, 'gi');
                if (regex.test(text)) {
                    const span = document.createElement('span');
                    span.innerHTML = text.replace(regex, '<span class="highlight">$&</span>');
                    textNode.parentNode.replaceChild(span, textNode);
                }
            }
        }
        
        // 复制功能
        document.addEventListener('click', function(e) {
            if (e.target.classList.contains('url-item') || 
                e.target.classList.contains('ip-item') || 
                e.target.classList.contains('domain-item')) {
                const text = e.target.textContent;
                navigator.clipboard.writeText(text).then(() => {
                    const originalBg = e.target.style.background;
                    e.target.style.background = '#d4edda';
                    setTimeout(() => {
                        e.target.style.background = originalBg;
                    }, 500);
                });
            }
        });
        
        // 展开所有
        function expandAll() {
            document.querySelectorAll('.domain-node').forEach(node => {
                node.classList.add('expanded');
                const content = node.querySelector('.domain-content');
                if (content) {
                    content.style.display = 'block';
                }
                const expandIcon = node.querySelector('.expand-icon');
                if (expandIcon) {
                    expandIcon.style.transform = 'rotate(90deg)';
                }
            });
        }
        
        // 折叠所有
        function collapseAll() {
            document.querySelectorAll('.domain-node').forEach(node => {
                node.classList.remove('expanded');
                const content = node.querySelector('.domain-content');
                if (content) {
                    content.style.display = 'none';
                }
                const expandIcon = node.querySelector('.expand-icon');
                if (expandIcon) {
                    expandIcon.style.transform = 'rotate(0deg)';
                }
            });
        }
        
        // 页面加载时初始化
        document.addEventListener('DOMContentLoaded', function() {
            // 确保所有domain-content初始状态为隐藏
            document.querySelectorAll('.domain-content').forEach(content => {
                if (!content.closest('.domain-node').classList.contains('expanded')) {
                    content.style.display = 'none';
                }
            });
        });
    </script>
</body>
</html>
"""
        
        return html_content
        
    def generate_domain_node(self, domain, data, level=0):
        """生成单个域名节点的HTML"""
        # 使用时间戳或随机数确保ID唯一性
        import time
        unique_suffix = int(time.time() * 1000000) % 1000000
        domain_id = f"domain_{domain.replace('.', '_')}_{level}_{unique_suffix}"
        
        # 计算各项数量
        urls_count = len(data['results'].get('urls', []))
        ips_count = len(data['results'].get('ips', []))
        exp_domains_count = len(data['expansion'].get('domains', []))
        exp_ips_count = len(data['expansion'].get('ips', []))
        
        # 统计信息
        stats = []
        if data['stats'].get('urls', 0) > 0:
            stats.append(f"🔗 {data['stats']['urls']} URLs")
        if data['stats'].get('ips', 0) > 0:
            stats.append(f"🖥️ {data['stats']['ips']} IPs")
        if data['stats'].get('expansion_domains', 0) > 0:
            stats.append(f"🌐 {data['stats']['expansion_domains']} 扩展域名")
        if data.get('vulnerabilities') or data.get('afrog_results'):
            vuln_count = len(data.get('vulnerabilities', [])) + len(data.get('afrog_results', []))
            stats.append(f"⚠️ {vuln_count} 漏洞")
            
        node_html = f"""
        <div class="domain-node" id="{domain_id}">
            <div class="domain-header" onclick="toggleDomain('{domain_id}')">
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span class="expand-icon">▶</span>
                    <span class="domain-name">{domain}</span>
                </div>
                <div class="domain-stats">
                    {' '.join(f'<span class="stat-badge">{stat}</span>' for stat in stats)}
                </div>
            </div>
            
            <div class="domain-content" style="display: none;">
                <div class="tabs">
                    <div class="tab active" data-tab="overview" onclick="switchTab('{domain_id}', 'overview')">概览</div>
                    <div class="tab" data-tab="urls" onclick="switchTab('{domain_id}', 'urls')">URLs</div>
                    <div class="tab" data-tab="ips" onclick="switchTab('{domain_id}', 'ips')">IPs</div>
                    <div class="tab" data-tab="expansion" onclick="switchTab('{domain_id}', 'expansion')">扩展目标</div>
                    <div class="tab" data-tab="vulnerabilities" onclick="switchTab('{domain_id}', 'vulnerabilities')">漏洞</div>
                    <div class="tab" data-tab="baseinfo" onclick="switchTab('{domain_id}', 'baseinfo')">端口扫描</div>
                </div>
                
                <!-- 概览标签 -->
                <div class="tab-content active" data-content="overview">
                    <div class="summary-grid">
                        <div class="summary-card">
                            <div class="summary-value">{data['stats'].get('urls', 0)}</div>
                            <div class="summary-label">发现URL</div>
                        </div>
                        <div class="summary-card">
                            <div class="summary-value">{data['stats'].get('ips', 0)}</div>
                            <div class="summary-label">发现IP</div>
                        </div>
                        <div class="summary-card">
                            <div class="summary-value">{data['stats'].get('expansion_domains', 0)}</div>
                            <div class="summary-label">扩展域名</div>
                        </div>
                        <div class="summary-card">
                            <div class="summary-value">{len(data.get('vulnerabilities', [])) + len(data.get('afrog_results', []))}</div>
                            <div class="summary-label">发现漏洞</div>
                        </div>
                    </div>
"""
        
        # 如果有子域名，在概览中显示（默认展开）
        if data.get('children'):
            node_html += """
                    <div style="margin-top: 30px;">
                        <div style="cursor: pointer; user-select: none; display: flex; align-items: center; gap: 10px;" onclick="toggleExpansionTree(event)">
                            <span class="expansion-tree-icon" style="font-size: 1.2em; transition: transform 0.3s; transform: rotate(90deg);">▶</span>
                            <h4 style="margin: 0; color: #495057;">🌳 扩展域名扫描结果</h4>
                        </div>
                        <div class="expansion-tree-content" style="display: block; margin-top: 15px;">
                            <div class="children-container" style="margin-left: 0;">
"""
            for child_domain, child_data in data['children'].items():
                node_html += self.generate_domain_node(child_domain, child_data, level + 1)
            node_html += """
                            </div>
                        </div>
                    </div>
"""
            
        node_html += """
                </div>
                
                <!-- URLs标签 -->
                <div class="tab-content" data-content="urls">
                    <div class="info-section">
                        <div class="info-title">🔗 发现的URLs</div>
                        <div class="url-list">
"""
        
        for url in data['results'].get('urls', []):
            title = data.get('url_titles', {}).get(url, '')
            if title:
                node_html += f'<div class="url-item"><a href="{url}" target="_blank">{url}</a> <span style="color: #6c757d;">[{title}]</span></div>'
            else:
                node_html += f'<div class="url-item"><a href="{url}" target="_blank">{url}</a></div>'
            
        node_html += """
                        </div>
                    </div>
"""
        
        # 显示扩展URL
        if data['expansion'].get('urls'):
            node_html += f"""
                    <div class="info-section">
                        <div class="info-title">🔍 扩展发现的URLs</div>
                        <div class="url-list">
"""
            for exp_url in data['expansion']['urls']:
                # 获取扩展URL的标题
                exp_title = data.get('expansion_url_titles', {}).get(exp_url, '')
                if exp_title:
                    node_html += f'<div class="url-item"><a href="{exp_url}" target="_blank">{exp_url}</a> <span style="color: #6c757d;">[{exp_title}]</span></div>'
                else:
                    node_html += f'<div class="url-item"><a href="{exp_url}" target="_blank">{exp_url}</a></div>'
            node_html += """
                        </div>
                    </div>
"""
        
        node_html += """
                </div>
                
                <!-- IPs标签 -->
                <div class="tab-content" data-content="ips">
                    <div class="info-section">
                        <div class="info-title">🖥️ 发现的IPs</div>
                        <div class="ip-list">
"""
        
        for ip in data['results'].get('ips', []):
            node_html += f'<div class="ip-item">{ip}</div>'
            
        node_html += """
                        </div>
                    </div>
"""
        
        # 显示扩展IP
        if data['expansion'].get('ips'):
            node_html += f"""
                    <div class="info-section">
                        <div class="info-title">📡 扩展发现的IPs</div>
                        <div class="ip-list">
"""
            for exp_ip in data['expansion']['ips']:
                node_html += f'<div class="ip-item">{exp_ip}</div>'
            node_html += """
                        </div>
                    </div>
"""
        
        node_html += """
                </div>
                
                <!-- 扩展目标标签 -->
                <div class="tab-content" data-content="expansion">
"""
        
        if data['expansion'].get('domains'):
            node_html += f"""
                    <div class="info-section">
                        <div class="info-title">🌐 扩展域名</div>
                        <div class="domain-list">
"""
            for exp_domain in data['expansion']['domains']:
                node_html += f'<div class="domain-item">{exp_domain}</div>'
            node_html += '</div></div>'
            
        if data['expansion'].get('ips'):
            node_html += f"""
                    <div class="info-section">
                        <div class="info-title">📡 扩展IP</div>
                        <div class="ip-list">
"""
            for exp_ip in data['expansion']['ips']:
                node_html += f'<div class="ip-item">{exp_ip}</div>'
            node_html += '</div></div>'
            
        node_html += """
                </div>
                
                <!-- 漏洞标签 -->
                <div class="tab-content" data-content="vulnerabilities">
"""
        
        # 显示普通漏洞
        if data.get('vulnerabilities'):
            node_html += '<div class="vuln-section">'
            for vuln in data['vulnerabilities']:
                node_html += f'<div class="vuln-item">{vuln}</div>'
            node_html += '</div>'
            
        # 显示afrog漏洞
        if data.get('afrog_results'):
            node_html += '<div class="vuln-section">'
            for vuln in data['afrog_results']:
                severity = vuln['severity'].lower()
                node_html += f"""
                    <div class="vuln-item vuln-{severity}">
                        <div class="vuln-header">
                            <span class="vuln-title">{vuln['poc_name']}</span>
                            <span class="severity-badge severity-{severity}">{vuln['severity'].upper()}</span>
                        </div>
                        <div style="margin-top: 10px;">
                            <a href="{vuln['target']}" target="_blank" style="color: #667eea;">{vuln['target']}</a>
                        </div>
                        {f'<div style="margin-top: 10px; color: #6c757d;">{vuln["detail"]}</div>' if vuln.get('detail') else ''}
                        {f'<div style="margin-top: 5px; color: #adb5bd; font-size: 0.8em;">POC ID: {vuln["poc_id"]}</div>' if vuln.get('poc_id') else ''}
                        {f'<div style="margin-top: 5px; color: #adb5bd; font-size: 0.8em;">作者: {vuln["author"]}</div>' if vuln.get('author') else ''}
                    </div>
"""
            node_html += '</div>'
            
        # 显示扩展URLs的afrog漏洞
        if data.get('expansion_afrog_results'):
            node_html += '<div class="vuln-section" style="margin-top: 20px;">'
            node_html += '<h4 style="color: #495057; margin-bottom: 15px;">🔍 扩展域名漏洞扫描结果</h4>'
            for vuln in data['expansion_afrog_results']:
                severity = vuln['severity'].lower()
                node_html += f"""
                    <div class="vuln-item vuln-{severity}">
                        <div class="vuln-header">
                            <span class="vuln-title">{vuln['poc_name']}</span>
                            <span class="severity-badge severity-{severity}">{vuln['severity'].upper()}</span>
                        </div>
                        <div style="margin-top: 10px;">
                            <a href="{vuln['target']}" target="_blank" style="color: #667eea;">{vuln['target']}</a>
                        </div>
                        {f'<div style="margin-top: 10px; color: #6c757d;">{vuln["detail"]}</div>' if vuln.get('detail') else ''}
                        {f'<div style="margin-top: 5px; color: #adb5bd; font-size: 0.8em;">POC ID: {vuln["poc_id"]}</div>' if vuln.get('poc_id') else ''}
                        {f'<div style="margin-top: 5px; color: #adb5bd; font-size: 0.8em;">作者: {vuln["author"]}</div>' if vuln.get('author') else ''}
                    </div>
"""
            node_html += '</div>'
            
        node_html += """
                </div>
                
                <!-- 端口扫描标签 -->
                <div class="tab-content" data-content="baseinfo">
                    <div class="info-section">
                        <div class="info-title">🔍 端口扫描结果</div>
                        <div class="base-info-content">{}</div>
                    </div>
""".format(data.get('fscan_results', '暂无端口扫描结果'))
        
        # 显示扩展IP的fscan扫描结果
        if data.get('expansion_fscan_results'):
            node_html += f"""
                    <div class="info-section" style="margin-top: 20px;">
                        <div class="info-title">📡 扩展IP端口扫描结果</div>
                        <div class="base-info-content">{data['expansion_fscan_results']}</div>
                    </div>
"""
        
        node_html += """
                </div>
""".format()
        
        node_html += """
            </div>
        </div>
"""
        
        return node_html
        
    def generate_report(self, output_file=None):
        """生成完整报告"""
        # 构建域名树
        self.build_domain_tree()
        
        # 生成HTML
        html_content = self.generate_html_report()
        
        # 确定输出文件路径
        if not output_file:
            output_file = f"reports/{self.root_domain}_tree_report.html"
            
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 写入文件
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        return output_path


def main():
    parser = argparse.ArgumentParser(description='生成树形结构的渗透测试扫描报告')
    parser.add_argument('domain', nargs='?', help='根域名')
    parser.add_argument('-o', '--output', help='输出文件路径')
    parser.add_argument('--open', action='store_true', help='生成后自动打开浏览器')
    
    args = parser.parse_args()
    
    # 自动检测域名
    if not args.domain:
        output_dir = Path('output')
        if output_dir.exists():
            # 只选择包含扫描结果的真实域名目录
            domains = []
            for d in output_dir.iterdir():
                if d.is_dir() and (d / 'finish.txt').exists():
                    domains.append(d.name)
            if domains:
                if len(domains) == 1:
                    args.domain = domains[0]
                    print(f"[*] 自动检测到域名: {args.domain}")
                else:
                    print("[*] 检测到多个域名:")
                    for i, domain in enumerate(domains, 1):
                        print(f"    {i}. {domain}")
                    choice = input("[?] 请选择域名编号: ")
                    try:
                        args.domain = domains[int(choice) - 1]
                    except:
                        print("[!] 无效选择")
                        sys.exit(1)
            else:
                print("[!] 未找到扫描结果")
                sys.exit(1)
    
    # 生成报告
    print(f"[*] 正在生成 {args.domain} 的树形扫描报告...")
    
    generator = TreeReportGenerator(args.domain)
    output_path = generator.generate_report(args.output)
    
    print(f"[✓] 报告已生成: {output_path}")
    
    # 自动打开浏览器
    if args.open:
        import webbrowser
        file_url = f"file://{output_path.absolute()}"
        webbrowser.open(file_url)
        print(f"[✓] 已在浏览器中打开报告")


if __name__ == '__main__':
    main()