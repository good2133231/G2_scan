#!/usr/bin/env python3
"""
多层扫描报告生成器
生成美观的HTML报告，展示多层扫描的完整结果
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import re


class MultilayerReportGenerator:
    def __init__(self, domain, output_dir="output"):
        self.domain = domain
        self.output_dir = Path(output_dir)
        self.domain_dir = self.output_dir / domain
        self.report_data = {
            'domain': domain,
            'generated_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'layers': {}
        }
        
    def analyze_layer1(self):
        """分析第一层扫描结果"""
        layer1_data = {
            'name': '第一层扫描（主域名）',
            'description': f'对 {self.domain} 的主域名扫描',
            'stats': {},
            'results': {}
        }
        
        # 读取基础信息
        base_info_file = self.domain_dir / f'base_info_{self.domain}.txt'
        if base_info_file.exists():
            with open(base_info_file, 'r', encoding='utf-8') as f:
                content = f.read()
                # 提取统计信息
                if '共有' in content:
                    matches = re.findall(r'共有\s*(\d+)\s*个', content)
                    if matches:
                        layer1_data['stats']['total_urls'] = int(matches[0])
                
        # 统计各类结果
        input_dir = self.domain_dir / 'input'
        if input_dir.exists():
            # A记录（IP）
            a_records_file = input_dir / 'a_records.txt'
            if a_records_file.exists():
                with open(a_records_file, 'r') as f:
                    ips = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    layer1_data['stats']['ips'] = len(ips)
                    layer1_data['results']['ips'] = ips[:10]  # 只显示前10个
            
            # URL统计
            urls_file = input_dir / 'urls.txt'
            if urls_file.exists():
                with open(urls_file, 'r') as f:
                    urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    layer1_data['stats']['urls'] = len(urls)
                    layer1_data['results']['urls'] = urls[:10]
                    
            # 代表性URL
            rep_urls_file = input_dir / 'representative_urls.txt'
            if rep_urls_file.exists():
                with open(rep_urls_file, 'r') as f:
                    rep_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    layer1_data['stats']['representative_urls'] = len(rep_urls)
                    
        # 扩展目标
        tuozhan_dir = self.domain_dir / 'tuozhan' / 'all_tuozhan'
        if tuozhan_dir.exists():
            # 扩展IP
            ip_file = tuozhan_dir / 'ip.txt'
            if ip_file.exists():
                with open(ip_file, 'r') as f:
                    expansion_ips = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    layer1_data['stats']['expansion_ips'] = len(expansion_ips)
                    
            # 扩展域名
            domains_file = tuozhan_dir / 'root_domains.txt'
            if domains_file.exists():
                with open(domains_file, 'r') as f:
                    expansion_domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    layer1_data['stats']['expansion_domains'] = len(expansion_domains)
                    layer1_data['results']['expansion_domains'] = expansion_domains[:10]
                    
            # 扩展URL
            urls_file = tuozhan_dir / 'urls.txt'
            if urls_file.exists():
                with open(urls_file, 'r') as f:
                    expansion_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    layer1_data['stats']['expansion_urls'] = len(expansion_urls)
                    
        # 漏洞发现
        vuln_file = self.domain_dir / '发现漏洞.txt'
        if vuln_file.exists():
            with open(vuln_file, 'r', encoding='utf-8') as f:
                vulns = f.read().strip().split('\n')
                layer1_data['stats']['vulnerabilities'] = len([v for v in vulns if v.strip()])
                layer1_data['results']['vulnerabilities'] = [v for v in vulns if v.strip()]
                
        # 解析afrog结果
        afrog_file = self.domain_dir / f'afrog_report_{self.domain}.json'
        if afrog_file.exists():
            layer1_data['afrog_results'] = self.parse_afrog_results(afrog_file)
                
        self.report_data['layers']['layer1'] = layer1_data
        
    def analyze_layer2(self):
        """分析第二层扩展扫描结果"""
        expansion_dir = self.domain_dir / 'expansion' / 'report'
        if not expansion_dir.exists():
            return
            
        layer2_data = {
            'name': '第二层扫描（扩展资产）',
            'description': '基于第一层发现的资产进行扩展扫描',
            'stats': {},
            'results': {},
            'details': {}
        }
        
        # 域名扫描结果
        domain_results_dir = expansion_dir / 'domain_scan_results'
        if domain_results_dir.exists():
            scanned_domains = []
            total_new_ips = 0
            total_new_urls = 0
            
            for domain_dir in domain_results_dir.iterdir():
                if domain_dir.is_dir():
                    domain_name = domain_dir.name
                    scanned_domains.append(domain_name)
                    
                    # 统计每个域名的结果
                    domain_stats = {}
                    
                    # 检查该域名的扫描结果
                    domain_output = domain_dir / domain_name
                    if domain_output.exists():
                        # 统计IP
                        ip_file = domain_output / 'input' / 'a_records.txt'
                        if ip_file.exists():
                            with open(ip_file, 'r') as f:
                                ips = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                                domain_stats['ips'] = len(ips)
                                total_new_ips += len(ips)
                                
                        # 统计URL
                        url_file = domain_output / 'input' / 'urls.txt'
                        if url_file.exists():
                            with open(url_file, 'r') as f:
                                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                                domain_stats['urls'] = len(urls)
                                total_new_urls += len(urls)
                                
                        # 检查扩展结果
                        tuozhan_dir = domain_output / 'tuozhan' / 'all_tuozhan'
                        if tuozhan_dir.exists():
                            # 新发现的域名
                            new_domains_file = tuozhan_dir / 'root_domains.txt'
                            if new_domains_file.exists():
                                with open(new_domains_file, 'r') as f:
                                    new_domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                                    domain_stats['new_domains'] = len(new_domains)
                                    
                    layer2_data['details'][domain_name] = domain_stats
                    
            layer2_data['stats']['scanned_domains'] = len(scanned_domains)
            layer2_data['stats']['total_new_ips'] = total_new_ips
            layer2_data['stats']['total_new_urls'] = total_new_urls
            layer2_data['results']['scanned_domains'] = scanned_domains[:10]
            
        # IP扫描结果
        ip_results_dir = expansion_dir / 'ip_scan_results'
        if ip_results_dir.exists():
            ip_scan_count = len(list(ip_results_dir.iterdir()))
            layer2_data['stats']['ip_scans'] = ip_scan_count
            
        # URL扫描结果
        url_results_dir = expansion_dir / 'url_scan_results'
        if url_results_dir.exists():
            httpx_result_file = url_results_dir / 'httpx_result.json'
            if httpx_result_file.exists():
                with open(httpx_result_file, 'r') as f:
                    url_count = sum(1 for line in f if line.strip())
                    layer2_data['stats']['url_scans'] = url_count
                    
        self.report_data['layers']['layer2'] = layer2_data
        
    def analyze_layer3_plus(self):
        """分析第三层及以上的扫描结果"""
        # 查找layer3及以上的目录
        expansion_base = self.domain_dir / 'expansion'
        if not expansion_base.exists():
            return
            
        for layer_dir in expansion_base.iterdir():
            if layer_dir.is_dir() and layer_dir.name.startswith('layer'):
                match = re.match(r'layer(\d+)', layer_dir.name)
                if match:
                    layer_num = int(match.group(1))
                    if layer_num >= 3:
                        self.analyze_layer_n(layer_num, layer_dir)
                        
    def parse_afrog_results(self, afrog_file):
        """解析afrog扫描结果"""
        afrog_data = []
        try:
            with open(afrog_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        try:
                            vuln = json.loads(line)
                            afrog_data.append({
                                'target': vuln.get('target', ''),
                                'poc_name': vuln.get('poc_info', {}).get('name', ''),
                                'severity': vuln.get('poc_info', {}).get('severity', ''),
                                'detail': vuln.get('poc_info', {}).get('detail', {}).get('description', ''),
                                'created_at': vuln.get('created_at', '')
                            })
                        except:
                            pass
        except:
            pass
        return afrog_data
        
    def analyze_layer_n(self, layer_num, layer_dir):
        """分析第N层扫描结果"""
        layer_data = {
            'name': f'第{layer_num}层扫描',
            'description': f'基于第{layer_num-1}层发现的资产继续扩展',
            'stats': {},
            'results': {}
        }
        
        # 分析该层的报告目录
        report_dir = layer_dir / 'report'
        if report_dir.exists():
            # 统计域名扫描结果
            domain_results_dir = report_dir / 'domain_scan_results'
            if domain_results_dir.exists():
                scanned_domains = len(list(domain_results_dir.iterdir()))
                layer_data['stats']['scanned_domains'] = scanned_domains
                
        # 检查合并的目标文件
        merged_dir = layer_dir / 'merged_targets'
        if merged_dir.exists():
            # 统计合并的IP
            ip_file = merged_dir / 'ip.txt'
            if ip_file.exists():
                with open(ip_file, 'r') as f:
                    ips = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    layer_data['stats']['merged_ips'] = len(ips)
                    
            # 统计合并的域名
            domains_file = merged_dir / 'root_domains.txt'
            if domains_file.exists():
                with open(domains_file, 'r') as f:
                    domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    layer_data['stats']['merged_domains'] = len(domains)
                    
        self.report_data['layers'][f'layer{layer_num}'] = layer_data
        
    def generate_html_report(self):
        """生成HTML报告"""
        html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.domain} - 多层扫描报告</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .header h1 {{
            margin: 0 0 10px 0;
            font-size: 2.5em;
        }}
        
        .header .subtitle {{
            opacity: 0.9;
            font-size: 1.1em;
        }}
        
        .layer-section {{
            background: white;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .layer-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid #e9ecef;
        }}
        
        .layer-title {{
            font-size: 1.8em;
            color: #495057;
            margin: 0;
        }}
        
        .layer-description {{
            color: #6c757d;
            font-size: 0.95em;
            margin-top: 5px;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }}
        
        .stat-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #e9ecef;
            transition: transform 0.2s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }}
        
        .stat-value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
            margin: 0;
        }}
        
        .stat-label {{
            color: #6c757d;
            font-size: 0.9em;
            margin-top: 5px;
        }}
        
        .results-section {{
            margin-top: 25px;
        }}
        
        .results-title {{
            font-size: 1.3em;
            color: #495057;
            margin-bottom: 15px;
            font-weight: 600;
        }}
        
        .result-list {{
            background: #f8f9fa;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
        }}
        
        .result-item {{
            padding: 8px 12px;
            margin: 5px 0;
            background: white;
            border-radius: 5px;
            border: 1px solid #e9ecef;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            word-break: break-all;
            transition: background 0.2s;
        }}
        
        .result-item:hover {{
            background: #f8f9fa;
        }}
        
        .result-item a {{
            color: inherit;
            text-decoration: none;
        }}
        
        .result-item a:hover {{
            text-decoration: underline;
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
        
        .domain-detail {{
            background: #e8f4fd;
            border-left: 4px solid #667eea;
            padding: 10px 15px;
            margin: 10px 0;
            border-radius: 0 5px 5px 0;
        }}
        
        .flow-diagram {{
            background: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }}
        
        .flow-diagram h2 {{
            color: #495057;
            margin-bottom: 20px;
        }}
        
        .flow-container {{
            display: flex;
            justify-content: center;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }}
        
        .flow-node {{
            background: #667eea;
            color: white;
            padding: 15px 25px;
            border-radius: 25px;
            font-weight: bold;
            position: relative;
        }}
        
        .flow-arrow {{
            font-size: 2em;
            color: #667eea;
            margin: 0 10px;
        }}
        
        .summary-section {{
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            border-radius: 10px;
            padding: 25px;
            margin-top: 30px;
        }}
        
        .summary-title {{
            font-size: 1.5em;
            color: #495057;
            margin-bottom: 15px;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
        }}
        
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .vulnerability-item {{
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 10px;
            border-radius: 5px;
            margin: 5px 0;
        }}
        
        .footer {{
            text-align: center;
            color: #6c757d;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e9ecef;
        }}
        
        .expand-btn {{
            background: #667eea;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.9em;
            margin-left: 10px;
        }}
        
        .expand-btn:hover {{
            background: #5a67d8;
        }}
        
        .collapsible {{
            display: none;
        }}
        
        .collapsible.show {{
            display: block;
        }}
        
        @media (max-width: 768px) {{
            .stats-grid {{
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            }}
            
            .flow-container {{
                flex-direction: column;
            }}
            
            .flow-arrow {{
                transform: rotate(90deg);
            }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{self.domain} - 多层扫描报告</h1>
        <div class="subtitle">生成时间: {self.report_data['generated_time']}</div>
    </div>
    
    <div class="flow-diagram">
        <h2>扫描层级关系</h2>
        <div class="flow-container">
"""
        
        # 添加流程图节点
        layer_count = len(self.report_data['layers'])
        for i, layer_key in enumerate(sorted(self.report_data['layers'].keys())):
            layer = self.report_data['layers'][layer_key]
            html_content += f'<div class="flow-node">{layer["name"]}</div>'
            if i < layer_count - 1:
                html_content += '<div class="flow-arrow">→</div>'
                
        html_content += """
        </div>
    </div>
"""
        
        # 生成每层的详细报告
        for layer_key in sorted(self.report_data['layers'].keys()):
            layer = self.report_data['layers'][layer_key]
            html_content += self.generate_layer_section(layer_key, layer)
            
        # 生成总结部分
        html_content += self.generate_summary_section()
        
        # 生成域名详情页面
        html_content += self.generate_domain_details()
        
        html_content += """
    <div class="footer">
        <p>渗透测试扫描平台 - 多层扫描报告</p>
    </div>
    
    <script>
        function toggleSection(sectionId) {
            const section = document.getElementById(sectionId);
            const btn = event.target;
            
            if (section.classList.contains('show')) {
                section.classList.remove('show');
                btn.textContent = '展开';
            } else {
                section.classList.add('show');
                btn.textContent = '收起';
            }
        }
        
        // 添加复制功能
        document.querySelectorAll('.result-item').forEach(item => {
            item.style.cursor = 'pointer';
            item.title = '点击复制';
            item.addEventListener('click', function() {
                const text = this.textContent;
                navigator.clipboard.writeText(text).then(() => {
                    const originalBg = this.style.background;
                    this.style.background = '#d4edda';
                    setTimeout(() => {
                        this.style.background = originalBg;
                    }, 500);
                });
            });
        });
    </script>
</body>
</html>
"""
        
        return html_content
        
    def generate_layer_section(self, layer_key, layer):
        """生成单层的HTML部分"""
        section_html = f"""
    <div class="layer-section">
        <div class="layer-header">
            <div>
                <h2 class="layer-title">{layer['name']}</h2>
                <div class="layer-description">{layer['description']}</div>
            </div>
        </div>
        
        <div class="stats-grid">
"""
        
        # 添加统计卡片
        stats_mapping = {
            'urls': ('URL数量', '🔗'),
            'ips': ('IP地址', '🖥️'),
            'expansion_domains': ('扩展域名', '🌐'),
            'expansion_ips': ('扩展IP', '📡'),
            'expansion_urls': ('扩展URL', '🔍'),
            'scanned_domains': ('扫描域名', '🎯'),
            'total_new_ips': ('新发现IP', '🆕'),
            'total_new_urls': ('新发现URL', '📋'),
            'vulnerabilities': ('发现漏洞', '⚠️'),
            'ip_scans': ('IP扫描任务', '🔧'),
            'url_scans': ('URL探测', '🌍'),
            'representative_urls': ('代表URL', '📌')
        }
        
        for stat_key, stat_value in layer.get('stats', {}).items():
            if stat_key in stats_mapping:
                label, icon = stats_mapping[stat_key]
                section_html += f"""
            <div class="stat-card">
                <div class="stat-value">{stat_value}</div>
                <div class="stat-label">{icon} {label}</div>
            </div>
"""
        
        section_html += """
        </div>
"""
        
        # 添加结果展示
        if layer.get('results'):
            section_html += """
        <div class="results-section">
            <h3 class="results-title">扫描结果预览</h3>
"""
            
            # 展示各类结果
            result_mapping = {
                'urls': 'URL列表',
                'ips': 'IP地址列表',
                'expansion_domains': '发现的新域名',
                'scanned_domains': '已扫描的域名',
                'vulnerabilities': '发现的漏洞'
            }
            
            for result_key, result_data in layer['results'].items():
                if result_key in result_mapping and result_data:
                    section_html += f"""
            <div class="result-list">
                <h4>{result_mapping[result_key]}</h4>
"""
                    # 显示所有数据，不省略
                    for item in result_data:
                        if result_key == 'vulnerabilities':
                            section_html += f'<div class="vulnerability-item">{item}</div>'
                        elif result_key == 'urls' and item.startswith('http'):
                            # URL可点击
                            section_html += f'<div class="result-item"><a href="{item}" target="_blank" style="color: inherit; text-decoration: none;">{item}</a></div>'
                        elif result_key == 'expansion_domains' or result_key == 'scanned_domains':
                            # 域名可点击，跳转到对应层的详情
                            if layer_key == 'layer1':
                                # 第一层的扩展域名，链接到第二层结果
                                domain_link = f"#layer2-{item.replace('.', '_')}"
                            else:
                                domain_link = f"#{layer_key}-{item.replace('.', '_')}"
                            section_html += f'<div class="result-item"><a href="{domain_link}" style="color: #667eea; text-decoration: none;">{item}</a></div>'
                        else:
                            section_html += f'<div class="result-item">{item}</div>'
                        
                    section_html += '</div>'
                    
            # 如果是第二层，显示域名扫描详情
            if layer_key == 'layer2' and 'details' in layer:
                section_html += """
            <div class="result-list">
                <h4>域名扫描详情</h4>
"""
                for domain, stats in layer['details'].items():
                    stats_text = []
                    if 'ips' in stats:
                        stats_text.append(f"{stats['ips']} 个IP")
                    if 'urls' in stats:
                        stats_text.append(f"{stats['urls']} 个URL")
                    if 'new_domains' in stats:
                        stats_text.append(f"{stats['new_domains']} 个新域名")
                        
                    section_html += f"""
                <div class="domain-detail" id="layer2-{domain.replace('.', '_')}">
                    <strong>{domain}</strong>: {', '.join(stats_text) if stats_text else '无结果'}
                    <a href="#detail-{domain.replace('.', '_')}" style="margin-left: 10px; color: #667eea;">查看详情</a>
                </div>
"""
                section_html += '</div>'
                
        # 显示afrog漏洞扫描结果
        if 'afrog_results' in layer and layer['afrog_results']:
            section_html += """
        <div class="results-section">
            <h3 class="results-title">🔍 Afrog漏洞扫描结果</h3>
            <div class="result-list">
"""
            for vuln in layer['afrog_results']:
                severity_color = {
                    'critical': '#dc3545',
                    'high': '#fd7e14',
                    'medium': '#ffc107',
                    'low': '#28a745',
                    'info': '#17a2b8'
                }.get(vuln['severity'].lower(), '#6c757d')
                
                section_html += f"""
                <div style="background: #f8f9fa; border-left: 4px solid {severity_color}; padding: 15px; margin: 10px 0; border-radius: 0 5px 5px 0;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <strong style="color: {severity_color};">{vuln['poc_name']}</strong>
                        <span style="background: {severity_color}; color: white; padding: 2px 8px; border-radius: 3px; font-size: 0.8em;">{vuln['severity'].upper()}</span>
                    </div>
                    <div style="margin-top: 10px;">
                        <a href="{vuln['target']}" target="_blank" style="color: #667eea; text-decoration: none;">{vuln['target']}</a>
                    </div>
                    {f'<div style="margin-top: 10px; color: #6c757d; font-size: 0.9em;">{vuln["detail"]}</div>' if vuln['detail'] else ''}
                    <div style="margin-top: 5px; color: #adb5bd; font-size: 0.8em;">发现时间: {vuln['created_at']}</div>
                </div>
"""
            section_html += '</div></div>'
                
        section_html += """
        </div>
    </div>
"""
        
        return section_html
        
    def generate_summary_section(self):
        """生成总结部分"""
        total_stats = defaultdict(int)
        
        # 汇总所有层的统计
        for layer in self.report_data['layers'].values():
            for stat_key, stat_value in layer.get('stats', {}).items():
                if isinstance(stat_value, int):
                    total_stats[stat_key] += stat_value
                    
        summary_html = """
    <div class="summary-section">
        <h2 class="summary-title">扫描总结</h2>
        <div class="summary-grid">
"""
        
        # 总体统计
        summary_html += f"""
            <div class="summary-card">
                <h3>总体统计</h3>
                <p>扫描层数: {len(self.report_data['layers'])}</p>
                <p>总发现IP: {total_stats.get('ips', 0) + total_stats.get('total_new_ips', 0)}</p>
                <p>总发现URL: {total_stats.get('urls', 0) + total_stats.get('total_new_urls', 0)}</p>
                <p>总发现域名: {total_stats.get('expansion_domains', 0) + total_stats.get('scanned_domains', 0)}</p>
            </div>
"""
        
        # 扫描效率
        if 'layer1' in self.report_data['layers'] and 'layer2' in self.report_data['layers']:
            layer1_targets = self.report_data['layers']['layer1']['stats'].get('expansion_domains', 0)
            layer2_scanned = self.report_data['layers']['layer2']['stats'].get('scanned_domains', 0)
            
            summary_html += f"""
            <div class="summary-card">
                <h3>扫描效率</h3>
                <p>一层发现扩展目标: {layer1_targets}</p>
                <p>二层实际扫描: {layer2_scanned}</p>
                <p>扫描覆盖率: {(layer2_scanned/layer1_targets*100 if layer1_targets > 0 else 0):.1f}%</p>
            </div>
"""
        
        # 安全发现
        vuln_count = total_stats.get('vulnerabilities', 0)
        summary_html += f"""
            <div class="summary-card">
                <h3>安全发现</h3>
                <p>发现漏洞: {vuln_count}</p>
                <p>风险等级: {'⚠️ 需要关注' if vuln_count > 0 else '✅ 暂无发现'}</p>
            </div>
"""
        
        summary_html += """
        </div>
    </div>
"""
        
        return summary_html
        
    def generate_domain_details(self):
        """生成域名详情页面"""
        details_html = """
    <div style="margin-top: 50px;">
        <h2 style="text-align: center; color: #495057; margin-bottom: 30px;">域名详细信息</h2>
"""
        
        # 遍历所有层的域名扫描结果
        if 'layer2' in self.report_data['layers'] and 'details' in self.report_data['layers']['layer2']:
            for domain, stats in self.report_data['layers']['layer2']['details'].items():
                # 读取该域名的详细扫描结果
                domain_dir = self.domain_dir / 'expansion' / 'report' / 'domain_scan_results' / domain / domain
                if domain_dir.exists():
                    details_html += f"""
        <div class="layer-section" id="detail-{domain.replace('.', '_')}" style="margin-top: 30px;">
            <div class="layer-header">
                <div>
                    <h2 class="layer-title">{domain} - 详细扫描结果</h2>
                    <div class="layer-description">第二层扩展扫描的详细信息</div>
                </div>
            </div>
"""
                    
                    # 读取该域名的基础信息
                    base_info_file = domain_dir / f'base_info_{domain}.txt'
                    if base_info_file.exists():
                        with open(base_info_file, 'r', encoding='utf-8') as f:
                            base_info = f.read()
                            
                        details_html += """
            <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 20px 0;">
                <h3>基础信息</h3>
                <pre style="white-space: pre-wrap; word-wrap: break-word; font-family: monospace; font-size: 0.9em;">{}</pre>
            </div>
""".format(base_info[:1000] + '...' if len(base_info) > 1000 else base_info)
                    
                    # 显示该域名发现的URL
                    urls_file = domain_dir / 'input' / 'urls.txt'
                    if urls_file.exists():
                        with open(urls_file, 'r') as f:
                            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                            
                        if urls:
                            details_html += f"""
            <div style="margin: 20px 0;">
                <h3>发现的URL ({len(urls)}个)</h3>
                <div style="max-height: 400px; overflow-y: auto; background: #f8f9fa; padding: 15px; border-radius: 8px;">
"""
                            for url in urls:
                                details_html += f'<div style="margin: 5px 0;"><a href="{url}" target="_blank" style="color: #667eea; text-decoration: none;">{url}</a></div>'
                            details_html += '</div></div>'
                    
                    # 显示该域名的扩展发现
                    tuozhan_dir = domain_dir / 'tuozhan' / 'all_tuozhan'
                    if tuozhan_dir.exists():
                        # 新发现的域名
                        new_domains_file = tuozhan_dir / 'root_domains.txt'
                        if new_domains_file.exists():
                            with open(new_domains_file, 'r') as f:
                                new_domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                                
                            if new_domains:
                                details_html += f"""
            <div style="margin: 20px 0;">
                <h3>新发现的域名 ({len(new_domains)}个)</h3>
                <div style="background: #e8f4fd; padding: 15px; border-radius: 8px;">
"""
                                for new_domain in new_domains:
                                    details_html += f'<div style="margin: 5px 0; font-family: monospace;">{new_domain}</div>'
                                details_html += '</div></div>'
                    
                    details_html += '</div>'
                    
        details_html += '</div>'
        return details_html
        
    def generate_report(self, output_file=None):
        """生成完整报告"""
        # 分析各层数据
        self.analyze_layer1()
        self.analyze_layer2()
        self.analyze_layer3_plus()
        
        # 生成HTML
        html_content = self.generate_html_report()
        
        # 确定输出文件路径
        if not output_file:
            output_file = f"reports/{self.domain}_multilayer_report.html"
            
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 写入文件
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        return output_path


def main():
    parser = argparse.ArgumentParser(description='生成多层扫描HTML报告')
    parser.add_argument('domain', nargs='?', help='目标域名')
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
    print(f"[*] 正在生成 {args.domain} 的多层扫描报告...")
    
    generator = MultilayerReportGenerator(args.domain)
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