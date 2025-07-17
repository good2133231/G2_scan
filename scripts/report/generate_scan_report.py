#!/usr/bin/env python3
"""
生成多层扫描结果的HTML可视化报告
显示每层扫描发现的目标和层级关系
"""

import os
import sys
import json
import argparse
import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import html

def load_json_lines(file_path):
    """加载JSON Lines格式文件"""
    results = []
    if file_path.exists():
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except:
                        continue
    return results

def make_urls_clickable(text):
    """将文本中的URL转换为可点击链接"""
    # 匹配URL的正则表达式
    url_pattern = r'(https?://[^\s<>"{}|\\^`\[\]]+)'
    
    def replace_url(match):
        url = match.group(1)
        return f'<a href="{html.escape(url)}" target="_blank" style="color: #54a0ff; text-decoration: underline;">{html.escape(url)}</a>'
    
    # 先进行HTML转义，然后替换URL
    escaped_text = html.escape(text)
    return re.sub(url_pattern, replace_url, escaped_text)

def collect_layer_data(output_dir, target_domain):
    """收集各层扫描数据"""
    layers_data = {}
    base_path = Path(output_dir) / target_domain
    
    # 第一层数据
    layer1_data = {
        'httpx_results': [],
        'expansion_targets': {
            'ips': [],
            'urls': [],
            'domains': []
        },
        'vulnerabilities': [],
        'fscan_results': [],
        'url_details': []
    }
    
    # 读取第一层httpx结果
    httpx_file = base_path / "result_all.json"
    if httpx_file.exists():
        layer1_data['httpx_results'] = load_json_lines(httpx_file)
        
        # 解析URL详细信息
        for entry in layer1_data['httpx_results']:
            url_info = {
                'url': entry.get('url', ''),
                'title': entry.get('title', ''),
                'status_code': entry.get('status_code', 0),
                'content_length': entry.get('content_length', 0),
                'tech': entry.get('tech', [])
            }
            layer1_data['url_details'].append(url_info)
    
    # 读取第一层扩展目标
    tuozhan_dir = base_path / "tuozhan" / "all_tuozhan"
    if tuozhan_dir.exists():
        # IP目标
        ip_file = tuozhan_dir / "ip.txt"
        if ip_file.exists():
            with open(ip_file, 'r') as f:
                layer1_data['expansion_targets']['ips'] = [
                    line.strip() for line in f 
                    if line.strip() and not line.startswith('#')
                ]
        
        # URL目标
        url_file = tuozhan_dir / "urls.txt"
        if url_file.exists():
            with open(url_file, 'r') as f:
                layer1_data['expansion_targets']['urls'] = [
                    line.strip() for line in f 
                    if line.strip() and not line.startswith('#')
                ]
        
        # 域名目标
        domain_file = tuozhan_dir / "root_domains.txt"
        if domain_file.exists():
            with open(domain_file, 'r') as f:
                layer1_data['expansion_targets']['domains'] = [
                    line.strip() for line in f 
                    if line.strip() and not line.startswith('#')
                ]
    
    # 读取漏洞信息
    afrog_reports = list(base_path.glob("afrog_report_*.json"))
    for report_file in afrog_reports:
        with open(report_file, 'r') as f:
            try:
                vulnerabilities = json.load(f)
                if isinstance(vulnerabilities, list):
                    layer1_data['vulnerabilities'].extend(vulnerabilities)
            except:
                pass
    
    # 读取fscan结果
    fscan_files = list(base_path.glob("fscan_*.txt"))
    for fscan_file in fscan_files:
        with open(fscan_file, 'r', encoding='utf-8') as f:
            content = f.read()
            layer1_data['fscan_results'].append({
                'filename': fscan_file.name,
                'content': content
            })
    
    layers_data[1] = layer1_data
    
    # 收集更高层的数据
    expansion_base = base_path / "expansion"
    
    # 第二层数据
    if (expansion_base / "report").exists():
        layer2_data = collect_expansion_layer_data(expansion_base, 2)
        if layer2_data:
            layers_data[2] = layer2_data
    
    # 第三层及更高层数据
    for layer_num in range(3, 10):  # 最多支持到第9层
        layer_dir = expansion_base / f"layer{layer_num}"
        if layer_dir.exists() and (layer_dir / "report").exists():
            layer_data = collect_expansion_layer_data(layer_dir, layer_num)
            if layer_data:
                layers_data[layer_num] = layer_data
        else:
            break
    
    return layers_data

def collect_expansion_layer_data(layer_base, layer_num):
    """收集扩展层的数据"""
    layer_data = {
        'scan_results': defaultdict(dict),
        'merged_targets': {
            'ips': [],
            'urls': [],
            'domains': []
        },
        'vulnerabilities': [],
        'fscan_results': [],
        'url_details': []
    }
    
    # 读取report目录下的扫描结果
    report_dir = layer_base / "report" if layer_num == 2 else layer_base / "report"
    if report_dir.exists():
        for task_dir in report_dir.iterdir():
            if task_dir.is_dir():
                task_name = task_dir.name
                
                # IP扫描结果
                if task_name.startswith("ip_"):
                    fscan_results = list(task_dir.glob("*/fscan_*.txt"))
                    layer_data['scan_results'][task_name] = {
                        'type': 'ip_scan',
                        'results': len(fscan_results)
                    }
                    
                    # 收集fscan结果内容
                    for fscan_file in fscan_results:
                        with open(fscan_file, 'r', encoding='utf-8') as f:
                            content = f.read()
                            layer_data['fscan_results'].append({
                                'filename': fscan_file.name,
                                'content': content,
                                'ip': task_name.replace('ip_', '').replace('_', '.')
                            })
                
                # URL扫描结果  
                elif task_name.startswith("url_"):
                    httpx_results = list(task_dir.glob("*/result_all.json"))
                    layer_data['scan_results'][task_name] = {
                        'type': 'url_scan',
                        'results': len(httpx_results)
                    }
                    
                    # 收集URL详细信息
                    for httpx_file in httpx_results:
                        httpx_data = load_json_lines(httpx_file)
                        for entry in httpx_data:
                            url_info = {
                                'url': entry.get('url', ''),
                                'title': entry.get('title', ''),
                                'status_code': entry.get('status_code', 0),
                                'content_length': entry.get('content_length', 0),
                                'tech': entry.get('tech', [])
                            }
                            layer_data['url_details'].append(url_info)
                
                # 域名扫描结果
                else:
                    domain_dirs = list(task_dir.glob("domain_scan_results/*"))
                    layer_data['scan_results'][task_name] = {
                        'type': 'domain_scan',
                        'domains': [d.name for d in domain_dirs if d.is_dir()]
                    }
    
    # 读取合并的扩展目标
    if layer_num == 2:
        merged_dir = layer_base / "layer2" / "merged_targets"
    else:
        merged_dir = layer_base / "merged_targets"
    
    if merged_dir.exists():
        # IP目标
        ip_file = merged_dir / "ip.txt"
        if ip_file.exists():
            with open(ip_file, 'r') as f:
                layer_data['merged_targets']['ips'] = [
                    line.strip() for line in f 
                    if line.strip() and not line.startswith('#')
                ]
        
        # URL目标
        url_file = merged_dir / "urls.txt"
        if url_file.exists():
            with open(url_file, 'r') as f:
                layer_data['merged_targets']['urls'] = [
                    line.strip() for line in f 
                    if line.strip() and not line.startswith('#')
                ]
        
        # 域名目标
        domain_file = merged_dir / "root_domains.txt"
        if domain_file.exists():
            with open(domain_file, 'r') as f:
                layer_data['merged_targets']['domains'] = [
                    line.strip() for line in f 
                    if line.strip() and not line.startswith('#')
                ]
    
    return layer_data

def generate_html_report(layers_data, target_domain, output_file):
    """生成HTML报告"""
    html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{target_domain} - 多层扫描报告</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: #1a1a2e;
            color: #eee;
            line-height: 1.6;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header .meta {{
            opacity: 0.9;
            font-size: 0.9em;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .summary-card {{
            background: #16213e;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }}
        
        .summary-card h3 {{
            font-size: 0.9em;
            opacity: 0.7;
            margin-bottom: 5px;
        }}
        
        .summary-card .value {{
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }}
        
        .layer-section {{
            background: #0f3460;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.3);
        }}
        
        .layer-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid #1a1a2e;
        }}
        
        .layer-header h2 {{
            font-size: 1.8em;
            color: #667eea;
        }}
        
        .layer-stats {{
            display: flex;
            gap: 30px;
        }}
        
        .stat {{
            text-align: center;
        }}
        
        .stat .label {{
            font-size: 0.8em;
            opacity: 0.7;
        }}
        
        .stat .count {{
            font-size: 1.5em;
            font-weight: bold;
            color: #e94560;
        }}
        
        .targets-grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-top: 20px;
        }}
        
        .target-box {{
            background: #1a1a2e;
            border-radius: 8px;
            padding: 20px;
            border: 1px solid #2a2a4e;
        }}
        
        .target-box h4 {{
            color: #667eea;
            margin-bottom: 15px;
            font-size: 1.1em;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .target-box .icon {{
            width: 24px;
            height: 24px;
            background: #667eea;
            border-radius: 50%;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
        }}
        
        .target-list {{
            max-height: 300px;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        
        .target-list::-webkit-scrollbar {{
            width: 6px;
        }}
        
        .target-list::-webkit-scrollbar-track {{
            background: #1a1a2e;
        }}
        
        .target-list::-webkit-scrollbar-thumb {{
            background: #667eea;
            border-radius: 3px;
        }}
        
        .target-item {{
            padding: 5px 0;
            border-bottom: 1px solid #2a2a4e;
            word-break: break-all;
        }}
        
        .target-item a {{
            color: #eee;
            text-decoration: none;
            transition: color 0.3s ease;
        }}
        
        .target-item a:hover {{
            color: #667eea;
            text-decoration: underline;
        }}
        
        .target-item:last-child {{
            border-bottom: none;
        }}
        
        .url-detail-item {{
            background: #0f3460;
            padding: 10px 15px;
            margin-bottom: 8px;
            border-radius: 5px;
            border-left: 3px solid #667eea;
        }}
        
        .url-detail-item .url {{
            color: #667eea;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        
        .url-detail-item .url a {{
            color: #667eea;
            text-decoration: none;
            transition: color 0.3s ease;
        }}
        
        .url-detail-item .url a:hover {{
            color: #54a0ff;
            text-decoration: underline;
        }}
        
        .url-detail-item .title {{
            color: #eee;
            margin-bottom: 3px;
        }}
        
        .url-detail-item .meta {{
            color: #888;
            font-size: 0.8em;
        }}
        
        .status-200 {{ color: #2ecc71; }}
        .status-301 {{ color: #f39c12; }}
        .status-302 {{ color: #f39c12; }}
        .status-403 {{ color: #e74c3c; }}
        .status-404 {{ color: #e74c3c; }}
        .status-500 {{ color: #e74c3c; }}
        
        .fscan-section {{
            background: #1a1a2e;
            border-radius: 8px;
            padding: 20px;
            margin-top: 20px;
            border: 1px solid #667eea;
        }}
        
        .fscan-section h4 {{
            color: #667eea;
            margin-bottom: 15px;
        }}
        
        .fscan-result {{
            background: #0f3460;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 15px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        
        .fscan-result .header {{
            color: #54a0ff;
            font-weight: bold;
            margin-bottom: 10px;
            background: #1a1a2e;
            padding: 8px 12px;
            border-radius: 4px;
            border-left: 3px solid #54a0ff;
        }}
        
        .fscan-content {{
            white-space: pre-wrap;
            max-height: 300px;
            overflow-y: auto;
            border: 1px solid #2a2a4e;
            padding: 10px;
            background: #1a1a2e;
            line-height: 1.4;
        }}
        
        .fscan-content a {{
            color: #54a0ff !important;
            text-decoration: underline;
            transition: color 0.3s ease;
        }}
        
        .fscan-content a:hover {{
            color: #667eea !important;
        }}
        
        .vulnerability-section {{
            background: #1a1a2e;
            border-radius: 8px;
            padding: 20px;
            margin-top: 20px;
            border: 1px solid #e94560;
        }}
        
        .vulnerability-section h4 {{
            color: #e94560;
            margin-bottom: 15px;
        }}
        
        .vuln-item {{
            background: #0f3460;
            padding: 10px 15px;
            border-radius: 5px;
            margin-bottom: 10px;
        }}
        
        .vuln-item a {{
            color: #888;
            text-decoration: none;
            transition: color 0.3s ease;
        }}
        
        .vuln-item a:hover {{
            color: #667eea;
            text-decoration: underline;
        }}
        
        .vuln-severity {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.8em;
            font-weight: bold;
            margin-right: 10px;
        }}
        
        .severity-high {{
            background: #e94560;
        }}
        
        .severity-medium {{
            background: #ff9f43;
        }}
        
        .severity-low {{
            background: #54a0ff;
        }}
        
        .flow-diagram {{
            background: #1a1a2e;
            border-radius: 8px;
            padding: 30px;
            margin: 30px 0;
            text-align: center;
        }}
        
        .flow-diagram h3 {{
            color: #667eea;
            margin-bottom: 20px;
        }}
        
        .flow-container {{
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 30px;
            flex-wrap: wrap;
        }}
        
        .flow-layer {{
            background: #0f3460;
            border: 2px solid #667eea;
            border-radius: 10px;
            padding: 20px 30px;
            position: relative;
            transition: all 0.3s ease;
        }}
        
        .flow-layer:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(102, 126, 234, 0.3);
        }}
        
        .flow-arrow {{
            font-size: 2em;
            color: #667eea;
        }}
        
        .empty-state {{
            text-align: center;
            padding: 40px;
            opacity: 0.5;
        }}
        
        @media (max-width: 768px) {{
            .targets-grid {{
                grid-template-columns: 1fr;
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
    <div class="container">
        <div class="header">
            <h1>🎯 {target_domain} 多层扫描报告</h1>
            <div class="meta">
                <p>📅 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>📊 扫描层数: {len(layers_data)} 层</p>
            </div>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>扫描层数</h3>
                <div class="value">{len(layers_data)}</div>
            </div>
            <div class="summary-card">
                <h3>发现的IP</h3>
                <div class="value">{sum(len(layer.get('expansion_targets', {}).get('ips', [])) + len(layer.get('merged_targets', {}).get('ips', [])) for layer in layers_data.values())}</div>
            </div>
            <div class="summary-card">
                <h3>发现的URL</h3>
                <div class="value">{sum(len(layer.get('expansion_targets', {}).get('urls', [])) + len(layer.get('merged_targets', {}).get('urls', [])) for layer in layers_data.values())}</div>
            </div>
            <div class="summary-card">
                <h3>发现的域名</h3>
                <div class="value">{sum(len(layer.get('expansion_targets', {}).get('domains', [])) + len(layer.get('merged_targets', {}).get('domains', [])) for layer in layers_data.values())}</div>
            </div>
        </div>
        
        <div class="flow-diagram">
            <h3>扫描层级关系图</h3>
            <div class="flow-container">
"""
    
    # 添加流程图
    for i, layer_num in enumerate(sorted(layers_data.keys())):
        html_content += f"""
                <div class="flow-layer">
                    <h4>第{layer_num}层</h4>
                    <p>{len(layers_data[layer_num].get('expansion_targets', {}).get('ips', [])) + len(layers_data[layer_num].get('merged_targets', {}).get('ips', []))} IPs</p>
                    <p>{len(layers_data[layer_num].get('expansion_targets', {}).get('urls', [])) + len(layers_data[layer_num].get('merged_targets', {}).get('urls', []))} URLs</p>
                    <p>{len(layers_data[layer_num].get('expansion_targets', {}).get('domains', [])) + len(layers_data[layer_num].get('merged_targets', {}).get('domains', []))} Domains</p>
                </div>
"""
        if i < len(layers_data) - 1:
            html_content += """                <div class="flow-arrow">→</div>
"""
    
    html_content += """            </div>
        </div>
"""
    
    # 生成每层的详细数据
    for layer_num in sorted(layers_data.keys()):
        layer = layers_data[layer_num]
        
        if layer_num == 1:
            targets = layer.get('expansion_targets', {})
            httpx_count = len(layer.get('httpx_results', []))
        else:
            targets = layer.get('merged_targets', {})
            httpx_count = 0
        
        ip_count = len(targets.get('ips', []))
        url_count = len(targets.get('urls', []))
        domain_count = len(targets.get('domains', []))
        
        html_content += f"""
        <div class="layer-section">
            <div class="layer-header">
                <h2>第 {layer_num} 层扫描结果</h2>
                <div class="layer-stats">
"""
        
        if layer_num == 1:
            html_content += f"""                    <div class="stat">
                        <div class="label">HTTP探测</div>
                        <div class="count">{httpx_count}</div>
                    </div>
"""
        
        html_content += f"""                    <div class="stat">
                        <div class="label">IP目标</div>
                        <div class="count">{ip_count}</div>
                    </div>
                    <div class="stat">
                        <div class="label">URL目标</div>
                        <div class="count">{url_count}</div>
                    </div>
                    <div class="stat">
                        <div class="label">域名目标</div>
                        <div class="count">{domain_count}</div>
                    </div>
                </div>
            </div>
"""
        
        # 显示目标详情
        if ip_count > 0 or url_count > 0 or domain_count > 0:
            html_content += """            <div class="targets-grid">
"""
            
            # IP目标
            if ip_count > 0:
                html_content += """                <div class="target-box">
                    <h4><span class="icon">🖥️</span>IP目标</h4>
                    <div class="target-list">
"""
                for ip in targets['ips'][:50]:  # 限制显示前50个
                    html_content += f'                        <div class="target-item">{html.escape(ip)}</div>\n'
                if len(targets['ips']) > 50:
                    html_content += f'                        <div class="target-item">... 还有 {len(targets["ips"]) - 50} 个IP</div>\n'
                html_content += """                    </div>
                </div>
"""
            
            # URL目标详情
            url_details = layer.get('url_details', [])
            if url_details:
                html_content += """                <div class="target-box">
                    <h4><span class="icon">🌐</span>URL详情</h4>
                    <div class="target-list">
"""
                for url_info in url_details[:30]:  # 限制显示前30个
                    url = url_info.get('url', '')
                    title = url_info.get('title', '')
                    status_code = url_info.get('status_code', 0)
                    content_length = url_info.get('content_length', 0)
                    
                    html_content += f"""                        <div class="url-detail-item">
                            <div class="url"><a href="{html.escape(url)}" target="_blank">{html.escape(url)}</a></div>
                            <div class="title">{html.escape(title) if title else '[无标题]'}</div>
                            <div class="meta">
                                <span class="status-{status_code}">状态码: {status_code}</span> | 
                                大小: {content_length} bytes
                            </div>
                        </div>
"""
                if len(url_details) > 30:
                    html_content += f'                        <div class="target-item">... 还有 {len(url_details) - 30} 个URL</div>\n'
                html_content += """                    </div>
                </div>
"""
            elif url_count > 0:
                # 后备方案：显示简单URL列表
                html_content += """                <div class="target-box">
                    <h4><span class="icon">🌐</span>URL目标</h4>
                    <div class="target-list">
"""
                for url in targets['urls'][:30]:  # 限制显示前30个
                    if url.startswith(('http://', 'https://')):
                        html_content += f'                        <div class="target-item"><a href="{html.escape(url)}" target="_blank">{html.escape(url)}</a></div>\n'
                    else:
                        html_content += f'                        <div class="target-item">{html.escape(url)}</div>\n'
                if len(targets['urls']) > 30:
                    html_content += f'                        <div class="target-item">... 还有 {len(targets["urls"]) - 30} 个URL</div>\n'
                html_content += """                    </div>
                </div>
"""
            
            # 域名目标
            if domain_count > 0:
                html_content += """                <div class="target-box">
                    <h4><span class="icon">🔍</span>域名目标</h4>
                    <div class="target-list">
"""
                for domain in targets['domains'][:30]:  # 限制显示前30个
                    html_content += f'                        <div class="target-item">{html.escape(domain)}</div>\n'
                if len(targets['domains']) > 30:
                    html_content += f'                        <div class="target-item">... 还有 {len(targets["domains"]) - 30} 个域名</div>\n'
                html_content += """                    </div>
                </div>
"""
            
            html_content += """            </div>
"""
        else:
            html_content += """            <div class="empty-state">
                <p>该层暂无扩展目标</p>
            </div>
"""
        
        # 显示漏洞信息（如果有）
        vulnerabilities = layer.get('vulnerabilities', [])
        if vulnerabilities:
            html_content += """            <div class="vulnerability-section">
                <h4>🚨 发现的漏洞</h4>
"""
            for vuln in vulnerabilities[:10]:  # 限制显示前10个
                severity = vuln.get('severity', 'low')
                vuln_url = vuln.get('url', '')
                html_content += f"""                <div class="vuln-item">
                    <span class="vuln-severity severity-{severity}">{severity.upper()}</span>
                    <strong>{html.escape(vuln.get('name', 'Unknown'))}</strong>
                    <br><small><a href="{html.escape(vuln_url)}" target="_blank">{html.escape(vuln_url)}</a></small>
                </div>
"""
            if len(vulnerabilities) > 10:
                html_content += f"""                <div class="vuln-item">
                    <em>... 还有 {len(vulnerabilities) - 10} 个漏洞</em>
                </div>
"""
            html_content += """            </div>
"""
        
        # 显示fscan结果（如果有）
        fscan_results = layer.get('fscan_results', [])
        if fscan_results:
            html_content += """            <div class="fscan-section">
                <h4>🔍 端口扫描结果 (fscan)</h4>
"""
            for fscan_result in fscan_results[:5]:  # 限制显示前5个
                ip = fscan_result.get('ip', fscan_result.get('filename', ''))
                content = fscan_result.get('content', '')
                
                html_content += f"""                <div class="fscan-result">
                    <div class="header">📍 {html.escape(ip)}</div>
                    <div class="fscan-content">{make_urls_clickable(content)}</div>
                </div>
"""
            if len(fscan_results) > 5:
                html_content += f"""                <div class="fscan-result">
                    <div class="header">... 还有 {len(fscan_results) - 5} 个扫描结果</div>
                </div>
"""
            html_content += """            </div>
"""
        
        html_content += """        </div>
"""
    
    html_content += """    </div>
</body>
</html>"""
    
    # 写入文件
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"✅ HTML报告已生成: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="生成多层扫描HTML报告")
    parser.add_argument("target_domain", nargs='?', help="目标域名")
    parser.add_argument("-o", "--output", help="输出文件路径")
    parser.add_argument("--output-dir", default="output", help="扫描结果目录")
    
    args = parser.parse_args()
    
    # 自动检测域名
    if not args.target_domain:
        # 尝试从output目录找到域名
        output_path = Path(args.output_dir)
        if output_path.exists():
            domain_dirs = [d for d in output_path.iterdir() if d.is_dir() and '.' in d.name]
            if domain_dirs:
                args.target_domain = domain_dirs[0].name
                print(f"🔍 自动检测到域名: {args.target_domain}")
            else:
                print("❌ 未找到扫描结果目录，请指定目标域名")
                sys.exit(1)
        else:
            print("❌ output目录不存在")
            sys.exit(1)
    
    # 收集数据
    print(f"📊 收集 {args.target_domain} 的扫描数据...")
    layers_data = collect_layer_data(args.output_dir, args.target_domain)
    
    if not layers_data:
        print("❌ 未找到任何扫描数据")
        sys.exit(1)
    
    print(f"✅ 发现 {len(layers_data)} 层扫描数据")
    
    # 确定输出文件
    if not args.output:
        output_file = Path(args.output_dir) / args.target_domain / f"scan_report_{args.target_domain}.html"
        output_file.parent.mkdir(parents=True, exist_ok=True)
    else:
        output_file = Path(args.output)
    
    # 生成报告
    generate_html_report(layers_data, args.target_domain, output_file)
    
    # 显示统计信息
    print("\n📈 扫描统计:")
    for layer_num in sorted(layers_data.keys()):
        layer = layers_data[layer_num]
        if layer_num == 1:
            targets = layer.get('expansion_targets', {})
        else:
            targets = layer.get('merged_targets', {})
        
        print(f"   第{layer_num}层: {len(targets.get('ips', []))} IPs, " + 
              f"{len(targets.get('urls', []))} URLs, {len(targets.get('domains', []))} Domains")
    
    print(f"\n🌐 在浏览器中打开: file://{output_file.absolute()}")

if __name__ == "__main__":
    main()