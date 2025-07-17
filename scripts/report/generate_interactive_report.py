#!/usr/bin/env python3
"""
生成交互式多层扫描结果HTML报告
支持点击域名查看详细信息，可以在不同层级之间导航
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

def load_relationships(target_domain):
    """加载域名发现关系数据"""
    relationships_file = Path("output") / target_domain / "domain_discovery_relationships.json"
    if relationships_file.exists():
        with open(relationships_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {"relationships": [], "discovery_methods": {}}

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
    url_pattern = r'(https?://[^\s<>"{}|\\^`\[\]]+)'
    
    def replace_url(match):
        url = match.group(1)
        return f'<a href="{html.escape(url)}" target="_blank" style="color: #54a0ff; text-decoration: underline;">{html.escape(url)}</a>'
    
    escaped_text = html.escape(text)
    return re.sub(url_pattern, replace_url, escaped_text)

def load_representative_urls(base_path):
    """加载representative_urls.txt中的URL信息"""
    urls_file = base_path / "input" / "representative_urls.txt"
    urls_info = []
    
    if urls_file.exists():
        with open(urls_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # 解析URL格式：https://example.com [Title][size:1234]
                    url_match = re.match(r'^(https?://[^\s]+)(?:\s+\[([^\]]*)\])?(?:\[size:(\d+)\])?', line)
                    if url_match:
                        url = url_match.group(1)
                        title = url_match.group(2) or ""
                        size = url_match.group(3) or "0"
                        urls_info.append({
                            'url': url,
                            'title': title,
                            'content_length': int(size)
                        })
                    else:
                        # 简单URL格式
                        urls_info.append({
                            'url': line,
                            'title': '',
                            'content_length': 0
                        })
    
    return urls_info

def load_relationships(target_domain):
    """加载域名发现关系数据"""
    relationships_file = Path("output") / target_domain / "domain_discovery_relationships.json"
    if relationships_file.exists():
        with open(relationships_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    else:
        # 返回默认的空数据
        return {
            "relationships": [],
            "discovery_methods": {
                "FOFA搜索": {"description": "通过FOFA搜索引擎发现", "icon": "🔍", "color": "#3498db"},
                "IP反查": {"description": "通过IP地址反查域名", "icon": "🎯", "color": "#e74c3c"},
                "证书关联": {"description": "通过SSL证书SAN发现", "icon": "🔐", "color": "#f39c12"},
                "URL跳转": {"description": "通过HTTP跳转发现", "icon": "↗️", "color": "#27ae60"},
                "子域名枚举": {"description": "通过子域名爆破发现", "icon": "📡", "color": "#9b59b6"},
                "页面内容": {"description": "从页面内容提取", "icon": "📄", "color": "#1abc9c"},
                "DNS记录": {"description": "通过DNS查询发现", "icon": "🌐", "color": "#34495e"},
                "资源引用": {"description": "页面资源引用发现", "icon": "🔗", "color": "#e67e22"}
            }
        }

def collect_layer_data(output_dir, target_domain):
    """收集各层扫描数据"""
    layers_data = {}
    base_path = Path(output_dir) / target_domain
    
    # 第一层数据
    layer1_data = {
        'representative_urls': [],
        'expansion_targets': {
            'ips': [],
            'urls': [],
            'domains': []
        },
        'vulnerabilities': [],
        'fscan_results': [],
        'base_info': ""
    }
    
    # 优先从result_all.json读取URL信息
    result_json = base_path / "result_all.json"
    if result_json.exists():
        urls_from_json = []
        with open(result_json, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    urls_from_json.append({
                        'url': entry.get('url', ''),
                        'title': entry.get('title', ''),
                        'content_length': entry.get('content_length', 0)
                    })
                except:
                    continue
        if urls_from_json:
            layer1_data['representative_urls'] = urls_from_json
        else:
            # 如果result_all.json为空，则从representative_urls.txt读取
            layer1_data['representative_urls'] = load_representative_urls(base_path)
    else:
        # 如果没有result_all.json，则从representative_urls.txt读取
        layer1_data['representative_urls'] = load_representative_urls(base_path)
    
    # 读取base_info
    base_info_file = base_path / f"base_info_{target_domain}.txt"
    if base_info_file.exists():
        with open(base_info_file, 'r', encoding='utf-8') as f:
            layer1_data['base_info'] = f.read()
    
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
    layer2_dir = expansion_base / "layer2"
    if layer2_dir.exists():
        layer2_data = collect_expansion_layer_data(layer2_dir, 2)
        if layer2_data:
            layers_data[2] = layer2_data
    
    # 第三层及更高层数据
    for layer_num in range(3, 10):  # 最多支持到第9层
        layer_dir = expansion_base / f"layer{layer_num}"
        if layer_dir.exists():
            layer_data = collect_expansion_layer_data(layer_dir, layer_num)
            if layer_data:
                layers_data[layer_num] = layer_data
        else:
            break
    
    return layers_data

def collect_expansion_layer_data(expansion_base, layer_num):
    """收集扩展层数据"""
    layer_data = {
        'expansion_targets': {
            'ips': [],
            'urls': [],
            'domains': []
        },
        'domain_scan_results': {},
        'vulnerabilities': [],
        'fscan_results': []
    }
    
    # 遍历当前层的所有域名目录
    if expansion_base.exists():
        for domain_dir in expansion_base.iterdir():
            if domain_dir.is_dir():
                domain_name = domain_dir.name
                domain_info = {
                    'representative_urls': [],
                    'base_info': "",
                    'vulnerabilities': [],
                    'fscan_results': [],
                    'expansion_targets': {
                        'ips': [],
                        'urls': [],
                        'domains': []
                    }
                }
                
                # 优先从result_all.json读取URL信息
                result_json = domain_dir / "result_all.json"
                if result_json.exists():
                    urls_from_json = []
                    with open(result_json, 'r', encoding='utf-8') as f:
                        for line in f:
                            if line.strip():
                                try:
                                    url_data = json.loads(line.strip())
                                    if url_data.get('url') and url_data.get('title'):
                                        urls_from_json.append({
                                            'url': url_data['url'],
                                            'title': url_data['title'],
                                            'content_length': url_data.get('content_length', 0)
                                        })
                                except json.JSONDecodeError:
                                    continue
                    
                    if urls_from_json:
                        domain_info['representative_urls'] = urls_from_json
                
                # 如果没有从JSON读取到，则从representative_urls.txt读取
                if not domain_info['representative_urls']:
                    rep_urls_file = domain_dir / "representative_urls.txt"
                    if rep_urls_file.exists():
                        with open(rep_urls_file, 'r') as f:
                            urls = [line.strip() for line in f if line.strip()]
                            domain_info['representative_urls'] = [{'url': url, 'title': '无标题'} for url in urls]
                
                # 读取基础信息
                base_info_file = domain_dir / f"base_info_{domain_name}.txt"
                if base_info_file.exists():
                    with open(base_info_file, 'r') as f:
                        domain_info['base_info'] = f.read()
                
                # 读取漏洞信息
                vuln_file = domain_dir / f"afrog_report_{domain_name}.json"
                if vuln_file.exists():
                    with open(vuln_file, 'r') as f:
                        try:
                            vulns = json.load(f)
                            domain_info['vulnerabilities'] = vulns
                            layer_data['vulnerabilities'].extend(vulns)
                        except json.JSONDecodeError:
                            pass
                
                # 读取fscan结果
                fscan_file = domain_dir / f"fscan_report_{domain_name}.txt"
                if fscan_file.exists():
                    with open(fscan_file, 'r') as f:
                        fscan_content = f.read()
                        domain_info['fscan_results'] = [{
                            'filename': f"fscan_report_{domain_name}.txt",
                            'content': fscan_content
                        }]
                        layer_data['fscan_results'].append({
                            'domain': domain_name,
                            'content': fscan_content
                        })
                
                layer_data['domain_scan_results'][domain_name] = domain_info
    
    return layer_data

def generate_interactive_html_report(layers_data, target_domain, output_file):
    """生成交互式HTML报告"""
    
    html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🎯 {target_domain} - 多层扫描报告</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: rgba(255, 255, 255, 0.95);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }}
        
        .header h1 {{
            color: #2c3e50;
            text-align: center;
            margin-bottom: 10px;
        }}
        
        .header .meta {{
            text-align: center;
            color: #7f8c8d;
            font-size: 14px;
        }}
        
        .navigation {{
            background: rgba(255, 255, 255, 0.95);
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }}
        
        .nav-buttons {{
            display: flex;
            gap: 10px;
            justify-content: center;
            flex-wrap: wrap;
        }}
        
        .nav-button {{
            padding: 10px 20px;
            background: #3498db;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            transition: background 0.3s;
        }}
        
        .nav-button:hover {{
            background: #2980b9;
        }}
        
        .nav-button.active {{
            background: #e74c3c;
        }}
        
        .layer-content {{
            display: none;
            background: rgba(255, 255, 255, 0.95);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }}
        
        .layer-content.active {{
            display: block;
        }}
        
        .section {{
            margin-bottom: 30px;
        }}
        
        .section h2 {{
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 15px;
        }}
        
        .section h3 {{
            color: #34495e;
            margin-bottom: 10px;
        }}
        
        .url-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        
        .url-card {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #3498db;
        }}
        
        .url-card .url {{
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 8px;
        }}
        
        .url-card .url a {{
            color: #3498db;
            text-decoration: none;
        }}
        
        .url-card .url a:hover {{
            text-decoration: underline;
        }}
        
        .url-card .details {{
            font-size: 12px;
            color: #7f8c8d;
        }}
        
        .domain-clickable {{
            color: #e74c3c;
            cursor: pointer;
            text-decoration: underline;
            font-weight: bold;
        }}
        
        .domain-clickable:hover {{
            background: #fff3cd;
            padding: 2px 4px;
            border-radius: 3px;
        }}
        
        .vulnerability {{
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
        }}
        
        .vulnerability.high {{
            background: #fdcbcb;
            border-color: #e74c3c;
        }}
        
        .vulnerability.medium {{
            background: #ffeaa7;
            border-color: #f39c12;
        }}
        
        .vulnerability.low {{
            background: #d4edda;
            border-color: #27ae60;
        }}
        
        .fscan-content {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            white-space: pre-wrap;
            overflow-x: auto;
            margin: 10px 0;
        }}
        
        .stats {{
            display: flex;
            justify-content: space-around;
            margin-bottom: 20px;
        }}
        
        .stat {{
            text-align: center;
            padding: 15px;
            background: #3498db;
            color: white;
            border-radius: 8px;
            min-width: 100px;
        }}
        
        .stat .number {{
            font-size: 24px;
            font-weight: bold;
        }}
        
        .stat .label {{
            font-size: 12px;
            margin-top: 5px;
        }}
        
        .back-button {{
            display: none;
            margin-bottom: 15px;
        }}
        
        .back-button button {{
            padding: 8px 16px;
            background: #95a5a6;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }}
        
        .back-button button:hover {{
            background: #7f8c8d;
        }}
        
        /* 关系图样式 */
        .relationship-graph {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }}
        
        /* 网络图容器 */
        #networkGraph {{
            width: 100%;
            height: 600px;
            border: 1px solid #ddd;
            border-radius: 8px;
            background: #fafafa;
        }}
        
        /* SVG连接线样式 */
        .link {{
            stroke: #999;
            stroke-opacity: 0.6;
            stroke-width: 2;
        }}
        
        .link:hover {{
            stroke-opacity: 1;
            stroke-width: 3;
        }}
        
        .link-label {{
            fill: #666;
            font-size: 12px;
            text-anchor: middle;
        }}
        
        /* 力导向图节点样式 */
        .graph-node {{
            cursor: pointer;
        }}
        
        .graph-node circle {{
            stroke: #fff;
            stroke-width: 3;
        }}
        
        .graph-node text {{
            fill: #fff;
            font-size: 14px;
            font-weight: bold;
            text-anchor: middle;
            pointer-events: none;
        }}
        
        .graph-node.main circle {{
            fill: #e74c3c;
            r: 35;
        }}
        
        .graph-node.normal circle {{
            fill: #3498db;
            r: 30;
        }}
        
        /* 原有的层级布局样式 */
        .graph-container {{
            display: flex;
            flex-direction: column;
            gap: 50px;
            margin: 20px 0;
            padding: 20px;
            position: relative;
        }}
        
        .layer-row {{
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 80px;
            position: relative;
            min-height: 80px;
        }}
        
        .domain-node {{
            background: #3498db;
            color: white;
            padding: 12px 20px;
            border-radius: 25px;
            text-align: center;
            font-weight: bold;
            position: relative;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            cursor: pointer;
            transition: all 0.3s;
            font-size: 14px;
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}
        
        .domain-node:hover {{
            transform: translateY(-2px) scale(1.05);
            box-shadow: 0 6px 12px rgba(0,0,0,0.15);
            z-index: 10;
        }}
        
        .domain-node.main {{
            background: #e74c3c;
            font-size: 16px;
            padding: 15px 25px;
        }}
        
        /* 连接线 */
        .connection-line {{
            position: absolute;
            width: 1px;
            background: #bdc3c7;
            transform-origin: top center;
            z-index: -1;
        }}
        
        .connection-line::after {{
            content: '';
            position: absolute;
            bottom: -6px;
            left: -5px;
            width: 0;
            height: 0;
            border-left: 6px solid transparent;
            border-right: 6px solid transparent;
            border-top: 6px solid #bdc3c7;
        }}
        
        .discovery-method {{
            position: absolute;
            background: white;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 11px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            white-space: nowrap;
            z-index: 5;
        }}
        
        .legend {{
            margin-top: 30px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
        }}
        
        .legend-item {{
            display: inline-flex;
            align-items: center;
            margin: 5px 15px;
            font-size: 14px;
        }}
        
        .legend-icon {{
            margin-right: 8px;
            font-size: 18px;
        }}
        
        .relationship-card {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
            border-left: 4px solid #3498db;
        }}
        
        .relationship-card .from-to {{
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 5px;
        }}
        
        .relationship-card .method {{
            color: #e74c3c;
            font-size: 14px;
            margin-bottom: 5px;
        }}
        
        .relationship-card .details {{
            color: #7f8c8d;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎯 {target_domain} - 多层扫描报告</h1>
            <div class="meta">
                生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | 
                扫描层数: {len(layers_data)} 层
            </div>
        </div>
        
        <div class="navigation">
            <div class="nav-buttons">
"""
    
    # 添加关系图按钮
    html_content += '<button class="nav-button" onclick="showRelationshipGraph()">📊 发现路径图</button>\n'
    html_content += '<button class="nav-button" onclick="showRelationshipDetails()">📄 详细记录</button>\n'
    
    # 生成导航按钮
    for layer_num in sorted(layers_data.keys()):
        active_class = "active" if layer_num == 1 else ""
        html_content += f'<button class="nav-button {active_class}" onclick="showLayer({layer_num})">第{layer_num}层扫描</button>\n'
    
    html_content += """
            </div>
        </div>
        
        <div class="back-button" id="backButton">
            <button onclick="showMainView()">← 返回主视图</button>
        </div>
        
        <!-- 域名发现路径图页面 -->
        <div class="layer-content" id="relationshipGraph">
            <h2>📊 域名发现路径可视化</h2>
            <div class="relationship-graph">
                <div class="section">
                    <div id="graphVisualization" style="width: 100%; height: 600px; position: relative; overflow: auto; background: #f8f9fa; border-radius: 8px;"></div>
                </div>
                
                <div class="legend">
                    <h4>🔍 发现方式说明</h4>
                    <div class="legend-item"><span class="legend-icon">🔍</span> FOFA搜索 - 通过FOFA搜索引擎发现</div>
                    <div class="legend-item"><span class="legend-icon">🎯</span> IP反查 - 通过IP地址反查域名</div>
                    <div class="legend-item"><span class="legend-icon">🔐</span> 证书关联 - 通过SSL证书SAN发现</div>
                    <div class="legend-item"><span class="legend-icon">↗️</span> URL跳转 - 通过HTTP跳转发现</div>
                    <div class="legend-item"><span class="legend-icon">📡</span> 子域名枚举 - 通过子域名爆破发现</div>
                    <div class="legend-item"><span class="legend-icon">📄</span> 页面内容 - 从页面内容提取</div>
                    <div class="legend-item"><span class="legend-icon">🌐</span> DNS记录 - 通过DNS查询发现</div>
                    <div class="legend-item"><span class="legend-icon">🔗</span> 资源引用 - 页面资源引用发现</div>
                </div>
            </div>
        </div>
        
        <!-- 详细发现记录页面 -->
        <div class="layer-content" id="relationshipDetailPage">
            <h2>📄 域名发现详细记录</h2>
            <div class="relationship-graph">
                <div class="section">
                    <div id="relationshipDetails"></div>
                </div>
            </div>
        </div>
"""
    
    # 生成各层内容
    for layer_num in sorted(layers_data.keys()):
        layer_data = layers_data[layer_num]
        active_class = "active" if layer_num == 1 else ""
        
        html_content += f"""
        <div class="layer-content {active_class}" id="layer{layer_num}">
            <h2>第{layer_num}层扫描结果</h2>
"""
        
        if layer_num == 1:
            # 第一层特殊处理
            html_content += generate_layer1_content(layer_data, target_domain)
        else:
            # 其他层处理
            html_content += generate_expansion_layer_content(layer_data, layer_num)
        
        html_content += "</div>\n"
    
    # 生成域名详细视图
    for layer_num in sorted(layers_data.keys()):
        if layer_num > 1:
            layer_data = layers_data[layer_num]
            if 'domain_scan_results' in layer_data:
                for domain_name, domain_info in layer_data['domain_scan_results'].items():
                    html_content += generate_domain_detail_view(domain_name, domain_info, layer_num)
    
    # 添加JavaScript
    html_content += """
    </div>
    
    <script>
        function showLayer(layerNum) {
            // 隐藏所有层
            document.querySelectorAll('.layer-content').forEach(el => {
                el.classList.remove('active');
            });
            
            // 更新导航按钮
            document.querySelectorAll('.nav-button').forEach(btn => {
                btn.classList.remove('active');
            });
            
            // 显示选中的层
            document.getElementById('layer' + layerNum).classList.add('active');
            event.target.classList.add('active');
            
            // 隐藏返回按钮
            document.getElementById('backButton').style.display = 'none';
        }
        
        function showDomainDetail(domainName, layerNum) {
            // 隐藏所有层
            document.querySelectorAll('.layer-content').forEach(el => {
                el.classList.remove('active');
            });
            
            // 隐藏所有域名详细视图
            document.querySelectorAll('.domain-detail').forEach(el => {
                el.classList.remove('active');
            });
            
            // 显示选中的域名详细视图
            document.getElementById('domain_' + domainName).classList.add('active');
            
            // 显示返回按钮
            document.getElementById('backButton').style.display = 'block';
        }
        
        function showMainView() {
            // 隐藏所有域名详细视图
            document.querySelectorAll('.domain-detail').forEach(el => {
                el.classList.remove('active');
            });
            
            // 显示第一层
            document.getElementById('layer1').classList.add('active');
            
            // 隐藏返回按钮
            document.getElementById('backButton').style.display = 'none';
            
            // 重置导航按钮
            document.querySelectorAll('.nav-button').forEach(btn => {
                btn.classList.remove('active');
            });
            document.querySelectorAll('.nav-button')[1].classList.add('active'); // 第一层扫描按钮
        }
        
        function showRelationshipGraph() {
            // 隐藏所有内容
            document.querySelectorAll('.layer-content').forEach(el => {
                el.classList.remove('active');
            });
            
            // 更新导航按钮
            document.querySelectorAll('.nav-button').forEach(btn => {
                btn.classList.remove('active');
            });
            
            // 显示关系图
            document.getElementById('relationshipGraph').classList.add('active');
            event.target.classList.add('active');
            
            // 隐藏返回按钮
            document.getElementById('backButton').style.display = 'none';
            
            // 加载关系数据
            loadRelationshipData();
        }
        
        function showRelationshipDetails() {
            // 隐藏所有内容
            document.querySelectorAll('.layer-content').forEach(el => {
                el.classList.remove('active');
            });
            
            // 更新导航按钮
            document.querySelectorAll('.nav-button').forEach(btn => {
                btn.classList.remove('active');
            });
            
            // 显示详细记录页面
            document.getElementById('relationshipDetailPage').classList.add('active');
            event.target.classList.add('active');
            
            // 隐藏返回按钮
            document.getElementById('backButton').style.display = 'none';
            
            // 加载关系数据
            loadRelationshipData();
        }
        
        function loadRelationshipData() {
            // 关系数据
            const relationships = """ + json.dumps(load_relationships(target_domain)) + """;
            
            // 生成可视化图
            generateGraphVisualization(relationships);
            
            // 生成详细列表
            generateRelationshipDetails(relationships);
        }
        
        function generateGraphVisualization(data) {
            const container = document.getElementById('graphVisualization');
            container.innerHTML = '';
            
            // 创建SVG画布
            const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
            svg.setAttribute('width', '100%');
            svg.setAttribute('height', '100%');
            svg.style.position = 'absolute';
            svg.style.top = '0';
            svg.style.left = '0';
            container.appendChild(svg);
            
            // 创建DOM容器
            const domContainer = document.createElement('div');
            domContainer.className = 'graph-container';
            container.appendChild(domContainer);
            
            // 组织数据
            const layers = organizeDomainsByLayer(data.relationships);
            const nodePositions = {};
            const layerHeight = 120;
            const containerRect = container.getBoundingClientRect();
            
            // 渲染节点并记录位置
            layers.forEach((domains, layerIndex) => {
                const layerDiv = document.createElement('div');
                layerDiv.className = 'layer-row';
                layerDiv.style.marginTop = layerIndex === 0 ? '40px' : '80px';
                
                domains.forEach((domain, domainIndex) => {
                    const isMain = layerIndex === 0 && domain === '""" + target_domain + """';
                    const node = document.createElement('div');
                    node.className = `domain-node ${isMain ? 'main' : ''}`;
                    node.textContent = domain;
                    node.title = domain; // 完整域名悬停提示
                    node.onclick = () => showDomainFromGraph(domain, layerIndex + 1);
                    node.id = `node-${domain.replace(/\\./g, '-')}`;
                    layerDiv.appendChild(node);
                });
                
                domContainer.appendChild(layerDiv);
            });
            
            // 延迟绘制连接线，确保DOM已经渲染
            setTimeout(() => {
                // 获取所有节点的实际位置
                document.querySelectorAll('.domain-node').forEach(node => {
                    const rect = node.getBoundingClientRect();
                    const containerRect = container.getBoundingClientRect();
                    const domain = node.textContent;
                    nodePositions[domain] = {
                        x: rect.left + rect.width / 2 - containerRect.left,
                        y: rect.top + rect.height / 2 - containerRect.top
                    };
                });
                
                // 绘制连接线
                const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
                defs.innerHTML = `
                    <marker id="arrowhead" markerWidth="10" markerHeight="7" 
                     refX="10" refY="3.5" orient="auto">
                        <polygon points="0 0, 10 3.5, 0 7" fill="#666" />
                    </marker>
                `;
                svg.appendChild(defs);
                
                data.relationships.forEach(rel => {
                    const from = nodePositions[rel.from];
                    const to = nodePositions[rel.to];
                    
                    if (from && to) {
                        // 计算连接线路径
                        const dx = to.x - from.x;
                        const dy = to.y - from.y;
                        
                        // 创建曲线路径
                        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
                        const midY = from.y + dy / 2;
                        const d = `M ${from.x} ${from.y + 20} Q ${from.x} ${midY} ${to.x} ${to.y - 20}`;
                        path.setAttribute('d', d);
                        path.setAttribute('fill', 'none');
                        path.setAttribute('stroke', '#95a5a6');
                        path.setAttribute('stroke-width', '2');
                        path.setAttribute('marker-end', 'url(#arrowhead)');
                        path.classList.add('link');
                        
                        // 添加方法标签
                        const methodInfo = data.discovery_methods[rel.method] || {};
                        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                        text.setAttribute('x', from.x + dx / 2);
                        text.setAttribute('y', from.y + dy / 2);
                        text.setAttribute('text-anchor', 'middle');
                        text.setAttribute('class', 'link-label');
                        text.textContent = `${methodInfo.icon || '🔍'} ${rel.method}`;
                        
                        svg.appendChild(path);
                        svg.appendChild(text);
                    }
                });
            }, 100);
        }
        
        function generateRelationshipDetails(data) {
            const container = document.getElementById('relationshipDetails');
            let html = '';
            
            data.relationships.forEach(rel => {
                const methodInfo = data.discovery_methods[rel.method] || {};
                html += `
                    <div class="relationship-card" style="border-left-color: ${methodInfo.color || '#3498db'}">
                        <div class="from-to">${rel.from} → ${rel.to}</div>
                        <div class="method">${methodInfo.icon || '🔍'} ${rel.method}</div>
                        <div class="details">${rel.details}</div>
                    </div>
                `;
            });
            
            container.innerHTML = html;
        }
        
        function organizeDomainsByLayer(relationships) {
            const layers = [['""" + target_domain + """']];
            const domainToLayer = {'""" + target_domain + """': 0};
            
            // 简单的分层算法
            relationships.forEach(rel => {
                const fromLayer = domainToLayer[rel.from] || 0;
                const toLayer = fromLayer + 1;
                
                if (!domainToLayer[rel.to]) {
                    domainToLayer[rel.to] = toLayer;
                    
                    if (!layers[toLayer]) {
                        layers[toLayer] = [];
                    }
                    
                    if (!layers[toLayer].includes(rel.to)) {
                        layers[toLayer].push(rel.to);
                    }
                }
            });
            
            return layers;
        }
        
        function showDomainFromGraph(domain, layer) {
            // 根据域名判断是哪一层
            if (domain === '""" + target_domain + """') {
                showLayer(1);
            } else {
                // 尝试找到域名所在的层并显示
                showDomainDetail(domain, layer);
            }
        }
        
        // 初始化时显示第一层
        window.onload = function() {
            showLayer(1);
        };
    </script>
</body>
</html>
"""
    
    # 写入文件
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

def generate_layer1_content(layer_data, target_domain):
    """生成第一层内容"""
    content = ""
    
    # 统计信息
    url_count = len(layer_data['representative_urls'])
    vuln_count = len(layer_data['vulnerabilities'])
    fscan_count = len(layer_data['fscan_results'])
    
    content += f"""
    <div class="stats">
        <div class="stat">
            <div class="number">{url_count}</div>
            <div class="label">发现URL</div>
        </div>
        <div class="stat">
            <div class="number">{vuln_count}</div>
            <div class="label">漏洞数量</div>
        </div>
        <div class="stat">
            <div class="number">{fscan_count}</div>
            <div class="label">端口扫描</div>
        </div>
    </div>
"""
    
    # URL详细信息
    if layer_data['representative_urls']:
        content += """
        <div class="section">
            <h2>🌐 发现的URL</h2>
            <div class="url-grid">
"""
        
        for url_info in layer_data['representative_urls']:
            content += f"""
            <div class="url-card">
                <div class="url">
                    <a href="{url_info['url']}" target="_blank">{url_info['url']}</a>
                </div>
                <div class="details">
                    标题: {url_info['title'] or '无标题'}<br>
                    大小: {url_info['content_length']:,} 字节
                </div>
            </div>
"""
        
        content += """
            </div>
        </div>
"""
    
    # 扩展目标
    expansion_targets = layer_data['expansion_targets']
    if any(expansion_targets.values()):
        content += """
        <div class="section">
            <h2>🔍 扩展目标</h2>
"""
        
        if expansion_targets['domains']:
            content += "<h3>🌐 域名目标</h3>\n"
            for domain in expansion_targets['domains']:
                content += f'<div class="domain-clickable" onclick="showDomainDetail(\'{domain}\', 2)">{domain}</div>\n'
        
        if expansion_targets['ips']:
            content += "<h3>🎯 IP目标</h3>\n"
            for ip in expansion_targets['ips']:
                content += f"<div>{ip}</div>\n"
        
        if expansion_targets['urls']:
            content += "<h3>🔗 URL目标</h3>\n"
            for url in expansion_targets['urls']:
                content += f'<div><a href="{url}" target="_blank">{url}</a></div>\n'
        
        content += "</div>\n"
    
    # 漏洞信息
    if layer_data['vulnerabilities']:
        content += generate_vulnerabilities_section(layer_data['vulnerabilities'])
    
    # fscan结果
    if layer_data['fscan_results']:
        content += generate_fscan_section(layer_data['fscan_results'])
    
    return content

def generate_expansion_layer_content(layer_data, layer_num):
    """生成扩展层内容"""
    content = ""
    
    # 统计信息
    domain_count = len(layer_data.get('domain_scan_results', {}))
    vuln_count = sum(len(info.get('vulnerabilities', [])) for info in layer_data.get('domain_scan_results', {}).values())
    
    content += f"""
    <div class="stats">
        <div class="stat">
            <div class="number">{domain_count}</div>
            <div class="label">扫描域名</div>
        </div>
        <div class="stat">
            <div class="number">{vuln_count}</div>
            <div class="label">发现漏洞</div>
        </div>
    </div>
"""
    
    # 域名扫描结果
    if layer_data.get('domain_scan_results'):
        content += """
        <div class="section">
            <h2>🔍 域名扫描结果</h2>
"""
        
        for domain_name, domain_info in layer_data['domain_scan_results'].items():
            url_count = len(domain_info.get('representative_urls', []))
            vuln_count = len(domain_info.get('vulnerabilities', []))
            
            content += f"""
            <div class="url-card">
                <div class="url">
                    <span class="domain-clickable" onclick="showDomainDetail('{domain_name}', {layer_num})">{domain_name}</span>
                </div>
                <div class="details">
                    发现URL: {url_count} 个 | 漏洞数量: {vuln_count} 个
                </div>
            </div>
"""
        
        content += "</div>\n"
    
    return content

def generate_domain_detail_view(domain_name, domain_info, layer_num):
    """生成域名详细视图 - 与第一层格式完全一致"""
    content = f"""
    <div class="layer-content domain-detail" id="domain_{domain_name}">
        <h2>🌐 {domain_name} - 扫描结果</h2>
"""
    
    # 统计信息 - 与第一层一样的三个统计
    url_count = len(domain_info.get('representative_urls', []))
    vuln_count = len(domain_info.get('vulnerabilities', []))
    fscan_count = len(domain_info.get('fscan_results', []))
    
    content += f"""
    <div class="stats">
        <div class="stat">
            <div class="number">{url_count}</div>
            <div class="label">发现URL</div>
        </div>
        <div class="stat">
            <div class="number">{vuln_count}</div>
            <div class="label">漏洞数量</div>
        </div>
        <div class="stat">
            <div class="number">{fscan_count}</div>
            <div class="label">端口扫描</div>
        </div>
    </div>
"""
    
    # URL信息 - 与第一层格式完全一致
    if domain_info.get('representative_urls'):
        content += """
        <div class="section">
            <h2>🌐 发现的URL</h2>
            <div class="url-grid">
"""
        
        for url_info in domain_info['representative_urls']:
            content += f"""
            <div class="url-card">
                <div class="url">
                    <a href="{url_info['url']}" target="_blank">{url_info['url']}</a>
                </div>
                <div class="details">
                    标题: {url_info['title'] or '无标题'}<br>
                    大小: {url_info['content_length']:,} 字节
                </div>
            </div>
"""
        
        content += """
            </div>
        </div>
"""
    
    # 扩展目标 - 与第一层格式完全一致
    expansion_targets = domain_info.get('expansion_targets', {})
    if any(expansion_targets.values()):
        content += """
        <div class="section">
            <h2>🔍 扩展目标</h2>
"""
        
        if expansion_targets.get('domains'):
            content += "<h3>🌐 域名目标</h3>\n"
            # 判断当前层级，为扩展域名生成正确的链接
            next_layer = layer_num + 1
            for domain in expansion_targets['domains']:
                content += f'<div class="domain-clickable" onclick="showDomainDetail(\'{domain}\', {next_layer})">{domain}</div>\n'
        
        if expansion_targets.get('ips'):
            content += "<h3>🎯 IP目标</h3>\n"
            for ip in expansion_targets['ips']:
                content += f"<div>{ip}</div>\n"
        
        if expansion_targets.get('urls'):
            content += "<h3>🔗 URL目标</h3>\n"
            for url in expansion_targets['urls']:
                content += f'<div><a href="{url}" target="_blank">{url}</a></div>\n'
        
        content += "</div>\n"
    
    # 漏洞信息 - 与第一层格式完全一致
    if domain_info.get('vulnerabilities'):
        content += generate_vulnerabilities_section(domain_info['vulnerabilities'])
    
    # fscan结果 - 与第一层格式完全一致
    if domain_info.get('fscan_results'):
        content += generate_fscan_section(domain_info['fscan_results'])
    
    content += "</div>\n"
    
    return content

def generate_vulnerabilities_section(vulnerabilities):
    """生成漏洞部分"""
    content = """
    <div class="section">
        <h2>🚨 漏洞信息</h2>
"""
    
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'unknown').lower()
        content += f"""
        <div class="vulnerability {severity}">
            <strong>{vuln.get('name', 'Unknown')}</strong> 
            <span style="color: #e74c3c;">[{vuln.get('severity', 'UNKNOWN')}]</span><br>
            <strong>目标:</strong> {vuln.get('target', 'N/A')}<br>
            <strong>描述:</strong> {vuln.get('description', 'N/A')}
        </div>
"""
    
    content += "</div>\n"
    
    return content

def generate_fscan_section(fscan_results):
    """生成fscan结果部分"""
    content = """
    <div class="section">
        <h2>🔍 端口扫描结果</h2>
"""
    
    for fscan_result in fscan_results:
        content += f"""
        <h3 style="color: #54a0ff; background: #f8f9fa; padding: 10px; border-radius: 5px;">
            📍 {fscan_result['filename']}
        </h3>
        <div class="fscan-content">{make_urls_clickable(fscan_result['content'])}</div>
"""
    
    content += "</div>\n"
    
    return content

def main():
    parser = argparse.ArgumentParser(description='生成交互式多层扫描报告')
    parser.add_argument('target_domain', help='目标域名')
    parser.add_argument('--output-dir', default='output', help='输出目录 (默认: output)')
    parser.add_argument('--output-file', help='输出文件名 (默认: auto)')
    
    args = parser.parse_args()
    
    # 收集数据
    layers_data = collect_layer_data(args.output_dir, args.target_domain)
    
    if not layers_data:
        print("❌ 未找到扫描数据")
        sys.exit(1)
    
    # 生成输出文件名
    if args.output_file:
        output_file = args.output_file
    else:
        output_file = f"output/{args.target_domain}/interactive_scan_report_{args.target_domain}.html"
    
    # 生成报告
    generate_interactive_html_report(layers_data, args.target_domain, output_file)
    
    print(f"✅ 交互式报告已生成: {output_file}")

if __name__ == "__main__":
    main()