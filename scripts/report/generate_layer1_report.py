#!/usr/bin/env python3
"""
一层扫描报告生成器
生成美观的HTML报告，展示一层扫描的结果
"""

import json
import os
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter
import argparse

def parse_base_info(base_info_path):
    """解析base_info文件获取基础扫描信息"""
    urls = []
    ips = []
    domains = []
    
    try:
        with open(base_info_path, 'r', encoding='utf-8') as f:
            current_section = None
            for line in f:
                line = line.strip()
                if not line:
                    continue
                    
                if line.startswith('URL:'):
                    current_section = 'url'
                    # 提取URL和标题
                    parts = line.split(' -> ')
                    if len(parts) >= 2:
                        url = parts[0].replace('URL:', '').strip()
                        title = parts[1].strip() if len(parts) > 1 else ''
                        # 去除标题中的[size:xxx]部分
                        if '[size:' in title:
                            title = title.split('[size:')[0].strip()
                        urls.append({'url': url, 'title': title})
                elif line.startswith('IP:'):
                    current_section = 'ip'
                    ip = line.replace('IP:', '').strip()
                    ips.append(ip)
                elif line.startswith('域名:'):
                    current_section = 'domain'
                    domain = line.replace('域名:', '').strip()
                    domains.append(domain)
                elif current_section == 'domain' and line and not line.startswith('---'):
                    # 继续收集域名
                    domains.append(line)
                    
    except Exception as e:
        print(f"[!] 解析base_info文件失败: {e}")
        
    return urls, ips, domains

def parse_tuozhan_data(tuozhan_path):
    """解析拓展数据"""
    stats = {
        'fofa': {'ips': 0, 'domains': 0, 'urls': 0},
        'hunter': {'ips': 0, 'domains': 0, 'urls': 0},
        'ip_re': {'ips': 0, 'domains': 0},
        'url_body': {'domains': 0},
        'total': {'ips': 0, 'domains': 0, 'urls': 0}
    }
    
    # 解析all_tuozhan下的汇总数据
    all_tuozhan_path = tuozhan_path / 'all_tuozhan'
    if all_tuozhan_path.exists():
        # 统计IP
        ip_file = all_tuozhan_path / 'ip.txt'
        if ip_file.exists():
            with open(ip_file, 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        stats['total']['ips'] += 1
        
        # 统计URL
        url_file = all_tuozhan_path / 'urls.txt'
        if url_file.exists():
            with open(url_file, 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        stats['total']['urls'] += 1
        
        # 统计域名
        domain_file = all_tuozhan_path / 'root_domains.txt'
        if domain_file.exists():
            with open(domain_file, 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        stats['total']['domains'] += 1
    
    # 解析各个来源的详细数据
    for source in ['fofa', 'hunter', 'ip_re']:
        source_path = tuozhan_path / source
        if source_path.exists():
            for file in source_path.iterdir():
                if file.suffix == '.txt':
                    with open(file, 'r') as f:
                        content = f.read()
                        lines = [l for l in content.split('\n') if l.strip() and not l.startswith('#')]
                        
                        # 根据内容判断类型
                        if any(':' in line for line in lines[:5]):  # URL格式
                            stats[source]['urls'] += len(lines)
                        elif any('.' in line and line.count('.') >= 3 for line in lines[:5]):  # IP格式
                            stats[source]['ips'] += len(lines)
                        else:  # 域名格式
                            stats[source]['domains'] += len(lines)
    
    return stats

def parse_security_scan_results(domain_path):
    """解析安全扫描结果"""
    security_stats = {
        'afrog': {'total': 0, 'vulns': []},
        'fscan': {'total': 0, 'services': []}
    }
    
    # 查找afrog报告
    for file in domain_path.glob('afrog_report_*.json'):
        try:
            with open(file, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    security_stats['afrog']['total'] = len(data)
                    for item in data:
                        if isinstance(item, dict):
                            vuln_info = {
                                'name': item.get('PocInfo', {}).get('Name', 'Unknown'),
                                'severity': item.get('PocInfo', {}).get('Severity', 'Unknown'),
                                'target': item.get('FullTarget', '')
                            }
                            security_stats['afrog']['vulns'].append(vuln_info)
        except Exception as e:
            print(f"[!] 解析afrog报告失败: {e}")
    
    # 查找fscan报告
    for file in domain_path.glob('fscan_result_*.txt'):
        try:
            with open(file, 'r') as f:
                content = f.read()
                # 简单统计开放端口数量
                port_lines = [l for l in content.split('\n') if 'open' in l.lower()]
                security_stats['fscan']['total'] = len(port_lines)
        except Exception as e:
            print(f"[!] 解析fscan报告失败: {e}")
    
    return security_stats

def generate_html_report(domain, data):
    """生成HTML报告"""
    html_template = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{domain} - 一层扫描报告</title>
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
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
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
        
        .header p {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        
        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }}
        
        .stat-card h3 {{
            color: #666;
            font-size: 0.9em;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .stat-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            color: var(--primary-color);
            margin: 10px 0;
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
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: 600;
        }}
        
        .badge-success {{
            background-color: var(--success-color);
            color: white;
        }}
        
        .badge-warning {{
            background-color: var(--warning-color);
            color: white;
        }}
        
        .badge-danger {{
            background-color: var(--danger-color);
            color: white;
        }}
        
        .source-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }}
        
        .source-stat {{
            background: var(--light-bg);
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }}
        
        .source-stat h4 {{
            color: var(--dark-bg);
            margin-bottom: 10px;
            font-size: 1.1em;
        }}
        
        .source-stat .detail {{
            font-size: 0.9em;
            color: #666;
            margin: 5px 0;
        }}
        
        .progress-bar {{
            width: 100%;
            height: 20px;
            background-color: var(--light-bg);
            border-radius: 10px;
            overflow: hidden;
            margin-top: 10px;
        }}
        
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, var(--success-color), var(--primary-color));
            transition: width 0.3s ease;
        }}
        
        .footer {{
            text-align: center;
            padding: 30px 0;
            color: #666;
            font-size: 0.9em;
        }}
        
        @media (max-width: 768px) {{
            .stats-grid {{
                grid-template-columns: 1fr;
            }}
            
            .header h1 {{
                font-size: 2em;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{domain}</h1>
            <p>一层扫描报告 - {scan_time}</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>发现URL</h3>
                <div class="number">{url_count}</div>
            </div>
            <div class="stat-card">
                <h3>发现IP</h3>
                <div class="number">{ip_count}</div>
            </div>
            <div class="stat-card">
                <h3>反查域名</h3>
                <div class="number">{domain_count}</div>
            </div>
            <div class="stat-card">
                <h3>安全漏洞</h3>
                <div class="number" style="color: {vuln_color}">{vuln_count}</div>
            </div>
        </div>
        
        <div class="section">
            <h2>📊 拓展统计</h2>
            <div class="source-stats">
                <div class="source-stat">
                    <h4>FOFA查询</h4>
                    <div class="detail">IP: {fofa_ips}</div>
                    <div class="detail">域名: {fofa_domains}</div>
                    <div class="detail">URL: {fofa_urls}</div>
                </div>
                <div class="source-stat">
                    <h4>Hunter查询</h4>
                    <div class="detail">IP: {hunter_ips}</div>
                    <div class="detail">域名: {hunter_domains}</div>
                    <div class="detail">URL: {hunter_urls}</div>
                </div>
                <div class="source-stat">
                    <h4>IP反查</h4>
                    <div class="detail">IP: {ipre_ips}</div>
                    <div class="detail">域名: {ipre_domains}</div>
                </div>
                <div class="source-stat">
                    <h4>汇总结果</h4>
                    <div class="detail">总IP: {total_ips}</div>
                    <div class="detail">总域名: {total_domains}</div>
                    <div class="detail">总URL: {total_urls}</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>🌐 发现的URL</h2>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>URL</th>
                        <th>标题</th>
                    </tr>
                </thead>
                <tbody>
                    {url_rows}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>🖥️ 发现的IP</h2>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>IP地址</th>
                        <th>反查域名数</th>
                    </tr>
                </thead>
                <tbody>
                    {ip_rows}
                </tbody>
            </table>
        </div>
        
        {security_section}
        
        <div class="section">
            <h2>📈 扫描建议</h2>
            <p>基于一层扫描结果，发现以下拓展目标：</p>
            <ul style="margin-top: 15px; margin-left: 20px;">
                <li>🔍 <strong>{total_ips}</strong> 个IP目标可进行端口扫描</li>
                <li>🌐 <strong>{total_urls}</strong> 个URL目标可进行深度探测</li>
                <li>🏢 <strong>{total_domains}</strong> 个新域名可进行完整扫描</li>
            </ul>
            <p style="margin-top: 15px;">建议执行二层扫描以深入挖掘这些目标：<code>./scan.sh -s 2</code></p>
        </div>
        
        <div class="footer">
            <p>Generated by 渗透测试扫描平台 | {scan_time}</p>
        </div>
    </div>
</body>
</html>"""
    
    # 准备数据
    urls = data.get('urls', [])
    ips = data.get('ips', [])
    domains = data.get('domains', [])
    tuozhan_stats = data.get('tuozhan_stats', {})
    security_stats = data.get('security_stats', {})
    
    # 生成URL行
    url_rows = []
    for url_info in urls[:100]:  # 限制显示前100个
        url = url_info.get('url', '')
        title = url_info.get('title', '')
        url_rows.append(f'<tr><td><a href="{url}" target="_blank" class="url-link">{url}</a></td><td>{title}</td></tr>')
    
    if len(urls) > 100:
        url_rows.append(f'<tr><td colspan="2" style="text-align: center; color: #666;">... 还有 {len(urls) - 100} 个URL未显示 ...</td></tr>')
    
    # 生成IP行
    ip_rows = []
    domain_counter = Counter(domains)
    for ip in ips[:50]:  # 限制显示前50个
        domain_count = sum(1 for d in domains if ip in d)  # 简单匹配
        ip_rows.append(f'<tr><td>{ip}</td><td>{domain_count}</td></tr>')
    
    if len(ips) > 50:
        ip_rows.append(f'<tr><td colspan="2" style="text-align: center; color: #666;">... 还有 {len(ips) - 50} 个IP未显示 ...</td></tr>')
    
    # 生成安全扫描部分
    security_section = ""
    vuln_count = len(security_stats.get('afrog', {}).get('vulns', []))
    vuln_color = "var(--danger-color)" if vuln_count > 0 else "var(--success-color)"
    
    if vuln_count > 0:
        vuln_rows = []
        for vuln in security_stats['afrog']['vulns'][:20]:  # 限制显示前20个
            severity_badge = f'<span class="badge badge-{get_severity_class(vuln["severity"])}">{vuln["severity"]}</span>'
            vuln_rows.append(f'<tr><td>{vuln["name"]}</td><td>{severity_badge}</td><td>{vuln["target"]}</td></tr>')
        
        security_section = f"""
        <div class="section">
            <h2>🔒 安全扫描结果</h2>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>漏洞名称</th>
                        <th>严重程度</th>
                        <th>目标</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(vuln_rows)}
                </tbody>
            </table>
        </div>
        """
    
    # 填充模板
    html = html_template.format(
        domain=domain,
        scan_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        url_count=len(urls),
        ip_count=len(ips),
        domain_count=len(set(domains)),
        vuln_count=vuln_count,
        vuln_color=vuln_color,
        fofa_ips=tuozhan_stats.get('fofa', {}).get('ips', 0),
        fofa_domains=tuozhan_stats.get('fofa', {}).get('domains', 0),
        fofa_urls=tuozhan_stats.get('fofa', {}).get('urls', 0),
        hunter_ips=tuozhan_stats.get('hunter', {}).get('ips', 0),
        hunter_domains=tuozhan_stats.get('hunter', {}).get('domains', 0),
        hunter_urls=tuozhan_stats.get('hunter', {}).get('urls', 0),
        ipre_ips=tuozhan_stats.get('ip_re', {}).get('ips', 0),
        ipre_domains=tuozhan_stats.get('ip_re', {}).get('domains', 0),
        total_ips=tuozhan_stats.get('total', {}).get('ips', 0),
        total_domains=tuozhan_stats.get('total', {}).get('domains', 0),
        total_urls=tuozhan_stats.get('total', {}).get('urls', 0),
        url_rows='\n'.join(url_rows) if url_rows else '<tr><td colspan="2" style="text-align: center; color: #666;">暂无数据</td></tr>',
        ip_rows='\n'.join(ip_rows) if ip_rows else '<tr><td colspan="2" style="text-align: center; color: #666;">暂无数据</td></tr>',
        security_section=security_section
    )
    
    return html

def get_severity_class(severity):
    """获取严重程度对应的CSS类"""
    severity = severity.lower()
    if severity in ['critical', 'high']:
        return 'danger'
    elif severity in ['medium']:
        return 'warning'
    else:
        return 'success'

def main():
    parser = argparse.ArgumentParser(description='生成一层扫描HTML报告')
    parser.add_argument('domain', nargs='?', help='目标域名')
    parser.add_argument('-o', '--output', help='输出文件路径')
    parser.add_argument('--open', action='store_true', help='生成后自动打开浏览器')
    
    args = parser.parse_args()
    
    # 获取项目根目录
    project_root = Path(__file__).parent.parent.parent
    output_dir = project_root / 'output'
    
    # 如果没有指定域名，尝试自动检测
    if not args.domain:
        domains = [d.name for d in output_dir.iterdir() if d.is_dir() and not d.name.endswith('_finish') and not d.name.endswith('_vul')]
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
    
    # 检查域名目录
    domain_path = output_dir / args.domain
    if not domain_path.exists():
        print(f"[!] 未找到域名目录: {domain_path}")
        sys.exit(1)
    
    print(f"[*] 开始生成 {args.domain} 的一层扫描报告...")
    
    # 收集数据
    data = {}
    
    # 解析base_info
    base_info_path = domain_path / f'base_info_{args.domain}.txt'
    if base_info_path.exists():
        urls, ips, domains = parse_base_info(base_info_path)
        data['urls'] = urls
        data['ips'] = ips
        data['domains'] = domains
        print(f"[*] 发现 {len(urls)} 个URL, {len(ips)} 个IP, {len(domains)} 个域名")
    else:
        print(f"[!] 未找到base_info文件: {base_info_path}")
        data['urls'] = []
        data['ips'] = []
        data['domains'] = []
    
    # 解析拓展数据
    tuozhan_path = domain_path / 'tuozhan'
    if tuozhan_path.exists():
        tuozhan_stats = parse_tuozhan_data(tuozhan_path)
        data['tuozhan_stats'] = tuozhan_stats
        print(f"[*] 拓展统计: 总计 {tuozhan_stats['total']['ips']} 个IP, {tuozhan_stats['total']['domains']} 个域名, {tuozhan_stats['total']['urls']} 个URL")
    else:
        data['tuozhan_stats'] = {}
    
    # 解析安全扫描结果
    security_stats = parse_security_scan_results(domain_path)
    data['security_stats'] = security_stats
    if security_stats['afrog']['vulns']:
        print(f"[*] 发现 {len(security_stats['afrog']['vulns'])} 个安全漏洞")
    
    # 生成HTML
    html_content = generate_html_report(args.domain, data)
    
    # 确定输出路径
    if args.output:
        output_path = Path(args.output)
    else:
        reports_dir = project_root / 'reports'
        reports_dir.mkdir(exist_ok=True)
        output_path = reports_dir / f'{args.domain}_layer1_report.html'
    
    # 写入文件
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"[✓] 报告已生成: {output_path}")
    
    # 打开浏览器
    if args.open:
        import webbrowser
        webbrowser.open(f'file://{output_path.absolute()}')
        print("[✓] 已在浏览器中打开报告")

if __name__ == '__main__':
    main()