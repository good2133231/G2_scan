#!/usr/bin/env python3
"""
报告摘要工具 - 快速查看HTML报告的关键信息
"""

import sys
import re
from pathlib import Path
from html.parser import HTMLParser


class ReportParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_stat_value = False
        self.in_stat_label = False
        self.in_layer_title = False
        self.in_result_item = False
        self.stats = {}
        self.layers = []
        self.current_stat_value = None
        self.results = []
        
    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == 'div' and 'class' in attrs_dict:
            if 'stat-value' in attrs_dict['class']:
                self.in_stat_value = True
            elif 'stat-label' in attrs_dict['class']:
                self.in_stat_label = True
            elif 'result-item' in attrs_dict['class']:
                self.in_result_item = True
        elif tag == 'h2' and 'class' in attrs_dict and 'layer-title' in attrs_dict['class']:
            self.in_layer_title = True
            
    def handle_endtag(self, tag):
        if tag == 'div':
            self.in_stat_value = False
            self.in_stat_label = False
            self.in_result_item = False
        elif tag == 'h2':
            self.in_layer_title = False
            
    def handle_data(self, data):
        data = data.strip()
        if not data:
            return
            
        if self.in_stat_value:
            self.current_stat_value = data
        elif self.in_stat_label and self.current_stat_value:
            # 移除emoji
            label = re.sub(r'[^\w\s\u4e00-\u9fff]', '', data).strip()
            if label:
                self.stats[label] = self.current_stat_value
            self.current_stat_value = None
        elif self.in_layer_title:
            self.layers.append(data)
        elif self.in_result_item:
            self.results.append(data)


def main():
    if len(sys.argv) > 1:
        report_file = sys.argv[1]
    else:
        # 默认查找最新的报告
        reports_dir = Path('reports')
        if reports_dir.exists():
            html_files = list(reports_dir.glob('*_multilayer_report.html'))
            if html_files:
                report_file = str(max(html_files, key=lambda x: x.stat().st_mtime))
            else:
                print("❌ 未找到报告文件")
                sys.exit(1)
        else:
            print("❌ reports目录不存在")
            sys.exit(1)
            
    if not Path(report_file).exists():
        print(f"❌ 报告文件不存在: {report_file}")
        sys.exit(1)
        
    # 解析报告
    parser = ReportParser()
    with open(report_file, 'r', encoding='utf-8') as f:
        parser.feed(f.read())
        
    # 显示摘要
    print(f"\n{'='*60}")
    print(f"📊 多层扫描报告摘要")
    print(f"{'='*60}")
    print(f"📁 报告文件: {report_file}")
    print(f"🎯 目标域名: {Path(report_file).stem.split('_')[0]}")
    
    if parser.layers:
        print(f"\n📈 扫描层级 ({len(parser.layers)}层):")
        for i, layer in enumerate(parser.layers, 1):
            print(f"   {i}. {layer}")
            
    if parser.stats:
        print(f"\n📊 关键统计:")
        # 按类别组织统计
        categories = {
            'URL': ['URL数量', 'URL探测', '扩展URL', '新发现URL', '代表URL'],
            'IP': ['IP地址', '扩展IP', '新发现IP', 'IP扫描任务'],
            '域名': ['扩展域名', '扫描域名'],
            '安全': ['发现漏洞']
        }
        
        for category, labels in categories.items():
            values = []
            for label in labels:
                if label in parser.stats:
                    values.append(f"{label}: {parser.stats[label]}")
            if values:
                print(f"\n   {category}相关:")
                for v in values:
                    print(f"      • {v}")
                    
    # 计算总数
    total = sum(int(v) for v in parser.stats.values() if v.isdigit())
    print(f"\n   📊 总发现数量: {total}")
    
    if parser.results:
        print(f"\n🔍 部分发现结果 (前5个):")
        for i, result in enumerate(parser.results[:5], 1):
            print(f"   {i}. {result}")
            
    print(f"\n💡 使用浏览器打开查看完整报告:")
    print(f"   file://{Path(report_file).absolute()}")
    print(f"{'='*60}\n")


if __name__ == '__main__':
    main()