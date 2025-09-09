#!/usr/bin/env python3
"""
从fscan结果中提取URL
"""
import re
import sys
from pathlib import Path

def extract_urls_from_fscan(fscan_result_file):
    """从fscan结果文件中提取URL"""
    urls = set()
    
    if not Path(fscan_result_file).exists():
        return urls
    
    with open(fscan_result_file, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    # 匹配 [*] WebTitle http://... 或 https://... 的行
    pattern = r'\[\*\]\s*WebTitle\s+(https?://[^\s]+)'
    matches = re.findall(pattern, content)
    
    for url in matches:
        # 清理URL，移除末尾可能的空格或特殊字符
        url = url.strip()
        urls.add(url)
    
    return urls

def main():
    if len(sys.argv) < 2:
        print("Usage: extract_fscan_urls.py <fscan_result.txt> [output_file]")
        sys.exit(1)
    
    fscan_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    urls = extract_urls_from_fscan(fscan_file)
    
    if output_file:
        with open(output_file, 'w') as f:
            for url in sorted(urls):
                f.write(f"{url}\n")
        print(f"提取到 {len(urls)} 个URL，已保存到 {output_file}")
    else:
        for url in sorted(urls):
            print(url)

if __name__ == "__main__":
    main()