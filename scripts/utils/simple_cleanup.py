#!/usr/bin/env python3
"""
简化版清理脚本 - 适配v2.1简化结构
"""

import os
import shutil
from pathlib import Path
import argparse
from datetime import datetime

class SimpleCleanup:
    def __init__(self, project_root="."):
        self.project_root = Path(project_root)
        
    def cleanup_temp_files(self, dry_run=False):
        """清理临时文件"""
        temp_dir = self.project_root / "temp"
        removed_count = 0
        
        if temp_dir.exists():
            for file_path in temp_dir.iterdir():
                if file_path.is_file():
                    if not dry_run:
                        file_path.unlink()
                    print(f"{'[预览]' if dry_run else '[删除]'} 临时文件: {file_path}")
                    removed_count += 1
        
        return removed_count
    
    def cleanup_target_results(self, target_name, dry_run=False):
        """清理特定目标的扫描结果"""
        removed_items = []
        
        # 一层扫描结果
        main_result = self.project_root / "output" / target_name
        if main_result.exists():
            if not dry_run:
                shutil.rmtree(main_result)
            print(f"{'[预览]' if dry_run else '[删除]'} 一层结果: {main_result}")
            removed_items.append(main_result)
        
        # 二层扫描结果
        expansion_result = self.project_root / "output" / "expansions" / target_name
        if expansion_result.exists():
            if not dry_run:
                shutil.rmtree(expansion_result)
            print(f"{'[预览]' if dry_run else '[删除]'} 二层结果: {expansion_result}")
            removed_items.append(expansion_result)
        
        return removed_items
    
    def cleanup_old_results(self, days=7, dry_run=False):
        """清理N天前的结果"""
        from datetime import timedelta
        cutoff_time = datetime.now() - timedelta(days=days)
        removed_count = 0
        
        # 检查一层结果
        output_dir = self.project_root / "output"
        if output_dir.exists():
            for target_dir in output_dir.iterdir():
                if target_dir.is_dir() and target_dir.name != "expansions":
                    mod_time = datetime.fromtimestamp(target_dir.stat().st_mtime)
                    if mod_time < cutoff_time:
                        if not dry_run:
                            shutil.rmtree(target_dir)
                        print(f"{'[预览]' if dry_run else '[删除]'} 旧结果: {target_dir}")
                        removed_count += 1
        
        # 检查二层结果
        expansions_dir = output_dir / "expansions"
        if expansions_dir.exists():
            for target_dir in expansions_dir.iterdir():
                if target_dir.is_dir():
                    mod_time = datetime.fromtimestamp(target_dir.stat().st_mtime)
                    if mod_time < cutoff_time:
                        if not dry_run:
                            shutil.rmtree(target_dir)
                        print(f"{'[预览]' if dry_run else '[删除]'} 旧扩展: {target_dir}")
                        removed_count += 1
        
        return removed_count
    
    def show_project_status(self):
        """显示项目状态"""
        print("📊 项目状态")
        print("=" * 40)
        
        # 检查核心文件
        core_files = [
            ("scan.sh", "一层主扫描脚本"),
            ("expand.sh", "二层扩展脚本"),
            ("scripts/core/start.py", "数据处理核心"),
            ("config/subdomains.txt", "子域名字典"),
            ("config/resolvers.txt", "DNS解析器"),
            ("tools/scanner/subfinder", "子域名收集工具"),
            ("tools/scanner/httpx", "HTTP探测工具"),
            ("tools/scanner/afrog", "漏洞扫描工具"),
            ("tools/scanner/fscan", "端口扫描工具"),
        ]
        
        print("\n📁 核心文件:")
        for file_path, description in core_files:
            full_path = self.project_root / file_path
            status = "✅" if full_path.exists() else "❌"
            print(f"  {status} {description}: {file_path}")
        
        # 统计扫描结果
        output_dir = self.project_root / "output"
        main_count = 0
        expansion_count = 0
        
        if output_dir.exists():
            # 一层结果
            for item in output_dir.iterdir():
                if item.is_dir() and item.name != "expansions":
                    main_count += 1
            
            # 二层结果
            expansions_dir = output_dir / "expansions"
            if expansions_dir.exists():
                for item in expansions_dir.iterdir():
                    if item.is_dir():
                        expansion_count += 1
        
        print(f"\n📊 扫描结果:")
        print(f"  一层扫描: {main_count} 个目标")
        print(f"  二层扩展: {expansion_count} 个目标")
        
        # 临时文件统计
        temp_dir = self.project_root / "temp"
        temp_count = 0
        if temp_dir.exists():
            temp_count = len([f for f in temp_dir.iterdir() if f.is_file()])
        print(f"  临时文件: {temp_count} 个")

def main():
    parser = argparse.ArgumentParser(description="简化版清理工具")
    parser.add_argument("--project-root", default=".", help="项目根目录")
    
    subparsers = parser.add_subparsers(dest='command', help='可用命令')
    
    # 状态查看
    subparsers.add_parser('status', help='显示项目状态')
    
    # 清理临时文件
    temp_parser = subparsers.add_parser('temp', help='清理临时文件')
    temp_parser.add_argument('--dry-run', action='store_true', help='预览模式')
    
    # 清理目标结果
    target_parser = subparsers.add_parser('target', help='清理特定目标')
    target_parser.add_argument('target_name', help='目标名称')
    target_parser.add_argument('--dry-run', action='store_true', help='预览模式')
    
    # 清理旧结果
    old_parser = subparsers.add_parser('old', help='清理旧结果')
    old_parser.add_argument('days', type=int, help='清理N天前的结果')
    old_parser.add_argument('--dry-run', action='store_true', help='预览模式')
    
    args = parser.parse_args()
    cleanup = SimpleCleanup(args.project_root)
    
    if args.command == 'status':
        cleanup.show_project_status()
    elif args.command == 'temp':
        count = cleanup.cleanup_temp_files(args.dry_run)
        print(f"\n清理完成: {count} 个临时文件")
    elif args.command == 'target':
        items = cleanup.cleanup_target_results(args.target_name, args.dry_run)
        print(f"\n清理完成: {len(items)} 个目标结果")
    elif args.command == 'old':
        count = cleanup.cleanup_old_results(args.days, args.dry_run)
        print(f"\n清理完成: {count} 个旧结果")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()