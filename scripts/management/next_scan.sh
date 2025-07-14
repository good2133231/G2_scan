#!/bin/bash
# 下一代扫描快捷脚本

set -e

# 配置
SOURCE_DOMAIN="${1:-grandmarkets.com}"
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🔍 为 $SOURCE_DOMAIN 准备下一代扫描..."

# 发现可用的tuozhan结果
echo "📊 发现扩展结果..."
python3 "$BASE_DIR/tuozhan_manager.py" discover

# 准备扫描结构
echo "🏗️  准备扫描结构..."
SCAN_STRUCTURE=$(python3 "$BASE_DIR/tuozhan_manager.py" prepare "$SOURCE_DOMAIN")

if [ $? -eq 0 ]; then
    echo "✅ 扫描结构创建成功"
    echo "📋 使用说明:"
    echo "   1. 查看生成的目录: ls -la generations/$SOURCE_DOMAIN/"
    echo "   2. 进入最新的扫描目录"
    echo "   3. 运行: ./scripts/scan_all.sh"
    echo ""
    echo "🚀 快速开始:"
    echo "   cd \$(ls -td generations/$SOURCE_DOMAIN/gen_* | head -1)"
    echo "   ./scripts/scan_all.sh"
else
    echo "❌ 扫描结构创建失败"
    exit 1
fi