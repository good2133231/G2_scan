#!/bin/bash
# 重启扫描脚本 - 修复了DNS反查阻塞问题

# 找到项目根目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"

# 向上查找包含scan.sh的目录
while [[ ! -f "$PROJECT_ROOT/scan.sh" && "$PROJECT_ROOT" != "/" ]]; do
    PROJECT_ROOT="$(dirname "$PROJECT_ROOT")"
done

if [[ ! -f "$PROJECT_ROOT/scan.sh" ]]; then
    echo "❌ 无法找到scan.sh，当前目录: $SCRIPT_DIR"
    exit 1
fi

echo "✅ 找到项目根目录: $PROJECT_ROOT"

# 切换到项目根目录
cd "$PROJECT_ROOT"

# 清理可能的阻塞进程
echo "🧹 清理可能的阻塞进程..."
pkill -f "python3.*start.py" || true
pkill -f "httpx" || true
pkill -f "rapiddns" || true

# 清理临时文件
echo "🧹 清理临时文件..."
rm -f temp/*.txt temp/*.json 2>/dev/null || true

# 确保目标文件存在
echo "vtmarkets.com" > data/input/url

# 显示修复状态
echo "🔧 IP反查功能修复完成:"
echo "   ✅ 保留完整的IP反查功能"
echo "   ✅ 添加了RapidDns线程池执行，避免阻塞"
echo "   ✅ 增加了多层超时机制 (15秒/45秒/8分钟)"
echo "   ✅ 分批处理IP，避免过载"
echo "   ✅ 添加了进度显示和详细日志"
echo "   ✅ 三种反查方式: dnsdblookup -> RapidDns -> ip138"

echo ""
echo "🚀 重新启动扫描..."
echo "💡 建议使用: screen -S scan ./restart_scan.sh"
echo "📊 扫描过程中会显示详细的反查进度"
echo ""

# 启动扫描
exec ./scan.sh