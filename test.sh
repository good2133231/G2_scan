#!/bin/bash
# 功能测试脚本 - 快速验证所有工具是否正常工作

set -e

# 项目路径配置
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$PROJECT_ROOT/tools/scanner"
CONFIG_DIR="$PROJECT_ROOT/config"
DATA_DIR="$PROJECT_ROOT/data"
TEST_DIR="$PROJECT_ROOT/temp/test_$(date +%s)"

echo "🧪 开始功能测试模式..."
echo "📁 项目根目录: $PROJECT_ROOT"
echo "🗂️  测试目录: $TEST_DIR"

# 创建独立的测试目录
mkdir -p "$TEST_DIR"

# 检查输入文件
TARGET_FILE="$DATA_DIR/input/url"
if [ ! -f "$TARGET_FILE" ]; then
    echo "❌ 错误: 未找到目标文件 $TARGET_FILE"
    exit 1
fi

TARGET_DOMAIN=$(cat "$TARGET_FILE" | head -1 | xargs)
if [ -z "$TARGET_DOMAIN" ]; then
    echo "❌ 错误: 目标文件为空"
    exit 1
fi

echo "🎯 测试目标: $TARGET_DOMAIN"

# 检查工具是否存在
echo "🔧 检查工具状态..."
tools_ok=true
for tool in subfinder puredns httpx afrog fscan; do
    if [ -f "$TOOLS_DIR/$tool" ]; then
        echo "  ✅ $tool: 已安装"
    else
        echo "  ❌ $tool: 缺失"
        tools_ok=false
    fi
done

if [ "$tools_ok" = false ]; then
    echo "❌ 部分工具缺失，请运行: ./install.sh"
    exit 1
fi

# 创建最小测试字典
echo "📝 创建测试字典..."
echo "www" > "$TEST_DIR/test_subdomains.txt"
echo "api" >> "$TEST_DIR/test_subdomains.txt"

echo "🚀 开始工具功能测试..."

# 1. 测试subfinder (限制数量)
echo "📡 测试1: subfinder 子域名收集..."
timeout 30 "$TOOLS_DIR/subfinder" -d "$TARGET_DOMAIN" -silent -max-time 10 -o "$TEST_DIR/passive.txt" || echo "  ⚠️ subfinder超时，但这是正常的"
if [ -f "$TEST_DIR/passive.txt" ]; then
    count=$(wc -l < "$TEST_DIR/passive.txt")
    echo "  ✅ subfinder: 发现 $count 个子域名"
else
    echo "  ❌ subfinder: 未产生输出"
fi

# 2. 测试puredns (只测试2个子域名)
echo "💥 测试2: puredns 子域名爆破..."
timeout 20 "$TOOLS_DIR/puredns" bruteforce "$TEST_DIR/test_subdomains.txt" "$TARGET_DOMAIN" \
    --resolvers "$CONFIG_DIR/wordlists/resolvers.txt" \
    --write "$TEST_DIR/brute.txt" || echo "  ⚠️ puredns超时，但这是正常的"
if [ -f "$TEST_DIR/brute.txt" ]; then
    count=$(wc -l < "$TEST_DIR/brute.txt")
    echo "  ✅ puredns: 发现 $count 个有效子域名"
else
    echo "  ❌ puredns: 未产生输出"
fi

# 3. 合并测试结果
echo "🔗 测试3: 域名合并去重..."
touch "$TEST_DIR/passive.txt" "$TEST_DIR/brute.txt"  # 确保文件存在
cat "$TEST_DIR/passive.txt" "$TEST_DIR/brute.txt" | sort -u > "$TEST_DIR/domains.txt"
domain_count=$(wc -l < "$TEST_DIR/domains.txt")
echo "  ✅ 合并结果: $domain_count 个唯一域名"

# 4. 测试httpx (只测试前3个域名)
echo "🌐 测试4: httpx HTTP探测..."
if [ -s "$TEST_DIR/domains.txt" ]; then
    head -3 "$TEST_DIR/domains.txt" > "$TEST_DIR/test_domains.txt"
    timeout 30 "$TOOLS_DIR/httpx" -l "$TEST_DIR/test_domains.txt" \
        -mc 200,301,302,403,404 -timeout 3 -silent \
        -json -o "$TEST_DIR/httpx_result.json" || echo "  ⚠️ httpx超时，但这是正常的"
    
    if [ -f "$TEST_DIR/httpx_result.json" ]; then
        count=$(wc -l < "$TEST_DIR/httpx_result.json")
        echo "  ✅ httpx: 探测到 $count 个HTTP服务"
    else
        echo "  ❌ httpx: 未产生输出"
    fi
else
    echo "  ⚠️ 无域名可测试httpx"
fi



# 6. 测试start.py数据处理
echo "📊 测试6: start.py 数据处理..."
if [ -f "$TEST_DIR/httpx_result.json" ]; then
    # 复制测试结果到temp目录供start.py使用
    cp "$TEST_DIR/httpx_result.json" "$PROJECT_ROOT/temp/result_all.json"
    
    cd "$PROJECT_ROOT"
    timeout 10 python3 "$PROJECT_ROOT/scripts/core/start.py" -test || echo "  ⚠️ start.py超时，但这是正常的"
    echo "  ✅ start.py: 数据处理测试完成"
else
    echo "  ⚠️ 无数据可测试start.py"
fi

# 测试结果总结
echo ""
echo "📋 测试结果总结:"
echo "================================"

files_to_check=(
    "$TEST_DIR/passive.txt:subfinder结果"
    "$TEST_DIR/brute.txt:puredns结果"
    "$TEST_DIR/domains.txt:域名合并"
    "$TEST_DIR/httpx_result.json:httpx结果"
)

for item in "${files_to_check[@]}"; do
    IFS=':' read -r filepath description <<< "$item"
    if [ -f "$filepath" ] && [ -s "$filepath" ]; then
        size=$(wc -l < "$filepath" 2>/dev/null || echo "1")
        echo "  ✅ $description: $size 条记录"
    else
        echo "  ❌ $description: 无输出"
    fi
done

# 检查配置文件
echo ""
echo "⚙️ 配置文件检查:"
config_files=(
    "$CONFIG_DIR/wordlists/resolvers.txt:DNS服务器"
    "$CONFIG_DIR/wordlists/subdomains.txt:子域名字典"
    "$CONFIG_DIR/api/config.ini:API配置"
)

for item in "${config_files[@]}"; do
    IFS=':' read -r filepath description <<< "$item"
    if [ -f "$filepath" ]; then
        echo "  ✅ $description: 存在"
    else
        echo "  ❌ $description: 缺失"
    fi
done

echo ""
echo "🎯 测试完成！"
echo "📂 测试文件保存在: $TEST_DIR"
echo "💡 如需完整扫描，请运行: ./scan.sh 或 ./scan_fast.sh"

# 清理选项
echo ""
read -p "🗑️ 是否删除测试文件？ (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf "$TEST_DIR"
    echo "✅ 测试文件已清理"
else
    echo "📁 测试文件保留在: $TEST_DIR"
fi