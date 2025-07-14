#!/bin/bash
# 主扫描入口脚本

set -e

# 项目路径配置
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$PROJECT_ROOT/tools/scanner"
CONFIG_DIR="$PROJECT_ROOT/config"
DATA_DIR="$PROJECT_ROOT/data"
OUTPUT_DIR="$PROJECT_ROOT/output"
SCRIPTS_DIR="$PROJECT_ROOT/scripts"
TEMP_DIR="$PROJECT_ROOT/temp"

# 确保所有目录存在
mkdir -p "$OUTPUT_DIR"/{domains,reports,generations,logs}
mkdir -p "$TEMP_DIR"
mkdir -p "$DATA_DIR/input"

# 检查输入文件
TARGET_FILE="$DATA_DIR/input/url"
if [ ! -f "$TARGET_FILE" ]; then
    echo "❌ 错误: 未找到目标文件 $TARGET_FILE"
    echo "请创建该文件并填入目标域名"
    exit 1
fi

TARGET_DOMAIN=$(cat "$TARGET_FILE" | head -1 | xargs)
if [ -z "$TARGET_DOMAIN" ]; then
    echo "❌ 错误: 目标文件为空"
    exit 1
fi

echo "🎯 目标域名: $TARGET_DOMAIN"
echo "📁 项目根目录: $PROJECT_ROOT"

# 检查工具是否存在
for tool in subfinder puredns httpx; do
    if [ ! -f "$TOOLS_DIR/$tool" ]; then
        echo "❌ 错误: 工具 $tool 不存在，请先运行安装脚本"
        exit 1
    fi
done

# 执行扫描流程
echo "🚀 开始扫描流程..."

# 1. 子域名收集
echo "📡 步骤1: 子域名收集..."
"$TOOLS_DIR/subfinder" -dL "$TARGET_FILE" -all -o "$TEMP_DIR/passive.txt"

# 2. 子域名爆破
echo "💥 步骤2: 子域名爆破..."
"$TOOLS_DIR/puredns" bruteforce "$CONFIG_DIR/wordlists/subdomains.txt" "$TARGET_DOMAIN" \
    --resolvers "$CONFIG_DIR/wordlists/resolvers.txt" \
    --write "$TEMP_DIR/brute.txt"

# 3. 合并去重
echo "🔗 步骤3: 合并去重..."
cat "$TEMP_DIR/passive.txt" "$TEMP_DIR/brute.txt" | sort -u > "$TEMP_DIR/domain_life"

# 4. 域名解析验证
echo "🔍 步骤4: 域名解析验证..."
"$TOOLS_DIR/puredns" resolve "$TEMP_DIR/domain_life" \
    --resolvers "$CONFIG_DIR/wordlists/resolvers.txt" \
    --wildcard-tests 50 --wildcard-batch 1000000 \
    --write "$TEMP_DIR/httpx_url"

# 5. HTTP探测
echo "🌐 步骤5: HTTP探测..."
"$TOOLS_DIR/httpx" -l "$TEMP_DIR/httpx_url" \
    -mc 200,301,302,403,404 -timeout 2 \
    -favicon -hash md5,mmh3 -retries 1 -t 300 -rl 1000000 \
    -resume -extract-fqdn -tls-grab -json \
    -o "$TEMP_DIR/result_all.json"

# 6. 数据处理和分析
echo "📊 步骤6: 数据处理和分析..."
cd "$PROJECT_ROOT"
python3 "$SCRIPTS_DIR/core/start.py"

echo "✅ 扫描完成！"
echo "📂 查看结果: ls -la $OUTPUT_DIR/"
