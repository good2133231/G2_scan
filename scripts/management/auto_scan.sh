#!/bin/bash
# 自动化多代扫描脚本

TARGET_DOMAIN="${1:-grandmarkets.com}"
MAX_GENERATIONS="${2:-3}"

echo "🚀 开始自动化多代扫描"
echo "🎯 目标域名: $TARGET_DOMAIN"
echo "🔢 最大代数: $MAX_GENERATIONS"

# 第一代扫描
echo "📍 执行第一代扫描..."
echo "$TARGET_DOMAIN" > url
./go.sh

# 循环执行后续代数
for ((gen=1; gen<=MAX_GENERATIONS; gen++)); do
    echo ""
    echo "📍 准备第 $((gen+1)) 代扫描..."
    
    # 检查是否有扩展结果
    if ! python tuozhan_manager.py discover | grep -q "$TARGET_DOMAIN"; then
        echo "❌ 未发现 $TARGET_DOMAIN 的扩展结果，停止扫描"
        break
    fi
    
    # 准备扫描
    if python tuozhan_manager.py prepare "$TARGET_DOMAIN" > /dev/null; then
        echo "✅ 第 $((gen+1)) 代扫描结构已创建"
        
        # 执行扫描
        LATEST_GEN=$(ls -td generations/$TARGET_DOMAIN/gen_* | head -1)
        echo "🔍 执行扫描: $LATEST_GEN"
        
        cd "$LATEST_GEN"
        timeout 3600 ./scripts/scan_all.sh || echo "⚠️ 扫描超时或失败"
        cd - > /dev/null
        
        echo "✅ 第 $((gen+1)) 代扫描完成"
    else
        echo "❌ 第 $((gen+1)) 代扫描准备失败"
        break
    fi
    
    sleep 10  # 避免过于频繁
done

echo ""
echo "🎉 自动化扫描完成！"
echo "📊 查看结果: ls -la generations/$TARGET_DOMAIN/"