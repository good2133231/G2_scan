#!/bin/bash
# 清理测试数据脚本

echo "🧹 清理测试数据..."

# 清理output目录
if [ -d "output/vtmarkets.com" ]; then
    echo "   删除 output/vtmarkets.com/"
    rm -rf output/vtmarkets.com
fi

# 清理reports目录
if [ -f "reports/vtmarkets.com_unified_report.html" ]; then
    echo "   删除报告文件"
    rm -f reports/vtmarkets.com_*.html
fi

# 清理temp目录
if [ -f "temp/result_all.json" ]; then
    echo "   删除 temp/result_all.json"
    rm -f temp/result_all.json
fi

# 清理日志
if [ -d "temp/log" ]; then
    echo "   清理日志文件"
    rm -rf temp/log/*
fi

echo "✅ 清理完成！"
echo ""
echo "📝 提示："
echo "   - 使用 ./create_test_data.sh 创建新的测试数据"
echo "   - 使用 ./generate_report.sh 生成报告"