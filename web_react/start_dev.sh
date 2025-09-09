#!/bin/bash

echo "🚀 启动渗透扫描平台 React 开发服务器"
echo "============================================"

# 检查Node.js版本
if ! command -v node &> /dev/null; then
    echo "❌ 错误: 未找到Node.js，请先安装Node.js 16+"
    exit 1
fi

NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 16 ]; then
    echo "❌ 错误: Node.js版本过低，需要16+，当前版本: $(node -v)"
    exit 1
fi

echo "✅ Node.js版本: $(node -v)"

# 检查npm
if ! command -v npm &> /dev/null; then
    echo "❌ 错误: 未找到npm"
    exit 1
fi

echo "✅ npm版本: $(npm -v)"

# 检查是否已安装依赖
if [ ! -d "node_modules" ]; then
    echo "📦 首次运行，正在安装依赖..."
    npm install
    if [ $? -ne 0 ]; then
        echo "❌ 依赖安装失败"
        exit 1
    fi
    echo "✅ 依赖安装完成"
else
    echo "✅ 依赖已存在"
fi

# 检查后端服务
echo "🔍 检查Python后端API服务状态..."
if curl -s -u admin:MyStr0ngP@ssw0rd! http://localhost:5000/domain/mt5crm.com &> /dev/null; then
    echo "✅ Python后端API服务正常运行 (端口5000)"
else
    echo "⚠️  警告: Python后端API服务未运行，请先启动："
    echo "   运行: cd .. && ./start_production_web.sh"
    echo ""
    echo "📝 说明: React前端需要Python后端提供数据API"
fi

echo ""
echo "🏗️  系统架构说明:"
echo "   📱 React前端 (端口3000) - 用户界面"
echo "   🔄 API代理转发 - /api/* 请求转发到后端"
echo "   🐍 Python后端 (端口5000) - 数据API服务"
echo ""
echo "🌐 启动React开发服务器..."
echo "   - 本地访问: http://localhost:3000"
echo "   - 外网访问: http://139.59.122.117:3000"
echo "   - API代理目标: http://localhost:5000"
echo ""
echo "💡 开发提示:"
echo "   - 修改代码会自动热更新"
echo "   - 按 Ctrl+C 停止服务器"
echo "   - 查看浏览器控制台获取调试信息"
echo ""

# 启动开发服务器
npm run dev
