#!/bin/bash

echo "🚀 启动渗透扫描平台 - 纯API后端"
echo "=================================="

# 停止旧的Web服务
echo "🛑 停止旧的Web界面服务..."
pkill -f "gunicorn.*wsgi:application" 2>/dev/null || true
pkill -f "python.*app_simple.py" 2>/dev/null || true

sleep 2

# 检查端口是否释放
if lsof -i:5000 >/dev/null 2>&1; then
    echo "⚠️  端口5000仍被占用，强制清理..."
    fuser -k 5000/tcp 2>/dev/null || true
    sleep 2
fi

# 检查Gunicorn是否安装
if ! command -v gunicorn &> /dev/null; then
    echo "📦 安装Gunicorn生产服务器..."
    pip3 install gunicorn
fi

# 启动生产级API后端
echo "🐍 启动Gunicorn生产级API服务..."
cd web
gunicorn -w 3 \
    -b 0.0.0.0:5000 \
    --timeout 120 \
    --keep-alive 2 \
    --max-requests 1000 \
    --max-requests-jitter 50 \
    --access-logfile /tmp/api_access.log \
    --error-logfile /tmp/api_error.log \
    --log-level info \
    --daemon \
    app_api_only:app

# 等待服务启动
sleep 3

# 检查服务状态
if curl -s http://localhost:5000/health >/dev/null 2>&1; then
    echo "✅ API后端服务启动成功!"
    echo ""
    echo "📋 服务信息:"
    echo "   - API地址: http://0.0.0.0:5000"
    echo "   - 健康检查: http://localhost:5000/health"
    echo "   - 认证: admin/MyStr0ngP@ssw0rd!"
    echo ""
    echo "🔗 API端点:"
    echo "   GET  /health                    - 健康检查"
    echo "   GET  /domain/<domain>           - 获取域名数据"
    echo "   GET  /scan_status/<domain>      - 获取扫描状态"
    echo "   GET  /logs/<domain>             - 获取日志"
    echo "   GET  /raw_data/<domain>         - 获取原始数据"
    echo "   POST /start_scan                - 启动扫描"
    echo "   POST /stop_scan                 - 停止扫描"
    echo ""
    echo "💡 测试API:"
    echo "   curl -u admin:MyStr0ngP@ssw0rd! http://localhost:5000/health"
    echo ""
    echo "🎯 下一步: 启动React前端"
    echo "   cd web_react && ./start_dev.sh"
else
    echo "❌ API后端服务启动失败"
    exit 1
fi
