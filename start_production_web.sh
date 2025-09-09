#!/bin/bash

echo "🚀 启动生产级Web服务 (Gunicorn) - 解决CONNECTION_RESET问题"
echo "============================================================"

# 停止可能还在运行的Flask开发服务器
pkill -f "python3.*app_simple" 2>/dev/null
pkill -f "gunicorn" 2>/dev/null
sleep 2

# 切换到项目目录
cd /opt/info_get/start_game_test

# 创建日志目录
mkdir -p logs

# 启动Gunicorn生产服务器
echo "正在启动Gunicorn服务器..."

# Gunicorn配置参数说明:
# --bind 0.0.0.0:5000        - 绑定所有网络接口的5000端口
# --workers 4                - 4个工作进程（根据CPU核心数调整）
# --threads 2                - 每个工作进程2个线程
# --worker-class sync        - 使用同步工作类（稳定）
# --worker-connections 1000  - 每个工作进程的最大连接数
# --max-requests 1000        - 每个工作进程处理1000请求后重启（防内存泄漏）
# --max-requests-jitter 100  - 添加随机性避免同时重启
# --keepalive 5              - HTTP keep-alive连接超时时间
# --timeout 120              - 工作进程超时时间
# --graceful-timeout 30      - 优雅关闭超时时间
# --preload                  - 预加载应用（提高性能）
# --access-logfile           - 访问日志文件
# --error-logfile            - 错误日志文件
# --log-level info           - 日志级别
# --daemon                   - 后台运行

gunicorn \
    --bind 0.0.0.0:5000 \
    --workers 6 \
    --threads 4 \
    --worker-class gthread \
    --worker-connections 2000 \
    --max-requests 2000 \
    --max-requests-jitter 200 \
    --keep-alive 10 \
    --timeout 60 \
    --graceful-timeout 15 \
    --preload \
    --access-logfile logs/gunicorn_access.log \
    --error-logfile logs/gunicorn_error.log \
    --log-level info \
    --daemon \
    wsgi:application

# 检查服务启动状态
sleep 3
gunicorn_pid=$(ps aux | grep "gunicorn.*wsgi:application" | grep -v grep | head -1 | awk '{print $2}')

if [ -n "$gunicorn_pid" ]; then
    echo "✅ Gunicorn服务启动成功!"
    echo "📋 服务信息:"
    echo "   - PID: $gunicorn_pid"
    echo "   - 地址: http://0.0.0.0:5000"
    echo "   - 公网: http://139.59.122.117:5000"
    echo "   - 工作进程: 6个 (优化浏览器并发)"
    echo "   - 线程数: 每进程4个 (gthread类型)"
    echo "   - Keep-alive: 10秒 (浏览器友好)"
    echo ""
    
    echo "📊 进程状态:"
    ps aux | grep "gunicorn.*wsgi" | grep -v grep
    
    echo ""
    echo "📋 日志文件:"
    echo "   - 访问日志: logs/gunicorn_access.log"
    echo "   - 错误日志: logs/gunicorn_error.log"
    
    echo ""
    echo "🎯 优势:"
    echo "   ✅ 解决CONNECTION_RESET问题"
    echo "   ✅ 支持并发连接"
    echo "   ✅ 生产级稳定性"
    echo "   ✅ HTTP Keep-alive支持"
    echo "   ✅ 自动进程管理"
    
    echo ""
    echo "🔧 管理命令:"
    echo "   查看状态: ps aux | grep gunicorn"
    echo "   停止服务: pkill -f gunicorn"
    echo "   重启服务: ./start_production_web.sh"
    
else
    echo "❌ Gunicorn服务启动失败"
    echo "📋 检查错误日志:"
    tail -20 logs/gunicorn_error.log 2>/dev/null || echo "无错误日志"
    exit 1
fi

echo ""
echo "🌐 服务已启动，请访问: http://139.59.122.117:5000"
echo "💡 CONNECTION_RESET问题应该已彻底解决！"
