#!/bin/bash

# 渗透扫描平台 - 服务健康监控脚本
# 用于监控前端和后端服务状态，自动重启异常服务

LOG_FILE="/tmp/health_monitor.log"
API_URL="http://localhost:5000/health"
FRONTEND_URL="http://localhost:3000"
API_AUTH="admin:MyStr0ngP@ssw0rd!"

# 日志函数
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# 检查API服务
check_api() {
    log "🔍 检查API服务..."
    
    # 检查进程
    API_PROCESSES=$(ps aux | grep -E "gunicorn.*app_api_only" | grep -v grep | wc -l)
    if [ "$API_PROCESSES" -eq 0 ]; then
        log "❌ API进程未运行，尝试重启..."
        cd /opt/info_get/start_game_test
        ./start_api_backend.sh >> "$LOG_FILE" 2>&1
        sleep 5
        return 1
    fi
    
    # 检查HTTP响应
    HTTP_STATUS=$(curl -s -u "$API_AUTH" -o /dev/null -w "%{http_code}" "$API_URL" 2>/dev/null)
    if [ "$HTTP_STATUS" != "200" ]; then
        log "❌ API服务响应异常 (HTTP $HTTP_STATUS)，尝试重启..."
        pkill -f "gunicorn.*app_api_only"
        sleep 3
        cd /opt/info_get/start_game_test
        ./start_api_backend.sh >> "$LOG_FILE" 2>&1
        sleep 5
        return 1
    fi
    
    log "✅ API服务正常 ($API_PROCESSES 个进程)"
    return 0
}

# 检查前端服务
check_frontend() {
    log "🔍 检查前端服务..."
    
    # 检查Vite进程
    VITE_PROCESSES=$(ps aux | grep -E "node.*vite" | grep -v grep | wc -l)
    if [ "$VITE_PROCESSES" -eq 0 ]; then
        log "❌ 前端进程未运行，尝试重启..."
        cd /opt/info_get/start_game_test/web_react
        nohup npm run dev > /tmp/react_new.log 2>&1 &
        sleep 10
        return 1
    fi
    
    # 检查端口监听
    PORT_LISTENING=$(lsof -i:3000 2>/dev/null | grep LISTEN | wc -l)
    if [ "$PORT_LISTENING" -eq 0 ]; then
        log "❌ 前端端口3000未监听，尝试重启..."
        pkill -f "node.*vite"
        sleep 3
        cd /opt/info_get/start_game_test/web_react
        nohup npm run dev > /tmp/react_new.log 2>&1 &
        sleep 10
        return 1
    fi
    
    log "✅ 前端服务正常 ($VITE_PROCESSES 个进程)"
    return 0
}

# 检查系统资源
check_resources() {
    log "🔍 检查系统资源..."
    
    # 内存使用率
    MEMORY_USAGE=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
    log "📊 内存使用率: ${MEMORY_USAGE}%"
    
    # 磁盘使用率
    DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    log "💾 磁盘使用率: ${DISK_USAGE}%"
    
    # CPU负载
    LOAD_AVG=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    log "⚡ CPU负载: $LOAD_AVG"
    
    # 警告检查
    if (( $(echo "$MEMORY_USAGE > 90" | bc -l) )); then
        log "⚠️  内存使用率过高: ${MEMORY_USAGE}%"
    fi
    
    if [ "$DISK_USAGE" -gt 90 ]; then
        log "⚠️  磁盘使用率过高: ${DISK_USAGE}%"
    fi
}

# 主监控循环
main() {
    log "🚀 启动服务健康监控..."
    log "📋 监控目标:"
    log "   - API服务: $API_URL"
    log "   - 前端服务: $FRONTEND_URL"
    log "   - 系统资源监控"
    log ""
    
    while true; do
        log "=== 健康检查开始 ==="
        
        # 检查服务
        check_api
        API_STATUS=$?
        
        check_frontend  
        FRONTEND_STATUS=$?
        
        check_resources
        
        # 总结状态
        if [ $API_STATUS -eq 0 ] && [ $FRONTEND_STATUS -eq 0 ]; then
            log "🎉 所有服务运行正常"
        else
            log "⚠️  部分服务需要关注"
        fi
        
        log "=== 健康检查完成 ==="
        log ""
        
        # 等待下次检查
        sleep 60
    done
}

# 脚本入口
case "$1" in
    "start")
        main
        ;;
    "check")
        log "🔍 执行一次性健康检查..."
        check_api
        check_frontend
        check_resources
        log "✅ 检查完成"
        ;;
    "status")
        echo "=== 服务状态 ==="
        echo "API进程数: $(ps aux | grep -E "gunicorn.*app_api_only" | grep -v grep | wc -l)"
        echo "前端进程数: $(ps aux | grep -E "node.*vite" | grep -v grep | wc -l)"
        echo "API端口: $(lsof -i:5000 2>/dev/null | grep LISTEN | wc -l) 个监听"
        echo "前端端口: $(lsof -i:3000 2>/dev/null | grep LISTEN | wc -l) 个监听"
        ;;
    *)
        echo "用法: $0 {start|check|status}"
        echo "  start  - 启动持续监控"
        echo "  check  - 执行一次检查"
        echo "  status - 显示服务状态"
        exit 1
        ;;
esac
