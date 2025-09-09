#!/bin/bash

# 渗透扫描平台服务监控脚本
# 自动检测和重启崩溃的服务

LOG_FILE="/tmp/service_monitor.log"
REACT_LOG="/tmp/react_monitor.log"
API_LOG="/tmp/api_monitor.log"

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

check_api_service() {
    if ! pgrep -f "gunicorn.*app_api_only" > /dev/null; then
        log_message "❌ API服务已停止，正在重启..."
        cd /opt/info_get/start_game_test
        ./start_api_backend.sh >> "$API_LOG" 2>&1
        sleep 5
        
        if pgrep -f "gunicorn.*app_api_only" > /dev/null; then
            log_message "✅ API服务重启成功"
        else
            log_message "❌ API服务重启失败"
        fi
    else
        # 检查API健康状态
        if curl -s -u admin:MyStr0ngP@ssw0rd! "http://localhost:5000/health" > /dev/null; then
            log_message "✅ API服务正常运行"
        else
            log_message "⚠️ API服务响应异常"
        fi
    fi
}

check_react_service() {
    if ! lsof -i:3000 > /dev/null 2>&1; then
        log_message "❌ React前端已停止，正在重启..."
        cd /opt/info_get/start_game_test/web_react
        
        # 清理旧进程
        pkill -f "node.*vite" 2>/dev/null
        sleep 2
        
        # 重启React服务
        nohup npm run dev > "$REACT_LOG" 2>&1 &
        sleep 10
        
        if lsof -i:3000 > /dev/null 2>&1; then
            log_message "✅ React前端重启成功"
        else
            log_message "❌ React前端重启失败，检查日志: $REACT_LOG"
        fi
    else
        # 检查前端健康状态
        if curl -s "http://localhost:3000" > /dev/null; then
            log_message "✅ React前端正常运行"
        else
            log_message "⚠️ React前端响应异常"
        fi
    fi
}

check_system_resources() {
    # 检查内存使用率
    MEMORY_USAGE=$(free | grep Mem | awk '{printf("%.1f", $3/$2 * 100.0)}')
    log_message "📊 内存使用率: ${MEMORY_USAGE}%"
    
    # 检查磁盘使用率
    DISK_USAGE=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
    log_message "💾 磁盘使用率: ${DISK_USAGE}%"
    
    # 警告阈值
    if (( $(echo "$MEMORY_USAGE > 90" | bc -l) )); then
        log_message "⚠️ 内存使用率过高: ${MEMORY_USAGE}%"
    fi
    
    if (( DISK_USAGE > 90 )); then
        log_message "⚠️ 磁盘使用率过高: ${DISK_USAGE}%"
    fi
}

main() {
    log_message "🔍 开始服务监控检查..."
    
    check_api_service
    check_react_service
    check_system_resources
    
    log_message "✅ 监控检查完成"
    echo "----------------------------------------" >> "$LOG_FILE"
}

# 如果作为脚本直接运行
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
