#!/bin/bash
# 基于配置文件启动Web报告系统

set -e

# 设置颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 项目根目录
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo -e "${BLUE}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     🎯 渗透扫描平台 - Web展示系统 🎯         ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# 检查配置文件
CONFIG_FILE="config/web_config.yaml"
if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}❌ 配置文件不存在: $CONFIG_FILE${NC}"
    echo -e "${YELLOW}请确保配置文件存在${NC}"
    exit 1
fi

echo -e "${GREEN}✅ 找到配置文件: $CONFIG_FILE${NC}"

# 检查Python环境
echo -e "${BLUE}🔍 检查环境...${NC}"

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python3 未安装${NC}"
    exit 1
fi

# 安装依赖
echo -e "${BLUE}📦 检查并安装依赖...${NC}"

# 检查并安装所需包
PACKAGES=("flask" "flask-cors" "flask-httpauth" "pyyaml")
for package in "${PACKAGES[@]}"; do
    if ! python3 -c "import ${package//-/_}" 2>/dev/null; then
        echo -e "${YELLOW}正在安装 $package...${NC}"
        pip3 install $package
    fi
done

# 检查output目录
if [ ! -d "output" ]; then
    echo -e "${YELLOW}⚠️  output目录不存在，请先运行扫描${NC}"
    echo -e "${YELLOW}   使用 ./scan.sh 运行扫描${NC}"
    exit 1
fi

# 从配置文件读取端口
PORT=$(python3 -c "import yaml; print(yaml.safe_load(open('$CONFIG_FILE'))['server']['port'])")
AUTH_ENABLED=$(python3 -c "import yaml; print(yaml.safe_load(open('$CONFIG_FILE'))['auth']['enabled'])")
USERNAME=$(python3 -c "import yaml; print(yaml.safe_load(open('$CONFIG_FILE'))['auth']['username'])")

# 统计扫描结果
DOMAIN_COUNT=$(find output -maxdepth 1 -type d -name "*.*" | wc -l)
echo -e "${GREEN}✅ 发现 ${DOMAIN_COUNT} 个域名的扫描结果${NC}"

# 获取公网IP
echo -e "${BLUE}🌐 获取服务器信息...${NC}"
PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || echo "未知")

# 清理旧进程
echo -e "${BLUE}🧹 清理旧进程...${NC}"
pkill -f "web_report_config.py" 2>/dev/null || true

# 创建日志目录
LOG_DIR=$(python3 -c "import yaml; from pathlib import Path; print(Path(yaml.safe_load(open('$CONFIG_FILE'))['logging']['file']).parent)")
mkdir -p "$LOG_DIR"

# 防火墙提示
echo ""
echo -e "${YELLOW}🔥 防火墙配置提示${NC}"
echo -e "${YELLOW}────────────────────────────────────────${NC}"
echo -e "${YELLOW}请确保防火墙已开放 ${PORT} 端口：${NC}"
echo -e "${GREEN}# CentOS/RHEL:${NC}"
echo -e "sudo firewall-cmd --permanent --add-port=${PORT}/tcp"
echo -e "sudo firewall-cmd --reload"
echo -e "${GREEN}# Ubuntu/Debian:${NC}"
echo -e "sudo ufw allow ${PORT}/tcp"
echo ""

# 显示配置信息
echo -e "${BLUE}📋 当前配置:${NC}"
echo -e "   配置文件: $CONFIG_FILE"
echo -e "   服务端口: $PORT"
echo -e "   认证状态: $([ "$AUTH_ENABLED" = "True" ] && echo "已启用" || echo "已禁用")"
if [ "$AUTH_ENABLED" = "True" ]; then
    echo -e "   用户名: $USERNAME"
    echo -e "   ${YELLOW}⚠️  请确保已修改默认密码！${NC}"
fi
echo ""

# 启动服务
echo -e "${GREEN}🚀 启动Web报告服务...${NC}"
echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           🌐 服务已启动！                         ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}📍 访问地址:${NC}"
echo -e "   本地: http://127.0.0.1:${PORT}"
echo -e "   公网: http://${PUBLIC_IP}:${PORT}"
echo ""
echo -e "${YELLOW}💡 使用 Ctrl+C 停止服务${NC}"
echo -e "${YELLOW}📝 配置文件: config/web_config.yaml${NC}"
echo -e "${YELLOW}────────────────────────────────────────${NC}"
echo ""

# 启动Flask应用（使用简化版）
python3 web/app_simple.py