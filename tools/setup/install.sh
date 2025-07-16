#!/bin/bash
# 工具安装脚本

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$PROJECT_ROOT/tools"
CONFIG_DIR="$PROJECT_ROOT/config"

echo "🚀 开始安装扫描工具..."

# 创建目录结构
mkdir -p "$TOOLS_DIR"/{scanner,auxiliary,custom}
mkdir -p "$CONFIG_DIR"/{wordlists,filters,api}

cd "$TOOLS_DIR/scanner"

# 下载核心工具
echo "📥 下载扫描工具..."

# subfinder
if [ ! -f "subfinder" ]; then
    echo "下载 subfinder..."
    wget -q https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder-linux-amd64.tar.gz
    tar -xzf subfinder-linux-amd64.tar.gz
    chmod +x subfinder
    rm subfinder-linux-amd64.tar.gz
fi

# puredns
if [ ! -f "puredns" ]; then
    echo "下载 puredns..."
    wget -q https://github.com/d3mondev/puredns/releases/download/v2.1.1/puredns-Linux-amd64.tgz
    tar -xzf puredns-Linux-amd64.tgz
    chmod +x puredns
    rm puredns-Linux-amd64.tgz
fi

# httpx
if [ ! -f "httpx" ]; then
    echo "下载 httpx..."
    wget -q https://github.com/projectdiscovery/httpx/releases/latest/download/httpx-linux-amd64.tar.gz
    tar -xzf httpx-linux-amd64.tar.gz
    chmod +x httpx
    rm httpx-linux-amd64.tar.gz
fi

# afrog
if [ ! -f "afrog" ]; then
    echo "下载 afrog..."
    wget -q https://github.com/zan8in/afrog/releases/latest/download/afrog-linux-amd64.tar.gz
    tar -xzf afrog-linux-amd64.tar.gz
    chmod +x afrog
    rm afrog-linux-amd64.tar.gz
fi

# fscan
if [ ! -f "fscan" ]; then
    echo "下载 fscan..."
    wget -q https://github.com/shadow1ng/fscan/releases/latest/download/fscan-linux-amd64 -O fscan
    chmod +x fscan
fi

cd "$PROJECT_ROOT"

# 安装Python依赖
echo "🐍 安装Python依赖..."
python3 -m pip install httpx requests tldextract tqdm aiofiles dnspython python-dateutil

# 创建配置文件
echo "🔧 创建配置文件..."

# resolvers.txt
cat > "$CONFIG_DIR/wordlists/resolvers.txt" << 'RESOLVERS'
8.8.8.8
1.1.1.1
114.114.114.114
223.5.5.5
208.67.222.222
9.9.9.9
RESOLVERS

# subdomains.txt
cat > "$CONFIG_DIR/wordlists/subdomains.txt" << 'SUBDOMAINS'
www
mail
ftp
admin
api
test
dev
stage
staging
prod
production
app
web
portal
dashboard
login
auth
secure
vpn
remote
m
mobile
wap
static
assets
cdn
img
images
upload
uploads
download
downloads
SUBDOMAINS

# config.ini
cat > "$CONFIG_DIR/api/config.ini" << 'CONFIG'
[DEFAULT]
TEST_EMAIL = your_fofa_email@example.com
TEST_KEY = your_fofa_api_key
CONFIG

# tlds.txt
cat > "$CONFIG_DIR/wordlists/tlds.txt" << 'TLDS'
com
net
org
edu
gov
mil
int
co
io
me
tv
cc
biz
info
name
pro
TLDS

# 创建过滤文件
touch "$CONFIG_DIR/filters"/{cdn.txt,filter-domain.txt,filter_domains-动态.txt,fofa_query_blacklist.txt}

# 创建示例目标文件
echo "example.com" > "$PROJECT_ROOT/data/input/url"

echo "✅ 安装完成！"
echo ""
echo "📋 使用说明："
echo "1. 修改目标文件: echo 'your-domain.com' > data/input/url"
echo "2. 配置API: nano config/api/config.ini"
echo "3. 开始扫描: ./scan.sh"
