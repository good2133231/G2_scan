#!/bin/bash

echo "🏭 构建React生产版本"
echo "=========================="

# 检查依赖
if [ ! -d "node_modules" ]; then
    echo "📦 安装依赖..."
    npm install
fi

# 构建生产版本
echo "🔨 构建生产版本..."
npm run build

if [ $? -ne 0 ]; then
    echo "❌ 构建失败"
    exit 1
fi

echo "✅ 构建完成"

# 创建生产环境nginx配置
echo "📝 创建nginx配置..."
cat > nginx-react.conf << 'EOF'
server {
    listen 3000;
    server_name _;
    
    # React静态文件
    location / {
        root /opt/info_get/start_game_test/web_react/dist;
        try_files $uri $uri/ /index.html;
        
        # 缓存静态资源
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
    }
    
    # API代理到Python后端
    location /api/ {
        proxy_pass http://127.0.0.1:5000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # 处理认证
        proxy_set_header Authorization "Basic YWRtaW46TXlTdHIwbmdQQHNzdzByZCE=";
    }
}
EOF

echo ""
echo "🎉 生产版本构建完成！"
echo "=========================="
echo ""
echo "📁 构建文件位置: ./dist/"
echo "📋 nginx配置文件: ./nginx-react.conf"
echo ""
echo "🚀 部署方式选择:"
echo ""
echo "1️⃣  使用nginx (推荐生产环境):"
echo "   sudo cp nginx-react.conf /etc/nginx/sites-available/react-frontend"
echo "   sudo ln -s /etc/nginx/sites-available/react-frontend /etc/nginx/sites-enabled/"
echo "   sudo nginx -t && sudo systemctl reload nginx"
echo ""
echo "2️⃣  使用serve (简单部署):"
echo "   npm install -g serve"
echo "   serve -s dist -l 3000"
echo ""
echo "3️⃣  继续使用开发服务器:"
echo "   ./start_dev.sh"
echo ""
echo "🌐 访问地址:"
echo "   http://139.59.122.117:3000"
echo ""
echo "⚠️  注意: 确保Python后端服务正在运行 (端口5000)"
