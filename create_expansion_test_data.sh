#!/bin/bash
# 创建更丰富的二层扫描测试数据

echo "🔧 创建扩展层测试数据..."

# 基础目录
BASE_DIR="output/vtmarkets.com/expansion/report/domain_scan_results"

# 1. vtmarkets.net 数据
DOMAIN="vtmarkets.net"
mkdir -p "$BASE_DIR/$DOMAIN/$DOMAIN"
cd "$BASE_DIR/$DOMAIN/$DOMAIN"

# base_info文件
cat > base_info_$DOMAIN.txt << 'EOF'
==============================
[基础信息汇总] 域名: vtmarkets.net
==============================
关联真实IP:
  - 185.199.108.153
  - 185.199.109.153

URL和标题:
  - https://www.vtmarkets.net [VT Markets Network Portal][size:45678]
  - https://api.vtmarkets.net [API Gateway v2][size:1234]
  - https://docs.vtmarkets.net [VT Markets Documentation][size:89012]
  - https://status.vtmarkets.net [System Status Page][size:23456]

IP反查域名:
  - 185.199.108.153 -> pages.github.com, *.github.io
  - 185.199.109.153 -> pages.github.com, *.github.io
EOF

# fscan结果
cat > fscan_result_$DOMAIN.txt << 'EOF'
(icmp) Target 185.199.108.153 is alive
(icmp) Target 185.199.109.153 is alive
[*] Icmp alive hosts len is: 2
185.199.108.153:80 open
185.199.108.153:443 open
185.199.109.153:80 open
185.199.109.153:443 open
[*] alive ports len is: 4
[+] 185.199.108.153 http://185.199.108.153:80 [301] [Redirect to HTTPS]
[+] 185.199.108.153 https://185.199.108.153:443 [200] [GitHub Pages]
[+] 185.199.109.153 http://185.199.109.153:80 [301] [Redirect to HTTPS]
[+] 185.199.109.153 https://185.199.109.153:443 [200] [GitHub Pages]
EOF

# afrog结果
cat > afrog_report_$DOMAIN.json << 'EOF'
[
  {
    "PocInfo": {
      "Id": "github-pages-takeover",
      "Name": "GitHub Pages子域名接管",
      "Author": "test",
      "Severity": "high",
      "Description": "GitHub Pages配置错误可能导致子域名接管"
    },
    "Target": "https://docs.vtmarkets.net",
    "FullTarget": "https://docs.vtmarkets.net/",
    "Extra": {
      "cname": "vtmarkets.github.io"
    }
  }
]
EOF

# 2. vtmarketsweb.com 数据
cd ../../../..
DOMAIN="vtmarketsweb.com"
mkdir -p "$BASE_DIR/$DOMAIN/$DOMAIN"
cd "$BASE_DIR/$DOMAIN/$DOMAIN"

# base_info文件
cat > base_info_$DOMAIN.txt << 'EOF'
==============================
[基础信息汇总] 域名: vtmarketsweb.com
==============================
关联真实IP:
  - 172.67.182.145
  - 104.21.49.234

URL和标题:
  - https://www.vtmarketsweb.com [VT Markets Web Platform][size:156789]
  - https://trade.vtmarketsweb.com [Trading Platform - Login][size:34567]
  - https://mobile.vtmarketsweb.com [Mobile Trading App][size:45678]
  - https://api.vtmarketsweb.com [API Service Endpoint][size:2345]
  - https://cdn.vtmarketsweb.com [CDN Resources][size:567]

IP反查域名:
  - 172.67.182.145 -> cloudflare.com (CDN)
  - 104.21.49.234 -> cloudflare.com (CDN)
EOF

# fscan结果
cat > fscan_result_$DOMAIN.txt << 'EOF'
(icmp) Target 172.67.182.145 is alive
(icmp) Target 104.21.49.234 is alive
[*] Icmp alive hosts len is: 2
172.67.182.145:80 open
172.67.182.145:443 open
172.67.182.145:8443 open
104.21.49.234:80 open
104.21.49.234:443 open
104.21.49.234:8080 open
[*] alive ports len is: 6
[+] 172.67.182.145 http://172.67.182.145:80 [403] [Cloudflare Block]
[+] 172.67.182.145 https://172.67.182.145:443 [403] [Cloudflare Block]
[+] WebTitle http://172.67.182.145:8443 code:200 len:1234 title:CloudFlare
[+] 104.21.49.234 http://104.21.49.234:80 [403] [Cloudflare Block]
[+] 104.21.49.234 https://104.21.49.234:443 [403] [Cloudflare Block]
[+] WebTitle http://104.21.49.234:8080 code:200 len:567 title:Test Page
EOF

# afrog结果
cat > afrog_report_$DOMAIN.json << 'EOF'
[
  {
    "PocInfo": {
      "Id": "cors-misconfiguration",
      "Name": "CORS配置错误",
      "Author": "test",
      "Severity": "medium",
      "Description": "API端点存在CORS配置错误，可能导致跨域数据泄露"
    },
    "Target": "https://api.vtmarketsweb.com",
    "FullTarget": "https://api.vtmarketsweb.com/v1/user",
    "Extra": {
      "Access-Control-Allow-Origin": "*"
    }
  },
  {
    "PocInfo": {
      "Id": "api-key-leak",
      "Name": "API密钥泄露",
      "Author": "test",
      "Severity": "critical",
      "Description": "在JavaScript文件中发现硬编码的API密钥"
    },
    "Target": "https://mobile.vtmarketsweb.com",
    "FullTarget": "https://mobile.vtmarketsweb.com/js/config.js",
    "Extra": {
      "api_key": "sk_live_4242424242424242"
    }
  }
]
EOF

# 3. syyshop.com 数据（特殊案例：较少资产）
cd ../../../..
DOMAIN="syyshop.com"
mkdir -p "$BASE_DIR/$DOMAIN/$DOMAIN"
cd "$BASE_DIR/$DOMAIN/$DOMAIN"

# base_info文件
cat > base_info_$DOMAIN.txt << 'EOF'
==============================
[基础信息汇总] 域名: syyshop.com
==============================
关联真实IP:
  - 47.91.234.123

URL和标题:
  - https://www.syyshop.com [商城首页][size:234567]

IP反查域名:
  - 47.91.234.123 -> shop.example.com, test.shop.com
EOF

# fscan结果
cat > fscan_result_$DOMAIN.txt << 'EOF'
(icmp) Target 47.91.234.123 is alive
[*] Icmp alive hosts len is: 1
47.91.234.123:80 open
47.91.234.123:443 open
47.91.234.123:3306 open
47.91.234.123:6379 open
[*] alive ports len is: 4
[+] 47.91.234.123 http://47.91.234.123:80 [200] [Shop Homepage]
[+] 47.91.234.123 https://47.91.234.123:443 [200] [Shop Homepage]
[+] mysql 47.91.234.123:3306 unauthorized
[+] redis 47.91.234.123:6379 unauthorized
EOF

# afrog结果（无漏洞）
cat > afrog_report_$DOMAIN.json << 'EOF'
[]
EOF

# 返回项目根目录
cd ../../../../../..

echo "✅ 扩展层测试数据创建完成！"
echo ""
echo "📊 创建的测试数据："
echo "  1. vtmarkets.net - 4个URL, 1个高危漏洞"
echo "  2. vtmarketsweb.com - 5个URL, 2个漏洞(1个严重, 1个中危)"
echo "  3. syyshop.com - 1个URL, 无漏洞"
echo ""
echo "💡 运行 ./generate_report.sh vtmarkets.com 查看效果"