#!/bin/bash
# 创建测试数据脚本

echo "🔧 创建测试数据..."

# 一层扫描测试数据
mkdir -p output/vtmarkets.com
cd output/vtmarkets.com

# 创建fscan测试结果
cat > fscan_result_vtmarkets.com.txt << 'EOF'
(icmp) Target 211.245.20.103 is alive
(icmp) Target 211.245.20.104 is alive
(icmp) Target 211.245.20.105 is alive
[*] Icmp alive hosts len is: 3
211.245.20.103:80 open
211.245.20.103:443 open
211.245.20.103:8080 open
211.245.20.104:80 open
211.245.20.104:443 open
211.245.20.104:3306 open
211.245.20.105:22 open
211.245.20.105:80 open
211.245.20.105:443 open
[*] alive ports len is: 9
[+] 211.245.20.103 http://211.245.20.103:80 [302] [VT Markets - Online Trading]
[+] 211.245.20.103 https://211.245.20.103:443 [200] [VT Markets | Trade CFDs]
[+] 211.245.20.104 http://211.245.20.104:80 [200] [API Gateway]
[+] 211.245.20.104 https://211.245.20.104:443 [200] [API Gateway]
[+] 211.245.20.105 http://211.245.20.105:80 [403] [403 Forbidden]
[+] 211.245.20.105 https://211.245.20.105:443 [403] [403 Forbidden]
[+] mysql 211.245.20.104:3306:admin password is root
[+] SSH 211.245.20.105:22 banner: SSH-2.0-OpenSSH_7.4
EOF

# 创建afrog测试结果
cat > afrog_report_vtmarkets.com.json << 'EOF'
[
  {
    "PocInfo": {
      "Id": "CVE-2021-21234",
      "Name": "Spring Boot Actuator 信息泄露",
      "Author": "test",
      "Severity": "medium",
      "Description": "Spring Boot Actuator 端点未授权访问"
    },
    "Target": "https://api.vtmarkets.com",
    "FullTarget": "https://api.vtmarkets.com/actuator/env",
    "Extra": {
      "request": "GET /actuator/env HTTP/1.1",
      "response": "HTTP/1.1 200 OK"
    }
  },
  {
    "PocInfo": {
      "Id": "CVE-2022-22965",
      "Name": "Spring4Shell RCE",
      "Author": "test",
      "Severity": "critical",
      "Description": "Spring Framework 远程代码执行漏洞"
    },
    "Target": "https://www.vtmarkets.com",
    "FullTarget": "https://www.vtmarkets.com/",
    "Extra": {
      "vulnerable": true
    }
  }
]
EOF

# 创建二层扫描测试数据
mkdir -p expansion/report/domain_scan_results/vtaffiliates.com/vtaffiliates.com
cd expansion/report/domain_scan_results/vtaffiliates.com/vtaffiliates.com

# 二层fscan结果
cat > fscan_result_vtaffiliates.com.txt << 'EOF'
(icmp) Target 192.168.1.100 is alive
(icmp) Target 192.168.1.101 is alive
[*] Icmp alive hosts len is: 2
192.168.1.100:80 open
192.168.1.100:443 open
192.168.1.101:80 open
192.168.1.101:443 open
192.168.1.101:8888 open
[*] alive ports len is: 5
[+] 192.168.1.100 http://192.168.1.100:80 [200] [VT Affiliates Portal]
[+] 192.168.1.100 https://192.168.1.100:443 [200] [VT Affiliates Portal]
[+] 192.168.1.101 http://192.168.1.101:80 [200] [Affiliate Dashboard]
[+] 192.168.1.101 https://192.168.1.101:443 [200] [Affiliate Dashboard]
[+] 192.168.1.101 http://192.168.1.101:8888 [200] [Admin Panel]
EOF

# 二层afrog结果
cat > afrog_report_vtaffiliates.com.json << 'EOF'
[
  {
    "PocInfo": {
      "Id": "SQL-Injection-001",
      "Name": "SQL注入漏洞",
      "Author": "test",
      "Severity": "high",
      "Description": "登录页面存在SQL注入"
    },
    "Target": "https://www.vtaffiliates.com",
    "FullTarget": "https://www.vtaffiliates.com/login.php?id=1",
    "Extra": {
      "payload": "1' or '1'='1"
    }
  }
]
EOF

# 创建base_info文件
cd ../../../../..
cat > base_info_vtaffiliates.com.txt << 'EOF'
========================================
扫描目标: vtaffiliates.com
扫描时间: 2025-07-17 10:00:00
========================================

【URL发现】
- https://www.vtaffiliates.com [VT Markets Affiliates | VT Affiliates | VT Forex Affiliates][size:239296]
- https://go.vtaffiliates.com [][size:101123]
- https://portal.vtaffiliates.com [Affiliate Portal - Login][size:45678]

【IP发现】
- 192.168.1.100
- 192.168.1.101

【反查域名】
- 192.168.1.100 -> portal.vtaffiliates.com, admin.vtaffiliates.com
- 192.168.1.101 -> api.vtaffiliates.com, track.vtaffiliates.com
EOF

# 返回项目根目录
cd ../../../..

echo "✅ 测试数据创建完成！"
echo "📂 查看一层数据: ls -la output/vtmarkets.com/"
echo "📂 查看二层数据: ls -la output/vtmarkets.com/expansion/report/domain_scan_results/"