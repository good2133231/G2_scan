# 🎯 渗透测试自动化扫描平台 v2.0

一个现代化的域名资产发现与漏洞扫描自动化平台，采用 React + TypeScript 前端和 Python Flask API 后端架构。

## ✨ 核心特性

- **🏗️ 现代化架构**: React + TypeScript + Ant Design 前端，Python Flask + Gunicorn 后端
- **🔍 完整扫描流程**: 子域名发现 → HTTP探测 → 漏洞扫描 → 报告生成
- **🎯 目标管理**: 添加、删除、批量导入扫描目标，支持数据库持久化
- **🔄 多层扫描**: 支持无限层递归扫描，自动发现新资产
- **📊 实时监控**: Web界面实时查看扫描状态、进度和日志
- **🌐 RESTful API**: 标准化的API接口，支持程序化调用
- **🛡️ 安全认证**: HTTP Basic Auth 保护，防止未授权访问
- **🔧 生产级稳定**: Gunicorn多进程服务器，高可用性保障

## 🏗️ 系统架构

```
🌐 前端 (React + TypeScript + Ant Design)
   ↓ HTTP API调用 (端口: 3000)
🔄 Vite开发服务器 + API代理
   ↓ 代理转发 (/api -> :5000)
🚀 后端 (Gunicorn + Flask + SQLite)
   ├── 主进程 (Master) - 端口: 5000
   ├── 工作进程 (Worker 1-4)
   └── 数据库 (scan_platform.db)
   ↓
🔧 扫描引擎 (subfinder/puredns/httpx/afrog/fscan)
   ↓
📊 结果存储 (data/ 目录)
```

## 📁 项目结构

```
渗透测试扫描平台/
├── web_react/                 # 🌐 React前端
│   ├── src/
│   │   ├── components/        # React组件
│   │   │   ├── DomainDetail.tsx      # 域名详情页
│   │   │   ├── TargetManagement.tsx  # 目标管理
│   │   │   ├── ScanResults.tsx       # 扫描结果
│   │   │   ├── TerminalLogs.tsx      # 终端日志
│   │   │   ├── ScanStatus.tsx        # 扫描状态
│   │   │   └── RawData.tsx           # 原始数据
│   │   ├── services/
│   │   │   └── api.ts         # API服务封装
│   │   └── types/
│   │       └── index.ts       # TypeScript类型定义
│   ├── package.json           # 依赖配置
│   ├── vite.config.ts         # Vite配置
│   └── start_dev.sh           # 开发服务器启动脚本
│
├── web/                       # 🐍 Python后端API
│   ├── app_api_only.py        # Flask API应用
│   └── data/                  # SQLite数据库
│       └── scan_platform.db   # 目标和任务数据
│
├── tools/scanner/             # 🔧 扫描工具
│   ├── subfinder              # 子域名发现
│   ├── puredns                # DNS解析验证
│   ├── httpx                  # HTTP探测
│   ├── afrog                  # 漏洞扫描
│   └── fscan                  # 端口和服务扫描
│
├── data/                      # 📊 扫描数据存储
├── output/                    # 📄 扫描结果
├── reports/                   # 📋 HTML报告
├── logs/                      # 📝 系统日志
│
├── start_api_backend.sh       # 🚀 后端启动脚本
├── scan.sh                    # 🔍 主扫描脚本
└── README.md                  # 📚 项目说明
```

## 🚀 快速开始

### 1. 启动后端API服务

```bash
# 启动生产级Gunicorn后端
./start_api_backend.sh

# 验证后端服务
curl -u admin:MyStr0ngP@ssw0rd! http://localhost:5000/health
```

### 2. 启动前端开发服务器

```bash
cd web_react
./start_dev.sh

# 或者手动启动
npm install
npm run dev
```

### 3. 访问Web界面

- **前端界面**: http://localhost:3000
- **后端API**: http://localhost:5000
- **认证信息**: admin / MyStr0ngP@ssw0rd!

## 🎯 功能模块

### 📋 目标管理
- ✅ 添加单个扫描目标
- ✅ 批量导入目标列表  
- ✅ 查看目标状态和进度
- ✅ 删除和编辑目标信息
- ✅ 数据库持久化存储

### 🔍 扫描功能
- ✅ 子域名发现 (subfinder)
- ✅ DNS解析验证 (puredns) 
- ✅ HTTP状态探测 (httpx)
- ✅ 漏洞扫描 (afrog)
- ✅ 端口扫描 (fscan)
- 🚧 多层递归扫描
- 🚧 扫描进度实时监控

### 📊 结果查看
- ✅ 扫描结果可视化展示
- ✅ 四大模块：扫描结果/终端日志/扫描状态/原始数据
- ✅ 统计信息汇总 (URL/IP端口/扩展域名/漏洞数量)
- ✅ 漏洞详情和风险等级
- 🚧 HTML报告导出
- 🚧 数据导出功能

## 🔧 API接口

### 认证方式
所有API请求需要HTTP Basic Auth认证：
- 用户名：`admin`  
- 密码：`MyStr0ngP@ssw0rd!`

### 核心接口

#### 系统健康检查
```bash
GET /health
# 响应: {"status": "ok", "message": "API服务正常运行"}
```

#### 目标管理
```bash
# 获取所有目标
GET /targets
# 响应: {"status": "success", "targets": [...], "total": 0}

# 添加新目标  
POST /targets
Content-Type: application/json
{"domain": "example.com", "notes": "测试目标"}

# 删除目标
DELETE /targets/1

# 批量添加目标
POST /targets/batch  
Content-Type: application/json
{"domains": ["domain1.com", "domain2.com"], "notes": "批量导入"}
```

#### 扫描数据
```bash
# 获取域名扫描数据
GET /domain/example.com

# 获取扫描状态
GET /scan_status/example.com  

# 获取扫描日志
GET /logs/example.com

# 获取原始数据  
GET /raw_data/example.com

# 启动扫描
POST /start_scan
{"domain": "example.com", "layer": 1}

# 停止扫描  
POST /stop_scan
{"domain": "example.com"}
```

## ⚙️ 配置说明

### 后端配置 (web/app_api_only.py)
- **端口**: 5000
- **工作进程**: 4个Gunicorn workers  
- **数据库**: SQLite (web/data/scan_platform.db)
- **认证**: HTTP Basic Auth
- **日志**: /tmp/api_access.log, /tmp/api_error.log

### 前端配置 (web_react/vite.config.ts)  
- **端口**: 3000
- **代理**: /api -> localhost:5000
- **热重载**: 开发模式支持
- **构建输出**: dist/

## 🛠️ 开发指南

### 技术栈
- **前端**: React 18 + TypeScript + Ant Design + Vite
- **后端**: Python 3 + Flask + Gunicorn + SQLite  
- **扫描**: subfinder + puredns + httpx + afrog + fscan

### 开发环境设置
```bash
# 安装Python依赖
pip3 install flask gunicorn

# 安装Node.js依赖  
cd web_react
npm install

# 启动开发模式
./start_api_backend.sh      # 后端
cd web_react && npm run dev  # 前端
```

### 目录权限
```bash
chmod +x start_api_backend.sh
chmod +x web_react/start_dev.sh  
chmod +x scan.sh
chmod 755 tools/scanner/*
```

## 🔒 安全说明

- ✅ HTTP Basic Auth认证保护所有API
- ✅ 输入验证和SQL注入防护
- ✅ CORS跨域访问控制
- ⚠️ 建议生产环境使用HTTPS
- ⚠️ 定期更换认证密码
- ⚠️ 限制网络访问范围

## 📝 更新日志

### v2.0.0 (2025-09-03)
- 🎉 全面重构为现代化架构
- ✨ 新增React + TypeScript前端  
- 🚀 升级到Gunicorn生产服务器
- 📋 实现完整的目标管理功能
- 🔧 标准化RESTful API设计
- 📊 重构数据展示界面
- 🛡️ 增强安全认证机制
- 🔍 优化扫描引擎集成

### v1.x (历史版本)  
- 基础扫描功能实现
- 简单Web界面
- HTML报告生成

## 🤝 贡献指南

欢迎提交Issue和Pull Request！

1. Fork本项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)  
5. 创建Pull Request

## 📄 许可证

本项目采用MIT许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 📞 支持

如有问题，请通过以下方式联系：

- 📧 Email: your-email@example.com
- 💬 Issue: [GitHub Issues](https://github.com/your-repo/issues)
- 📚 文档: [项目Wiki](https://github.com/your-repo/wiki)

---

🌟 **如果这个项目对你有帮助，请给我们一个Star！** ⭐