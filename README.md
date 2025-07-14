# 🚀 渗透测试自动化扫描平台

一个完整的域名资产发现与漏洞扫描自动化平台，支持多代扫描、智能过滤和结果分析。

## ✨ 核心特性

- **🔍 全面的子域名发现**: 被动收集 + 主动爆破 + DNS解析验证
- **🌐 HTTP服务探测**: 状态码识别、指纹识别、SSL证书抓取
- **🛡️ 漏洞扫描**: 集成afrog漏洞扫描引擎
- **🔄 多代扩展扫描**: 基于发现结果自动生成下一代扫描任务
- **📊 智能数据分析**: 自动分类、过滤和报告生成
- **🚮 智能清理**: 分类清理临时文件和分析结果

## 🏗️ 项目结构

```
scan-platform/
├── scan.sh                    # 🚀 主扫描脚本
├── scan_fast.sh               # ⚡ 快速扫描脚本
├── test.sh                    # 🧪 功能测试脚本
├── install.sh                 # 📦 工具安装脚本
│
├── tools/scanner/             # 🔧 扫描工具集
│   ├── subfinder             # 子域名收集
│   ├── puredns               # DNS解析/爆破
│   ├── httpx                 # HTTP探测
│   ├── afrog                 # 漏洞扫描
│   └── fscan                 # 端口扫描
│
├── config/                   # ⚙️ 配置文件
│   ├── wordlists/           # 字典文件
│   ├── filters/             # 过滤规则
│   └── api/config.ini       # API配置
│
├── data/input/url           # 🎯 目标域名文件
│
├── scripts/                 # 📝 脚本集
│   ├── core/start.py        # 数据处理核心
│   ├── management/          # 扩展扫描管理
│   └── utils/               # 工具脚本
│
├── output/                  # 📊 输出结果
│   ├── domains/            # 域名信息
│   ├── reports/            # 扫描报告
│   └── generations/        # 分代扫描结果
│
└── temp/                   # 🗂️ 临时文件
```

## 🎯 扫描流程

1. **子域名收集** → subfinder被动收集
2. **子域名爆破** → puredns主动爆破
3. **DNS解析** → 验证域名有效性
4. **HTTP探测** → httpx服务发现
5. **数据分析** → start.py智能分析
6. **扩展发现** → 基于结果生成新目标

## 🌟 主要功能

### 🔍 资产发现
- 支持FOFA、Hunter API集成
- 智能CDN检测和过滤
- 多源域名收集和验证

### 📊 数据分析
- 状态码分类处理
- IP地址反向解析
- 域名相似度分析
- 自动生成分析报告

### 🔄 扩展扫描
- 基于发现结果自动生成下一代扫描
- 支持多级扩展和批量处理
- 智能目标分组和管理

### 🧹 智能清理
- 扫描前临时文件清理
- 分析结果选择性清理
- 支持预览和备份模式

## 🚀 快速开始

### 1. 环境准备
```bash
# 安装所有工具
./install.sh

# 检查安装状态
./test.sh
```

### 2. 配置目标
```bash
# 设置目标域名
echo "example.com" > data/input/url

# 配置API（可选）
nano config/api/config.ini
```

### 3. 开始扫描
```bash
# 完整扫描
./scan.sh

# 快速扫描
./scan_fast.sh
```

### 4. 查看结果
```bash
# 扫描结果概览
ls -la output/

# 查看域名信息
cat output/domains/example.com/urls.txt

# 查看分析报告
cat output/reports/scan/example.com*/base_info_*.txt
```

## 🛠️ 高级功能

### 扩展扫描管理
```bash
# 发现扩展结果
python3 scripts/management/tuozhan_manager.py discover

# 准备下代扫描
python3 scripts/management/tuozhan_manager.py prepare example.com

# 执行扩展扫描
cd output/generations/example.com/gen_*/
./scripts/scan_all.sh
```

### 智能清理
```bash
# 扫描前清理临时文件
./scripts/utils/smart_cleanup.sh --temp

# 重新分析前清理报告
./scripts/utils/smart_cleanup.sh --results

# 预览清理内容
./scripts/utils/smart_cleanup.sh --temp --dry-run
```

## 📋 配置说明

### API配置
编辑 `config/api/config.ini`:
```ini
[DEFAULT]
TEST_EMAIL = your_fofa_email@example.com
TEST_KEY = your_fofa_api_key
```

### 字典配置
- `config/wordlists/subdomains.txt` - 子域名爆破字典
- `config/wordlists/resolvers.txt` - DNS服务器列表
- `config/filters/` - CDN和域名过滤规则

## 🔧 故障排除

### 常见问题
```bash
# 工具缺失
./install.sh

# 权限问题
chmod +x scan*.sh tools/scanner/*

# Python依赖
pip3 install -r docs/requirements.txt

# 配置修复
./fix_config.sh
```

### 调试模式
```bash
# 详细日志
./scan.sh 2>&1 | tee scan.log

# 功能测试
./test.sh

# 检查进度
./check_progress.sh
```

## 📈 性能对比

| 扫描模式 | 字典大小 | 预计时间 | 适用场景 |
|---------|----------|----------|----------|
| 快速扫描 | ~25个子域名 | 2-5分钟 | 快速验证、演示 |
| 完整扫描 | ~177k个子域名 | 30-60分钟 | 深度挖掘、生产 |

## 🎯 使用方法

### 基础扫描流程
```bash
# 1. 准备环境
./install.sh && ./test.sh

# 2. 设置目标
echo "target.com" > data/input/url

# 3. 执行扫描
./scan.sh

# 4. 查看结果
ls -la output/reports/scan/
```

### 清理和重新扫描
```bash
# 清理临时文件（保留分析结果）
./scripts/utils/smart_cleanup.sh --temp

# 重新开始扫描
./scan.sh
```

### 清理分析结果
```bash
# 清理所有分析结果
./scripts/utils/smart_cleanup.sh --results

# 重新分析
python3 scripts/core/start.py
```

### 扩展扫描工作流
```bash
# 1. 发现扩展目标
python3 scripts/management/tuozhan_manager.py discover

# 2. 准备下代扫描
python3 scripts/management/tuozhan_manager.py prepare target.com

# 3. 执行扩展扫描
cd output/generations/target.com/gen_*/
./scripts/scan_all.sh

# 4. 查看扩展结果
ls -la results/
```

### 测试和验证
```bash
# 功能测试
./test.sh

# 快速验证
./scan_fast.sh

# 预览清理
./scripts/utils/smart_cleanup.sh --temp --dry-run
```

### 日常维护
```bash
# 清理旧日志
./scripts/utils/smart_cleanup.sh --logs

# 检查工具状态
./test.sh

# 更新字典
cp new_subdomains.txt config/wordlists/subdomains.txt
```

---

**🎉 现在您的渗透测试自动化平台已经完全设置好了！**

开始您的第一次扫描：`echo "target.com" > data/input/url && ./scan.sh`