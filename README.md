# 🚀 渗透测试自动化扫描平台

一个简洁高效的域名资产发现与漏洞扫描自动化平台，专注核心功能。

## ✨ 核心特性

- **🔍 完整扫描流程**: 子域名发现 → HTTP探测 → 漏洞扫描
- **🔄 二层扩展扫描**: 基于一层结果自动扩展攻击面
- **🧪 测试模式**: 精简参数快速验证流程
- **🛡️ 漏洞检测**: 集成afrog和fscan工具
- **🎯 智能过滤**: 自动过滤CDN和噪音数据

## 🏗️ 项目结构

```
scan-platform/
├── scan.sh                    # 🚀 一层主扫描脚本
├── expand.sh                  # 🔄 二层扩展扫描脚本
├── install.sh                 # 📦 工具安装脚本
│
├── config/                    # ⚙️ 配置文件
│   ├── subdomains.txt         # 子域名字典
│   ├── resolvers.txt          # DNS解析器
│   ├── api/config.ini         # API配置
│   └── filters/               # 过滤规则
│
├── scripts/                   # 📝 核心脚本
│   ├── core/start.py          # 数据处理和漏洞扫描
│   ├── management/            # 扩展扫描管理
│   └── utils/                 # 工具脚本
│
├── tools/scanner/             # 🔧 扫描工具
│   ├── subfinder, puredns, httpx, afrog, fscan
│
├── data/input/url             # 🎯 目标域名文件
├── output/                    # 📊 扫描结果
└── temp/                      # 🗂️ 临时文件
```

## 🚀 快速开始

### 1. 安装工具

```bash
chmod +x tools/setup/install.sh
./tools/setup/install.sh
```

### 2. 配置目标

```bash
echo "target.com" > data/input/url
```

### 3. 开始扫描

```bash
# 测试模式（推荐首次使用）
./scan.sh --test

# 生产模式（完整扫描）
./scan.sh
```

## 📊 完整执行流程

### 🎯 一层主扫描流程

```
data/input/url → 子域名收集 → 子域名爆破 → DNS解析验证 → HTTP探测 → 数据处理 → afrog漏洞扫描 → fscan端口扫描
```

**执行命令:**
```bash
# 测试模式（精简参数）
./scan.sh --test

# 生产模式（完整参数）
./scan.sh
```

**输出结果:** `output/target.com/`
```
target.com/
├── urls.txt                  # HTTP探测成功的URL列表
├── a_records.txt             # A记录解析结果
├── representative_urls.txt   # 去重后的代表性URL
├── finish.txt                # 扫描完成标记
├── afrog_report_*.json       # afrog漏洞扫描报告
├── fscan_result_*.txt        # fscan端口扫描报告
└── tuozhan/all_tuozhan/      # 扩展目标（用于二层扫描）
    ├── ip.txt                # 发现的IP地址
    ├── urls.txt              # 扩展URL目标
    └── root_domains.txt      # 新发现的根域名
```

### 🔄 二层扩展扫描流程

基于一层扫描发现的扩展目标，进行深度挖掘：

**执行命令:**
```bash
# 测试模式二层扫描
./expand.sh target.com run --test

# 生产模式二层扫描
./expand.sh target.com run
```

**输出结果:** `output/expansions/target.com/gen_YYYYMMDD_HHMMSS/`
```
gen_20250715_123456/
├── expansion_summary.txt     # 扩展任务摘要
├── run_all_expansions.sh     # 一键执行脚本
├── ip_scans/                 # IP端口扫描结果
├── url_scans/                # URL探测结果
└── domain_scans/             # 新域名完整扫描
```

### 🔄 多层套娃扫描

对二层发现的新域名继续进行扫描：

```bash
# 1. 一层扫描
echo "target.com" > data/input/url
./scan.sh

# 2. 二层扩展
./expand.sh target.com run

# 3. 对新发现的域名进行三层扫描
echo "discovered-new-domain.com" > data/input/url
./scan.sh

# 4. 继续扩展...
./expand.sh discovered-new-domain.com run
```

## ⚙️ 参数说明

### 测试模式 vs 生产模式

| 模式 | 参数 | 子域名字典 | 线程数 | HTTP线程 | 适用场景 |
|------|------|------------|--------|----------|----------|
| 测试 | `--test` | 前100行 | 20 | 50 | 快速验证流程 |
| 生产 | 默认 | 完整字典 | 200 | 300 | 深度扫描 |

### start.py参数

- **测试模式**: 传递`-test`参数，使用精简的afrog和fscan参数
- **生产模式**: 使用完整的漏洞扫描参数

## 🎯 使用场景

### 场景1: 单个目标完整挖掘

```bash
# 1. 设置目标
echo "target.com" > data/input/url

# 2. 一层主扫描
./scan.sh

# 3. 二层扩展扫描
./expand.sh target.com run

# 4. 查看结果
ls -la output/target.com/
ls -la output/expansions/target.com/
```

### 场景2: 快速测试验证

```bash
# 1. 测试模式一层扫描
echo "target.com" > data/input/url
./scan.sh --test

# 2. 测试模式二层扫描
./expand.sh target.com run --test
```

### 场景3: 批量目标处理

```bash
# 循环处理多个目标
for target in target1.com target2.com target3.com; do
    echo "$target" > data/input/url
    ./scan.sh --test
    ./expand.sh "$target" run --test
done
```

## 📁 核心文件说明

### 主要脚本

- **scan.sh**: 一层主扫描脚本，执行完整的子域名发现和漏洞扫描流程
- **expand.sh**: 二层扩展扫描脚本，基于一层结果进行深度挖掘
- **scripts/core/start.py**: 数据处理核心，负责调用afrog和fscan

### 配置文件

- **config/subdomains.txt**: 子域名爆破字典
- **config/resolvers.txt**: DNS解析器列表
- **config/api/config.ini**: FOFA/Hunter API配置

### 输出文件

- **output/target.com/**: 一层扫描结果
- **output/expansions/**: 二层扩展扫描结果

## 🔧 常见问题

### Q: 如何修改扫描参数？

**A**: 编辑对应脚本中的参数:
- 子域名收集线程: 修改scan.sh中的`-t`参数
- 子域名字典大小: 修改scan.sh中的`head -100`数量
- HTTP探测线程: 修改scan.sh中httpx的`-t`参数

### Q: 如何添加自定义字典？

**A**: 替换`config/subdomains.txt`文件内容

### Q: 如何配置API密钥？

**A**: 编辑`config/api/config.ini`:
```ini
[DEFAULT]
TEST_EMAIL = your_fofa_email
TEST_KEY = your_fofa_key
```

### Q: 如何查看扫描日志？

**A**: 扫描过程中的输出会直接显示在终端，漏洞扫描结果保存在对应的JSON和TXT文件中

## 🛡️ 安全说明

本工具仅用于授权的渗透测试和安全研究：

1. **获得授权**: 只能对拥有或获得授权的目标进行扫描
2. **遵守法律**: 确保扫描活动符合当地法律法规  
3. **负责使用**: 合理控制扫描频率，避免影响目标系统
4. **数据保护**: 妥善保护扫描结果，避免泄露敏感信息

## 📝 更新日志

### v2.1 (2025-07-15) - 流程简化 + 路径优化
- ✅ **简化核心流程**: 回到基础的一层→二层扫描流程
- ✅ **精简脚本**: 移除复杂的管理功能，专注核心扫描
- ✅ **优化test参数**: 精确控制字典大小和线程数
- ✅ **自动临时文件清理**: 扫描完成后自动清理temp目录
- 🆕 **环境变量优化**: 使用SCAN_PROJECT_ROOT环境变量避免复杂相对路径
- 🆕 **配置路径统一**: start.py使用环境变量统一配置文件路径
- 🆕 **移除符号链接**: 不再创建不必要的tools/scripts符号链接

### v2.0 - 架构优化  
- 🔄 多层扫描架构
- 🧹 智能管理系统
- 📊 简化输出结构

### v1.x - 基础功能
- 🔍 子域名发现和HTTP探测
- 🛡️ 漏洞扫描集成

---

🎯 **专注核心，简洁高效** | 🔍 **一层主扫，二层扩展** | 🛡️ **漏洞检测，深度分析**