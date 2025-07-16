# 🤖 Claude Code 项目记忆文档

## 📝 项目概览

这是一个**渗透测试自动化扫描平台**，专注于域名资产发现与漏洞扫描。项目包含一层主扫描和二层扩展扫描功能。

## 🏗️ 核心架构

### 主要组件
- **scan.sh**: 一层主扫描脚本（子域名发现 → HTTP探测 → 漏洞扫描）
- **expand.sh**: 二层扩展扫描脚本（基于一层结果的深度挖掘）
- **scripts/core/start.py**: 数据处理和漏洞扫描核心逻辑
- **scripts/management/expansion_processor.py**: 扩展任务生成器
- **scripts/utils/smart_cleanup.sh**: 智能清理工具

### 工具集成
- **subfinder**: 子域名被动收集
- **puredns**: 子域名爆破和DNS解析验证
- **httpx**: HTTP探测和指纹识别
- **afrog**: 漏洞扫描（URL目标）
- **fscan**: 端口扫描（IP目标）

## 🔧 技术特点

### 扫描流程
1. **一层扫描**: `data/input/url` → 子域名收集 → HTTP探测 → 漏洞扫描
2. **二层扩展**: 基于一层发现的IP/URL/域名进行扩展扫描
3. **智能过滤**: 自动过滤CDN、噪音数据、重复域名

### 过滤机制
- **静态过滤**: `config/filters/filter-domain.txt`
- **动态过滤**: `config/filters/filter_domains-动态.txt`（运行时自动添加）
- **CDN过滤**: 自动识别和过滤CDN IP和域名
- **目标域名保护**: 确保目标域名本身不被过滤

### 多进程设计
- JSON解析使用多进程处理提升性能
- 异步DNS反查提升效率
- 智能chunk分割优化内存使用

## 🐛 常见问题与解决方案

### 1. filter_domains未定义错误
**问题**: `NameError: name 'filter_domains' is not defined`
**解决**: 确保所有调用`merge_all_expanded_results`的地方都传递`filter_domains`参数

### 2. puredns命令错误
**问题**: `puredns error: open vtmarkets.com: no such file or directory`
**解决**: 修正puredns命令参数顺序，域名应作为位置参数而非-d参数

### 3. 目标域名被误过滤
**问题**: 目标域名在动态过滤列表中被过滤
**解决**: 在`parse_json_lines_chunk`中添加目标域名保护逻辑

### 4. 日志目录不存在
**问题**: expansion任务中日志路径不存在
**解决**: 在写入日志前创建对应的目录结构

## 📊 文件结构理解

### 输出目录结构
```
output/target.com/
├── input/                     # 扫描输入文件
│   ├── urls.txt              # URL列表
│   ├── a_records.txt         # A记录列表
│   └── representative_urls.txt # 代表性URL（afrog目标）
├── tuozhan/all_tuozhan/      # 扩展目标
│   ├── ip.txt               # IP目标（fscan扫描）
│   ├── urls.txt             # URL目标（httpx探测）
│   └── root_domains.txt     # 新发现域名（完整扫描）
└── base_info_target.com.txt  # 基础信息汇总
```

### 配置文件说明
- `config/api/config.ini`: FOFA/Hunter API配置
- `config/filters/`: 各类过滤规则
- `config/subdomains.txt`: 子域名爆破字典
- `config/resolvers.txt`: DNS解析器列表

## 🔄 工作流程

### 用户选择策略
- **所有YES/NO选项均选择YES**（自动化处理）
- 测试模式优先，生产模式谨慎
- 错误处理优先修复而非跳过

### 开发模式
1. 理解需求 → 分析问题 → 制定方案
2. 逐步实现 → 测试验证 → 文档更新
3. 优先修复核心功能，再优化性能

### 代码风格
- 保持现有结构和命名习惯
- 添加详细的状态输出和错误处理
- 使用async/await优化IO操作
- 多进程提升计算密集型任务性能

## 🚨 重要提醒

1. **安全为先**: 仅用于授权测试，严禁恶意使用
2. **备份重要**: 修改前备份关键配置和数据
3. **测试优先**: 新功能先在测试模式验证
4. **日志详细**: 保持详细的执行日志便于调试
5. **错误处理**: 优雅处理异常情况，避免中断扫描

## 📈 性能优化要点

- 使用多进程处理大量JSON数据
- 异步处理DNS反查和API请求
- 智能chunk分割避免内存溢出
- CDN过滤减少无效扫描
- 去重机制避免重复处理

---
*📅 最后更新: 2025-07-16*
*🤖 Claude Code记忆文档*