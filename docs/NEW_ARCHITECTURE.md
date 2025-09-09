# 🎯 新扫描架构设计

## 核心理念
- **去层级化**：每个域名都是独立的扫描单元，不再有"层"的概念
- **关系追踪**：通过关系图记录域名之间的发现关系
- **灵活扫描**：可以选择性地对扩展域名进行深度扫描

## 扫描模式

### scan -s 1 (快速扩展扫描)
1. 对主域名进行完整扫描（子域名发现、httpx、fscan、afrog）
2. 收集扩展信息：
   - 扩展域名 → 记录到关系图，不进行深度扫描
   - 扩展IP → 使用fscan进行端口扫描
   - 扩展URL → 使用httpx获取标题，afrog扫描漏洞
3. 结果保存在主域名目录下

### scan -s 2 (深度扩展扫描)
1. 执行scan -s 1的所有功能
2. 对每个扩展域名作为新的独立域名进行完整扫描
3. 每个扩展域名有自己独立的目录结构

## 目录结构
```
output/
├── dlsm.com/                          # 主域名目录
│   ├── scan_info.json                 # 扫描元信息
│   ├── relationships.json             # 关系数据
│   ├── base_info_dlsm.com.txt        # 基础信息
│   ├── result_all.json                # httpx扫描结果
│   ├── input/                         
│   │   └── representative_urls.txt    # 代表性URL
│   ├── tuozhan/                       # 扩展信息
│   │   └── all_tuozhan/
│   │       ├── root_domains.txt       # 扩展域名列表
│   │       ├── ips.txt                # 扩展IP列表
│   │       └── urls.txt               # 扩展URL列表
│   ├── expand_quick_scan/             # 扩展快速扫描结果
│   │   ├── fscan_ips.txt              # 扩展IP的fscan结果
│   │   ├── httpx_urls.json            # 扩展URL的httpx结果
│   │   └── afrog_urls.json            # 扩展URL的afrog结果
│   └── finish.txt                     # 完成标记
│
└── subdomain.dlsm.com/                # 扩展域名独立目录（scan -s 2时创建）
    └── ... (结构同主域名)
```

## 关系数据格式 (relationships.json)
```json
{
  "domain": "dlsm.com",
  "scan_time": "2025-07-23 10:00:00",
  "scan_mode": "s1",
  "discovered_by": null,  // 主域名为null
  "discovered_from": null,
  "discoveries": {
    "domains": [
      {
        "domain": "subdomain1.dlsm.com",
        "method": "subdomain_enum",
        "scanned": false  // scan -s 2时变为true
      },
      {
        "domain": "related.example.com",
        "method": "ip_reverse",
        "scanned": false
      }
    ],
    "ips": [
      {
        "ip": "1.2.3.4",
        "method": "dns_resolve",
        "scanned": true  // 扩展IP会被fscan扫描
      }
    ],
    "urls": [
      {
        "url": "https://api.partner.com",
        "method": "body_extract",
        "scanned": true  // 扩展URL会被httpx/afrog扫描
      }
    ]
  }
}
```

## Web界面功能

### 域名列表页
- 显示所有已扫描的域名
- 标记哪些是主域名，哪些是扩展域名
- 显示扫描模式（s1/s2）
- 快速操作：对未扫描的扩展域名发起扫描

### 域名详情页
- 显示扫描结果（URLs、IPs、漏洞等）
- 显示扩展信息（分类展示）
- 扩展域名可点击，跳转到对应的扫描结果
- "扫描此域名"按钮（对未扫描的扩展域名）

### 关系图页面
- 可视化展示域名之间的发现关系
- 节点大小表示资产数量
- 不同颜色表示扫描状态
- 点击节点可跳转到域名详情

## 实现步骤
1. 修改scan.sh支持新的扫描模式
2. 修改start.py处理扩展资产的快速扫描
3. 创建关系数据记录机制
4. 修改Web界面适配新架构
5. 实现Web界面的扫描触发功能