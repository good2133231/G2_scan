# 📚 渗透扫描平台 - 文档中心

## 📖 **核心文档**

### **项目主文档**
- [`README.md`](../README.md) - 项目主要说明和使用指南
- [`工具使用说明.md`](../工具使用说明.md) - 详细工具使用说明

### **配置文档**  
- [`config/web_config.yaml`](../config/web_config.yaml) - Web服务配置文件

## 🔧 **修复历史文档**

### **连接问题修复**
- [`fix_history/CONNECTION_RESET_SOLUTION.md`](fix_history/CONNECTION_RESET_SOLUTION.md) - CONNECTION_RESET问题解决方案
- [`fix_history/BROWSER_CONNECTION_FINAL_FIX.md`](fix_history/BROWSER_CONNECTION_FINAL_FIX.md) - 浏览器连接最终修复

### **前端错误修复**
- [`fix_history/FINAL_VUE_JS_FIX.md`](fix_history/FINAL_VUE_JS_FIX.md) - Vue.js前端错误彻底修复

### **综合修复总结**
- [`fix_history/FINAL_FIX_SUMMARY.md`](fix_history/FINAL_FIX_SUMMARY.md) - 所有问题修复总结

## 🚀 **核心脚本说明**

### **扫描脚本**
- [`scan.sh`](../scan.sh) - 主要扫描脚本
- [`scan_v2.sh`](../scan_v2.sh) - 扫描脚本v2版本

### **Web服务脚本**
- [`start_production_web.sh`](../start_production_web.sh) - 生产级Web服务启动（推荐）
- [`start_web_config.sh`](../start_web_config.sh) - 开发模式Web服务启动
- [`wsgi.py`](../wsgi.py) - Gunicorn WSGI入口文件

## 📁 **目录结构说明**

```
start_game_test/
├── README.md              # 项目主说明
├── 工具使用说明.md          # 工具使用指南
├── scan.sh                # 主扫描脚本  
├── scan_v2.sh             # 扫描脚本v2
├── wsgi.py                # WSGI入口
├── start_production_web.sh # 生产服务启动
├── start_web_config.sh    # 开发服务启动
├── config/                # 配置文件目录
├── web/                   # Web应用代码
├── tools/                 # 扫描工具集
├── output/                # 扫描结果输出
├── logs/                  # 日志文件
├── docs/                  # 文档目录
│   ├── README.md          # 本文档索引
│   └── fix_history/       # 修复历史文档
└── scripts/               # 辅助脚本
```

## 🎯 **快速开始**

1. **启动Web服务**：`./start_production_web.sh`
2. **访问界面**：`http://YOUR_IP:5000`
3. **开始扫描**：在Web界面添加目标域名
4. **查看结果**：实时监控扫描进度和结果

## 📞 **技术支持**

如需技术支持或遇到问题，请参考：
1. 项目主文档中的常见问题解答
2. 修复历史文档中的已知问题解决方案
3. Web界面中的实时日志和调试信息

---

*文档更新时间: 2025-09-01*  
*项目版本: v3.3 - 性能优化 + 系统清理*
