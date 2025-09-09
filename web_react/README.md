# 渗透扫描平台 - React版本

这是使用 React + TypeScript + Ant Design 重构的渗透扫描平台前端。

## 🚀 技术栈

- **React 18** - 现代化的用户界面库
- **TypeScript** - 类型安全的JavaScript
- **Ant Design 5** - 企业级UI组件库
- **Vite** - 快速的构建工具
- **Axios** - HTTP客户端

## 📁 项目结构

```
src/
├── components/          # React组件
│   ├── DomainDetail.tsx    # 域名详情主组件
│   ├── StatsCards.tsx      # 统计卡片组件
│   ├── ScanResults.tsx     # 扫描结果组件
│   ├── TerminalLogs.tsx    # 终端日志组件
│   ├── ScanStatus.tsx      # 扫描状态组件
│   ├── RawData.tsx         # 原始数据组件
│   └── *.css              # 组件样式文件
├── services/           # API服务
│   └── api.ts             # API接口封装
├── types/              # TypeScript类型定义
│   └── index.ts           # 数据类型定义
├── App.tsx             # 主应用组件
├── main.tsx            # 应用入口
└── index.css           # 全局样式
```

## 🎯 核心功能

### 1. 四个主要标签页
- **扫描结果** - 显示URL、域名、IP端口等扫描结果
- **终端日志** - 实时显示扫描过程日志
- **扫描状态** - 显示扫描进度和各阶段状态
- **原始数据** - 显示原始扫描数据文件

### 2. 统计卡片过滤
- 点击统计卡片可过滤扫描结果内容
- 支持按URL、IP/端口、域名、漏洞类型过滤
- 过滤只影响"扫描结果"标签页

### 3. 实时更新
- 终端日志自动刷新
- 扫描状态实时更新
- 支持暂停/继续更新

### 4. 数据交互
- 搜索和过滤功能
- 数据导出和复制
- 响应式设计

## 🛠️ 开发指南

### 安装依赖
```bash
cd web_react
npm install
```

### 开发模式
```bash
npm run dev
```
访问: http://localhost:3000

### 构建生产版本
```bash
npm run build
```

### 预览生产版本
```bash
npm run preview
```

## 🔧 配置说明

### API代理配置
在 `vite.config.ts` 中配置了API代理：
```typescript
proxy: {
  '/api': {
    target: 'http://localhost:5000',
    changeOrigin: true,
    secure: false,
  }
}
```

### 认证配置
在 `src/services/api.ts` 中配置了基础认证：
```typescript
auth: {
  username: 'admin',
  password: 'MyStr0ngP@ssw0rd!'
}
```

## 🎨 设计特点

### 1. 现代化UI
- 毛玻璃效果背景
- 渐变色彩搭配
- 流畅的动画过渡
- 响应式布局

### 2. 用户体验
- 直观的标签页切换
- 清晰的数据过滤逻辑
- 实时状态反馈
- 便捷的数据操作

### 3. 性能优化
- 组件懒加载
- 数据缓存
- 虚拟滚动（大数据量）
- 防抖搜索

## 🐛 调试说明

### 开发者工具
- React DevTools
- TypeScript 类型检查
- Vite 热更新
- 浏览器控制台日志

### 常见问题
1. **API连接失败** - 检查后端服务是否启动
2. **认证失败** - 确认用户名密码正确
3. **数据不更新** - 检查网络连接和API响应

## 📝 更新日志

### v1.0.0 (2025-01-XX)
- ✅ 完成React + TypeScript重构
- ✅ 实现四个主要标签页
- ✅ 统计卡片过滤功能
- ✅ 实时数据更新
- ✅ 响应式设计
- ✅ 现代化UI设计

## 🤝 贡献指南

1. Fork项目
2. 创建功能分支
3. 提交更改
4. 推送到分支
5. 创建Pull Request

## 📄 许可证

MIT License
