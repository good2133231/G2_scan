import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',  // 绑定所有网络接口，允许外网访问
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:5000',  // 代理到Python后端API
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path.replace(/^\/api/, ''),  // 移除/api前缀
        configure: (proxy, options) => {
          proxy.on('proxyReq', (proxyReq, req, res) => {
            // 添加Basic Auth认证
            const auth = Buffer.from('admin:MyStr0ngP@ssw0rd!').toString('base64');
            proxyReq.setHeader('Authorization', `Basic ${auth}`);
          });
        }
      }
    }
  },
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
  }
})
