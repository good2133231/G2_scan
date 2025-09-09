import axios from 'axios'
import { DomainData, ScanStatus, LogEntry, RawDataFiles } from '../types'

// 配置axios实例
const api = axios.create({
  baseURL: '/api',
  timeout: 30000,
  auth: {
    username: 'admin',
    password: 'MyStr0ngP@ssw0rd!'
  }
})

// 请求拦截器
api.interceptors.request.use(
  (config) => {
    console.log('API请求:', config.method?.toUpperCase(), config.url)
    return config
  },
  (error) => {
    console.error('请求错误:', error)
    return Promise.reject(error)
  }
)

// 响应拦截器
api.interceptors.response.use(
  (response) => {
    console.log('API响应:', response.status, response.config.url)
    return response
  },
  (error) => {
    console.error('响应错误:', error.response?.status, error.config?.url, error.message)
    return Promise.reject(error)
  }
)

// 获取域名详细数据
export const fetchDomainData = async (domain: string): Promise<DomainData> => {
  try {
    const response = await api.get(`/domain/${domain}`)
    return response.data
  } catch (error) {
    console.error('获取域名数据失败:', error)
    throw error
  }
}

// 获取扫描状态
export const fetchScanStatus = async (domain: string): Promise<ScanStatus> => {
  try {
    const response = await api.get(`/scan_status/${domain}`)
    return response.data
  } catch (error) {
    console.error('获取扫描状态失败:', error)
    throw error
  }
}

// 获取终端日志
export const fetchLogs = async (domain: string): Promise<LogEntry[]> => {
  try {
    const response = await api.get(`/logs/${domain}`)
    return response.data
  } catch (error) {
    console.error('获取日志失败:', error)
    throw error
  }
}

// 获取原始数据
export const fetchRawData = async (domain: string): Promise<RawDataFiles> => {
  try {
    const response = await api.get(`/raw_data/${domain}`)
    return response.data
  } catch (error) {
    console.error('获取原始数据失败:', error)
    throw error
  }
}

// 启动扫描
export const startScan = async (domain: string, layer?: number): Promise<void> => {
  try {
    await api.post(`/start_scan`, { domain, layer })
  } catch (error) {
    console.error('启动扫描失败:', error)
    throw error
  }
}

// 停止扫描
export const stopScan = async (domain: string): Promise<void> => {
  try {
    await api.post(`/stop_scan`, { domain })
  } catch (error) {
    console.error('停止扫描失败:', error)
    throw error
  }
}

// 目标管理API
export const fetchTargets = async (): Promise<any> => {
  try {
    const response = await api.get('/targets')
    return response.data
  } catch (error) {
    console.error('获取目标列表失败:', error)
    throw error
  }
}

export const addTarget = async (domain: string, notes?: string): Promise<any> => {
  try {
    const response = await api.post('/targets', { domain, notes })
    return response.data
  } catch (error) {
    console.error('添加目标失败:', error)
    throw error
  }
}

export const deleteTarget = async (targetId: number): Promise<any> => {
  try {
    const response = await api.delete(`/targets/${targetId}`)
    if (response.status === 200) {
      return response.data
    } else {
      throw new Error(`删除失败: HTTP ${response.status}`)
    }
  } catch (error: any) {
    console.error('删除目标失败:', error)
    if (error.response) {
      // 服务器返回错误
      throw new Error(error.response.data?.error || `删除失败: ${error.response.status}`)
    } else if (error.request) {
      // 网络错误
      throw new Error('网络连接失败，请检查网络或稍后重试')
    } else {
      // 其他错误
      throw new Error(error.message || '删除失败，未知错误')
    }
  }
}

export const updateTarget = async (targetId: number, data: { notes?: string; status?: string }): Promise<any> => {
  try {
    const response = await api.put(`/targets/${targetId}`, data)
    return response.data
  } catch (error) {
    console.error('更新目标失败:', error)
    throw error
  }
}

export const addBatchTargets = async (domains: string[], notes?: string): Promise<any> => {
  try {
    const response = await api.post('/targets/batch', { domains, notes })
    return response.data
  } catch (error) {
    console.error('批量添加目标失败:', error)
    throw error
  }
}
