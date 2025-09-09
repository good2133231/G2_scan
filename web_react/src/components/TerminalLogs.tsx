import React, { useState, useEffect, useRef } from 'react'
import { Card, Switch, Button, Space, Typography, Tag, Input } from 'antd'
import { 
  ConsoleSqlOutlined, 
  PauseOutlined, 
  PlayCircleOutlined,
  ClearOutlined,
  DownloadOutlined,
  SearchOutlined
} from '@ant-design/icons'
import { fetchLogs } from '../services/api'
import { LogEntry } from '../types'
import './TerminalLogs.css'

const { Text } = Typography
const { Search } = Input

interface TerminalLogsProps {
  domain: string
}

const TerminalLogs: React.FC<TerminalLogsProps> = ({ domain }) => {
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [loading, setLoading] = useState(false)
  const [autoScroll, setAutoScroll] = useState(true)
  const [isPaused, setIsPaused] = useState(false)
  const [searchTerm, setSearchTerm] = useState('')
  const logContainerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    loadLogs()
    // 只有在未暂停时才设置定时刷新，避免对已完成扫描的无意义请求
    if (!isPaused) {
      const interval = setInterval(() => {
        loadLogs()
      }, 5000) // 增加间隔到5秒，减少请求频率

      return () => clearInterval(interval)
    }
  }, [domain, isPaused])

  useEffect(() => {
    // 自动滚动到底部
    if (autoScroll && logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight
    }
  }, [logs, autoScroll])

  const loadLogs = async () => {
    try {
      setLoading(true)
      const logData = await fetchLogs(domain)
      setLogs(logData)
    } catch (error) {
      console.error('加载日志失败:', error)
    } finally {
      setLoading(false)
    }
  }

  const getLogLevelColor = (level: string) => {
    switch (level) {
      case 'error': return '#ff4d4f'
      case 'warning': return '#faad14'
      case 'success': return '#52c41a'
      case 'info':
      default: return '#1890ff'
    }
  }

  const getLogLevelIcon = (level: string) => {
    switch (level) {
      case 'error': return '❌'
      case 'warning': return '⚠️'
      case 'success': return '✅'
      case 'info':
      default: return 'ℹ️'
    }
  }

  const filteredLogs = logs.filter(log => 
    !searchTerm || 
    log.message.toLowerCase().includes(searchTerm.toLowerCase()) ||
    log.source?.toLowerCase().includes(searchTerm.toLowerCase())
  )

  const handleClearLogs = () => {
    setLogs([])
  }

  const handleDownloadLogs = () => {
    const logText = logs.map(log => 
      `[${log.timestamp}] [${log.level.toUpperCase()}] ${log.source ? `[${log.source}] ` : ''}${log.message}`
    ).join('\n')
    
    const blob = new Blob([logText], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${domain}_logs_${new Date().toISOString().slice(0, 19)}.txt`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  return (
    <div className="terminal-logs fade-in">
      <Card 
        title={
          <Space>
            <ConsoleSqlOutlined style={{ color: '#52c41a' }} />
            <span>终端日志</span>
            <Tag color={isPaused ? 'orange' : 'green'}>
              {isPaused ? '已暂停' : '实时更新'}
            </Tag>
          </Space>
        }
        extra={
          <Space>
            <Search
              placeholder="搜索日志..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{ width: 200 }}
              prefix={<SearchOutlined />}
            />
            <Switch
              checked={autoScroll}
              onChange={setAutoScroll}
              checkedChildren="自动滚动"
              unCheckedChildren="手动滚动"
            />
            <Button
              type={isPaused ? 'primary' : 'default'}
              icon={isPaused ? <PlayCircleOutlined /> : <PauseOutlined />}
              onClick={() => setIsPaused(!isPaused)}
            >
              {isPaused ? '继续' : '暂停'}
            </Button>
            <Button
              icon={<ClearOutlined />}
              onClick={handleClearLogs}
            >
              清空
            </Button>
            <Button
              icon={<DownloadOutlined />}
              onClick={handleDownloadLogs}
              disabled={logs.length === 0}
            >
              下载
            </Button>
          </Space>
        }
      >
        <div className="log-stats">
          <Space>
            <Text type="secondary">总计: {logs.length} 条</Text>
            <Text type="secondary">显示: {filteredLogs.length} 条</Text>
            {searchTerm && (
              <Tag color="blue">搜索: {searchTerm}</Tag>
            )}
          </Space>
        </div>

        <div 
          ref={logContainerRef}
          className="log-container"
        >
          {filteredLogs.length === 0 ? (
            <div className="empty-logs">
              <ConsoleSqlOutlined style={{ fontSize: 48, color: '#d9d9d9' }} />
              <Text type="secondary">
                {searchTerm ? '没有找到匹配的日志' : '暂无日志数据'}
              </Text>
            </div>
          ) : (
            filteredLogs.map((log, index) => (
              <div 
                key={index} 
                className={`log-entry log-${log.level}`}
              >
                <div className="log-header">
                  <span className="log-icon">
                    {getLogLevelIcon(log.level)}
                  </span>
                  <span className="log-timestamp">
                    {new Date(log.timestamp).toLocaleString()}
                  </span>
                  <Tag 
                    color={getLogLevelColor(log.level)}
                  >
                    {log.level.toUpperCase()}
                  </Tag>
                  {log.source && (
                    <Tag  color="default">
                      {log.source}
                    </Tag>
                  )}
                </div>
                <div className="log-message">
                  {log.message}
                </div>
              </div>
            ))
          )}
        </div>

        {loading && (
          <div className="log-loading">
            <Text type="secondary">加载中...</Text>
          </div>
        )}
      </Card>
    </div>
  )
}

export default TerminalLogs
