import React, { useState, useEffect } from 'react'
import { Card, Progress, Tag, Row, Col, Timeline, Button, Space, Statistic } from 'antd'
import { 
  BarChartOutlined, 
  PlayCircleOutlined, 
  PauseCircleOutlined,
  ClockCircleOutlined,
  CheckCircleOutlined,
  ExclamationCircleOutlined,
  SyncOutlined
} from '@ant-design/icons'
import { fetchScanStatus, startScan, stopScan } from '../services/api'
import { ScanStatus as ScanStatusType } from '../types'
import './ScanStatus.css'

interface ScanStatusProps {
  domain: string
}

const ScanStatus: React.FC<ScanStatusProps> = ({ domain }) => {
  const [scanStatus, setScanStatus] = useState<ScanStatusType | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    loadScanStatus()
    // 只有在扫描进行中时才设置定时刷新
    let interval: number | null = null
    
    const setupInterval = () => {
      if (scanStatus && !scanStatus.scan_completed) {
        interval = setInterval(loadScanStatus, 5000) // 增加间隔到5秒
      }
    }
    
    setupInterval()
    
    return () => {
      if (interval) clearInterval(interval)
    }
  }, [domain, scanStatus?.scan_completed])

  const loadScanStatus = async () => {
    try {
      const status = await fetchScanStatus(domain)
      setScanStatus(status)
    } catch (error) {
      console.error('加载扫描状态失败:', error)
    }
  }

  const handleStartScan = async () => {
    try {
      setLoading(true)
      await startScan(domain)
      await loadScanStatus()
    } catch (error) {
      console.error('启动扫描失败:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleStopScan = async () => {
    try {
      setLoading(true)
      await stopScan(domain)
      await loadScanStatus()
    } catch (error) {
      console.error('停止扫描失败:', error)
    } finally {
      setLoading(false)
    }
  }

  const getStageLabel = (stageKey: string) => {
    const labels: Record<string, string> = {
      'subdomain_discovery': '子域名发现',
      'http_probe': 'HTTP探测',
      'vulnerability_scan': '漏洞扫描',
      'port_scan': '端口扫描',
      'expand_scan': '扩展资产扫描',
      'report_generation': '报告生成'
    }
    return labels[stageKey] || stageKey
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'success'
      case 'in_progress': return 'processing'
      case 'failed': return 'error'
      case 'pending':
      default: return 'default'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircleOutlined />
      case 'in_progress': return <SyncOutlined spin />
      case 'failed': return <ExclamationCircleOutlined />
      case 'pending':
      default: return <ClockCircleOutlined />
    }
  }

  const getStatusText = (status: string) => {
    switch (status) {
      case 'completed': return '已完成'
      case 'in_progress': return '进行中'
      case 'failed': return '失败'
      case 'pending':
      default: return '等待中'
    }
  }

  if (!scanStatus) {
    return (
      <div className="scan-status fade-in">
        <Card loading title="扫描状态">
          加载中...
        </Card>
      </div>
    )
  }

  const orderedStageKeys = [
    'subdomain_discovery',
    'http_probe', 
    'vulnerability_scan',
    'port_scan',
    'expand_scan',
    'report_generation'
  ].filter(key => scanStatus.scan_stages[key])

  return (
    <div className="scan-status fade-in">
      {/* 扫描概览 */}
      <Card 
        title={
          <Space>
            <BarChartOutlined style={{ color: '#1890ff' }} />
            <span>扫描概览</span>
            <Tag color={scanStatus.scan_completed ? 'success' : 'processing'}>
              {scanStatus.scan_completed ? '扫描完成' : '扫描中'}
            </Tag>
          </Space>
        }
        extra={
          <Space>
            <Button
              type="primary"
              icon={<PlayCircleOutlined />}
              onClick={handleStartScan}
              loading={loading}
              disabled={!scanStatus.scan_completed}
            >
              重新扫描
            </Button>
            <Button
              icon={<PauseCircleOutlined />}
              onClick={handleStopScan}
              loading={loading}
              disabled={scanStatus.scan_completed}
              danger
            >
              停止扫描
            </Button>
          </Space>
        }
      >
        <Row gutter={[24, 16]}>
          <Col xs={24} sm={8}>
            <Card size="small" className="status-card">
              <Statistic
                title="总体进度"
                value={scanStatus.progress || 0}
                suffix="%"
                valueStyle={{ color: scanStatus.scan_completed ? '#3f8600' : '#1890ff' }}
              />
              <Progress 
                percent={scanStatus.progress || 0}
                status={scanStatus.scan_completed ? 'success' : 'active'}
                size="default"
              />
            </Card>
          </Col>
          <Col xs={24} sm={8}>
            <Card size="small" className="status-card">
              <Statistic
                title="当前阶段"
                value={getStageLabel(scanStatus.current_stage)}
                valueStyle={{ fontSize: 16 }}
              />
            </Card>
          </Col>
          <Col xs={24} sm={8}>
            <Card size="small" className="status-card">
              <Statistic
                title="开始时间"
                value={scanStatus.start_time ? new Date(scanStatus.start_time).toLocaleString() : '-'}
                valueStyle={{ fontSize: 14 }}
              />
            </Card>
          </Col>
        </Row>
      </Card>

      {/* 扫描阶段进度 */}
      <Card 
        title={
          <Space>
            <ClockCircleOutlined style={{ color: '#52c41a' }} />
            <span>扫描阶段进度</span>
          </Space>
        }
        style={{ marginTop: 24 }}
      >
        <Timeline 
          mode="left"
          items={orderedStageKeys.map((stageKey) => {
            const stage = scanStatus.scan_stages[stageKey]
            if (!stage) return null as any

            return {
              key: stageKey,
              dot: getStatusIcon(stage.status),
              color: getStatusColor(stage.status),
              children: (
                <div className="timeline-content">
                  <div className="stage-header">
                    <h4>{getStageLabel(stageKey)}</h4>
                    <Tag color={getStatusColor(stage.status)}>
                      {getStatusText(stage.status)}
                    </Tag>
                  </div>
                  
                  {stage.status === 'in_progress' && (
                    <Progress 
                      percent={stage.progress || 0}
                      size="small"
                      status="active"
                    />
                  )}
                  
                  <div className="stage-details">
                    {stage.start_time && (
                      <div className="time-info">
                        <span>开始: {new Date(stage.start_time).toLocaleString()}</span>
                        {stage.end_time && (
                          <span style={{ marginLeft: 16 }}>
                            结束: {new Date(stage.end_time).toLocaleString()}
                          </span>
                        )}
                      </div>
                    )}
                    
                    {stage.details && (
                      <div className="stage-description">
                        {stage.details}
                      </div>
                    )}
                    
                    {stage.error && (
                      <div className="stage-error">
                        <ExclamationCircleOutlined style={{ marginRight: 8, color: '#ff4d4f' }} />
                        {stage.error}
                      </div>
                    )}
                  </div>
                </div>
              )
            }
          }).filter(Boolean)}
        />
      </Card>
    </div>
  )
}

export default ScanStatus
