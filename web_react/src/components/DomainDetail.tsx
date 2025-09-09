import React, { useState, useEffect } from 'react'
import { Card, Tabs, Tag, Typography, Space, Spin } from 'antd'
import { 
  LineChartOutlined, 
  GlobalOutlined,
  ConsoleSqlOutlined,
  FileTextOutlined,
  BarChartOutlined,
} from '@ant-design/icons'
import StatsCards from './StatsCards'
import ScanResults from './ScanResults'
import TerminalLogs from './TerminalLogs'
import ScanStatus from './ScanStatus'
import RawData from './RawData'
import { DomainData, FilterType } from '../types'
import { fetchDomainData } from '../services/api'
import './DomainDetail.css'

const { Title } = Typography

interface DomainDetailProps {
  domain?: string
}

const DomainDetail: React.FC<DomainDetailProps> = ({ domain = 'mt5crm.com' }) => {
  const [loading, setLoading] = useState(true)
  const [domainData, setDomainData] = useState<DomainData | null>(null)
  const [activeTab, setActiveTab] = useState('scan')
  const [activeFilter, setActiveFilter] = useState<FilterType>(null)
  const [currentLayer, setCurrentLayer] = useState('1')



  useEffect(() => {
    loadDomainData()
  }, [domain])

  const loadDomainData = async () => {
    if (!domain) {
      setLoading(false)
      return
    }
    
    try {
      setLoading(true)
      const data = await fetchDomainData(domain)
      setDomainData(data)
    } catch (error) {
      console.error('加载域名数据失败:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleFilterChange = (filter: FilterType) => {
    setActiveFilter(filter)
    // 点击统计卡片时，只在扫描结果标签页内过滤，不切换标签
    if (activeTab !== 'scan') {
      setActiveTab('scan')
    }
  }

  const handleTabChange = (key: string) => {
    setActiveTab(key)
    // 切换标签页时清除过滤器
    if (key !== 'scan') {
      setActiveFilter(null)
    }
  }

  if (loading) {
    return (
      <div className="loading-container">
        <Spin size="large" />
        <div style={{ marginTop: 16 }}>加载中...</div>
      </div>
    )
  }

  if (!domainData) {
    return <div>数据加载失败</div>
  }

  return (
    <div className="domain-detail fade-in">
      {/* 域名标题 */}
      <Card className="domain-header-card">
        <div className="domain-header">
          <div className="domain-info">
            <Title level={2} className="domain-title">
              <GlobalOutlined style={{ marginRight: 12, color: '#409eff' }} />
              {domain}
            </Title>
            <Space>
              <Tag color="blue">{Object.keys(domainData.layers).length} 层扫描</Tag>
              <Tag color="green">2025/9/3 13:41:03</Tag>
            </Space>
          </div>
        </div>
      </Card>

      {/* 统计卡片 */}
      <StatsCards 
        domainData={domainData}
        activeFilter={activeFilter}
        onFilterChange={handleFilterChange}
      />

      {/* 主要内容标签页 */}
      <Card className="main-content-card">
        <Tabs 
          activeKey={activeTab} 
          onChange={handleTabChange}
          className="main-tabs"
          size="large"
          items={[
            {
              key: 'scan',
              label: (
                <span>
                  <BarChartOutlined />
                  扫描结果
                </span>
              ),
              children: (
                <ScanResults 
                  domainData={domainData}
                  activeFilter={activeFilter}
                  currentLayer={currentLayer}
                  onLayerChange={setCurrentLayer}
                />
              )
            },
            // 只在显示全部时显示这三个标签页
            ...(!activeFilter ? [
              {
                key: 'logs',
                label: (
                  <span>
                    <ConsoleSqlOutlined />
                    终端日志
                  </span>
                ),
                children: <TerminalLogs domain={domain} />
              },
              {
                key: 'status',
                label: (
                  <span>
                    <LineChartOutlined />
                    扫描状态
                  </span>
                ),
                children: <ScanStatus domain={domain} />
              },
              {
                key: 'rawdata',
                label: (
                  <span>
                    <FileTextOutlined />
                    原始数据
                  </span>
                ),
                children: <RawData domain={domain} activeFilter={activeFilter} />
              }
            ] : [])
          ]}
        />
      </Card>
    </div>
  )
}

export default DomainDetail
