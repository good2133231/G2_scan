import React, { useState, useEffect } from 'react'
import { Card, Collapse, Typography, Tag, Button, Space, Input } from 'antd'
import { 
  FileTextOutlined, 
  InfoCircleOutlined, 
  SettingOutlined,
  BugOutlined,
  SearchOutlined,
  GlobalOutlined,
  DownloadOutlined,
  CopyOutlined
} from '@ant-design/icons'
import { fetchRawData } from '../services/api'
import { RawDataFiles, FilterType } from '../types'
import './RawData.css'

const { Panel } = Collapse
const { Text } = Typography

interface RawDataProps {
  domain: string
  activeFilter: FilterType
}

const RawData: React.FC<RawDataProps> = ({ domain, activeFilter }) => {
  const [rawData, setRawData] = useState<RawDataFiles | null>(null)
  const [loading, setLoading] = useState(false)
  const [searchTerm, setSearchTerm] = useState('')

  useEffect(() => {
    loadRawData()
  }, [domain])

  const loadRawData = async () => {
    try {
      setLoading(true)
      const data = await fetchRawData(domain)
      setRawData(data)
    } catch (error) {
      console.error('加载原始数据失败:', error)
    } finally {
      setLoading(false)
    }
  }

  const shouldShowSection = (sectionType: string) => {
    if (!activeFilter) return true
    
    const filterMap: Record<string, string[]> = {
      'urls': ['basic', 'fofa'],
      'ports': ['technical', 'vulnerability'],
      'domains': ['basic', 'fofa', 'content_mining'],
      'vulns': ['vulnerability']
    }
    
    return filterMap[activeFilter]?.includes(sectionType) || false
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      console.log('已复制到剪贴板')
    })
  }

  const downloadData = (content: string, filename: string) => {
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const highlightSearchTerm = (text: string, term: string) => {
    if (!term) return text
    
    const regex = new RegExp(`(${term})`, 'gi')
    return text.replace(regex, '<mark>$1</mark>')
  }

  const filterContent = (content: string) => {
    if (!searchTerm) return content
    
    const lines = content.split('\n')
    const filteredLines = lines.filter(line => 
      line.toLowerCase().includes(searchTerm.toLowerCase())
    )
    
    return filteredLines.join('\n')
  }

  if (loading) {
    return (
      <div className="raw-data fade-in">
        <Card loading title="原始数据">
          加载中...
        </Card>
      </div>
    )
  }

  if (!rawData) {
    return (
      <div className="raw-data fade-in">
        <Card title="原始数据">
          <Text type="secondary">暂无原始数据</Text>
        </Card>
      </div>
    )
  }

  const dataItems = [
    {
      key: 'basic',
      title: '基础信息汇总',
      icon: <InfoCircleOutlined />,
      content: rawData.basic_info,
      color: '#1890ff'
    },
    {
      key: 'technical',
      title: '扩展技术信息',
      icon: <SettingOutlined />,
      content: rawData.technical_info,
      color: '#52c41a'
    },
    {
      key: 'vulnerability',
      title: '漏洞扫描原始数据',
      icon: <BugOutlined />,
      content: rawData.vulnerability_data,
      color: '#ff4d4f'
    },
    {
      key: 'fofa',
      title: 'FOFA空间引擎数据',
      icon: <SearchOutlined />,
      content: rawData.fofa_results,
      color: '#722ed1'
    },
    {
      key: 'content_mining',
      title: '内容挖掘分析数据',
      icon: <GlobalOutlined />,
      content: rawData.content_mining,
      color: '#fa8c16'
    }
  ].filter(item => item.content && shouldShowSection(item.key))

  return (
    <div className="raw-data fade-in">
      <Card 
        title={
          <Space>
            <FileTextOutlined style={{ color: '#1890ff' }} />
            <span>原始扫描数据</span>
            {activeFilter && (
              <Tag color="blue">
                {activeFilter === 'urls' ? 'URL相关' :
                 activeFilter === 'ports' ? 'IP/端口相关' :
                 activeFilter === 'domains' ? '域名相关' :
                 activeFilter === 'vulns' ? '漏洞相关' : '全部'} 专项数据
              </Tag>
            )}
          </Space>
        }
        extra={
          <Input.Search
            placeholder="搜索数据内容..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{ width: 250 }}
            allowClear
          />
        }
      >
        {dataItems.length === 0 ? (
          <div className="empty-data">
            <FileTextOutlined style={{ fontSize: 48, color: '#d9d9d9' }} />
            <Text type="secondary">
              {activeFilter ? '当前过滤条件下暂无数据' : '暂无原始数据'}
            </Text>
          </div>
        ) : (
          <Collapse 
            defaultActiveKey={dataItems.map(item => item.key)}
            className="raw-data-collapse"
          >
            {dataItems.map((item) => {
              const filteredContent = filterContent(item.content || '')
              
              return (
                <Panel
                  key={item.key}
                  header={
                    <Space>
                      <span style={{ color: item.color }}>{item.icon}</span>
                      <span>{item.title}</span>
                      <Tag color={item.color}>
                        {(item.content || '').split('\n').length} 行
                      </Tag>
                      {searchTerm && filteredContent && (
                        <Tag color="blue">
                          匹配 {filteredContent.split('\n').length} 行
                        </Tag>
                      )}
                    </Space>
                  }
                  extra={
                    <Space onClick={(e) => e.stopPropagation()}>
                      <Button
                        size="small"
                        icon={<CopyOutlined />}
                        onClick={() => copyToClipboard(item.content || '')}
                      >
                        复制
                      </Button>
                      <Button
                        size="small"
                        icon={<DownloadOutlined />}
                        onClick={() => downloadData(
                          item.content || '', 
                          `${domain}_${item.key}_${new Date().toISOString().slice(0, 10)}.txt`
                        )}
                      >
                        下载
                      </Button>
                    </Space>
                  }
                >
                  <div className="raw-data-content">
                    {filteredContent ? (
                      <pre 
                        dangerouslySetInnerHTML={{
                          __html: highlightSearchTerm(filteredContent, searchTerm)
                        }}
                      />
                    ) : (
                      <Text type="secondary">
                        {searchTerm ? '没有找到匹配的内容' : '暂无数据'}
                      </Text>
                    )}
                  </div>
                </Panel>
              )
            })}
          </Collapse>
        )}
      </Card>
    </div>
  )
}

export default RawData
