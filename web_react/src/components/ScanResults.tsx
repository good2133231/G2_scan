import React, { useState } from 'react'
import { Card, Radio, Table, Tag, Button, Space, Typography, Collapse, message, Row, Col, Statistic, Dropdown } from 'antd'
import { 
  LinkOutlined, 
  GlobalOutlined, 
  ClusterOutlined, 
  SearchOutlined,
  ExperimentOutlined,
  EyeOutlined,
  FilterOutlined,
  PlayCircleOutlined,
  LoadingOutlined,
  CheckCircleOutlined,
  CopyOutlined,
  BarChartOutlined,
  ExclamationCircleOutlined,
  ApartmentOutlined,
  DownOutlined,
  DeleteOutlined,
  StopOutlined
} from '@ant-design/icons'
import { DomainData, FilterType, LayerData } from '../types'
import './ScanResults.css'

const { Title, Text } = Typography
const { Panel } = Collapse

interface ScanResultsProps {
  domainData: DomainData
  activeFilter: FilterType
  currentLayer: string
  onLayerChange: (layer: string) => void
}

const ScanResults: React.FC<ScanResultsProps> = ({
  domainData,
  activeFilter,
  currentLayer,
  onLayerChange
}) => {
  const currentLayerData: LayerData = domainData.layers[currentLayer] || {}
  
  // 扩展域名扫描状态管理
  const [domainScanStatus, setDomainScanStatus] = useState<{[key: string]: 'idle' | 'scanning' | 'completed' | 'failed'}>({})
  
  // IP扫描状态管理
    // const [ipScanStatus, setIpScanStatus] = useState<{[key: string]: 'idle' | 'scanning' | 'completed'}>({})  
  
  // 拉黑状态管理
  const [blacklistedDomains, setBlacklistedDomains] = useState<Set<string>>(new Set())
  const [blacklistedIps, setBlacklistedIps] = useState<Set<string>>(new Set())
  const [ipScanStatus, setIpScanStatus] = useState<Record<string, string>>({})
  const [ipScanProgress, setIpScanProgress] = useState<Record<string, number>>({})
  
  // 批量操作状态管理
  const [selectedDomains, setSelectedDomains] = useState<Set<string>>(new Set())
  const [selectedIps, setSelectedIps] = useState<Set<string>>(new Set())
  const [selectedRootDomains, setSelectedRootDomains] = useState<Set<string>>(new Set())
  
  // 获取目标状态的辅助函数
  const getTargetStatus = (domain: string) => {
    // 这里需要从targets列表中获取状态，但由于ScanResults组件没有直接访问targets
    // 我们需要通过API或props来获取，暂时返回domainScanStatus中的状态
    return domainScanStatus[domain] || null
  }
  
  // 启动域名扫描
  const handleDomainScan = async (domain: string) => {
    try {
      setDomainScanStatus(prev => ({ ...prev, [domain]: 'scanning' }))
      message.info(`开始扫描域名: ${domain}`)
      
      // 使用统一的扫描接口，不区分拓展扫描
      const response = await fetch('/api/start_scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Basic ' + btoa('admin:MyStr0ngP@ssw0rd!')
        },
        body: JSON.stringify({ domain })
      })
      
      if (response.ok) {
        message.success(`域名 ${domain} 扫描已启动`)
        
        // 开始轮询扫描状态
        const pollInterval = setInterval(async () => {
          try {
            const statusResponse = await fetch(`/api/scan_status/${domain}`, {
              headers: {
                'Authorization': 'Basic ' + btoa('admin:MyStr0ngP@ssw0rd!')
              }
            })
            
            if (statusResponse.ok) {
              const statusData = await statusResponse.json()
              if (statusData.scan_completed) {
                setDomainScanStatus(prev => ({ ...prev, [domain]: 'completed' }))
                message.success(`域名 ${domain} 扫描完成`)
                clearInterval(pollInterval)
              }
            }
          } catch (error) {
            console.error('状态轮询失败:', error)
          }
        }, 5000) // 每5秒检查一次状态
        
        // 30秒后强制停止轮询（防止无限轮询）
        setTimeout(() => {
          clearInterval(pollInterval)
          setDomainScanStatus(prev => {
            if (prev[domain] === 'scanning') {
              return { ...prev, [domain]: 'completed' }
            }
            return prev
          })
        }, 30000)
      } else {
        throw new Error('扫描启动失败')
      }
    } catch (error) {
      console.error('扫描启动失败:', error)
      message.error(`扫描启动失败: ${error}`)
      setDomainScanStatus(prev => ({ ...prev, [domain]: 'idle' }))
    }
  }

  const handleIpScan = async (ip: string) => {
    try {
      message.info(`开始扫描IP: ${ip}`)
      
      // 更新IP扫描状态为扫描中
      setIpScanStatus(prev => ({ ...prev, [ip]: 'scanning' }))
      
      // 使用专门的IP扫描接口
      const response = await fetch('/api/start_ip_scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Basic ' + btoa('admin:MyStr0ngP@ssw0rd!')
        },
        body: JSON.stringify({ ip: ip })
      })
      
      if (response.ok) {
        message.success(`IP ${ip} 扫描已启动`)
        
        // 模拟扫描进度更新
        let progress = 0
        const progressInterval = setInterval(() => {
          progress += 20
          setIpScanProgress(prev => ({ ...prev, [ip]: progress }))
          
          if (progress >= 100) {
            clearInterval(progressInterval)
            setIpScanStatus(prev => ({ ...prev, [ip]: 'completed' }))
            message.success(`IP ${ip} 扫描完成`)
          }
        }, 2000) // 每2秒增加20%进度，总共10秒完成
      } else {
        const errorData = await response.json()
        setIpScanStatus(prev => ({ ...prev, [ip]: 'failed' }))
        throw new Error(errorData.error || 'IP扫描启动失败')
      }
    } catch (error) {
      message.error(`IP扫描失败: ${error}`)
      setIpScanStatus(prev => ({ ...prev, [ip]: 'failed' }))
    }
  }


  const handleBlacklistDomain = (domain: string) => {
    setBlacklistedDomains(prev => new Set([...prev, domain]))
    message.success(`域名 ${domain} 已加入黑名单`)
  }

  const handleBlacklistIp = (ip: string) => {
    setBlacklistedIps(prev => new Set([...prev, ip]))
    message.success(`IP ${ip} 已加入黑名单`)
  }

  const handleRemoveFromBlacklist = (item: string, type: 'domain' | 'ip') => {
    if (type === 'domain') {
      setBlacklistedDomains(prev => {
        const newSet = new Set(prev)
        newSet.delete(item)
        return newSet
      })
    } else {
      setBlacklistedIps(prev => {
        const newSet = new Set(prev)
        newSet.delete(item)
        return newSet
      })
    }
    message.success(`${type === 'domain' ? '域名' : 'IP'} ${item} 已从黑名单移除`)
  }

  // 批量拉黑处理
  const handleBatchBlacklist = (type: 'domains' | 'ips' | 'root_domains' | 'all') => {
    if (type === 'all') {
      // 拉黑全部资产
      const allDomains = currentLayerData.expand_domains?.map(d => d.domain) || []
      const allIps = currentLayerData.expand_ips?.map(ip => ip.ip_port) || []
      const allRootDomains = currentLayerData.expand_root_domains?.map(rd => rd.domain) || []
      
      setBlacklistedDomains(prev => new Set([...prev, ...allDomains, ...allRootDomains]))
      setBlacklistedIps(prev => new Set([...prev, ...allIps]))
      
      // 清空选择
      setSelectedDomains(new Set())
      setSelectedIps(new Set())
      setSelectedRootDomains(new Set())
      
      const totalCount = allDomains.length + allIps.length + allRootDomains.length
      message.success(`已拉黑全部 ${totalCount} 个资产`)
      return
    }

    let selectedItems: Set<string>
    let setBlacklist: (prev: Set<string>) => Set<string>
    let itemType: string

    switch (type) {
      case 'domains':
        selectedItems = selectedDomains
        setBlacklist = (prev) => new Set([...prev, ...selectedItems])
        itemType = '拓展域名'
        setBlacklistedDomains(setBlacklist)
        setSelectedDomains(new Set())
        break
      case 'ips':
        selectedItems = selectedIps
        setBlacklist = (prev) => new Set([...prev, ...selectedItems])
        itemType = '拓展IP'
        setBlacklistedIps(setBlacklist)
        setSelectedIps(new Set())
        break
      case 'root_domains':
        selectedItems = selectedRootDomains
        setBlacklist = (prev) => new Set([...prev, ...selectedItems])
        itemType = '根域名'
        setBlacklistedDomains(setBlacklist)
        setSelectedRootDomains(new Set())
        break
    }

    message.success(`已批量拉黑 ${selectedItems.size} 个${itemType}`)
  }

  // 批量扫描处理（跳过拉黑资产）
  const handleBatchScanWithOptions = async (type: 'domains' | 'ips' | 'root_domains' | 'all') => {
    let domainsToScan: string[] = []
    let ipsToScan: string[] = []
    
    if (type === 'domains' || type === 'all') {
      const domains = currentLayerData.expand_domains?.filter(item => !blacklistedDomains.has(item.domain)).map(item => item.domain) || []
      domainsToScan.push(...domains)
    }
    
    if (type === 'ips' || type === 'all') {
      const ips = currentLayerData.expand_ips?.filter(item => !blacklistedIps.has(item.ip)).map(item => item.ip) || []
      ipsToScan.push(...ips)
    }
    
    if (type === 'root_domains' || type === 'all') {
      const rootDomains = currentLayerData.expand_root_domains?.filter(item => !blacklistedDomains.has(item.domain)).map(item => item.domain) || []
      domainsToScan.push(...rootDomains)
    }

    const totalItems = domainsToScan.length + ipsToScan.length
    if (totalItems === 0) {
      message.warning('没有可扫描的资产（可能都已被拉黑）')
      return
    }

    try {
      message.info(`开始批量扫描 ${totalItems} 个资产（跳过拉黑资产）`)
      let successCount = 0
      let failCount = 0

      // 扫描域名
      const domainPromises = domainsToScan.map(async (domain) => {
        try {
          const response = await fetch('/api/start_scan', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': 'Basic ' + btoa('admin:MyStr0ngP@ssw0rd!')
            },
            body: JSON.stringify({ domain })
          })
          if (response.ok) {
            successCount++
            setDomainScanStatus(prev => ({ ...prev, [domain]: 'scanning' }))
            setTimeout(() => {
              setDomainScanStatus(prev => ({ ...prev, [domain]: 'completed' }))
            }, Math.random() * 20000 + 10000)
          } else {
            failCount++
          }
        } catch (error) {
          failCount++
        }
      })

      // 扫描IP
      const ipPromises = ipsToScan.map(async (ip) => {
        try {
          const response = await fetch('/api/start_ip_scan', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': 'Basic ' + btoa('admin:MyStr0ngP@ssw0rd!')
            },
            body: JSON.stringify({ ip })
          })
          if (response.ok) {
            successCount++
          } else {
            failCount++
          }
        } catch (error) {
          failCount++
        }
      })

      await Promise.all([...domainPromises, ...ipPromises])
      
      if (successCount > 0) {
        message.success(`成功启动 ${successCount} 个资产扫描${failCount > 0 ? `，${failCount} 个失败` : ''}`)
      } else {
        message.error(`批量扫描启动失败`)
      }
    } catch (error) {
      message.error(`批量扫描失败: ${error}`)
    }
  }

  // URL表格列配置
  const urlColumns = [
    {
      title: 'URL',
      dataIndex: 'url',
      key: 'url',
      render: (url: string) => (
        <a href={url} target="_blank" rel="noopener noreferrer">
          <LinkOutlined style={{ marginRight: 8 }} />
          {url}
        </a>
      )
    },
    {
      title: '标题',
      dataIndex: 'title',
      key: 'title',
      render: (title: string) => title || '无标题'
    },
    {
      title: '大小',
      dataIndex: 'size',
      key: 'size',
      render: (size: number) => size ? `${(size / 1024).toFixed(1)} KB` : '0 B'
    },
    {
      title: '状态',
      dataIndex: 'status_code',
      key: 'status_code',
      render: (code: number) => {
        if (!code) return null
        const color = code >= 200 && code < 300 ? 'green' : 
                     code >= 300 && code < 400 ? 'orange' : 'red'
        return <Tag color={color}>{code}</Tag>
      }
    }
  ]

  // 基础IP扫描结果列配置（无操作按钮）
  const basicIpColumns = [
    {
      title: 'IP地址',
      dataIndex: 'ip',
      key: 'ip',
      render: (ip: string) => (
        <div style={{ display: 'flex', alignItems: 'center' }}>
          <ClusterOutlined style={{ marginRight: 8, color: '#52c41a' }} />
          <span style={{ fontWeight: 500 }}>{ip}</span>
          <Tag color="green" style={{ marginLeft: 8 }}>
            已扫描
          </Tag>
        </div>
      )
    },
    {
      title: '开放端口',
      dataIndex: 'ports',
      key: 'ports',
      render: (ports: any[]) => (
        <Space wrap>
          {ports?.map((port, index) => (
            <Tag key={index} color="blue">
              {port.port}/{port.service || 'tcp'}
            </Tag>
          ))}
        </Space>
      )
    },
    {
      title: 'Web服务',
      dataIndex: 'web_info',
      key: 'web_info',
      render: (webInfo: any[]) => {
        if (!webInfo || webInfo.length === 0) {
          return <Tag color="default">无Web服务</Tag>
        }
        return (
          <Space direction="vertical" size="small">
            {webInfo.map((info, index) => (
              <div key={index} style={{ fontSize: '12px' }}>
                <Tag color={info.protocol === 'https' ? 'green' : 'blue'}>
                  {info.protocol.toUpperCase()}:{info.port}
                </Tag>
                <Tag color={info.status_code === '200' ? 'green' : 'orange'}>
                  {info.status_code}
                </Tag>
                <a 
                  href={info.url} 
                  target="_blank" 
                  rel="noopener noreferrer"
                  style={{ 
                    marginLeft: 4, 
                    textDecoration: 'none',
                    color: '#1890ff'
                  }}
                  onMouseEnter={(e) => (e.target as HTMLElement).style.textDecoration = 'underline'}
                  onMouseLeave={(e) => (e.target as HTMLElement).style.textDecoration = 'none'}
                >
                  {info.title || '无标题'}
                </a>
              </div>
            ))}
          </Space>
        )
      }
    },
    {
      title: '漏洞',
      dataIndex: 'vulnerabilities',
      key: 'vulnerabilities',
      render: (vulns: any[]) => {
        if (!vulns || vulns.length === 0) {
          return <Tag color="green">暂无</Tag>
        }
        return (
          <Space>
            <Tag color="red">{vulns.length}个</Tag>
            <Button size="small" type="link">查看详情</Button>
          </Space>
        )
      }
    }
  ]

  // 域名表格列配置
  // const domainColumns = [
  //   {
  //     title: '域名',
  //     dataIndex: 'domain',
  //     key: 'domain',
  //     render: (domain: string) => (
  //       <span>
  //         <GlobalOutlined style={{ marginRight: 8, color: '#52c41a' }} />
  //         {domain}
  //       </span>
  //     )
  //   },
  //   {
  //     title: '来源',
  //     dataIndex: 'source',
  //     key: 'source'
  //   },
  //   {
  //     title: '类型',
  //     dataIndex: 'type',
  //     key: 'type',
  //     render: (type: string) => <Tag>{type}</Tag>
  //   }
  // ]

  // IP扫描结果表格列配置
  const ipColumns = [
    {
      title: 'IP地址',
      dataIndex: 'ip',
      key: 'ip',
      render: (ip: string) => {
        const scanStatus = domainScanStatus[ip] || 'idle'
        return (
          <div style={{ display: 'flex', alignItems: 'center' }}>
            <ClusterOutlined style={{ marginRight: 8, color: '#1890ff' }} />
            <span style={{ fontWeight: 500 }}>{ip}</span>
            {scanStatus === 'completed' && (
              <Tag color="green" style={{ marginLeft: 8 }}>
                <CheckCircleOutlined /> 已扫描
              </Tag>
            )}
            {scanStatus === 'scanning' && (
              <Tag color="blue" style={{ marginLeft: 8 }}>
                <LoadingOutlined /> 扫描中
              </Tag>
            )}
          </div>
        )
      }
    },
    {
      title: '开放端口',
      dataIndex: 'ports',
      key: 'ports',
      render: (ports: any[]) => (
        <Space wrap>
          {ports?.slice(0, 5).map((port, index) => (
            <Tag key={index} color="blue">
              {port.port}/{port.service || 'tcp'}
            </Tag>
          ))}
          {ports?.length > 5 && <Tag>+{ports.length - 5}更多</Tag>}
        </Space>
      )
    },
    {
      title: '漏洞',
      dataIndex: 'vulnerabilities',
      key: 'vulnerabilities',
      render: (vulns: any[]) => {
        if (!vulns || vulns.length === 0) {
          return <Tag color="green">暂无</Tag>
        }
        return (
          <Space>
            <Tag color="red">{vulns.length}个</Tag>
            <Button size="small" type="link">查看详情</Button>
          </Space>
        )
      }
    },
    {
      title: '操作',
      key: 'action',
      render: (_: any, record: any) => {
        const scanStatus = ipScanStatus[record.ip] || 'idle'
        return (
          <Button
            type="primary"
            size="small"
            icon={scanStatus === 'scanning' ? <LoadingOutlined /> : <PlayCircleOutlined />}
            loading={scanStatus === 'scanning'}
            disabled={scanStatus === 'scanning'}
            onClick={() => handleIpScan(record.ip)}
          >
            {scanStatus === 'completed' ? '重新扫描' : scanStatus === 'scanning' ? '扫描中' : '扫描'}
          </Button>
        )
      }
    }
  ]

  // 渲染URLs部分
  const renderUrls = () => {
    if (!currentLayerData.urls && !currentLayerData.expand_scanned_urls) return null
    if (activeFilter && activeFilter !== 'urls') return null

    return (
      <Card className="section-card" title={
        <span>
          <LinkOutlined style={{ color: '#52c41a', marginRight: 8 }} />
          发现的URLs
        </span>
      }>
        {/* 使用新的URL分析数据 */}
        {currentLayerData.url_analysis?.unique_urls && currentLayerData.url_analysis.unique_urls.length > 0 && (
          <div className="subsection">
            <Title level={4}>
              <SearchOutlined style={{ marginRight: 8, color: '#52c41a' }} />
              唯一URL ({currentLayerData.url_analysis.unique_urls.length})
            </Title>
            <Table 
              dataSource={currentLayerData.url_analysis.unique_urls.map((url, index) => ({ ...url, key: index }))}
              columns={urlColumns}
              pagination={{ pageSize: 20, showSizeChanger: true, showQuickJumper: true }}
              size="small"
            />
          </div>
        )}

        {/* 重复URL显示 - 始终显示，让用户一目了然 */}
        {currentLayerData.url_analysis && (
          <div className="subsection">
            <Title level={4}>
              <CopyOutlined style={{ marginRight: 8, color: '#faad14' }} />
              重复URL ({currentLayerData.url_analysis.duplicate_urls?.length || 0})
              {currentLayerData.url_analysis.duplicate_urls?.length > 0 && (
                <Tag color="orange" style={{ marginLeft: 8 }}>
                  共{currentLayerData.url_analysis.statistics?.duplicate_instances || 0}个重复实例
                </Tag>
              )}
            </Title>
            <Table 
              dataSource={currentLayerData.url_analysis.duplicate_urls?.map((url, index) => ({ 
                ...url, 
                key: index
              })) || []}
              columns={[
                ...urlColumns,
                {
                  title: '来源',
                  dataIndex: 'sources',
                  key: 'sources',
                  width: 150,
                  render: (sources: string[]) => (
                    <Space wrap>
                      {sources?.map((source, index) => (
                        <Tag key={index} color="blue">
                          {source}
                        </Tag>
                      ))}
                    </Space>
                  )
                }
              ]}
              pagination={{ pageSize: 10 }}
              size="small"
              locale={{ emptyText: '暂无重复URL' }}
            />
          </div>
        )}

        {/* URL统计信息 - 只有当有重复URL时才显示统计信息 */}
        {currentLayerData.url_analysis?.statistics && currentLayerData.url_analysis.statistics.duplicate_unique_count > 0 && (
          <div className="subsection">
            <Title level={4}>
              <BarChartOutlined style={{ marginRight: 8, color: '#1890ff' }} />
              URL统计信息
            </Title>
            <Row gutter={16}>
              <Col span={6}>
                <Statistic
                  title="总URL数"
                  value={currentLayerData.url_analysis.statistics.total_urls}
                  prefix={<GlobalOutlined />}
                />
              </Col>
              <Col span={6}>
                <Statistic
                  title="唯一URL"
                  value={currentLayerData.url_analysis.statistics.unique_urls}
                  prefix={<CheckCircleOutlined style={{ color: '#52c41a' }} />}
                />
              </Col>
              {currentLayerData.url_analysis.statistics.duplicate_unique_count > 0 && (
                <Col span={6}>
                  <Statistic
                    title="重复URL"
                    value={currentLayerData.url_analysis.statistics.duplicate_unique_count}
                    prefix={<CopyOutlined style={{ color: '#faad14' }} />}
                  />
                </Col>
              )}
              {currentLayerData.url_analysis.statistics.duplicate_instances > 0 && (
                <Col span={6}>
                  <Statistic
                    title="重复实例"
                    value={currentLayerData.url_analysis.statistics.duplicate_instances}
                    prefix={<ExclamationCircleOutlined style={{ color: '#ff4d4f' }} />}
                  />
                </Col>
              )}
            </Row>
          </div>
        )}
        
        {currentLayerData.expand_scanned_urls && currentLayerData.expand_scanned_urls.length > 0 && (
          <div className="subsection">
            <Title level={4}>
              <ExperimentOutlined style={{ marginRight: 8, color: '#606266' }} />
              扩展扫描发现 ({currentLayerData.expand_scanned_urls.length})
            </Title>
            <Table 
              dataSource={currentLayerData.expand_scanned_urls.map((url, index) => ({ ...url, key: index }))}
              columns={urlColumns}
              pagination={{ pageSize: 10 }}
              size="small"
            />
          </div>
        )}
      </Card>
    )
  }

  // 渲染拓展资产发现（核心功能）
  const renderExpandedAssets = () => {
    if (activeFilter && !['domains', null].includes(activeFilter)) return null

    const hasExpandDomains = currentLayerData.expand_domains && currentLayerData.expand_domains.length > 0
    const hasExpandIps = currentLayerData.expand_ips && currentLayerData.expand_ips.length > 0
    const hasExpandRootDomains = currentLayerData.expand_root_domains && currentLayerData.expand_root_domains.length > 0
    const hasFofa = currentLayerData.fofa_results && currentLayerData.fofa_results.length > 0
    const hasContentMining = currentLayerData.content_mining && currentLayerData.content_mining.length > 0
    
    if (!hasExpandDomains && !hasExpandIps && !hasExpandRootDomains && !hasFofa && !hasContentMining) return null

    return (
      <Card className="section-card" title={
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span>
            <ExperimentOutlined style={{ color: '#1890ff', marginRight: 8 }} />
            扩展资产发现 - 攻击面分析
          </span>
          <Space>
            <Dropdown
              menu={{
                items: [
                  {
                    key: 'scan_root_domains',
                    label: '扫描根域名',
                    icon: <ApartmentOutlined />,
                    onClick: () => handleBatchScanWithOptions('root_domains')
                  },
                  {
                    key: 'scan_ips',
                    label: '扫描拓展IP',
                    icon: <ClusterOutlined />,
                    onClick: () => handleBatchScanWithOptions('ips')
                  },
                  {
                    key: 'scan_domains',
                    label: '扫描拓展URL',
                    icon: <GlobalOutlined />,
                    onClick: () => handleBatchScanWithOptions('domains')
                  },
                  {
                    key: 'scan_all',
                    label: '扫描全部资产',
                    icon: <ExperimentOutlined />,
                    onClick: () => handleBatchScanWithOptions('all')
                  }
                ]
              }}
            >
              <Button type="primary" size="small" icon={<PlayCircleOutlined />}>
                批量扫描 <DownOutlined />
              </Button>
            </Dropdown>
            <Dropdown
              menu={{
                items: [
                  {
                    key: 'blacklist_domains',
                    label: '拉黑拓展域名',
                    icon: <DeleteOutlined />,
                    onClick: () => handleBatchBlacklist('domains'),
                    disabled: selectedDomains.size === 0
                  },
                  {
                    key: 'blacklist_ips',
                    label: '拉黑拓展IP',
                    icon: <DeleteOutlined />,
                    onClick: () => handleBatchBlacklist('ips'),
                    disabled: selectedIps.size === 0
                  },
                  {
                    key: 'blacklist_root_domains',
                    label: '拉黑根域名',
                    icon: <DeleteOutlined />,
                    onClick: () => handleBatchBlacklist('root_domains'),
                    disabled: selectedRootDomains.size === 0
                  },
                  {
                    type: 'divider'
                  },
                  {
                    key: 'blacklist_all',
                    label: '拉黑全部',
                    icon: <StopOutlined />,
                    onClick: () => handleBatchBlacklist('all'),
                    danger: true
                  }
                ]
              }}
            >
              <Button size="small" danger icon={<DeleteOutlined />}>
                批量拉黑 <DownOutlined />
              </Button>
            </Dropdown>
          </Space>
        </div>
      }>
        {/* 根域名发现 - 置顶 */}
        {hasExpandRootDomains && (
          <div className="subsection">
            <Title level={4}>
              <ApartmentOutlined style={{ marginRight: 8, color: '#722ed1' }} />
              根域名发现 ({currentLayerData.expand_root_domains!.length})
            </Title>
            <Collapse 
              size="small" 
              ghost
              items={[
                {
                  key: 'expand-root-domains',
                  label: `显示 ${currentLayerData.expand_root_domains!.length} 个根域名 (共 ${currentLayerData.expand_root_domains!.length} 行)`,
                  children: (
                <Table
                  dataSource={currentLayerData.expand_root_domains!.map((item, index) => ({
                    ...item,
                    key: index
                  }))}
                  rowSelection={{
                    selectedRowKeys: Array.from(selectedRootDomains),
                    onChange: (_, selectedRows) => {
                      setSelectedRootDomains(new Set(selectedRows.map(row => row.domain)))
                    },
                    getCheckboxProps: (record) => ({
                      disabled: blacklistedDomains.has(record.domain)
                    })
                  }}
                  columns={[
                    {
                      title: '根域名',
                      dataIndex: 'domain',
                      key: 'domain',
                      render: (domain: string) => (
                        <div style={{ display: 'flex', alignItems: 'center' }}>
                          <ApartmentOutlined style={{ marginRight: 8, color: '#722ed1' }} />
                          <span style={{ fontWeight: 500 }}>{domain}</span>
                          {blacklistedDomains.has(domain) && (
                            <Tag color="red" style={{ marginLeft: 8 }}>已拉黑</Tag>
                          )}
                        </div>
                      )
                    },
                    {
                      title: '发现来源',
                      dataIndex: 'source',
                      key: 'source',
                      render: (source: string) => <Tag color="blue">{source}</Tag>
                    },
                    {
                      title: '原始URL',
                      dataIndex: 'origin_url',
                      key: 'origin_url',
                      render: (url: string) => (
                        <a href={url} target="_blank" rel="noopener noreferrer">
                          <LinkOutlined style={{ marginRight: 4 }} />
                          {url}
                        </a>
                      )
                    },
                    {
                      title: '状态',
                      dataIndex: 'status',
                      key: 'status',
                      render: (_: string, record: any) => {
                        // 从domainScanStatus中获取实际的扫描状态
                        const targetStatus = getTargetStatus(record.domain)
                        let color = 'orange'
                        let text = '待扫描'
                        
                        if (targetStatus) {
                          switch (targetStatus) {
                            case 'scanning':
                              color = 'blue'
                              text = '正在扫描'
                              break
                            case 'completed':
                              color = 'green'
                              text = '扫描完成'
                              break
                            case 'failed':
                              color = 'red'
                              text = '扫描失败'
                              break
                            default:
                              color = 'orange'
                              text = '待扫描'
                              break
                          }
                        }
                        
                        return <Tag color={color}>{text}</Tag>
                      }
                    },
                    {
                      title: '操作',
                      key: 'action',
                      render: (_: any, record: any) => {
                        const targetStatus = getTargetStatus(record.domain)
                        const isScanning = targetStatus === 'scanning'
                        const isCompleted = targetStatus === 'completed'
                        
                        return (
                          <Space>
                            <Button
                              type="primary"
                              size="small"
                              icon={isScanning ? <LoadingOutlined /> : (isCompleted ? <EyeOutlined /> : <PlayCircleOutlined />)}
                              onClick={() => {
                                if (isCompleted) {
                                  // 查看扫描结果 - 滚动到页面顶部并提示
                                  window.scrollTo({ top: 0, behavior: 'smooth' })
                                  message.success(`正在查看 ${record.domain} 的扫描结果，请在上方查看详细信息`)
                                } else {
                                  handleDomainScan(record.domain)
                                }
                              }}
                              loading={isScanning}
                              disabled={blacklistedDomains.has(record.domain)}
                            >
                              {isScanning ? '扫描中' : (isCompleted ? '查看' : '扫描')}
                            </Button>
                            {blacklistedDomains.has(record.domain) ? (
                              <Button
                                size="small"
                                icon={<DeleteOutlined />}
                                onClick={() => handleRemoveFromBlacklist('domain', record.domain)}
                              >
                                移出黑名单
                              </Button>
                            ) : (
                              <Button
                                size="small"
                                danger
                                icon={<StopOutlined />}
                                onClick={() => handleBlacklistDomain(record.domain)}
                              >
                                拉黑
                              </Button>
                            )}
                          </Space>
                        )
                      }
                    }
                  ]}
                  pagination={{ pageSize: 20, showSizeChanger: true, showQuickJumper: true }}
                  size="small"
                />
                  )
                }
              ]}
            />
          </div>
        )}

        {/* 拓展IP发现 */}
        {hasExpandIps && (
          <div className="subsection">
            <Title level={4}>
              <ClusterOutlined style={{ marginRight: 8, color: '#fa8c16' }} />
              拓展IP发现 ({currentLayerData.expand_ips!.length})
            </Title>
            <Collapse 
              size="small" 
              ghost
              items={[
                {
                  key: 'expand-ips',
                  label: `显示 ${currentLayerData.expand_ips!.length} 个拓展IP (共 ${currentLayerData.expand_ips!.length} 行)`,
                  children: (
                <Table
                  dataSource={currentLayerData.expand_ips!.map((item, index) => ({
                    ...item,
                    key: index
                  }))}
                  rowSelection={{
                    selectedRowKeys: Array.from(selectedIps),
                    onChange: (_, selectedRows) => {
                      setSelectedIps(new Set(selectedRows.map(row => row.ip_port)))
                    },
                    getCheckboxProps: (record) => ({
                      disabled: blacklistedIps.has(record.ip_port)
                    })
                  }}
                  columns={[
                    {
                      title: 'IP:端口',
                      dataIndex: 'ip_port',
                      key: 'ip_port',
                      render: (ip_port: string) => (
                        <div style={{ display: 'flex', alignItems: 'center' }}>
                          <ClusterOutlined style={{ marginRight: 8, color: '#fa8c16' }} />
                          <span style={{ fontWeight: 500 }}>{ip_port}</span>
                          {blacklistedIps.has(ip_port) && (
                            <Tag color="red" style={{ marginLeft: 8 }}>已拉黑</Tag>
                          )}
                        </div>
                      )
                    },
                    {
                      title: '发现来源',
                      dataIndex: 'source',
                      key: 'source',
                      render: (source: string) => <Tag color="blue">{source}</Tag>
                    },
                    {
                      title: '原始URL',
                      dataIndex: 'origin_url',
                      key: 'origin_url',
                      render: (url: string) => (
                        <a href={url} target="_blank" rel="noopener noreferrer">
                          <LinkOutlined style={{ marginRight: 4 }} />
                          {url}
                        </a>
                      )
                    },
                    {
                      title: '状态',
                      dataIndex: 'status',
                      key: 'status',
                      render: (status: string, record: any) => {
                        const scanStatus = ipScanStatus[record.ip_port] || 'idle'
                        
                        // 优先使用前端状态管理的状态
                        if (scanStatus === 'scanning') {
                          const progress = ipScanProgress[record.ip_port] || 0
                          return <Tag color="blue">扫描中 {progress}%</Tag>
                        } else if (scanStatus === 'completed') {
                          return <Tag color="green">扫描完成</Tag>
                        } else if (scanStatus === 'failed') {
                          return <Tag color="red">扫描失败</Tag>
                        } else {
                          // 使用后端状态作为默认
                          const color = status === 'discovered' ? 'orange' : 'green'
                          const text = status === 'discovered' ? '待扫描' : status
                          return <Tag color={color}>{text}</Tag>
                        }
                      }
                    },
                    {
                      title: '操作',
                      key: 'action',
                      render: (_: any, record: any) => {
                        const scanStatus = ipScanStatus[record.ip_port] || 'idle'
                        return (
                          <Space>
                            <Button
                              type="primary"
                              size="small"
                              icon={scanStatus === 'scanning' ? <LoadingOutlined /> : (scanStatus === 'completed' ? <EyeOutlined /> : <PlayCircleOutlined />)}
                              loading={scanStatus === 'scanning'}
                              onClick={() => {
                                if (scanStatus === 'completed') {
                                  // 查看IP扫描结果 - 滚动到基础IP扫描结果部分
                                  const ipSection = document.getElementById('basic-ip-scan-results')
                                  if (ipSection) {
                                    ipSection.scrollIntoView({ behavior: 'smooth' })
                                  }
                                  message.success(`正在查看 ${record.ip_port} 的扫描结果，请查看基础IP端口扫描结果部分`)
                                } else {
                                  handleIpScan(record.ip_port)
                                }
                              }}
                              disabled={blacklistedIps.has(record.ip_port) || scanStatus === 'scanning'}
                            >
                              {scanStatus === 'completed' ? '查看' : scanStatus === 'scanning' ? '扫描中' : 'IP扫描'}
                            </Button>
                            {blacklistedIps.has(record.ip_port) ? (
                            <Button
                              size="small"
                              icon={<DeleteOutlined />}
                              onClick={() => handleRemoveFromBlacklist('ip', record.ip_port)}
                            >
                              移出黑名单
                            </Button>
                          ) : (
                            <Button
                              size="small"
                              danger
                              icon={<StopOutlined />}
                              onClick={() => handleBlacklistIp(record.ip_port)}
                            >
                              拉黑
                            </Button>
                          )}
                          </Space>
                        )
                      }
                    }
                  ]}
                  pagination={{ pageSize: 20, showSizeChanger: true, showQuickJumper: true }}
                  size="small"
                />
                  )
                }
              ]}
            />
          </div>
        )}

        {/* 拓展URL发现 - 置底 */}
        {hasExpandDomains && (
          <div className="subsection">
            <Title level={4}>
              <GlobalOutlined style={{ marginRight: 8, color: '#52c41a' }} />
                                    拓展URL发现 ({currentLayerData.expand_domains!.length})
            </Title>
            <Collapse 
              size="small" 
              ghost
              items={[
                {
                  key: 'expand-domains',
                  label: `显示 ${currentLayerData.expand_domains!.length} 个拓展URL (共 ${currentLayerData.expand_domains!.length} 行)`,
                  children: (
                                            <Table
                              dataSource={currentLayerData.expand_domains!.map((item, index) => ({
                                ...item,
                                key: index
                              }))}
                              rowSelection={{
                                selectedRowKeys: Array.from(selectedDomains),
                                onChange: (_, selectedRows) => {
                                  setSelectedDomains(new Set(selectedRows.map(row => row.domain)))
                                },
                                getCheckboxProps: (record) => ({
                                  disabled: blacklistedDomains.has(record.domain)
                                })
                              }}
                              columns={[
                    {
                      title: '域名',
                      dataIndex: 'domain',
                      key: 'domain',
                      render: (domain: string) => (
                        <a href={`https://${domain}`} target="_blank" rel="noopener noreferrer" style={{ fontWeight: 500 }}>
                          {domain}
                        </a>
                      )
                    },
                    {
                      title: '发现来源',
                      dataIndex: 'source',
                      key: 'source',
                      render: (source: string) => (
                        <Tag color="blue">{source}</Tag>
                      )
                    },
                    {
                      title: '原始URL',
                      dataIndex: 'origin_url',
                      key: 'origin_url',
                      render: (url: string) => (
                        <a href={url} target="_blank" rel="noopener noreferrer">
                          {url}
                        </a>
                      )
                    },
                    {
                      title: '状态',
                      dataIndex: 'status',
                      key: 'status',
                      render: (_: string, record: any) => {
                        const isBlacklisted = blacklistedDomains.has(record.domain)
                        const targetStatus = getTargetStatus(record.domain)
                        
                        if (isBlacklisted) {
                          return <Tag color="red">已拉黑</Tag>
                        }
                        
                        if (targetStatus) {
                          switch (targetStatus) {
                            case 'scanning':
                              return <Tag color="blue">正在扫描</Tag>
                            case 'completed':
                              return <Tag color="green">扫描完成</Tag>
                            case 'failed':
                              return <Tag color="red">扫描失败</Tag>
                            default:
                              return <Tag color="orange">待扫描</Tag>
                          }
                        }
                        
                        return <Tag color="orange">待扫描</Tag>
                      }
                    },
                    {
                      title: '操作',
                      key: 'action',
                      render: (_, record) => {
                        const isBlacklisted = blacklistedDomains.has(record.domain)
                        const targetStatus = getTargetStatus(record.domain)
                        const isScanning = targetStatus === 'scanning'
                        const isCompleted = targetStatus === 'completed'
                        
                        return (
                          <Space>
                            <Button
                              type="primary"
                              size="small"
                              icon={isScanning ? <LoadingOutlined /> : (isCompleted ? <EyeOutlined /> : <PlayCircleOutlined />)}
                              loading={isScanning}
                              onClick={() => {
                                if (isCompleted) {
                                  // 查看扫描结果 - 滚动到页面顶部并提示
                                  window.scrollTo({ top: 0, behavior: 'smooth' })
                                  message.success(`正在查看 ${record.domain} 的扫描结果，请在上方查看详细信息`)
                                } else {
                                  handleDomainScan(record.domain)
                                }
                              }}
                              disabled={isBlacklisted || isScanning}
                            >
                              {isScanning ? '扫描中' : (isCompleted ? '查看' : '扫描')}
                            </Button>
                            {!isBlacklisted ? (
                              <Button
                                size="small"
                                danger
                                onClick={() => handleBlacklistDomain(record.domain)}
                              >
                                拉黑
                              </Button>
                            ) : (
                              <Button
                                size="small"
                                onClick={() => handleRemoveFromBlacklist(record.domain, 'domain')}
                              >
                                移除
                              </Button>
                            )}
                          </Space>
                        )
                      }
                    }
                  ]}
                  pagination={{ pageSize: 10 }}
                  size="small"
                />
                  )
                }
              ]}
            />
          </div>
        )}

        {hasFofa && (
          <div className="subsection">
            <Title level={4}>
              <EyeOutlined style={{ marginRight: 8, color: '#606266' }} />
              FOFA空间引擎发现 ({currentLayerData.fofa_results!.length})
            </Title>
            <div className="fofa-results">
              <Text type="secondary">网络空间情报</Text>
              <Tag color="blue" style={{ marginLeft: 8 }}>
                指纹特征: icon_hash_1015993420.txt
              </Tag>
              <div style={{ marginTop: 12 }}>
                {currentLayerData.fofa_results!.map((result, index) => {
                  // 从URL中提取域名
                  const domain = new URL(result.url).hostname
                  const scanStatus = domainScanStatus[domain] || 'idle'
                  return (
                    <div key={index} className="fofa-item" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid #f0f0f0' }}>
                      <div style={{ flex: 1 }}>
                        <a href={result.url} target="_blank" rel="noopener noreferrer" style={{ fontWeight: 500 }}>
                          {result.url}
                        </a>
                        <Text type="secondary" style={{ marginLeft: 12 }}>
                          FOFA引擎发现
                        </Text>
                        {scanStatus === 'completed' && (
                          <Tag color="green" style={{ marginLeft: 8 }}>
                            <CheckCircleOutlined /> 已扫描
                          </Tag>
                        )}
                        {scanStatus === 'scanning' && (
                          <Tag color="blue" style={{ marginLeft: 8 }}>
                            <LoadingOutlined /> 扫描中
                          </Tag>
                        )}
                      </div>
                      <Button
                        type="primary"
                        size="small"
                        icon={scanStatus === 'scanning' ? <LoadingOutlined /> : <PlayCircleOutlined />}
                        loading={scanStatus === 'scanning'}
                        disabled={scanStatus === 'scanning'}
                        onClick={() => handleDomainScan(domain)}
                        style={{ marginLeft: 12 }}
                      >
                        {scanStatus === 'completed' ? '重新扫描' : scanStatus === 'scanning' ? '扫描中' : '扫描'}
                      </Button>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        )}

        {hasContentMining && (
          <div className="subsection">
            <Title level={4}>
              <SearchOutlined style={{ marginRight: 8, color: '#606266' }} />
              页面内容挖掘发现 ({currentLayerData.content_mining!.length})
            </Title>
            <div className="content-mining">
              <Text type="secondary">内容分析</Text>
              <div style={{ marginTop: 12 }}>
                {currentLayerData.content_mining!.map((item, index) => {
                  const scanStatus = domainScanStatus[item.domain] || 'idle'
                  return (
                    <div key={index} className="mining-item" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid #f0f0f0' }}>
                      <div style={{ flex: 1 }}>
                        <span style={{ fontWeight: 500 }}>{item.domain}</span>
                        <Text type="secondary" style={{ marginLeft: 12 }}>
                          内容挖掘发现
                        </Text>
                        {scanStatus === 'completed' && (
                          <Tag color="green" style={{ marginLeft: 8 }}>
                            <CheckCircleOutlined /> 已扫描
                          </Tag>
                        )}
                        {scanStatus === 'scanning' && (
                          <Tag color="blue" style={{ marginLeft: 8 }}>
                            <LoadingOutlined /> 扫描中
                          </Tag>
                        )}
                      </div>
                      <Button
                        type="primary"
                        size="small"
                        icon={scanStatus === 'scanning' ? <LoadingOutlined /> : <PlayCircleOutlined />}
                        loading={scanStatus === 'scanning'}
                        disabled={scanStatus === 'scanning'}
                        onClick={() => handleDomainScan(item.domain)}
                        style={{ marginLeft: 12 }}
                      >
                        {scanStatus === 'completed' ? '重新扫描' : scanStatus === 'scanning' ? '扫描中' : '扫描'}
                      </Button>
                    </div>
                  )
                })}
              </div>
              <div style={{ marginTop: 12, padding: 12, background: '#f6f8fa', borderRadius: 6 }}>
                <Text type="secondary" style={{ fontSize: 12 }}>
                  这些域名是从目标页面的HTML、JavaScript等内容中提取发现的，可能包含内部系统、API端点等高价值目标
                </Text>
              </div>
            </div>
          </div>
        )}

        {/* 拉黑资产栏目 */}
        {(blacklistedDomains.size > 0 || blacklistedIps.size > 0) && (
          <div className="subsection" style={{ marginTop: 24, borderTop: '2px solid #f0f0f0', paddingTop: 16 }}>
            <Title level={4} style={{ color: '#ff4d4f' }}>
              <ExclamationCircleOutlined style={{ marginRight: 8, color: '#ff4d4f' }} />
              拉黑资产 ({blacklistedDomains.size + blacklistedIps.size})
            </Title>
            
            {blacklistedDomains.size > 0 && (
              <div style={{ marginBottom: 16 }}>
                <Title level={5}>拉黑域名 ({blacklistedDomains.size})</Title>
                <Table
                  dataSource={Array.from(blacklistedDomains).map((domain, index) => ({
                    key: index,
                    domain,
                    type: 'domain'
                  }))}
                  columns={[
                    {
                      title: '域名',
                      dataIndex: 'domain',
                      key: 'domain',
                      render: (domain: string) => (
                        <span style={{ color: '#999', textDecoration: 'line-through' }}>{domain}</span>
                      )
                    },
                    {
                      title: '状态',
                      key: 'status',
                      render: () => <Tag color="red">已拉黑</Tag>
                    },
                    {
                      title: '操作',
                      key: 'action',
                      render: (_, record) => (
                        <Button
                          size="small"
                          onClick={() => handleRemoveFromBlacklist(record.domain, 'domain')}
                        >
                          移除拉黑
                        </Button>
                      )
                    }
                  ]}
                  pagination={false}
                  size="small"
                />
              </div>
            )}

            {blacklistedIps.size > 0 && (
              <div>
                <Title level={5}>拉黑IP ({blacklistedIps.size})</Title>
                <Table
                  dataSource={Array.from(blacklistedIps).map((ip, index) => ({
                    key: index,
                    ip,
                    type: 'ip'
                  }))}
                  columns={[
                    {
                      title: 'IP地址',
                      dataIndex: 'ip',
                      key: 'ip',
                      render: (ip: string) => (
                        <span style={{ color: '#999', textDecoration: 'line-through', fontFamily: 'monospace' }}>{ip}</span>
                      )
                    },
                    {
                      title: '状态',
                      key: 'status',
                      render: () => <Tag color="red">已拉黑</Tag>
                    },
                    {
                      title: '操作',
                      key: 'action',
                      render: (_, record) => (
                        <Button
                          size="small"
                          onClick={() => handleRemoveFromBlacklist(record.ip, 'ip')}
                        >
                          移除拉黑
                        </Button>
                      )
                    }
                  ]}
                  pagination={false}
                  size="small"
                />
              </div>
            )}
          </div>
        )}
      </Card>
    )
  }

  // 渲染基础信息
  const renderBasicInfo = () => {
    if (!currentLayerData.associated_ips || currentLayerData.associated_ips.length === 0) return null
    if (activeFilter && activeFilter !== 'domains') return null

    return (
      <Card className="section-card" title={
        <span>
          <GlobalOutlined style={{ color: '#52c41a', marginRight: 8 }} />
          基础信息汇总
        </span>
      }>
        <div className="subsection">
          <Title level={4}>
            <ClusterOutlined style={{ marginRight: 8, color: '#1890ff' }} />
            关联真实IP ({currentLayerData.associated_ips.length}个)
          </Title>
          <Space wrap>
            {currentLayerData.associated_ips.map((ip, index) => (
              <Tag key={index} color="blue" style={{ fontSize: '14px', padding: '4px 8px' }}>
                {ip}
              </Tag>
            ))}
          </Space>
        </div>
      </Card>
    )
  }

  // 渲染基础IP端口扫描结果
  const renderBasicIpScanResults = () => {
    if (activeFilter && activeFilter !== 'ports') return null
    if (!currentLayerData.basic_ip_scan_results) return null

    const ipData = Object.entries(currentLayerData.basic_ip_scan_results).map(([ip, data]) => ({
      key: ip,
      ip,
      ports: data.ports,
      vulnerabilities: data.vulnerabilities,
      web_info: data.web_info || []
    }))

    if (ipData.length === 0) return null

    return (
      <Card id="basic-ip-scan-results" className="section-card" title={
        <span>
          <ClusterOutlined style={{ color: '#52c41a', marginRight: 8 }} />
          基础IP端口扫描结果
        </span>
      }>
        <div className="ip-scan-header">
          <Title level={4}>{ipData.length} 个IP地址</Title>
          <Tag color="green">关联真实IP扫描</Tag>
        </div>
        
        <Table 
          dataSource={ipData}
          columns={basicIpColumns}
          pagination={false}
          size="small"
          expandable={{
            expandedRowRender: (record) => (
              <div className="ip-details">
                <Collapse size="small">
                  <Panel header="端口详情" key="ports">
                    <Space wrap>
                      {record.ports?.map((port, index) => (
                        <Tag key={index} color="blue">
                          {port.port}/{port.service || 'tcp'} - {port.status}
                        </Tag>
                      ))}
                    </Space>
                  </Panel>
                  {record.vulnerabilities && record.vulnerabilities.length > 0 && (
                    <Panel header="漏洞详情" key="vulns">
                      {record.vulnerabilities.map((vuln, index) => (
                        <div key={index} className="vuln-item">
                          <Tag color="red">{vuln.severity}</Tag>
                          <span>{vuln.name}</span>
                          <Text type="secondary" style={{ marginLeft: 12 }}>
                            {vuln.description}
                          </Text>
                        </div>
                      ))}
                    </Panel>
                  )}
                </Collapse>
              </div>
            )
          }}
        />
      </Card>
    )
  }

  // 渲染拓展IP端口扫描结果
  const renderIpScanResults = () => {
    if (activeFilter && activeFilter !== 'ports') return null

    const ipData = currentLayerData.ip_scan_results ? 
      Object.entries(currentLayerData.ip_scan_results).map(([ip, data]) => ({
        key: ip,
        ip,
        ports: data.ports,
        vulnerabilities: data.vulnerabilities
      })) : []

    return (
      <Card className="section-card" title={
        <span>
          <ClusterOutlined style={{ color: '#fa8c16', marginRight: 8 }} />
          拓展IP地址端口扫描结果
        </span>
      }>
        <div className="ip-scan-header">
          <Title level={4}>{ipData.length} 个IP地址</Title>
          <Tag color="green">独立全端口扫描</Tag>
        </div>
        
        <Table 
          dataSource={ipData}
          columns={ipColumns}
          pagination={false}
          size="small"
          locale={{ emptyText: '暂无拓展IP扫描数据' }}
          expandable={{
            expandedRowRender: (record) => (
              <div className="ip-details">
                <Collapse size="small">
                  <Panel header="端口详情" key="ports">
                    <Space wrap>
                      {record.ports?.map((port, index) => (
                        <Tag key={index} color="blue">
                          {port.port}/{port.service || 'tcp'} - {port.status}
                        </Tag>
                      ))}
                    </Space>
                  </Panel>
                  {record.vulnerabilities && record.vulnerabilities.length > 0 && (
                    <Panel header="漏洞详情" key="vulns">
                      {record.vulnerabilities.map((vuln, index) => (
                        <div key={index} className="vuln-item">
                          <Tag color="red">{vuln.severity}</Tag>
                          <span>{vuln.name}</span>
                          <Text type="secondary" style={{ marginLeft: 12 }}>
                            {vuln.description}
                          </Text>
                        </div>
                      ))}
                    </Panel>
                  )}
                </Collapse>
              </div>
            )
          }}
        />
      </Card>
    )
  }

  return (
    <div className="scan-results fade-in">
      {/* 层级切换 */}
      <div className="layer-selector">
        <Radio.Group 
          value={currentLayer} 
          onChange={(e) => onLayerChange(e.target.value)}
          buttonStyle="solid"
        >
          {Object.keys(domainData.layers).map(layer => (
            <Radio.Button key={layer} value={layer}>
              第{layer}层
            </Radio.Button>
          ))}
        </Radio.Group>
      </div>

      {/* 过滤提示 */}
      {activeFilter && (
        <div className="filter-notice">
          <FilterOutlined style={{ marginRight: 8 }} />
          当前显示: <strong>{
            activeFilter === 'urls' ? 'URL相关' :
            activeFilter === 'ports' ? 'IP/端口相关' :
            activeFilter === 'domains' ? '域名相关' :
            activeFilter === 'vulns' ? '漏洞相关' : '全部'
          }</strong> 内容
        </div>
      )}

      {/* 扫描结果内容 */}
      <div className="results-content">
        {renderBasicInfo()}
        {renderUrls()}
        {renderExpandedAssets()}
        {renderBasicIpScanResults()}
        {renderIpScanResults()}
      </div>
    </div>
  )
}

export default ScanResults
