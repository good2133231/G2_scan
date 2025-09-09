import React from 'react'
import { Card, Row, Col, Statistic } from 'antd'
import { 
  LineChartOutlined, 
  LinkOutlined, 
  ClusterOutlined, 
  GlobalOutlined, 
  BugOutlined 
} from '@ant-design/icons'
import { DomainData, FilterType } from '../types'
import './StatsCards.css'

interface StatsCardsProps {
  domainData: DomainData
  activeFilter: FilterType
  onFilterChange: (filter: FilterType) => void
}

const StatsCards: React.FC<StatsCardsProps> = ({ 
  domainData, 
  activeFilter, 
  onFilterChange 
}) => {
  // 计算统计数据
  const calculateStats = () => {
    const layers = Object.values(domainData.layers)
    
    let totalUrls = 0
    let uniqueUrls = 0
    let duplicateUrls = 0
    let totalDomains = 0
    let totalIps = 0
    let totalVulns = 0

    layers.forEach(layer => {
      // URLs - 使用新的统计数据
      if (layer.url_analysis?.statistics) {
        totalUrls += layer.url_analysis.statistics.total_urls
        uniqueUrls += layer.url_analysis.statistics.unique_urls
        duplicateUrls += layer.url_analysis.statistics.duplicate_instances
      } else {
        // 兼容旧数据
        if (layer.urls) totalUrls += layer.urls.length
        uniqueUrls = totalUrls // 如果没有新统计，假设都是唯一的
      }
      if (layer.expand_scanned_urls) totalUrls += layer.expand_scanned_urls.length
      
      // 域名
      if (layer.expand_domains) {
        totalDomains += layer.expand_domains.length
      }
      if (layer.fofa_results) totalDomains += layer.fofa_results.length
      if (layer.content_mining) totalDomains += layer.content_mining.length
      
      // IP和端口 - 统计基础IP + 拓展IP
      if (layer.basic_ip_scan_results) totalIps += Object.keys(layer.basic_ip_scan_results).length
      if (layer.ip_scan_results) totalIps += Object.keys(layer.ip_scan_results).length
      
      // 漏洞 - 统计基础IP + 拓展IP的漏洞
      if (layer.basic_ip_scan_results) {
        Object.values(layer.basic_ip_scan_results).forEach(ipResult => {
          if (ipResult.vulnerabilities) {
            totalVulns += ipResult.vulnerabilities.length
          }
        })
      }
      if (layer.ip_scan_results) {
        Object.values(layer.ip_scan_results).forEach(ipResult => {
          if (ipResult.vulnerabilities) {
            totalVulns += ipResult.vulnerabilities.length
          }
        })
      }
    })

    return { 
      totalUrls, 
      uniqueUrls, 
      duplicateUrls, 
      totalDomains, 
      totalIps, 
      totalVulns 
    }
  }

  const stats = calculateStats()

  const statsConfig = [
    {
      key: null,
      title: '显示全部',
      value: Object.keys(domainData.layers).length,
      icon: <LineChartOutlined />,
      color: '#13C2C2'
    },
    {
      key: 'urls' as FilterType,
      title: '发现URL',
      value: stats.totalUrls,
      subtitle: `唯一:${stats.uniqueUrls} 重复:${stats.duplicateUrls}`,
      icon: <LinkOutlined />,
      color: '#409EFF'
    },
    {
      key: 'ports' as FilterType,
      title: 'IP/端口',
      value: stats.totalIps,
      icon: <ClusterOutlined />,
      color: '#E6A23C'
    },
    {
      key: 'domains' as FilterType,
      title: '扩展域名',
      value: stats.totalDomains,
      icon: <GlobalOutlined />,
      color: '#67C23A'
    },
    {
      key: 'vulns' as FilterType,
      title: '漏洞数量',
      value: stats.totalVulns,
      icon: <BugOutlined />,
      color: stats.totalVulns > 0 ? '#F56C6C' : '#909399'
    }
  ]

  return (
    <div className="stats-cards-container">
      <Row gutter={[16, 16]}>
        {statsConfig.map((stat) => (
          <Col xs={24} sm={12} md={8} lg={4.8} key={stat.key || 'all'}>
            <Card 
              className={`stat-card ${activeFilter === stat.key ? 'active' : ''}`}
              hoverable
              onClick={() => onFilterChange(stat.key)}
            >
              <div className="stat-content">
                <div 
                  className="stat-icon"
                  style={{ backgroundColor: stat.color }}
                >
                  {stat.icon}
                </div>
                <div className="stat-info">
                  <Statistic 
                    value={stat.value} 
                    valueStyle={{ 
                      fontSize: '24px', 
                      fontWeight: 'bold',
                      color: stat.color 
                    }}
                  />
                  <div className="stat-title">{stat.title}</div>
                  {stat.subtitle && (
                    <div className="stat-subtitle" style={{ 
                      fontSize: '12px', 
                      color: '#666', 
                      marginTop: '4px' 
                    }}>
                      {stat.subtitle}
                    </div>
                  )}
                </div>
              </div>
            </Card>
          </Col>
        ))}
      </Row>
      
      {activeFilter && (
        <div className="filter-indicator">
          <span>
            点击上方统计卡片可过滤显示对应内容 
            当前模式: <strong>{statsConfig.find(s => s.key === activeFilter)?.title} 过滤模式</strong>
          </span>
        </div>
      )}
      
      {!activeFilter && (
        <div className="filter-indicator">
          <span>
            点击上方统计卡片可过滤显示对应内容 
            当前模式: <strong>显示全部</strong>
          </span>
        </div>
      )}
    </div>
  )
}

export default StatsCards
