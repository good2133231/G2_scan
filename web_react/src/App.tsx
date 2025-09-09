import { useState } from 'react'
import { Layout } from 'antd'
import DomainDetail from './components/DomainDetail'
import TargetManagement from './components/TargetManagement'
import './App.css'

const { Header, Content } = Layout

function App() {
  const [currentPage, setCurrentPage] = useState('targets')
  const [selectedDomain, setSelectedDomain] = useState<string>('')

  const handleDomainSelect = (domain: string) => {
    setSelectedDomain(domain)
    setCurrentPage('domain')
  }

  const renderContent = () => {
    switch (currentPage) {
      case 'targets':
        return <TargetManagement onDomainSelect={handleDomainSelect} />
      case 'domain':
        return <DomainDetail domain={selectedDomain} />
      default:
        return <TargetManagement onDomainSelect={handleDomainSelect} />
    }
  }

  return (
    <Layout className="app-layout">
      <Header className="app-header">
        <div className="header-content">
          <div className="logo">
            <span className="logo-icon">🛡️</span>
            <span className="logo-text">渗透扫描平台</span>
          </div>
          <nav className="nav-menu">
            <a 
              href="#" 
              className={`nav-item ${currentPage === 'targets' ? 'active' : ''}`}
              onClick={(e) => {
                e.preventDefault()
                setCurrentPage('targets')
              }}
            >
              目标管理
            </a>
            <a 
              href="#" 
              className={`nav-item ${currentPage === 'domain' ? 'active' : ''}`}
              onClick={(e) => {
                e.preventDefault()
                setCurrentPage('domain')
              }}
            >
              域名资产
            </a>
            <a href="#" className="nav-item">关系图谱</a>
            <a href="#" className="nav-item">搜索</a>
          </nav>
        </div>
      </Header>
      <Content className="app-content">
        {renderContent()}
      </Content>
    </Layout>
  )
}

export default App
