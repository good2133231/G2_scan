import React, { useEffect, useRef, useState } from 'react'
import { Card, Typography, Tag, Button, Space } from 'antd'
import { 
  NodeIndexOutlined, 
  GlobalOutlined, 
  ClusterOutlined,
  LinkOutlined,
  ExpandOutlined,
  CompressOutlined
} from '@ant-design/icons'
import { DomainData } from '../types'
import './RelationshipGraph.css'

const { Text } = Typography

interface RelationshipGraphProps {
  domainData: DomainData
  currentLayer: string
}

interface GraphNode {
  id: string
  label: string
  type: 'main' | 'domain' | 'ip' | 'url'
  x: number
  y: number
  scanned?: boolean
}

interface GraphEdge {
  from: string
  to: string
  type: 'subdomain' | 'ip_resolve' | 'content_mining' | 'fofa'
}

const RelationshipGraph: React.FC<RelationshipGraphProps> = ({
  domainData,
  currentLayer
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [nodes, setNodes] = useState<GraphNode[]>([])
  const [edges, setEdges] = useState<GraphEdge[]>([])
  const [isFullscreen, setIsFullscreen] = useState(false)
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null)

  // 构建图数据
  useEffect(() => {
    const buildGraphData = () => {
      const newNodes: GraphNode[] = []
      const newEdges: GraphEdge[] = []
      const currentLayerData = domainData.layers[currentLayer] || {}

      // 主域名节点
      const mainDomain = domainData.domain
      newNodes.push({
        id: mainDomain,
        label: mainDomain,
        type: 'main',
        x: 400,
        y: 300,
        scanned: true
      })

      let nodeIndex = 1

      // 添加内容挖掘发现的域名
      if (currentLayerData.content_mining) {
        currentLayerData.content_mining.forEach((item, index) => {
          const angle = (index / currentLayerData.content_mining!.length) * 2 * Math.PI
          const radius = 150
          newNodes.push({
            id: item.domain,
            label: item.domain,
            type: 'domain',
            x: 400 + Math.cos(angle) * radius,
            y: 300 + Math.sin(angle) * radius,
            scanned: false
          })
          newEdges.push({
            from: mainDomain,
            to: item.domain,
            type: 'content_mining'
          })
        })
        nodeIndex += currentLayerData.content_mining.length
      }

      // 添加FOFA发现的域名
      if (currentLayerData.fofa_results) {
        currentLayerData.fofa_results.forEach((result, index) => {
          try {
            const domain = new URL(result.url).hostname
            if (!newNodes.find(n => n.id === domain)) {
              const angle = ((index + nodeIndex) / (currentLayerData.fofa_results!.length + nodeIndex)) * 2 * Math.PI
              const radius = 200
              newNodes.push({
                id: domain,
                label: domain,
                type: 'domain',
                x: 400 + Math.cos(angle) * radius,
                y: 300 + Math.sin(angle) * radius,
                scanned: false
              })
              newEdges.push({
                from: mainDomain,
                to: domain,
                type: 'fofa'
              })
            }
          } catch (e) {
            // 忽略无效URL
          }
        })
        nodeIndex += currentLayerData.fofa_results.length
      }

      // 添加IP节点
      if (currentLayerData.ip_scan_results) {
        Object.keys(currentLayerData.ip_scan_results).forEach((ip, index) => {
          const angle = ((index + nodeIndex) / (Object.keys(currentLayerData.ip_scan_results!).length + nodeIndex)) * 2 * Math.PI
          const radius = 120
          newNodes.push({
            id: ip,
            label: ip,
            type: 'ip',
            x: 400 + Math.cos(angle) * radius,
            y: 300 + Math.sin(angle) * radius,
            scanned: true
          })
          newEdges.push({
            from: mainDomain,
            to: ip,
            type: 'ip_resolve'
          })
        })
      }

      setNodes(newNodes)
      setEdges(newEdges)
    }

    buildGraphData()
  }, [domainData, currentLayer])

  // 绘制图形
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext('2d')
    if (!ctx) return

    // 清空画布
    ctx.clearRect(0, 0, canvas.width, canvas.height)

    // 绘制边
    edges.forEach(edge => {
      const fromNode = nodes.find(n => n.id === edge.from)
      const toNode = nodes.find(n => n.id === edge.to)
      
      if (fromNode && toNode) {
        ctx.beginPath()
        ctx.moveTo(fromNode.x, fromNode.y)
        ctx.lineTo(toNode.x, toNode.y)
        
        // 根据边的类型设置颜色
        switch (edge.type) {
          case 'content_mining':
            ctx.strokeStyle = '#1890ff'
            break
          case 'fofa':
            ctx.strokeStyle = '#52c41a'
            break
          case 'ip_resolve':
            ctx.strokeStyle = '#fa8c16'
            break
          default:
            ctx.strokeStyle = '#d9d9d9'
        }
        
        ctx.lineWidth = 2
        ctx.stroke()
      }
    })

    // 绘制节点
    nodes.forEach(node => {
      ctx.beginPath()
      ctx.arc(node.x, node.y, 20, 0, 2 * Math.PI)
      
      // 根据节点类型设置颜色
      switch (node.type) {
        case 'main':
          ctx.fillStyle = '#1890ff'
          break
        case 'domain':
          ctx.fillStyle = node.scanned ? '#52c41a' : '#faad14'
          break
        case 'ip':
          ctx.fillStyle = '#fa8c16'
          break
        default:
          ctx.fillStyle = '#d9d9d9'
      }
      
      ctx.fill()
      
      // 绘制节点边框
      ctx.strokeStyle = '#fff'
      ctx.lineWidth = 3
      ctx.stroke()
      
      // 绘制标签
      ctx.fillStyle = '#000'
      ctx.font = '12px Arial'
      ctx.textAlign = 'center'
      ctx.fillText(
        node.label.length > 15 ? node.label.substring(0, 15) + '...' : node.label,
        node.x,
        node.y + 35
      )
    })
  }, [nodes, edges])

  // 处理画布点击
  const handleCanvasClick = (event: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current
    if (!canvas) return

    const rect = canvas.getBoundingClientRect()
    const x = event.clientX - rect.left
    const y = event.clientY - rect.top

    // 检查是否点击了节点
    const clickedNode = nodes.find(node => {
      const distance = Math.sqrt((x - node.x) ** 2 + (y - node.y) ** 2)
      return distance <= 20
    })

    setSelectedNode(clickedNode || null)
  }

  const getNodeTypeIcon = (type: string) => {
    switch (type) {
      case 'main':
        return <GlobalOutlined />
      case 'domain':
        return <NodeIndexOutlined />
      case 'ip':
        return <ClusterOutlined />
      default:
        return <LinkOutlined />
    }
  }

  // const getEdgeTypeLabel = (type: string) => {
  //   switch (type) {
  //     case 'content_mining':
  //       return '内容挖掘'
  //     case 'fofa':
  //       return 'FOFA发现'
  //     case 'ip_resolve':
  //       return 'IP解析'
  //     default:
  //       return '关联'
  //   }
  // }

  return (
    <div className={`relationship-graph ${isFullscreen ? 'fullscreen' : ''}`}>
      <Card 
        title={
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>
              <NodeIndexOutlined style={{ marginRight: 8 }} />
              关系图谱 - {domainData.domain}
            </span>
            <Space>
              <Button
                size="small"
                icon={isFullscreen ? <CompressOutlined /> : <ExpandOutlined />}
                onClick={() => setIsFullscreen(!isFullscreen)}
              >
                {isFullscreen ? '退出全屏' : '全屏显示'}
              </Button>
            </Space>
          </div>
        }
        className="graph-card"
      >
        <div className="graph-container">
          <div className="graph-legend">
            <Space wrap>
              <Tag color="blue" icon={<GlobalOutlined />}>主域名</Tag>
              <Tag color="orange" icon={<NodeIndexOutlined />}>发现域名</Tag>
              <Tag color="green" icon={<NodeIndexOutlined />}>已扫描域名</Tag>
              <Tag color="volcano" icon={<ClusterOutlined />}>IP地址</Tag>
            </Space>
          </div>
          
          <canvas
            ref={canvasRef}
            width={800}
            height={600}
            onClick={handleCanvasClick}
            style={{ border: '1px solid #d9d9d9', borderRadius: '6px', cursor: 'pointer' }}
          />
          
          {selectedNode && (
            <div className="node-info">
              <Card size="small" title="节点信息">
                <Space direction="vertical" size="small">
                  <div>
                    {getNodeTypeIcon(selectedNode.type)}
                    <Text strong style={{ marginLeft: 8 }}>{selectedNode.label}</Text>
                  </div>
                  <div>
                    <Text type="secondary">类型: </Text>
                    <Tag color={selectedNode.type === 'main' ? 'blue' : selectedNode.type === 'ip' ? 'volcano' : 'orange'}>
                      {selectedNode.type === 'main' ? '主域名' : 
                       selectedNode.type === 'ip' ? 'IP地址' : '域名'}
                    </Tag>
                  </div>
                  <div>
                    <Text type="secondary">状态: </Text>
                    <Tag color={selectedNode.scanned ? 'green' : 'orange'}>
                      {selectedNode.scanned ? '已扫描' : '未扫描'}
                    </Tag>
                  </div>
                  <div>
                    <Text type="secondary">关联数: </Text>
                    <Text>{edges.filter(e => e.from === selectedNode.id || e.to === selectedNode.id).length}</Text>
                  </div>
                </Space>
              </Card>
            </div>
          )}
        </div>
        
        <div className="graph-stats">
          <Space>
            <Text type="secondary">节点总数: {nodes.length}</Text>
            <Text type="secondary">关系总数: {edges.length}</Text>
            <Text type="secondary">已扫描: {nodes.filter(n => n.scanned).length}</Text>
          </Space>
        </div>
      </Card>
    </div>
  )
}

export default RelationshipGraph
