import React, { useState, useEffect } from 'react'
import { 
  Card, 
  Table, 
  Button, 
  Modal, 
  Form, 
  Input, 
  Space, 
  Tag, 
  Popconfirm, 
  message, 
  Typography,
  Row,
  Col,
  Statistic,
  Dropdown,
  Select
} from 'antd'
import { 
  PlusOutlined, 
  DeleteOutlined, 

  PlayCircleOutlined,
  PauseCircleOutlined,
  UploadOutlined,
  GlobalOutlined,
  ClockCircleOutlined,
  CheckCircleOutlined,
  ExclamationCircleOutlined,
  DownOutlined,
  StopOutlined,
  SearchOutlined,
  FilterOutlined
} from '@ant-design/icons'
import { fetchTargets, addTarget, deleteTarget, updateTarget, addBatchTargets } from '../services/api'
import './TargetManagement.css'

const { TextArea } = Input
const { Text } = Typography

interface Target {
  id: number
  domain: string
  status: 'pending' | 'scanning' | 'completed' | 'failed' | 'paused'
  created_at: string
  updated_at: string
  scan_progress: number
  current_stage: string
  last_scan_time?: string
  notes: string
}

interface TargetManagementProps {
  onDomainSelect: (domain: string) => void
}

const TargetManagement: React.FC<TargetManagementProps> = ({ onDomainSelect }) => {
  const [targets, setTargets] = useState<Target[]>([])
  const [loading, setLoading] = useState(false)
  const [addModalVisible, setAddModalVisible] = useState(false)
  const [batchModalVisible, setBatchModalVisible] = useState(false)
  const [editModalVisible, setEditModalVisible] = useState(false)
  const [editingTarget, setEditingTarget] = useState<Target | null>(null)
  const [form] = Form.useForm()
  
  // 批量操作状态管理
  const [selectedTargets, setSelectedTargets] = useState<number[]>([])
  const [batchLoading, setBatchLoading] = useState(false)
  const [currentPage, setCurrentPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)
  const [batchForm] = Form.useForm()
  const [editForm] = Form.useForm()
  
  // 筛选状态管理
  const [searchText, setSearchText] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [notesFilter, setNotesFilter] = useState('')

  useEffect(() => {
    loadTargets()
  }, [])

  // 筛选逻辑
  const filteredTargets = targets.filter(target => {
    // 域名搜索
    const domainMatch = target.domain.toLowerCase().includes(searchText.toLowerCase())
    
    // 状态筛选
    const statusMatch = statusFilter === 'all' || target.status === statusFilter
    
    // 备注筛选
    const notesMatch = notesFilter === '' || 
      (target.notes && target.notes.toLowerCase().includes(notesFilter.toLowerCase()))
    
    return domainMatch && statusMatch && notesMatch
  })

  const loadTargets = async () => {
    try {
      setLoading(true)
      const response = await fetchTargets()
      setTargets(response.targets)
    } catch (error) {
      message.error('加载目标列表失败')
      console.error('加载目标失败:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleAddTarget = async (values: { domain: string; notes?: string }) => {
    try {
      await addTarget(values.domain, values.notes || '')
      message.success('目标添加成功')
      setAddModalVisible(false)
      form.resetFields()
      loadTargets()
    } catch (error: any) {
      message.error(error.response?.data?.error || '添加目标失败')
    }
  }

  const handleBatchAdd = async (values: { domains: string; notes?: string }) => {
    try {
      const domainList = values.domains
        .split('\n')
        .map(d => d.trim())
        .filter(d => d.length > 0)
      
      if (domainList.length === 0) {
        message.error('请输入至少一个域名')
        return
      }

      const response = await addBatchTargets(domainList, values.notes || '')
      
      if (response.added_targets.length > 0) {
        message.success(`成功添加 ${response.added_targets.length} 个目标`)
      }
      
      if (response.failed_targets.length > 0) {
        message.warning(`${response.failed_targets.length} 个目标添加失败`)
      }

      setBatchModalVisible(false)
      batchForm.resetFields()
      loadTargets()
    } catch (error: any) {
      message.error(error.response?.data?.error || '批量添加失败')
    }
  }

  const handleDeleteTarget = async (targetId: number, domain: string) => {
    try {
      await deleteTarget(targetId)
      message.success(`目标 ${domain} 删除成功`)
      loadTargets()
    } catch (error: any) {
      message.error(error.response?.data?.error || '删除目标失败')
    }
  }

  // const handleEditTarget = (target: Target) => {
  //   setEditingTarget(target)
  //   editForm.setFieldsValue({
  //     notes: target.notes,
  //     status: target.status
  //   })
  //   setEditModalVisible(true)
  // }

  const handleUpdateTarget = async (values: { notes?: string; status?: string }) => {
    if (!editingTarget) return

    try {
      await updateTarget(editingTarget.id, values)
      message.success('目标信息更新成功')
      setEditModalVisible(false)
      setEditingTarget(null)
      editForm.resetFields()
      loadTargets()
    } catch (error: any) {
      message.error(error.response?.data?.error || '更新目标失败')
    }
  }

  // 批量暂停目标
  const handleBatchPause = async () => {
    if (selectedTargets.length === 0) {
      message.warning('请先选择要暂停的目标')
      return
    }

    setBatchLoading(true)
    try {
      let successCount = 0
      let failCount = 0

      const promises = selectedTargets.map(async (targetId) => {
        try {
          await updateTarget(targetId, { status: 'paused' })
          successCount++
        } catch (error) {
          failCount++
        }
      })

      await Promise.all(promises)
      
      if (successCount > 0) {
        message.success(`成功暂停 ${successCount} 个目标${failCount > 0 ? `，${failCount} 个失败` : ''}`)
        setSelectedTargets([])
        loadTargets()
      } else {
        message.error('批量暂停失败')
      }
    } catch (error: any) {
      message.error('批量暂停失败')
    } finally {
      setBatchLoading(false)
    }
  }

  // 批量删除目标（只能删除已暂停的）
  const handleBatchDelete = async () => {
    if (selectedTargets.length === 0) {
      message.warning('请先选择要删除的目标')
      return
    }

    // 检查选中的目标是否都已暂停
    const selectedTargetObjects = targets.filter(target => selectedTargets.includes(target.id))
    const nonPausedTargets = selectedTargetObjects.filter(target => target.status !== 'paused')
    
    if (nonPausedTargets.length > 0) {
      message.error(`有 ${nonPausedTargets.length} 个目标未暂停，请先暂停后再删除`)
      return
    }

    setBatchLoading(true)
    try {
      let successCount = 0
      let failCount = 0

      const promises = selectedTargets.map(async (targetId) => {
        try {
          await deleteTarget(targetId)
          successCount++
        } catch (error) {
          failCount++
        }
      })

      await Promise.all(promises)
      
      if (successCount > 0) {
        message.success(`成功删除 ${successCount} 个目标${failCount > 0 ? `，${failCount} 个失败` : ''}`)
        setSelectedTargets([])
        loadTargets()
      } else {
        message.error('批量删除失败')
      }
    } catch (error: any) {
      message.error('批量删除失败')
    } finally {
      setBatchLoading(false)
    }
  }

  const getStatusColor = (status: string) => {
    const colors = {
      'pending': 'default',
      'scanning': 'processing',
      'completed': 'success',
      'failed': 'error',
      'paused': 'warning'
    }
    return colors[status as keyof typeof colors] || 'default'
  }

  const getStatusIcon = (status: string) => {
    const icons = {
      'pending': <ClockCircleOutlined />,
      'scanning': <PlayCircleOutlined />,
      'completed': <CheckCircleOutlined />,
      'failed': <ExclamationCircleOutlined />,
      'paused': <PauseCircleOutlined />
    }
    return icons[status as keyof typeof icons] || <ClockCircleOutlined />
  }

  const getStatusText = (status: string) => {
    const texts = {
      'pending': '等待中',
      'scanning': '扫描中',
      'completed': '已完成',
      'failed': '失败',
      'paused': '已暂停'
    }
    return texts[status as keyof typeof texts] || status
  }

  const columns = [
    {
      title: '域名',
      dataIndex: 'domain',
      key: 'domain',
      render: (domain: string) => (
        <Space>
          <GlobalOutlined style={{ color: '#1890ff' }} />
          <Text 
            strong 
            style={{ cursor: 'pointer', color: '#1890ff' }}
            onClick={() => onDomainSelect(domain)}
          >
            {domain}
          </Text>
        </Space>
      )
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (status: string) => (
        <Tag 
          color={getStatusColor(status)}
          icon={getStatusIcon(status)}
        >
          {getStatusText(status)}
        </Tag>
      )
    },
    {
      title: '进度',
      dataIndex: 'scan_progress',
      key: 'scan_progress',
      render: (progress: number) => `${progress}%`
    },
    {
      title: '当前阶段',
      dataIndex: 'current_stage',
      key: 'current_stage',
      render: (stage: string) => stage || '-'
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (time: string) => new Date(time).toLocaleString()
    },
    {
      title: '备注',
      dataIndex: 'notes',
      key: 'notes',
      render: (notes: string) => notes || '-'
    },
    {
      title: '操作',
      key: 'actions',
      render: (_: any, record: Target) => (
        <Space>
          <Button
            type="primary"
            size="small"
            icon={<GlobalOutlined />}
            onClick={() => onDomainSelect(record.domain)}
          >
            查看详情
          </Button>
          <Button
            type="default"
            size="small"
            icon={<PlayCircleOutlined />}
            onClick={() => {/* TODO: 启动扫描 */}}
          >
            重新扫描
          </Button>
          <Popconfirm
            title="确定要删除这个目标吗？"
            description="删除后将无法恢复，相关的扫描数据也会被清除。"
            onConfirm={() => handleDeleteTarget(record.id, record.domain)}
            okText="确定"
            cancelText="取消"
          >
            <Button
              size="small"
              danger
              icon={<DeleteOutlined />}
            >
              删除
            </Button>
          </Popconfirm>
        </Space>
      )
    }
  ]

  // 统计数据
  const stats = {
    total: filteredTargets.length,
    pending: filteredTargets.filter(t => t.status === 'pending').length,
    scanning: filteredTargets.filter(t => t.status === 'scanning').length,
    completed: filteredTargets.filter(t => t.status === 'completed').length,
    failed: filteredTargets.filter(t => t.status === 'failed').length,
    totalAll: targets.length  // 保留总数用于显示
  }

  return (
    <div className="target-management">
      {/* 统计卡片 */}
      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} sm={12} md={6} lg={4.8}>
          <Card>
            <Statistic
              title="总目标数"
              value={stats.total}
              prefix={<GlobalOutlined />}
              valueStyle={{ color: '#1890ff' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6} lg={4.8}>
          <Card>
            <Statistic
              title="等待扫描"
              value={stats.pending}
              prefix={<ClockCircleOutlined />}
              valueStyle={{ color: '#faad14' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6} lg={4.8}>
          <Card>
            <Statistic
              title="扫描中"
              value={stats.scanning}
              prefix={<PlayCircleOutlined />}
              valueStyle={{ color: '#52c41a' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6} lg={4.8}>
          <Card>
            <Statistic
              title="已完成"
              value={stats.completed}
              prefix={<CheckCircleOutlined />}
              valueStyle={{ color: '#52c41a' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6} lg={4.8}>
          <Card>
            <Statistic
              title="失败"
              value={stats.failed}
              prefix={<ExclamationCircleOutlined />}
              valueStyle={{ color: '#ff4d4f' }}
            />
          </Card>
        </Col>
      </Row>

      {/* 筛选工具栏 */}
      <Card style={{ marginBottom: 16 }}>
        <Row gutter={[16, 16]} align="middle">
          <Col xs={24} sm={8} md={6}>
            <Input
              placeholder="搜索域名..."
              prefix={<SearchOutlined />}
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
              allowClear
            />
          </Col>
          <Col xs={24} sm={8} md={6}>
            <Select
              placeholder="筛选状态"
              value={statusFilter}
              onChange={setStatusFilter}
              style={{ width: '100%' }}
            >
              <Select.Option value="all">全部状态</Select.Option>
              <Select.Option value="pending">等待中</Select.Option>
              <Select.Option value="scanning">扫描中</Select.Option>
              <Select.Option value="completed">已完成</Select.Option>
              <Select.Option value="failed">失败</Select.Option>
              <Select.Option value="paused">已暂停</Select.Option>
            </Select>
          </Col>
          <Col xs={24} sm={8} md={6}>
            <Input
              placeholder="筛选备注..."
              prefix={<FilterOutlined />}
              value={notesFilter}
              onChange={(e) => setNotesFilter(e.target.value)}
              allowClear
            />
          </Col>
          <Col xs={24} sm={24} md={6}>
            <Space>
              <Button 
                onClick={() => {
                  setSearchText('')
                  setStatusFilter('all')
                  setNotesFilter('')
                }}
              >
                清空筛选
              </Button>
              <span style={{ color: '#666' }}>
                显示 {filteredTargets.length} / {targets.length} 个目标
              </span>
            </Space>
          </Col>
        </Row>
      </Card>

      {/* 主要内容 */}
      <Card
        title={
          <Space>
            <GlobalOutlined />
            <span>目标管理</span>
          </Space>
        }
        extra={
          <Space>
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={() => setAddModalVisible(true)}
            >
              添加目标
            </Button>
            <Button
              icon={<UploadOutlined />}
              onClick={() => setBatchModalVisible(true)}
            >
              批量添加
            </Button>
            <Dropdown
              menu={{
                items: [
                  {
                    key: 'batch_pause',
                    label: '批量暂停',
                    icon: <PauseCircleOutlined />,
                    onClick: handleBatchPause,
                    disabled: selectedTargets.length === 0
                  },
                  {
                    key: 'batch_delete',
                    label: '批量删除',
                    icon: <DeleteOutlined />,
                    onClick: handleBatchDelete,
                    disabled: selectedTargets.length === 0,
                    danger: true
                  }
                ]
              }}
            >
              <Button 
                loading={batchLoading} 
                disabled={selectedTargets.length === 0}
                icon={<StopOutlined />}
              >
                批量操作 ({selectedTargets.length}) <DownOutlined />
              </Button>
            </Dropdown>
          </Space>
        }
      >
        <Table
          columns={columns}
          dataSource={filteredTargets}
          rowKey="id"
          loading={loading}
          rowSelection={{
            selectedRowKeys: selectedTargets,
            onChange: (selectedRowKeys) => {
              setSelectedTargets(selectedRowKeys as number[])
            },
            getCheckboxProps: (record) => ({
              name: record.domain
            })
          }}
          pagination={{
            current: currentPage,
            pageSize: pageSize,
            total: filteredTargets.length,
            showSizeChanger: true,
            showQuickJumper: true,
            showTotal: (total, range) => {
              if (total === 0) {
                return '暂无数据'
              }
              return `显示第 ${range[0]}-${range[1]} 条，共 ${total} 条记录`
            },
            pageSizeOptions: ['10', '20', '50', '100', '200'],
            showLessItems: true,
            responsive: true,
            size: 'default',
            locale: {
              items_per_page: '条/页',
              jump_to: '跳至',
              jump_to_confirm: '确定',
              page: '页'
            },
            onChange: (page, size) => {
              setCurrentPage(page)
              if (size !== pageSize) {
                setPageSize(size)
                setCurrentPage(1) // 切换页面大小时重置到第一页
              }
            },
            onShowSizeChange: (_, size) => {
              setPageSize(size)
              setCurrentPage(1) // 切换页面大小时重置到第一页
            }
          }}
        />
      </Card>

      {/* 添加目标模态框 */}
      <Modal
        title="添加新目标"
        open={addModalVisible}
        onCancel={() => {
          setAddModalVisible(false)
          form.resetFields()
        }}
        footer={null}
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={handleAddTarget}
        >
          <Form.Item
            name="domain"
            label="域名"
            rules={[
              { required: true, message: '请输入域名' },
              { pattern: /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/, message: '请输入有效的域名格式' }
            ]}
          >
            <Input placeholder="例如: example.com" />
          </Form.Item>
          <Form.Item
            name="notes"
            label="备注"
            rules={[
              { required: true, message: '请输入备注信息' },
              { min: 2, message: '备注至少需要2个字符' },
              { max: 200, message: '备注不能超过200个字符' }
            ]}
          >
            <TextArea 
              rows={3} 
              placeholder="请输入备注信息（必填，用于标识和筛选目标）" 
              showCount
              maxLength={200}
            />
          </Form.Item>
          <Form.Item>
            <Space>
              <Button type="primary" htmlType="submit">
                添加
              </Button>
              <Button onClick={() => {
                setAddModalVisible(false)
                form.resetFields()
              }}>
                取消
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* 批量添加模态框 */}
      <Modal
        title="批量添加目标"
        open={batchModalVisible}
        onCancel={() => {
          setBatchModalVisible(false)
          batchForm.resetFields()
        }}
        footer={null}
        width={600}
      >
        <Form
          form={batchForm}
          layout="vertical"
          onFinish={handleBatchAdd}
        >
          <Form.Item
            name="domains"
            label="域名列表"
            rules={[{ required: true, message: '请输入域名列表' }]}
          >
            <TextArea
              rows={8}
              placeholder={`每行一个域名，例如：
example1.com
example2.com
example3.com`}
            />
          </Form.Item>
          <Form.Item
            name="notes"
            label="统一备注"
          >
            <TextArea rows={2} placeholder="为所有目标添加统一的备注信息（可选）" />
          </Form.Item>
          <Form.Item>
            <Space>
              <Button type="primary" htmlType="submit">
                批量添加
              </Button>
              <Button onClick={() => {
                setBatchModalVisible(false)
                batchForm.resetFields()
              }}>
                取消
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* 编辑目标模态框 */}
      <Modal
        title={`编辑目标: ${editingTarget?.domain}`}
        open={editModalVisible}
        onCancel={() => {
          setEditModalVisible(false)
          setEditingTarget(null)
          editForm.resetFields()
        }}
        footer={null}
      >
        <Form
          form={editForm}
          layout="vertical"
          onFinish={handleUpdateTarget}
        >
          <Form.Item
            name="notes"
            label="备注"
            rules={[
              { required: true, message: '请输入备注信息' },
              { min: 2, message: '备注至少需要2个字符' },
              { max: 200, message: '备注不能超过200个字符' }
            ]}
          >
            <TextArea 
              rows={3} 
              placeholder="请输入备注信息（必填）" 
              showCount
              maxLength={200}
            />
          </Form.Item>
          <Form.Item>
            <Space>
              <Button type="primary" htmlType="submit">
                更新
              </Button>
              <Button onClick={() => {
                setEditModalVisible(false)
                setEditingTarget(null)
                editForm.resetFields()
              }}>
                取消
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}

export default TargetManagement
