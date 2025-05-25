import { useState, useEffect } from 'react';
import axios from 'axios';
import { Table, Select, Input, Button, Tag, Space, Card, Image, Modal } from 'antd';
import { CheckOutlined, CloseOutlined, DeleteOutlined, PlayCircleOutlined, LogoutOutlined } from '@ant-design/icons';
import styles from './AuditList.module.css';
import { useNavigate } from 'react-router-dom';

const { Option } = Select;

function AuditList({ user }) {
  const [diaries, setDiaries] = useState([]);
  const [statusFilter, setStatusFilter] = useState('all');
  const [titleFilter, setTitleFilter] = useState('');
  const [contentFilter, setContentFilter] = useState('');
  const [rejectReason, setRejectReason] = useState('');
  const [pagination, setPagination] = useState({
    current: 1,
    pageSize: 10,
    total: 0
  });
  const [videoModal, setVideoModal] = useState({ visible: false, url: '', poster: '' });
  const [videoCovers, setVideoCovers] = useState({});
  const navigate = useNavigate();

  useEffect(() => {
    fetchDiaries();
  }, [statusFilter, pagination.current, pagination.pageSize]);

  const fetchDiaries = async () => {
    try {
      const username = localStorage.getItem('username');
      const response = await axios.get(`/api/diaries?status=${statusFilter}&username=${username}&page=${pagination.current}&pageSize=${pagination.pageSize}&title=${encodeURIComponent(titleFilter)}&content=${encodeURIComponent(contentFilter)}`);
      setDiaries(response.data);
      setPagination(prev => ({
        ...prev,
        total: response.data.total
      }));
    } catch (error) {
      console.error('获取游记失败:', error);
    }
  };

  const handleAction = async (id, action, reason = null) => {
    try {
      const username = localStorage.getItem('username');
      await axios.put(`/api/diaries/${id}`, {
        status: action,
        rejectReason: reason,
        username,
      });
      fetchDiaries();
    } catch (error) {
      console.error('操作失败:', error);
    }
  };

  const getStatusTag = (status) => {
    switch (status) {
      case 'approved':
        return <Tag color="success">已通过</Tag>;
      case 'rejected':
        return <Tag color="error">未通过</Tag>;
      case 'pedding':
        return <Tag color="warning">待审核</Tag>;
      default:
        return <Tag>未知</Tag>;
    }
  };

  const columns = [
    {
      title: '标题',
      dataIndex: 'title',
      key: 'title',
      width: 200,
    },
    {
      title: '内容',
      dataIndex: 'content',
      key: 'content',
      width: 300,
      ellipsis: true,
    },
    {
      title: '图片',
      dataIndex: 'images',
      key: 'images',
      width: 150,
      className: 'image-cell',
      render: (images) => (
        <div style={{ 
          width: '150px', 
          overflowX: 'auto',
          whiteSpace: 'nowrap',
          '&::-webkit-scrollbar': {
            height: '6px',
          },
          '&::-webkit-scrollbar-thumb': {
            backgroundColor: '#d9d9d9',
            borderRadius: '3px',
          }
        }}>
          <Image.PreviewGroup>
            <Space size={8}>
              {images?.map((img, index) => (
                <Image
                  key={index}
                  src={img}
                  alt="Diary"
                  style={{ 
                    width: '50px', 
                    height: '75px', 
                    objectFit: 'cover',
                    display: 'inline-block',
                    flexShrink: 0,
                    cursor: 'pointer'
                  }}
                  preview={{
                    mask: false,
                    maskClassName: 'custom-image-mask',
                    rootClassName: 'custom-image-preview',
                    toolbarRender: () => null,
                    countRender: () => null
                  }}
                />
              ))}
            </Space>
          </Image.PreviewGroup>
        </div>
      ),
    },
    {
      title: '视频',
      dataIndex: 'video',
      key: 'video',
      width: 120,
      align: 'center',
      render: (video, record) => {
        if (!video) return null;
        // 封面优先取 images[0]，没有则用默认
        const poster = record.images && record.images.length > 0 ? record.images[0] : 'https://via.placeholder.com/120x75?text=Video';
        return (
          <div style={{ position: 'relative', display: 'inline-block', cursor: 'pointer' }}
            onClick={() => setVideoModal({ visible: true, url: video, poster })}
          >
            <img
              src={poster}
              alt="视频封面"
              style={{ width: 50, height: 75, objectFit: 'cover', borderRadius: 4, border: '1px solid #eee' }}
            />
            <PlayCircleOutlined style={{
              position: 'absolute',
              left: '50%',
              top: '50%',
              transform: 'translate(-50%, -50%)',
              fontSize: 28,
              color: 'rgba(0,0,0,0.7)'
            }} />
          </div>
        );
      }
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: (status) => getStatusTag(status),
      align: 'center',
    },
    {
      title: '发布时间',
      dataIndex: 'createdAt',
      key: 'createdAt',
      width: 160,
      align: 'center',
      sorter: (a, b) => new Date(a.createdAt) - new Date(b.createdAt),
      render: (val) => val ? new Date(val).toLocaleString() : '-',
    },
    {
      title: '更新时间',
      dataIndex: 'updatedAt',
      key: 'updatedAt',
      width: 160,
      align: 'center',
      sorter: (a, b) => new Date(a.updatedAt) - new Date(b.updatedAt),
      render: (val) => val ? new Date(val).toLocaleString() : '-',
    },
    {
      title: '拒绝原因',
      dataIndex: 'rejectReason',
      key: 'rejectReason',
      width: 200,
      render: (reason) => reason || '-',
    },
    {
      title: '操作',
      key: 'action',
      width: 200,
      render: (_, record) => (
        <Space>
          {record.status === 'pedding' && (
            <>
              <Button
                type="primary"
                icon={<CheckOutlined />}
                onClick={() => handleAction(record._id, 'approved')}
              >
                通过
              </Button>
              <Space>
                <Input
                  placeholder="拒绝原因"
                  onChange={(e) => setRejectReason(e.target.value)}
                  style={{ width: 120 }}
                />
                <Button
                  danger
                  icon={<CloseOutlined />}
                  onClick={() => handleAction(record._id, 'rejected', rejectReason)}
                >
                  拒绝
                </Button>
              </Space>
            </>
          )}
          {user.role === 'admin' && !record.isDeleted && (
            <Button
              danger
              icon={<DeleteOutlined />}
              onClick={() => handleAction(record._id, 'deleted')}
            >
              删除
            </Button>
          )}
        </Space>
      ),
    },
  ];

  return (
    <Card
      style={{ margin: '20px' }}
      extra={
        <Button
          type="primary"
          danger
          icon={<LogoutOutlined />}
          style={{ background: '#ff4d4f', borderColor: '#ff4d4f', color: '#fff' }}
          onClick={() => {
            localStorage.clear();
            navigate('/login');
          }}
        >退出</Button>
      }
    >
      <div style={{ marginBottom: 16 }}>
        <Space>
          <span>按状态筛选:</span>
          <Select
            value={statusFilter}
            onChange={setStatusFilter}
            style={{ width: 120 }}
          >
            <Option value="all">全部</Option>
            <Option value="pedding">待审核</Option>
            <Option value="approved">已通过</Option>
            <Option value="rejected">未通过</Option>
          </Select>
          <span>标题:</span>
          <Input
            value={titleFilter}
            onChange={e => setTitleFilter(e.target.value)}
            placeholder="请输入标题"
            style={{ width: 150 }}
            allowClear
          />
          <span>内容:</span>
          <Input
            value={contentFilter}
            onChange={e => setContentFilter(e.target.value)}
            placeholder="请输入内容"
            style={{ width: 150 }}
            allowClear
          />
          <Button type="primary" onClick={() => { setPagination(p => ({ ...p, current: 1 })); fetchDiaries(); }}>搜索</Button>
          <Button
            style={{ marginLeft: 8 }}
            onClick={() => {
              setStatusFilter('all');
              setTitleFilter('');
              setContentFilter('');
              setPagination(p => ({ ...p, current: 1 }));
              // setTimeout(() =>, 0);
              fetchDiaries()
            }}
          >重置</Button>
        </Space>
      </div>
      <Table
        columns={columns}
        dataSource={diaries}
        rowKey="_id"
        pagination={{
          ...pagination,
          onChange: (page, pageSize) => {
            setPagination(prev => ({
              ...prev,
              current: page,
              pageSize: pageSize
            }));
          },
          showSizeChanger: true,
          showTotal: (total) => `共 ${total} 条记录`
        }}
        scroll={{ x: 1300 }}
      />
      <Modal
        open={videoModal.visible}
        footer={null}
        onCancel={() => setVideoModal({ visible: false, url: '', poster: '' })}
        width={800}
        centered
        destroyOnHidden
        styles={{ padding: 0, textAlign: 'center', background: '#000' }}
      >
        <video
          src={videoModal.url}
          poster={videoModal.poster}
          controls
          autoPlay
          style={{ width: '100%', maxHeight: '70vh', background: '#000' }}
          onClick={e => {
            // 点击视频全屏
            if (e.target.requestFullscreen) e.target.requestFullscreen();
          }}
        />
      </Modal>
    </Card>
  );
}

export default AuditList;
