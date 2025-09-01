import { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { Form, Input, Button, Card, Alert } from 'antd';

function Login({ setUser }) {
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);

  const onFinish = async (values) => {
    setError('');
    setLoading(true);
    try {
      const response = await axios.post('/api/login', {
        username: values.username,
        password: values.password,
      });
      if (response.data.success) {
        localStorage.setItem('username', response.data.username);
        localStorage.setItem('role', response.data.role);
        setUser({ username: response.data.username, role: response.data.role });
        navigate('/');
      } else {
        setError('无效的用户名或密码');
      }
    } catch (err) {
      setError('登录失败');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight: '90vh', height: '0vh', overflow: 'hidden', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#fff' }}>
      <Card style={{ width: 350, boxShadow: '0 2px 8px #f0f1f2' }}>
        <h2 style={{ textAlign: 'center', marginBottom: 24 }}>登录</h2>
        {error && <Alert message={error} type="error" showIcon style={{ marginBottom: 16 }} />}
        <Form
          name="login"
          onFinish={onFinish}
          layout="vertical"
        >
          <Form.Item
            label="用户名"
            name="username"
            rules={[{ required: true, message: '请输入用户名' }]}
          >
            <Input placeholder="请输入用户名" autoComplete="username" />
          </Form.Item>
          <Form.Item
            label="密码"
            name="password"
            rules={[{ required: true, message: '请输入密码' }]}
          >
            <Input.Password placeholder="请输入密码" autoComplete="current-password" />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit" block loading={loading}>
              登录
            </Button>
          </Form.Item>
        </Form>
      </Card>
    </div>
  );
}

export default Login;
