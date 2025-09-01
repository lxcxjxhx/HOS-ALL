import React, { useState } from 'react';
import axios from 'axios';
import './Register.css';

const Register = () => {
  const [formData, setFormData] = useState({
    phone_number: '',
    username: '',
    password: '',
    gender: '',
    email: '',
    birth_date: '',
    role: 'user'
  });
  const [error, setError] = useState('');

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post('/api/auth/register', formData);
      localStorage.setItem('token', response.data.token);
      window.location.href = '/dashboard';
    } catch (err) {
      setError(err.response?.data?.message || err.message || '注册失败');
    }
  };

  return (
    <div className="register-container">
      <h2>注册</h2>
      {error && <p className="error">{error}</p>}
      <form onSubmit={handleSubmit}>
        <input type="text" name="phone_number" placeholder="手机号" value={formData.phone_number} onChange={handleChange} required />
        <input type="text" name="username" placeholder="用户名" value={formData.username} onChange={handleChange} required />
        <input type="password" name="password" placeholder="密码" value={formData.password} onChange={handleChange} required />
        <select name="gender" value={formData.gender} onChange={handleChange}>
          <option value="">选择性别</option>
          <option value="男">男</option>
          <option value="女">女</option>
          <option value="其他">其他</option>
        </select>
        <input type="email" name="email" placeholder="邮箱" value={formData.email} onChange={handleChange} />
        <input type="date" name="birth_date" value={formData.birth_date} onChange={handleChange} />
        <select name="role" value={formData.role} onChange={handleChange}>
          <option value="user">用户</option>
          <option value="admin">管理员</option>
        </select>
        <button type="submit">注册</button>
      </form>
      <p>已有账号？<a href="/login">登录</a></p>
    </div>
  );
};

export default Register;
