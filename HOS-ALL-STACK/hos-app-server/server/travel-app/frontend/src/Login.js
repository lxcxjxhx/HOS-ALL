import React, { useState } from 'react';
import axios from 'axios';
import './Login.css';

const Login = () => {
  const [formData, setFormData] = useState({
    phone_number: '',
    password: ''
  });
  const [error, setError] = useState('');

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post('/api/auth/login', formData);
      localStorage.setItem('token', response.data.token);
      window.location.href = '/dashboard';
    } catch (err) {
      setError(err.response?.data?.message || err.message || '登录失败');
    }
  };

  return (
    <div className="login-container">
      <h2>登录</h2>
      {error && <p className="error">{error}</p>}
      <form onSubmit={handleSubmit}>
        <input
          type="text"
          name="phone_number"
          placeholder="手机号"
          value={formData.phone_number}
          onChange={handleChange}
          required
        />
        <input
          type="password"
          name="password"
          placeholder="密码"
          value={formData.password}
          onChange={handleChange}
          required
        />
        <button type="submit">登录</button>
      </form>
      <p>没有账号？<a href="/register">注册</a></p>
    </div>
  );
};

export default Login;
