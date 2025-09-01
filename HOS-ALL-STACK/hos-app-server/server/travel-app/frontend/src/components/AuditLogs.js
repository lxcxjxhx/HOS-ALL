import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import './AuditLogs.css';

const AuditLogs = () => {
  const [logs, setLogs] = useState({ logins: [], preferences: [] });
  const [error, setError] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token) {
      navigate('/login');
      return;
    }

    axios
      .get('http://localhost:5000/api/audit/logs', {
        headers: { Authorization: `Bearer ${token}` },
      })
      .then((res) => setLogs(res.data))
      .catch((err) => {
        setError(err.response?.data?.message || '获取日志失败');
        if (err.response?.status === 401 || err.response?.status === 403) navigate('/login');
      });
  }, [navigate]);

  return (
    <div className="audit-logs-container">
      <h2>审计日志</h2>
      {error && <p className="error">{error}</p>}
      <h3>登录记录</h3>
      <ul>
        {logs.logins.map((log) => (
          <li key={log.id}>
            {log.User?.username || '未知用户'} - 登录时间: {new Date(log.login_time).toLocaleString()} - IP: {log.ip_address || '未知'}
          </li>
        ))}
      </ul>
      <h3>用户行为</h3>
      <ul>
        {logs.preferences.map((pref) => (
          <li key={pref.id}>
            {pref.User?.username || '未知用户'} - {pref.action} - 游记: {pref.Post?.title || '未知游记'} - 时间: {new Date(pref.visited_at).toLocaleString()}
          </li>
        ))}
      </ul>
      <button onClick={() => navigate('/dashboard')}>返回仪表盘</button>
    </div>
  );
};

export default AuditLogs;
