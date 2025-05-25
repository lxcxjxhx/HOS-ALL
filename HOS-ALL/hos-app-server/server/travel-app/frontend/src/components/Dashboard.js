import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { Bar } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend } from 'chart.js';
import './Dashboard.css';

ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

const Dashboard = () => {
  const [stats, setStats] = useState({ loginStats: [], preferenceStats: [], topPosts: [] });
  const [error, setError] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token) {
      navigate('/login');
      return;
    }

    axios
      .get('http://localhost:5000/api/audit/stats', {
        headers: { Authorization: `Bearer ${token}` },
      })
      .then((res) => setStats(res.data))
      .catch((err) => {
        setError(err.response?.data?.message || '获取统计数据失败');
        if (err.response?.status === 401) navigate('/login');
      });
  }, [navigate]);

  const chartData = {
    labels: stats.preferenceStats.map((stat) => stat.action),
    datasets: [
      {
        label: '行为次数',
        data: stats.preferenceStats.map((stat) => stat.count),
        backgroundColor: 'rgba(75, 192, 192, 0.2)',
        borderColor: 'rgba(75, 192, 192, 1)',
        borderWidth: 1,
      },
    ],
  };

  return (
    <div className="dashboard-container">
      <h2>仪表盘</h2>
      {error && <p className="error">{error}</p>}
      <button onClick={() => navigate('/audit-logs')}>查看审计日志</button>
      <h3>用户行为统计</h3>
      <div className="chart">
        <Bar data={chartData} options={{ responsive: true }} />
      </div>
      <h3>热门游记</h3>
      <ul>
        {stats.topPosts.map((post) => (
          <li key={post.post_id}>
            {post.Post?.title || '未知游记'} - 分数: {post.score}
          </li>
        ))}
      </ul>
      <h3>用户登录统计</h3>
      <ul>
        {stats.loginStats.map((stat) => (
          <li key={stat.user_id}>
            {stat.User?.username || '未知用户'} - 登录次数: {stat.count}
          </li>
        ))}
      </ul>
    </div>
  );
};

export default Dashboard;
