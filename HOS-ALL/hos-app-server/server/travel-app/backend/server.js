const express = require('express');
const cors = require('cors');
const sequelize = require('./config/db');

const authRoutes = require('./routes/auth');
const auditRoutes = require('./routes/audit');
const postRoutes = require('./routes/posts'); // 新增
const authMiddleware = require('./middleware/auth');

const app = express();

// 中间件
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// 连接数据库并同步模型
sequelize.sync({ force: false }).then(() => {
  console.log('MySQL 连接成功，表已同步');
}).catch((error) => {
  console.error('MySQL 连接失败:', error);
  process.exit(1);
});

// 路由
app.use('/api/auth', authRoutes);
app.use('/api/audit', authMiddleware, auditRoutes);
app.use('/api/posts', authMiddleware, postRoutes); // 新增

// 错误处理
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: '服务器错误' });
});

const port = 5000;
app.listen(port, () => console.log(`服务器运行在端口 ${port}`));
