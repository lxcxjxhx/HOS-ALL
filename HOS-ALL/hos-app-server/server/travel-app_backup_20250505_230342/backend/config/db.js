const Sequelize = require('sequelize');

const sequelize = new Sequelize('travel_app', 'travel_user', 'Root123!', {
  host: 'localhost',
  dialect: 'mysql',
  logging: console.log, // 启用 SQL 日志以调试
  pool: {
    max: 5,
    min: 0,
    acquire: 30000,
    idle: 10000
  }
});

// 测试连接
sequelize.authenticate()
  .then(() => console.log('MySQL 连接成功'))
  .catch(err => console.error('MySQL 连接失败:', err.message, err.stack));

module.exports = sequelize;
