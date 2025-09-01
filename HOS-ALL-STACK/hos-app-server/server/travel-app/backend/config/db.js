const Sequelize = require('sequelize');

const sequelize = new Sequelize('travel_app', 'travel_user', 'Root123!', {
  host: 'localhost',
  dialect: 'mysql',
  logging: false
});

// 测试连接
sequelize.authenticate()
  .then(() => console.log('MySQL 连接成功'))
  .catch(err => console.error('MySQL 连接失败:', err));

module.exports = sequelize;
