const db = require('./models');

async function syncDatabase() {
  try {
    await db.sequelize.sync({ alter: true });
    console.log('数据库同步成功');
  } catch (error) {
    console.error('数据库同步失败:', error);
  }
}

syncDatabase();
