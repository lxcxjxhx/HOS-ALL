const db = require('./models');

async function syncDatabase() {
  try {
    // 逐个模型同步
    for (const modelName of Object.keys(db)) {
      if (db[modelName].sync) {
        try {
          await db[modelName].sync({ alter: true, logging: console.log });
          console.log(`模型 ${modelName} 同步成功`);
        } catch (error) {
          console.error(`模型 ${modelName} 同步失败:`, error.message);
        }
      }
    }
    console.log('数据库同步完成');
    process.exit(0);
  } catch (error) {
    console.error('数据库同步失败:', error.message, error.stack);
    process.exit(1);
  }
}

syncDatabase();
