const { UserLogin } = require('../models');
const { Op } = require('sequelize');

async function cleanupExpiredSessions() {
  try {
    const deleted = await UserLogin.destroy({
      where: { expires_at: { [Op.lt]: new Date() } }
    });
    console.log(`已删除 ${deleted} 条过期会话`);
  } catch (error) {
    console.error('清理会话错误:', error);
  }
}

// 每小时运行一次
setInterval(cleanupExpiredSessions, 60 * 60 * 1000);

// 立即运行一次
cleanupExpiredSessions();

module.exports = cleanupExpiredSessions;
