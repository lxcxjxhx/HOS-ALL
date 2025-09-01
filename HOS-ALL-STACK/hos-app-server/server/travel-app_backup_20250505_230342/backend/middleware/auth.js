const jwt = require('jsonwebtoken');
const { UserLogin } = require('../models');
const { Op } = require('sequelize');

module.exports = async (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ message: '未提供令牌' });
  }

  try {
    // 从 user_logins 表查找令牌对应的 jwt_secret
    const loginSession = await UserLogin.findOne({
      where: {
        session_id: token,
        expires_at: { [Op.gt]: new Date() }
      }
    });

    if (!loginSession) {
      return res.status(401).json({ message: '令牌已过期或无效' });
    }

    // 使用动态 jwt_secret 验证令牌
    const decoded = jwt.verify(token, loginSession.jwt_secret);
    req.user = decoded; // { id, role }
    req.loginSession = loginSession; // 可选：传递会话信息
    next();
  } catch (error) {
    console.error('JWT 验证错误:', error.message);
    res.status(401).json({ message: '令牌无效' });
  }
};
