const express = require('express');
const router = express.Router();
const UserLogin = require('../models/UserLogin');

router.get('/logins', async (req, res) => {
  try {
    const logins = await UserLogin.findAll({
      where: { user_id: req.user.id },
      order: [['login_time', 'DESC']]
    });
    res.json(logins);
  } catch (error) {
    console.error('获取登录记录失败:', error);
    res.status(500).json({ message: '服务器错误' });
  }
});

module.exports = router;
