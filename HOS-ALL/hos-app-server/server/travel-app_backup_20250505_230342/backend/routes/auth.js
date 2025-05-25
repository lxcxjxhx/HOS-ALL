const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { User, UserLogin } = require('../models');
const { Op } = require('sequelize');

// 性别映射
const genderMap = {
  'male': '男',
  'female': '女',
  'other': '其他',
  '男': '男',
  '女': '女',
  '其他': '其他'
};

// 生成随机的 JWT_SECRET
const generateJwtSecret = () => {
  return crypto.randomBytes(64).toString('hex'); // 128 字符随机密钥
};

// 注册
router.post('/register', async (req, res) => {
  const { phone_number, username, password, gender, email, birth_date, role } = req.body;

  console.log('注册请求:', { phone_number, username, gender, email, birth_date, role });

  if (!phone_number || !username || !password) {
    return res.status(400).json({ message: '手机号、用户名和密码为必填项' });
  }

  if (password.length < 8) {
    return res.status(400).json({ message: '密码长度至少为8位' });
  }

  try {
    const existingUser = await User.findOne({ where: { [Op.or]: [{ phone_number }, { username }] } });
    console.log('检查现有用户:', existingUser ? existingUser.id : '无');
    if (existingUser) {
      if (existingUser.phone_number === phone_number) {
        return res.status(400).json({ message: '手机号已存在' });
      }
      if (existingUser.username === username) {
        return res.status(400).json({ message: '用户名已存在' });
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    console.log('密码哈希完成');
    const mappedGender = genderMap[gender.toLowerCase()] || '其他';

    const user = await User.create({
      phone_number,
      username,
      password: hashedPassword,
      gender: mappedGender,
      email: email || null,
      birth_date: birth_date || null,
      role: role || 'user'
    });
    console.log('用户创建:', user.id);

    const jwtSecret = generateJwtSecret();
    const token = jwt.sign({ id: user.id, role: user.role }, jwtSecret, { expiresIn: '1h' });
    console.log('JWT 生成:', token);

    await UserLogin.create({
      user_id: user.id,
      login_time: new Date(),
      ip_address: req.ip,
      device_info: req.get('User-Agent'),
      session_id: token,
      expires_at: new Date(Date.now() + 60 * 60 * 1000),
      jwt_secret: jwtSecret
    });
    console.log('会话创建');

    res.status(201).json({ token });
  } catch (error) {
    console.error('注册错误:', error.message, error.stack);
    res.status(500).json({ message: '注册失败', error: error.message });
  }
});

// 登录
router.post('/login', async (req, res) => {
  const { phone_number, password } = req.body;

  console.log('登录请求:', { phone_number });

  if (!phone_number || !password) {
    return res.status(400).json({ message: '手机号和密码为必填项' });
  }

  try {
    const user = await User.findOne({ where: { phone_number } });
    console.log('查询用户:', user ? user.id : '未找到');
    if (!user) {
      return res.status(400).json({ message: '手机号或密码错误' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    console.log('密码匹配:', isMatch);
    if (!isMatch) {
      return res.status(400).json({ message: '手机号或密码错误' });
    }

    const jwtSecret = generateJwtSecret();
    const token = jwt.sign({ id: user.id, role: user.role }, jwtSecret, { expiresIn: '1h' });
    console.log('JWT 生成:', token);

    await UserLogin.create({
      user_id: user.id,
      login_time: new Date(),
      ip_address: req.ip,
      device_info: req.get('User-Agent'),
      session_id: token,
      expires_at: new Date(Date.now() + 60 * 60 * 1000),
      jwt_secret: jwtSecret
    });
    console.log('会话创建');

    res.json({ token });
  } catch (error) {
    console.error('登录错误:', error.message, error.stack);
    res.status(500).json({ message: '登录失败', error: error.message });
  }
});

module.exports = router;
