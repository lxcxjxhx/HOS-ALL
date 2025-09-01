const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { User, VerificationCode } = require('../models');
const { Op } = require('sequelize');
const JWT_SECRET = 'your_jwt_secret_key';

// 性别映射
const genderMap = {
  'male': '男',
  'female': '女',
  'other': '其他',
  '男': '男',
  '女': '女',
  '其他': '其他'
};

// 注册
router.post('/register', async (req, res) => {
  const { phone_number, username, password, gender, email, birth_date, role } = req.body;

  if (!phone_number || !username || !password) {
    return res.status(400).json({ message: '手机号、用户名和密码为必填项' });
  }

  if (password.length < 8) {
    return res.status(400).json({ message: '密码长度至少为8位' });
  }

  try {
    const existingUser = await User.findOne({ where: { [Op.or]: [{ phone_number }, { username }] } });
    if (existingUser) {
      if (existingUser.phone_number === phone_number) {
        return res.status(400).json({ message: '手机号已存在' });
      }
      if (existingUser.username === username) {
        return res.status(400).json({ message: '用户名已存在' });
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const mappedGender = genderMap[gender.toLowerCase()] || '其他'; // 强制映射，忽略大小写

    const user = await User.create({
      phone_number,
      username,
      password: hashedPassword,
      gender: mappedGender,
      email: email || null,
      birth_date: birth_date || null,
      role: role || 'user'
    });

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({ token });
  } catch (error) {
    console.error('注册错误:', error);
    res.status(500).json({ message: '注册失败', error: error.message });
  }
});

// 登录
router.post('/login', async (req, res) => {
  const { phone_number, password } = req.body;

  if (!phone_number || !password) {
    return res.status(400).json({ message: '手机号和密码为必填项' });
  }

  try {
    const user = await User.findOne({ where: { phone_number } });
    if (!user) {
      return res.status(400).json({ message: '手机号或密码错误' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: '手机号或密码错误' });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    console.error('登录错误:', error);
    res.status(500).json({ message: '登录失败', error: error.message });
  }
});

module.exports = router;
