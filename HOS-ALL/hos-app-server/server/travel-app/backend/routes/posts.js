const express = require('express');
const router = express.Router();
const zlib = require('zlib');
const util = require('util');
const { Op } = require('sequelize');
const Post = require('../models/Post');
const User = require('../models/User');

const compress = util.promisify(zlib.deflate);
const decompress = util.promisify(zlib.inflate);

// 上传游记（普通用户）
router.post('/', async (req, res) => {
  const { title, content, image } = req.body;
  const userId = req.user.id;
  const userRole = req.user.role;

  if (userRole !== 'user') {
    return res.status(403).json({ message: '仅普通用户可上传游记' });
  }

  if (!title || !content) {
    return res.status(400).json({ message: '标题和内容为必填项' });
  }

  if (title.length > 255) {
    return res.status(400).json({ message: '标题长度不能超过255个字符' });
  }

  try {
    const compressedContent = await compress(Buffer.from(content));
    const post = await Post.create({
      user_id: userId,
      title,
      content: compressedContent,
      image: image || null,
      status: 'pending'
    });
    res.status(201).json({ id: post.id, title, content, image, status: post.status });
  } catch (error) {
    console.error('上传游记错误:', error);
    res.status(500).json({ message: '上传失败', error: error.message });
  }
});

// 获取游记列表（支持搜索、排序、分页）
router.get('/', async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const offset = (page - 1) * limit;
  const search = req.query.search || '';
  const sort = req.query.sort || 'created_at';
  const order = req.query.order || 'DESC';
  const status = req.query.status || '';

  try {
    let where = {};
    if (userRole !== 'admin') {
      where.user_id = userId;
    }
    if (search) {
      where.title = { [Op.like]: `%${search}%` };
    }
    if (status) {
      where.status = status;
    }

    const posts = await Post.findAll({
      where,
      include: [{ model: User, attributes: ['username', 'phone_number'] }],
      limit,
      offset,
      order: [[sort, order]]
    });
    const total = await Post.count({ where });

    // 解压缩 content
    const decompressedPosts = await Promise.all(posts.map(async (post) => {
      const data = post.toJSON();
      if (data.content) {
        const decompressed = await decompress(Buffer.from(data.content));
        data.content = decompressed.toString();
      }
      return data;
    }));

    res.json({
      posts: decompressedPosts,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit)
    });
  } catch (error) {
    console.error('获取游记错误:', error);
    res.status(500).json({ message: '获取失败', error: error.message });
  }
});

// 审核游记（管理员）
router.put('/:id', async (req, res) => {
  const { status, reason } = req.body;
  const userRole = req.user.role;
  const postId = req.params.id;

  if (userRole !== 'admin') {
    return res.status(403).json({ message: '仅管理员可审核游记' });
  }

  if (!['approved', 'rejected'].includes(status)) {
    return res.status(400).json({ message: '状态必须为 approved 或 rejected' });
  }

  if (status === 'rejected' && !reason) {
    return res.status(400).json({ message: '拒绝时必须提供原因' });
  }

  try {
    const post = await Post.findByPk(postId);
    if (!post) {
      return res.status(404).json({ message: '游记不存在' });
    }

    post.status = status;
    post.reason = reason || null;
    await post.save();

    const decompressedContent = await decompress(Buffer.from(post.content));
    res.json({
      id: post.id,
      title: post.title,
      content: decompressedContent.toString(),
      image: post.image,
      status: post.status,
      reason: post.reason
    });
  } catch (error) {
    console.error('审核游记错误:', error);
    res.status(500).json({ message: '审核失败', error: error.message });
  }
});

module.exports = router;
