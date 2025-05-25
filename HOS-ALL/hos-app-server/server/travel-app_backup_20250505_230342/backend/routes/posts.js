const express = require('express');
const router = express.Router();
const { Op } = require('sequelize');
const multer = require('multer');
const path = require('path');
const zlib = require('zlib');
const util = require('util');
const { Post, User, Favorite, Like, PostRanking } = require('../models');

const compress = util.promisify(zlib.deflate);
const decompress = util.promisify(zlib.inflate);

// 配置 multer 存储
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB 限制
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    if (extname && mimetype) {
      return cb(null, true);
    }
    cb(new Error('仅支持 JPEG/JPG/PNG 图片'));
  }
});

// 上传游记（普通用户）
router.post('/', upload.single('image'), async (req, res) => {
  const { title, content } = req.body;
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
    // 压缩 content
    const compressedContent = await compress(Buffer.from(content));
    const contentBase64 = compressedContent.toString('base64');

    // 保存图片路径
    const imagePath = req.file ? `/uploads/${req.file.filename}` : null;

    const post = await Post.create({
      user_id: userId,
      title,
      content: contentBase64,
      image: imagePath,
      status: 'pending'
    });

    res.status(201).json({ id: post.id, title, content, image: imagePath, status: post.status });
  } catch (error) {
    console.error('上传游记错误:', error.message, error.stack);
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
    if (status && ['pending', 'approved', 'rejected'].includes(status)) {
      where.status = status;
    }

    const validSortFields = ['created_at', 'updated_at', 'title'];
    const sortField = validSortFields.includes(sort) ? sort : 'created_at';
    const sortOrder = order.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

    console.log('执行 Post.findAndCountAll，包含 PostRanking');
    const posts = await Post.findAndCountAll({
      where,
      include: [
        { model: User, as: 'User', attributes: ['id', 'username'], required: false },
        { model: Favorite, as: 'Favorites', attributes: ['id', 'user_id'], required: false },
        { model: Like, as: 'Likes', attributes: ['id', 'user_id'], required: false },
        { model: PostRanking, as: 'Ranking', attributes: ['score', 'updated_at'], required: false }
      ],
      limit,
      offset,
      order: [[sortField, sortOrder]],
      logging: console.log
    });

    // 解压缩 content
    const decompressedPosts = await Promise.all(posts.rows.map(async (post) => {
      const data = post.toJSON();
      try {
        if (data.content && data.content.length > 0) {
          if (/^[A-Za-z0-9+/=]+$/.test(data.content)) {
            const compressedContent = Buffer.from(data.content, 'base64');
            const decompressedContent = await decompress(compressedContent);
            data.content = decompressedContent.toString();
          } else {
            data.content = null;
          }
        } else {
          data.content = null;
        }
      } catch (error) {
        console.error(`解压缩错误 (post ${data.id}):`, error.message);
        data.content = null;
      }
      return data;
    }));

    res.json({
      posts: decompressedPosts,
      total: posts.count,
      page,
      limit,
      totalPages: Math.ceil(posts.count / limit)
    });
  } catch (error) {
    console.error('获取游记错误:', error.message, error.stack);
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
    const post = await Post.findByPk(postId, {
      include: [
        { model: User, as: 'User', attributes: ['id', 'username'], required: false },
        { model: PostRanking, as: 'Ranking', attributes: ['score', 'updated_at'], required: false }
      ],
      logging: console.log
    });
    if (!post) {
      return res.status(404).json({ message: '游记不存在' });
    }

    post.status = status;
    post.reason = reason || null;
    await post.save();

    // 解压缩 content
    let decompressedContent = null;
    try {
      if (post.content && post.content.length > 0) {
        if (/^[A-Za-z0-9+/=]+$/.test(post.content)) {
          const compressedContent = Buffer.from(post.content, 'base64');
          decompressedContent = (await decompress(compressedContent)).toString();
        }
      }
    } catch (error) {
      console.error(`解压缩错误 (post ${post.id}):`, error.message);
    }

    res.json({
      id: post.id,
      title: post.title,
      content: decompressedContent,
      image: post.image,
      status: post.status,
      reason: post.reason,
      user: post.User,
      ranking: post.Ranking
    });
  } catch (error) {
    console.error('审核游记错误:', error.message, error.stack);
    res.status(500).json({ message: '审核失败', error: error.message });
  }
});

module.exports = router;
