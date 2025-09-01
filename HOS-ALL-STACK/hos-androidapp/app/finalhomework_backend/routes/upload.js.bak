const express = require("express");
const multer = require("multer");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const fsp = fs.promises;
const setting = require("../setting");
const UPLOAD_DIR = path.resolve(process.cwd(), "uploads");
const router = express.Router();
router.use(cors());
router.use(express.json());
// router.use(express.static(UPLOAD_DIR));

var { getFileByFileHash, createFile } = require("../mapper/FileDAO");
const authenticateToken = require("../middleware/auth");
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}
// 创建分片目录
const createChunkDir = async (fileHash) => {
  console.log("createChunkDir", fileHash);
  const chunkDir = path.join(UPLOAD_DIR, fileHash);
  if (!fs.existsSync(chunkDir)) {
    await fsp.mkdir(chunkDir, { recursive: true });
  }
  return chunkDir;
};

const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 15 * 1024 * 1024, // 15MB
  },
});
const upload_single = multer({ storage: multer.memoryStorage() });

// 确保临时目录存在
const TEMP_DIR = path.join(__dirname, "../temp");
if (!fs.existsSync(TEMP_DIR)) {
  fs.mkdirSync(TEMP_DIR, { recursive: true });
}

// 处理分片上传
router.post("/upload-chunk", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.json({
        code: 400,
        msg: "No file uploaded",
        data: null,
      });
    }

    const { fileHash, chunkIndex } = req.body;

    if (!fileHash || chunkIndex === undefined) {
      return res.json({
        code: 400,
        msg: "fileHash and chunkIndex are required",
        data: null,
      });
    }

    // 创建以fileHash命名的目录
    const chunkDir = path.join(TEMP_DIR, fileHash);
    if (!fs.existsSync(chunkDir)) {
      fs.mkdirSync(chunkDir, { recursive: true });
    }

    // 将分片写入文件
    const chunkPath = path.join(chunkDir, `${chunkIndex}`);
    fs.writeFileSync(chunkPath, req.file.buffer);

    res.json({
      code: 200,
      msg: "Chunk uploaded successfully",
      data: null,
    });
  } catch (error) {
    console.error("Upload chunk error:", error);
    res.json({
      code: 500,
      msg: "Upload chunk failed",
      data: null,
    });
  }
});

router.post(
  "/upload-single",
  upload_single.single("file"),
  async (req, res) => {
    const { file } = req;
    const { fileHash } = req.body;

    if (!file || !fileHash) {
      return res.json({ code: 400, msg: "缺少文件或Hash值", data: null });
    }

    // 取扩展名
    const ext = path.extname(file.originalname);
    const finalPath = path.join(UPLOAD_DIR, `${fileHash}${ext}`);

    // 写入文件
    fs.writeFileSync(finalPath, file.buffer);
    const record = await getFileByFileHash(fileHash);
    if (record) {
      record.status = 1;
      record.url = `http://${setting.IP}:${setting.PORT}/uploads/${fileHash}${ext}`;
      await record.save();
    }
    res.json({
      code: 200,
      msg: "上传成功",
      data: {
        url: `http://${setting.IP}:${setting.PORT}/uploads/${fileHash}${ext}`,
      },
    });
  }
);

router.post("/pre-sign", authenticateToken, async (req, res) => {
  const { fileHash, totalChunks, filename } = req.body;
  if (!fileHash || !totalChunks || !filename) {
    return res.json({ code: 400, msg: "参数错误", data: null });
  }
  let record = await getFileByFileHash(fileHash);

  if (record && record.status === 1) {
    return res.json({
      code: 200,
      msg: "文件已上传",
      data: {
        transferType: 1,
        uploadedChunks: null,
        needUploadChunks: null,
        fileUrl: record.url,
      },
    });
  }

  if (record) {
    const uploaded = record.uploaded || [];
    const needUploadChunks = Array.from(
      { length: totalChunks },
      (_, i) => i
    ).filter((i) => !uploaded.includes(i));
    return res.json({
      code: 200,
      msg: "文件未上传完整",
      data: {
        transferType: 2,
        uploadedChunks: uploaded,
        needUploadChunks,
      },
    });
  }

  const newFile = await createFile({
    filename,
    fileHash,
    totalChunks,
    uploaded: [],
    status: 3,
  });

  return res.json({
    code: 200,
    msg: "文件未上传",
    data: {
      transferType: 3,
      uploadedChunks: [],
      needUploadChunks: Array.from({ length: totalChunks }, (_, i) => i),
    },
  });
});

router.post("/pre-sign-single", authenticateToken, async (req, res) => {
  const { filename, fileHash } = req.body;
  if (!filename || !fileHash) {
    return res.json({ code: 400, msg: "参数错误", data: null });
  }
  const record = await getFileByFileHash(fileHash);
  if (record && record.status === 1) {
    return res.json({
      code: 200,
      msg: "文件已上传",
      data: {
        transferType: 1,
        uploadedChunks: null,
        needUploadChunks: null,
        fileUrl: record.url,
      },
    });
  }
  const newFile = await createFile({
    filename,
    fileHash,
    totalChunks: null,
    uploaded: null,
    status: 3,
  });

  return res.json({
    code: 200,
    msg: "文件未上传",
    data: {
      transferType: 3,
      uploadedChunks: null,
      needUploadChunks: null,
    },
  });
});

router.post("/report-chunk", authenticateToken, async (req, res) => {
  const { fileHash, chunkIndex } = req.body;

  const record = await getFileByFileHash(fileHash);
  if (!record) return res.json({ code: 404, msg: "文件未注册", data: null });

  if (!record.uploaded.includes(chunkIndex)) {
    record.uploaded.push(chunkIndex);
    record.status = 2;
    await record.save();
  }

  res.json({ code: 200, msg: "切片已记录", data: null });
});

router.post("/merge-report", authenticateToken, async (req, res) => {
  const { fileHash, filename } = req.body;
  const record = await getFileByFileHash(fileHash);

  if (!record || record.status !== 2) {
    return res.json({ code: 400, msg: "状态错误或文件未找到", data: null });
  }

  const ext = path.extname(filename);
  const chunkDir = path.join(UPLOAD_DIR, fileHash);
  const finalPath = path.join(UPLOAD_DIR, `${fileHash}${ext}`);

  const writeStream = fs.createWriteStream(finalPath);

  for (let i = 0; i < record.totalChunks; i++) {
    const chunkPath = path.join(chunkDir, `chunk_${i}`);
    const data = fs.readFileSync(chunkPath);
    writeStream.write(data);
  }

  writeStream.end();
  writeStream.on("finish", async () => {
    const fileUrl = `http://${setting.IP}:${setting.PORT}/uploads/${fileHash}${ext}`;
    record.status = 1;
    record.url = fileUrl;
    await record.save();
    res.json({ code: 200, msg: "文件上传完成", data: fileUrl });
  });
});

module.exports = router;
