var express = require("express");
var router = express.Router();
var {
  getDiariesWithPagination,
  createDiary,
  findByIdAndUpdate,
  getDiaryById,
} = require("../mapper/diaryDAO");
var authenticateToken = require("../middleware/auth");
const jwt = require("jsonwebtoken");
const settings = require("../setting");

/* GET users listing. */
router.get("/", async (req, res, next) => {});

/* GET diaries with pagination. */
router.get("/pagelist", authenticateToken, async (req, res, next) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const title = req.query.title || "";
    const authorId = req.query.authorId || null;
    const status = req.query.status || null;

    const diaries = await getDiariesWithPagination(
      page,
      limit,
      title,
      authorId,
      status
    );
    const total = diaries.length;
    res.json({
      code: 200,
      msg: "Success",
      data: diaries,
      total: total,
    });
  } catch (error) {
    next(error);
  }
});

function getCurrentTimeInUTC8() {
  const now = new Date();
  const utc8Offset = 8 * 60 * 60 * 1000; // 8 hours in milliseconds
  return new Date(now.getTime() + utc8Offset);
}

/* POST publish diary. */
router.post("/publish", authenticateToken, async (req, res, next) => {
  try {
    const { title, content, images, video } = req.body;

    // Check if required fields are provided
    if (!title || !content || !images || images.length === 0) {
      return res.json({
        code: 400,
        msg: "Title, content, and images are required",
        data: null,
      });
    }

    const token = req.headers["authorization"].split(" ")[1];
    const decoded = jwt.verify(token, settings.jwtSecret);
    const authorId = decoded.id;

    const newDiary = await createDiary({
      title,
      content,
      images,
      video: video || null,
      status: settings.PEDDING,
      authorId,
      rejectReason: null,
      createdAt: getCurrentTimeInUTC8(),
      updatedAt: getCurrentTimeInUTC8(),
      isDeleted: false,
    });

    res.json({
      code: 200,
      msg: "Diary published successfully",
      data: null,
    });
  } catch (error) {
    next(error);
  }
});

/* PUT update diary. */
router.put("/update", authenticateToken, async (req, res, next) => {
  try {
    const { _id, title, content, images, video } = req.body;

    // Check if required fields are provided
    if (!_id || !title || !content || !images || images.length === 0) {
      return res.json({
        code: 400,
        msg: "_id, title, content, and images are required",
        data: null,
      });
    }

    const updatedDiary = await findByIdAndUpdate(
      _id,
      {
        title,
        content,
        images,
        video: video || null,
        updatedAt: getCurrentTimeInUTC8(),
      },
      { new: true }
    );

    if (!updatedDiary) {
      return res.json({
        code: 404,
        msg: "Diary not found",
        data: null,
      });
    }

    res.json({
      code: 200,
      msg: "Diary updated successfully",
      data: updatedDiary,
    });
  } catch (error) {
    next(error);
  }
});

/* DELETE diary. */
router.delete("/delete", authenticateToken, async (req, res, next) => {
  try {
    const { _id } = req.body;

    // Check if _id is provided
    if (!_id) {
      return res.json({
        code: 400,
        msg: "_id is required",
        data: null,
      });
    }

    const deletedDiary = await findByIdAndUpdate(_id, { isDeleted: true });

    if (!deletedDiary) {
      return res.json({
        code: 404,
        msg: "Diary not found",
        data: null,
      });
    }

    res.json({
      code: 200,
      msg: "Diary deleted successfully",
      data: null,
    });
  } catch (error) {
    next(error);
  }
});

/* GET diary details. */
router.get("/detail", async (req, res, next) => {
  try {
    const { _id } = req.query;

    // Check if _id is provided
    if (!_id) {
      return res.json({
        code: 400,
        msg: "_id is required",
        data: null,
      });
    }

    const diary = await getDiaryById(_id);

    if (!diary) {
      return res.json({
        code: 404,
        msg: "Diary not found",
        data: null,
      });
    }

    res.json({
      code: 200,
      msg: "Diary details retrieved successfully",
      data: diary,
    });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
