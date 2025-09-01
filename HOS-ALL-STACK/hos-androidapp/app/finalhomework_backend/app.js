var express = require("express");
var path = require("path");
var cookieParser = require("cookie-parser");
var logger = require("morgan");
var mongoose = require("mongoose");
const settings = require("./setting");
var indexRouter = require("./routes/index");
var usersRouter = require("./routes/users");
var diaryRouter = require("./routes/diary");
var uploadRouter = require("./routes/upload");
const cors = require("cors");
const multer = require("multer");

var app = express();

// Enable CORS
app.use(cors());

// Configure multer for handling multipart/form-data
const upload = multer({
  limits: {
    fileSize: 15 * 1024 * 1024, // 10MB limit
  },
});

// Error handling middleware for multer
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(400).json({
        code: 400,
        msg: "File too large",
        data: null,
      });
    }
    return res.status(400).json({
      code: 400,
      msg: err.message,
      data: null,
    });
  }
  next(err);
});

// Connect to MongoDB
mongoose
  .connect(settings.MONGO_URL)
  .then(() => {
    console.log("Connected to MongoDB");
  })
  .catch((err) => {
    console.error("Error connecting to MongoDB:", err);
  });

app.use(logger("dev"));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Use multer middleware for routes that handle file uploads
app.use("/upload", uploadRouter);
app.use("/", indexRouter);
app.use("/users", usersRouter);
app.use("/diary", diaryRouter);

module.exports = app;
