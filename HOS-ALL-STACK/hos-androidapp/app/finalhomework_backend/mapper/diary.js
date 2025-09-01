var mongoose = require("mongoose");
const objectId = mongoose.Types.ObjectId;

var diarySchema = new mongoose.Schema({
  title: String,
  content: String,
  images: Array,
  video: String,
  authorId: objectId,
  status: String,
  rejectReason: String,
  createdAt: Date,
  updatedAt: Date,
  isDeleted: Boolean,
});

var Diary = mongoose.model("diary", diarySchema, "diary");

module.exports = Diary;
