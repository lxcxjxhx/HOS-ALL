var mongoose = require("mongoose");
const objectId = mongoose.Types.ObjectId;

var fileSchema = new mongoose.Schema({
  fileHash: String,
  filename: String,
  totalChunks: Number,
  uploaded: Array,
  status: Number,
  url: String,
});

var File = mongoose.model("file", fileSchema, "file");

module.exports = File;
