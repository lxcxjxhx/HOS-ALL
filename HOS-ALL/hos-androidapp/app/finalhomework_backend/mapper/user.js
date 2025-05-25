var mongoose = require("mongoose");
const objectId = mongoose.Types.ObjectId;

var userSchema = new mongoose.Schema({
  username: String,
  avatarUrl: String,
  password: String,
});

var User = mongoose.model("user", userSchema, "user");

module.exports = User;
