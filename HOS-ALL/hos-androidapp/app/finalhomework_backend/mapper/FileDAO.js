var File = require("./File");

const createFile = async (file) => {
  const newFile = new File(file);
  await newFile.save();
  return newFile;
};

const getFileByFileHash = async (fileHash) => {
  const file = await File.findOne({ fileHash });
  return file;
};

module.exports = {
  createFile,
  getFileByFileHash,
};
