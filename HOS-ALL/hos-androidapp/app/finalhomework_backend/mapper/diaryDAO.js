var Diary = require("./diary");
const User = require("./user"); // Assuming user model is in the same directory

const getDiaries = async () => {
  const diary = await Diary.find();
  return diary;
};

const getDiaryById = async (id) => {
  const diary = await Diary.findById(id);
  return diary;
};

const createDiary = async (diary) => {
  const newDiary = new Diary(diary);
  await newDiary.save();
  return newDiary;
};

const updateDiary = async (id, diary) => {
  const updatedDiary = await Diary.findByIdAndUpdate(id, diary, { new: true });
  return updatedDiary;
};

const deleteDiary = async (id) => {
  const deletedDiary = await Diary.findByIdAndDelete(id);
  return deletedDiary;
};

const getDiariesByAuthorId = async (authorId) => {
  const diaries = await Diary.find({ authorId });
  return diaries;
};

const getDiariesByStatus = async (status) => {
  const diaries = await Diary.find({ status });
  return diaries;
};

const getDiariesWithPagination = async (
  page,
  limit,
  title,
  authorId,
  status
) => {
  const skip = (page - 1) * limit;

  // 构建查询对象
  const searchQuery = {};
  if (title) {
    searchQuery.title = new RegExp(title, "i"); // 'i' for case-insensitive
  }
  if (authorId) {
    searchQuery.authorId = authorId;
  }
  if (status) {
    searchQuery.status = status;
  }

  searchQuery.isDeleted = false;

  const diaries = await Diary.find(searchQuery).skip(skip).limit(limit);

  // Fetch user details for each diary
  const diariesWithUserDetails = await Promise.all(
    diaries.map(async (diary) => {
      const user = await User.findById(diary.authorId);
      return {
        ...diary.toObject(),
        username: user ? user.username : null,
        avatarUrl: user ? user.avatarUrl : null,
      };
    })
  );

  return diariesWithUserDetails;
};

const findByIdAndUpdate = async (id, diary) => {
  const updatedDiary = await Diary.findByIdAndUpdate(id, diary, { new: true });
  return updatedDiary;
};

const deleteDiaryById = async (id) => {
  const deletedDiary = await Diary.findByIdAndUpdate(id, { isDeleted: true });
  return deletedDiary;
};

module.exports = {
  getDiaries,
  getDiaryById,
  createDiary,
  updateDiary,
  deleteDiary,
  getDiariesByAuthorId,
  getDiariesByStatus,
  getDiariesWithPagination,
  findByIdAndUpdate,
};
