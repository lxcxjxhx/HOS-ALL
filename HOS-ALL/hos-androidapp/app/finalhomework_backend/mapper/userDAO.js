const User = require("./user");

const getUsers = async () => {
  const users = await User.find();
  return users;
};

const getUserById = async (id) => {
  const user = await User.findById(id);
  return user;
};

const getUserByUsername = async (username) => {
  const user = await User.findOne({ username });
  return user;
};

const createUser = async (user) => {
  const newUser = await User.create(user);
  return newUser;
};

module.exports = { getUsers, getUserById, getUserByUsername, createUser };
