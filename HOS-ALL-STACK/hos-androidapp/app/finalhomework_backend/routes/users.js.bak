var express = require("express");
var router = express.Router();
const {
  getUsers,
  getUserByUsername,
  createUser,
} = require("../mapper/userDAO");
const jwt = require("jsonwebtoken");
const settings = require("../setting");

/* GET users listing. */
router.get("/", async (req, res, next) => {
  const users = await getUsers();
  res.json(users);
});

/* POST user login. */
router.post("/login", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    // const encryptedPassword = md5(password);

    const user = await getUserByUsername(username);
    if (!user || user.password !== password) {
      return res.json({
        code: 401,
        msg: "Invalid username or password",
        data: null,
      });
    }

    const token = jwt.sign({ id: user._id }, settings.jwtSecret, {
      expiresIn: "2h",
    });

    res.json({
      code: 200,
      msg: "Login successful",
      data: { token },
    });
  } catch (error) {
    next(error);
  }
});

/* POST user registration. */
router.post("/register", async (req, res, next) => {
  try {
    const { username, password, avatarUrl } = req.body;

    // Check if all fields are provided
    if (!username || !password || !avatarUrl) {
      return res.json({
        code: 400,
        msg: "Username, password, and avatarUrl are required",
        data: null,
      });
    }

    // Check if username already exists
    const existingUser = await getUserByUsername(username);
    if (existingUser) {
      return res.json({
        code: 409,
        msg: "Username already exists",
        data: null,
      });
    }

    // Create new user
    const newUser = await createUser({ username, password, avatarUrl });
    const token = jwt.sign({ id: newUser._id }, settings.jwtSecret, {
      expiresIn: "2h",
    });

    res.json({
      code: 200,
      msg: "User registered successfully",
      data: { token },
    });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
