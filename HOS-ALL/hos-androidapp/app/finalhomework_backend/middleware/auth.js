const jwt = require("jsonwebtoken");
const settings = require("../setting");

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      code: 401,
      msg: "Token not provided",
      data: null,
    });
  }

  jwt.verify(token, settings.jwtSecret, (err, user) => {
    if (err) {
      return res.status(403).json({
        code: 403,
        msg: "Token is not valid or expired",
        data: null,
      });
    }
    req.user = user;
    next();
  });
};

module.exports = authenticateToken;
