const jwt = require("jsonwebtoken");
const { config } = require("../config/secret");
const { UserModel } = require("../models/userModel");

exports.auth = (req, res, next) => {

  let token = req.header("x-api-key");
  if (!token) {
    return res.status(401).json({ err_msg: "need to send token to his endpoint url" })
  }
  try {

    let decodeToken = jwt.verify(token, config.tokenSecret);//בודק אם התוקן תקין 
    req.tokenData = decodeToken;

    next()
  }
  catch (err) {
    return res.status(401).json({ err_msg: "Token invalid or expired" })
  }
}

exports.authAdmin = async (req, res, next) => {
  let token = req.header("x-api-key");
  console.log(token);
  if (!token) {
    return res.status(401).json({ err_msg: "need to send token to his endpoint url" })
  }
  try {

    let decodeToken = jwt.verify(token, config.tokenSecret);//בודק אם התוקן תקין 

    const user = await UserModel.findOne({ _id: decodeToken?._id });
    if (!user) {
      return res.status(400).json({ err_msg: "there is no user" });
    }
console.log(user);
    if (user?.role !== "admin") {
      return res.status(401).json({ err_msg: "need to be admin to continue" })
    }

    req.tokenData = decodeToken;

    next()
  }
  catch (err) {
    return res.status(401).json({ err_msg: "Token invalid or expired" })
  }
}