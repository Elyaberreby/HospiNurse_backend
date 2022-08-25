const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { validateUser, UserModel, validateLogin, genToken, validateUpdate } = require("../models/userModel");
const { authUser, auth, authAdmin } = require("../middlewares/auth");
const { valid } = require("joi");
const router = express.Router();

router.get("/", (req, res) => {
  res.json({ msg: "Users work ****" });
})

//post
router.post("/", async (req, res) => {
  let validBody = validateUser(req.body);
  if (validBody.error) {
    return res.status(400).json(validBody.error.details);
  }
  try {
    let user = new UserModel(req.body);
    user.password = await bcrypt.hash(user.password, 10);
    await user.save();
    user.password = "******";
    res.status(201).json(user);
  }
  catch (err) {
    if (err.code == 11000) {
      return res.status(400).json({ code: 11000, err_msg: "Email already in system try log in" })
    }
    console.log(err);
    res.status(500).json(err);
  }
})



// post for login
router.post("/login", async (req, res) => {
  console.log(req.body);
  let validBody = validateLogin(req.body);
  if (validBody.error) {
    return res.status(400).json(validBody.error.details);
  }
  try {

    let user = await UserModel.findOne({ email: req.body.email })
    if (!user) {
      return res.status(401).json({ err_msg: "User not found in system" });
    }

    let validPass = await bcrypt.compare(req.body.password, user.password)
    if (!validPass) {
      return res.status(401).json({ err_msg: "Password not good , try again" });
    }
    let token = genToken(user._id)
    res.json({ token })

  }
  catch (err) {
    console.log(err);
    res.status(500).json(err);
  }
})


router.post("/verify", auth, async (req, res) => {
  try {
    const user = await UserModel.findOne({ _id: req.tokenData?._id });
    user.password ="";
    res.json({ data: user });
  }
  catch (err) {
    res.status(500).json(err);
  }
})

router.put("/update", auth, async (req, res) => {
  try {
    const validateUser = validateUpdate(req.body)
    if (validateUser.error) {
      return res.status(400).json(validateUser.error.details);

    }
    const salt = await bcrypt.genSalt(10);
    req.body.password = await bcrypt.hash(req.body.password, salt)
    const user = await UserModel.updateOne({ _id: req.tokenData?._id }, req.body);
    res.json(user);

  }
  catch (err) {
    res.status(500).json(err);
  }
});

router.put("/adminupdate", authAdmin, asycn(req, res))

module.exports = router;