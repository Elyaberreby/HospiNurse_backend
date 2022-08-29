const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { validateUser, UserModel, validateLogin, genToken, validateUpdate, validateAdmin, validateCall } = require("../models/userModel");
const { auth, authAdmin } = require("../middlewares/auth");
const { v4: uuidv4 } = require('uuid');
const router = express.Router();
//   מקבל את כול היוזרים , לקבל את היוזרים 
router.get("/", async (req, res) => {
  try {
    const users = await UserModel.find({});
    res.json(users);
  }
  catch (err) {
    res.status(500).json(err);
  }
})

// מחזיר את הפרטים על יוזר ספציפי
router.get("/one/:id", async (req, res) => {
  try {
    const users = await UserModel.findOne({ _id: req.params.id });
    res.json(users);
  }
  catch (err) {
    res.status(500).json(err);
  }
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
    user.password = "";
    res.json({ data: user });
  }
  catch (err) {
    res.status(500).json(err);
  }
});

router.post("/verifyadmin", authAdmin, async (req, res) => {
  try {
    const user = await UserModel.findOne({ _id: req.tokenData?._id });
    user.password = "";
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
// מאפשר למנהל לשנות פרטים של יוזרים
router.put("/adminupdate/:id", authAdmin, async (req, res) => {
  try {
    const validate = validateAdmin(req.body);
    if (validate.error) {
      return res.status(400).json(validate.error.details);
    }
    const salt = await bcrypt.genSalt(10);
    req.body.password = await bcrypt.hash(req.body.password, salt)
    const user = await UserModel.updateOne({ _id: req.params.id }, req.body);
    res.json(user);

  }
  catch (err) {
    res.status(500).json(err);
  }
});

//ראוט שמאפשר להוסיף ליוזר קריאה 
router.put("/addcall", auth, async (req, res) => {
  try {
    const validate = validateCall(req.body);
    if (validate.error) {
      return res.status(400).json(validate.error.details);
    }

    //req.tokenData?._id = (האיידי שאנחנו מקבלים מהמידלוור 
    //$push - מובנה במונגו, מאפשר לנו לדחופ תאים חדשים למערך 
    // callsId - הוספנו שדה שנקרה ככה שמכיל איי די יחודי שמזהה כול קריאה וקריאה 
    // uuidv4 - פאקדצ שהתקנו בשביל לייצר איי די יחודי 
    // ... - דיסטרקטשיין זה מעתיק את התאים שבתוך האובייקט ומחזיר לנו את הערך שלהם
    //req.body - אוביקט שמכיל בתוכו את הכותרת , במקרה שלנו האוביקט מכיל כותרת לקחנו את הערך שבכתורת והוספנו אותו למערך החדש

    const user = await UserModel.updateOne({ _id: req.tokenData?._id }, { $push: { calls: { callId: uuidv4(), ...req.body } } });
    res.json(user);
  }
  catch (err) {
    res.status(500).json(err);
  }
});

//להציג את הקריאות של היוזר
router.put("/deletecall/:id", auth, async (req, res) => {
  try {
    const user = await UserModel.updateOne({ _id: req.tokenData?._id }, { $pull: { calls: { callId: req.params.id } } });
    res.json(user);

  }
  catch (err) {
    console.log(err);
  }
});

module.exports = router;