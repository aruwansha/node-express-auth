const router = require("express").Router();
const User = require("../model/User");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
// import validator
const { registerValidation, loginValidation } = require("../validation");

router.post("/register", async (req, res) => {
  const { error } = registerValidation(req.body);
  if (error) return res.send(error.details[0].message);

  // checking if the user is already in db
  const emailExists = await User.findOne({ email: req.body.email });
  if (emailExists) return res.status(400).send("Email already exists");

  //   Hash the password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(req.body.password, salt);

  //  Create a new User
  const user = new User({
    name: req.body.name,
    email: req.body.email,
    password: hashedPassword,
  });
  try {
    await user.save();
    res.send({ user: user._id });
  } catch (err) {
    res.status(400).send(err);
  }
});

// Login
router.post("/login", async (req, res) => {
  const { error } = loginValidation(req.body);
  if (error) return res.send(error.details[0].message);

  // checking if the email exists in db
  const user = await User.findOne({ email: req.body.email });
  if (!user) return res.status(400).send("Email or password is wrong");
  // password is correct
  const validPass = await bcrypt.compare(req.body.password, user.password);
  if (!validPass) return res.status(400).send("Email or password is wrong");

  // create and assign a token
  const token = jwt.sign({ _id: user._id }, process.env.TOKEN_SECRET);
  res.header("auth-token", token).send(token);
});

module.exports = router;
