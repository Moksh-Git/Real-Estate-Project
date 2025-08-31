import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import prisma from "../lib/prisma.js";

export const register = async (req, res) => {
  const { username, email, password } = req.body;
  // HASH THE PASSWORD
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    console.log(hashedPassword);

    // CREATE NEW USER AND SAVE TO DB
    const newUser = await prisma.user.create({
      data: {
        username,
        email,
        password: hashedPassword,
      },
    });

    console.log(newUser);
    res.status(201).json({ message: "User Created successfully" });
  } catch (err) {
    res.status(500).json({ message: "Failed to create user" });
  }
};

export const login = async (req, res) => {
  //db operations
  const { username, password } = req.body;
  try {
    // CHECK IF USER EXIST OR NOT

    const user = await prisma.user.findUnique({
      where: { username },
    });

    if (!user) return res.status(401).json({ message: "Invalid Credentials!" });

    //if user exist CHECK IF PASSWORD IS CORRECT

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid)
      return res.status(401).json({ message: "Invalid Credentials!" });

    //is password is correct GENERATE COOKIE TOKEN AND SEND TO USER

    // res.setHeader('Set-Cookie',"test=" + "myValue").json("Success")
    const age = 1000 * 60 * 60 * 24 * 7;

    const token = jwt.sign(
      {
        id: user.id,
        isAdmin: false,
      },
      process.env.JWT_SECRET_KEY,
      { expiresIn: age }
    );

    const {password: userPassword, ...userInfo} = user

    res
      .cookie("token", token, {
        httpOnly: true,
        // secure: true
        maxAge: age,
      })
      .status(200)
      .json(userInfo);
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Failed to login" });
  }
};

export const logout = (req, res) => {
  //db operations
  res.clearCookie("token").status(200).json({message: "Logout Successful"})
};
