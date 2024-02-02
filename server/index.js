import express, { json } from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import bcryptjs from "bcryptjs";
import jwt from "jsonwebtoken";

const app = express();
dotenv.config();
app.use(json());

mongoose.connect(process.env.MONGO_KEY).then(() => {
  console.log("DB Connected");
});

const userSchema = mongoose.Schema({
  username: {
    type: String,
    require: true,
    unique: true,
  },
  email: {
    type: String,
    require: true,
    unique: true,
  },
  password: {
    type: String,
    require: true,
  },
});

const User = mongoose.model("user", userSchema);

app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({
        message: "Username already exists",
      });
    }

    const hashedPassword = bcryptjs.hashSync(password, 4);
    const user = new User({ username, email, password: hashedPassword });
    await user.save();

    const token = jwt.sign({ userId: user._id }, process.env.JWT_KEY);
    res.status(200).json({
      message: "User Created",
      token,
    });
  } catch (error) {
    res.status(500).json({
      message: error.message,
    });
  }
});

app.post("/signin", async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({
        message: "User Not Found",
      });
    }

    const passwordMatch = bcryptjs.compareSync(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({
        message: "Incorrect Password",
      });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_KEY);
    res.status(200).json({
      token,
    });
  } catch (error) {
    res.status(500).json({
      message: error.message,
    });
  }
});

app.listen(3001, () => {
  console.log("Server Started!!!");
});
