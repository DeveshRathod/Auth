import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
dotenv.config();

mongoose.connect(process.env.MONGO).then(() => {
  console.log("DB Connected");
});

const app = express();

app.listen(3001, () => {
  console.log("Server Started!!!");
});
