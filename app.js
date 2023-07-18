import express from "express";
import bodyParser from "body-parser";
import http from "http";
import helmet from "helmet";
import compression from "compression";
import morgan from "morgan";
import fs from "fs";

import feedRoutes from "./routes/feed.js";
import imagesRoutes from "./routes/images.js";
import authRoutes from "./routes/auth.js";
import userRoutes from "./routes/user.js";

import mongoose from "mongoose";

import multer from "multer";

import socket from "./socket.js";

import path from "path";

import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);

const __dirname = path.dirname(__filename);

const app = express();

const accessLogStream = fs.createWriteStream(
  path.join(__dirname, "access.log"),
  { flags: "a" }
);

app.use(helmet()); // Secure headers
app.use(compression()); // Compressing data
app.use(morgan("combined", { stream: accessLogStream })); // Request login log

import { v4 } from "uuid";

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "images");
  },
  filename: function (req, file, cb) {
    const type = file.mimetype.split("/")[1];
    const fileName = v4() + "." + type;
    cb(null, fileName);
  },
  limits: {
    fileSize: 100 * 1024 * 1024, // Limit the file size to 100 MB
  },
});

const fileFilter = (req, file, cb) => {
  if (
    file.mimetype === "image/png" ||
    file.mimetype === "image/jpg" ||
    file.mimetype === "image/jpeg"
  ) {
    cb(null, true);
  } else {
    cb(null, false);
  }
};
// app.use(bodyParser.urlencoded()); // x-www-form-urlencoded <form>
app.use(bodyParser.json()); // application/json
app.use(
  multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
      fileSize: 100 * 1024 * 1024, // Limit the file size to 100 MB
    },
  }).single("image")
);

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "http://localhost:3000");
  res.setHeader(
    "Access-Control-Allow-Methods",
    "OPTIONS, GET, POST, PUT, PATCH, DELETE"
  );
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  next();
});

app.use("/feed", feedRoutes);
app.use("/images", imagesRoutes);
app.use("/auth", authRoutes);
app.use("/user", userRoutes);

app.use((error, req, res, next) => {
  console.log(error);
  const status = error.statusCode || 500;
  const message = error.message;
  const data = error.data;
  res.status(status).json({ message: message, data: data });
});

const server = http.createServer(app);
const io = socket.init(server);

console.log(process.env.MONGO_USER);
mongoose.set("strictQuery", true);
mongoose
  .connect(
    `mongodb+srv://${process.env.MONGO_USER}:${process.env.MONGO_PASSWORD}@cluster0.ssc1tcl.mongodb.net/${process.env.MONGO_DEFAULT_DATABASE}?retryWrites=true&w=majority`
  )
  .then((result) => {
    server.listen(process.env.PORT || 3000);
    io.on("connection", (socket) => {
      console.log("A user connected!");
    });
  })
  .catch((err) => console.log(err));
