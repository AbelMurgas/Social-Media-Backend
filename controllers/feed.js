import validator from "express-validator";

import io from "../socket.js";
import Post from "../models/post.js";
import User from "../models/user.js";

import file from "../utils/file.js";
const { validationResult } = validator;

export const getPosts = async (req, res, next) => {
  const currentPage = req.query.page || 1;
  const perPage = 2;
  try {
    const totalItems = await Post.find().countDocuments();
    const posts = await Post.find()
      .skip((currentPage - 1) * perPage)
      .limit(perPage)
      .sort({createdAt: 1})
      .populate("creator");
    if (!posts) {
      error = new Error("Posts no found");
      error.statusCode = 404;
      throw error;
    }
    res.status(200).json({
      posts: posts,
      totalItems: totalItems,
    });
  } catch {
    if (!error.status) {
      error.status = 500;
    }
    next(error);
  }
};

export const createPost = async (req, res, next) => {
  const errors = validationResult(req);
  try {
    if (!errors.isEmpty()) {
      const error = new Error("Validation failed, enterred data is incorrect");
      error.statusCode = 422;
      throw error;
    }
    if (!req.file) {
      const error = new Error("No image provided.");
      error.statusCode = 422;
      throw error;
    }
    const imageUrl = req.file.path.replace("\\", "/");
    const title = req.body.title;
    const content = req.body.content;
    const user = await User.findById(req.userId);
    const post = new Post({
      title: title,
      content: content,
      imageUrl: imageUrl,
      creator: user._id,
    });
    user.posts.push(post._id);
    await post.save();
    await user.save();
    io.getIO().emit("posts", {
      action: "create",
      post: { ...post._doc, creator: { _id: req.userId, name: user.name } },
    });
    res.status(201).json({
      message: "Post created successfully!",
      post: {
        _id: new Date().toISOString(),
        title: title,
        content: content,
        creator: { _id: user._id, name: user.name },
        createdAt: new Date(),
      },
    });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    if (req.file) {
      file.clearImage(req.file.path);
    }
    console.log(err);
    next(err);
  }
};

export const getPost = async (req, res, next) => {
  const postId = req.params.postId;
  try {
    const post = await Post.findById(postId).select("-__v");
    if (!post) {
      const error = new Error("Post not found");
      error.statusCode = 204;
      throw error;
    }
    post.imageUrl = post.imageUrl.replace(/images\\/g, "");
    res.status(200).json({
      post: post,
    });
  } catch (error) {
    if (!error.statusCode) {
      error.statusCode = 500;
    }
    next(error);
  }
};

export const updatePost = async (req, res, next) => {
  const postId = req.params.postId;
  const errors = validationResult(req);
  try {
    if (!errors.isEmpty()) {
      const error = new Error("Validation failed, enterred data is incorrect");
      error.statusCode = 422;
      throw error;
    }
    const title = req.body.title;
    const content = req.body.content;
    let imageUrl;
    const post = await Post.findById(postId).populate("creator");
    if (!post) {
      const error = new Error("Post no found");
      error.statusCode = 404;
      throw error;
    }
    if (post.creator._id.toString() !== req.userId) {
      const error = new Error("Not authorized");
      error.statusCode = 403;
      throw error;
    }
    if (!req.file) {
      imageUrl = post.imageUrl;
    } else {
      file.clearImage(post.imageUrl);
      imageUrl = req.file.path.replace("\\", "/");
    }
    post.title = title;
    post.imageUrl = imageUrl;
    post.content = content;
    await post.save();
    io.getIO().emit("posts", { action: "update", post: post });
    res.status(200).json({ message: "Post updated!", post: post });
  } catch (error) {
    try {
      file.clearImage(req.file.path);
    } catch {
      console.log("File no found");
    }
    if (!error.statusCode) {
      error.statusCode = 500;
    }
    next(error);
  }
};

export const deletePost = async (req, res, next) => {
  const postId = req.params.postId;
  try {
    const post = await Post.findById(postId);
    if (!post) {
      const error = new Error("Post not found");
      error.statusCode = 404;
      throw error;
    }
    if (post.creator.toString() !== req.userId) {
      const error = new Error("Not authorized");
      error.statusCode = 403;
      throw error;
    }
    const user = await User.findById(post.creator);
    user.posts.pull(postId);
    await user.save();
    const postDeleted = await Post.findByIdAndDelete(post);
    file.clearImage(postDeleted.imageUrl);
    const posts = await Post.find()
    .sort({createdAt: 1})
    .populate("creator");
    io.getIO().emit("posts", {
      action: "delete",
      post: postDeleted,
    });
    res.status(200).json({ message: "Successfully deleted" });
  } catch (error) {
    if (!error.statusCode) {
      error.statusCode = 500;
    }
    next(error);
  }
};
