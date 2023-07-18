import express from "express";

import { getPosts, createPost, getPost, updatePost, deletePost } from "../controllers/feed.js";

import { feedValidator } from "../utils/validator.js";
import isAuth from "../middleware/is-auth.js";

const router = express.Router();

// GET /feed/posts
router.get("/posts",isAuth, getPosts);

// POST /feed/post
router.post("/post",isAuth, feedValidator, createPost);

router.get("/post/:postId",isAuth, getPost);

router.put("/post/:postId",isAuth, feedValidator, updatePost);

router.delete("/post/:postId",isAuth, deletePost)

export default router;
