import express from "express";
import { getStatus, updatedStatus } from "../controllers/user.js";
import isAuth from "../middleware/is-auth.js";

const router = express.Router();

router.get("/status", isAuth, getStatus);
router.put("/status", isAuth, updatedStatus);

export default router;
