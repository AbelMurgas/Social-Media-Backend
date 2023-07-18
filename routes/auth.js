import express from "express";

import { login, signup } from "../controllers/auth.js";
import { userValidator } from "../utils/validator.js";


const router = express.Router();

router.put("/signup", userValidator, signup);

router.post("/login", login);

export default router;
