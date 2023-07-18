import express from "express"

import { serveImage } from "../controllers/image.js"

const router = express.Router()

router.get('/:imageName', serveImage);

export default router;