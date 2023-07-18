import dotenv from "dotenv"
import path from "path"

import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);

const __dirname = path.dirname(__filename);

dotenv.config({
    path: path.resolve(__dirname, `${process.env.NODE_ENV}`.trim() + '.env')
});

const config = {
    NODE_ENV : process.env.NODE_ENV || 'development',
    PORT : process.env.PORT || 3000,
    MONGO_USER : process.env.MONGO_USER,
    MONGO_PASSWORD : process.env.MONGO_PASSWORD,
    MONGO_DEFAULT_DATABASE : process.env.MONGO_DEFAULT_DATABASE
}

export default config