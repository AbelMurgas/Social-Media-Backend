import path from "path";
import fs from "fs"
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);

const __dirname = path.dirname(__filename);

export default class file {
 static clearImage = (filePath) =>{
  if (!filePath){
   console.log("no file received")
   return false
  }
  filePath = path.join(__dirname, "..", filePath);
  if (fs.existsSync(filePath)) {
   fs.unlink(filePath, err => {
    console.log(err)
   })
   return true 
  }
 }
}