import fs from "fs";

export const serveImage = (req, res, next) => {
  const encodedImageName = req.params.imageName;
  const decodedImageName = decodeURIComponent(encodedImageName);
  const imagePath = `images/${decodedImageName}`;
  fs.readFile(imagePath, (error, data) => {
    if (error) {
      return next(error);
    }
    const fileExtension = decodedImageName.split(".").pop();
    let contentType;
    switch (fileExtension) {
      case "jpeg":
      case "jpg":
        contentType = "image/jpeg";
        break;
      case "png":
        contentType = "image/png";
        break;
      case "gif":
        contentType = "image/gif";
        break;
      default:
        contentType = "application/octet-stream";
    }
    res.contentType("image/jpeg");
    res.send(data);
  });
};
