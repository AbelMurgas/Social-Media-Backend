import User from "../models/user.js";

export const getStatus = (req, res, next) => {
  const userId = req.userId;
  User.findById(userId)
    .then((user) => {
      if (!user) {
        const err = new Error("Access denied");
        err.statusCode = 401;
        throw err;
      }
      res.status(200).json({
        status: user.status,
      });
    })
    .catch((err) => {
      if (!err.statusCode) {
        err.statusCode = 500;
      }
      next(err);
    });
};

export const updatedStatus = (req, res, next) => {
  const newStatus = req.body.newStatus;
  const userId = req.userId;
  User.findById(userId)
    .then((user) => {
      if (!user) {
        const err = new Error("Access denied");
        err.statusCode = 401;
        throw err;
      }
      user.status = newStatus;
      return user.save();
    })
    .then((result) => {
      res.status(201).json({ message: "User status updated!" });
    })
    .catch((err) => {
      if (!err.statusCode) {
        err.statusCode = 500;
      }
      next(err);
    });
};
