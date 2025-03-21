const express = require("express");
const { updateUser } = require("../controllers/userController");
const authMiddleware = require("../middlewares/authMiddleware");

const router = express.Router();

router.put("/:id", authMiddleware, updateUser);

module.exports = router;
