const express = require("express");
const {
  createProduct,
  getAllProducts,
  getProductById,
  updateProduct,
  deleteProduct,
} = require("../controllers/productController");
const authMiddleware = require("../middlewares/authMiddleware");

const router = express.Router();

router.post("/", authMiddleware, createProduct);
router.get("/", getAllProducts);
router.get("/:pid", getProductById);
router.put("/:pid", authMiddleware, updateProduct);
router.delete("/:pid", authMiddleware, deleteProduct);

module.exports = router;
