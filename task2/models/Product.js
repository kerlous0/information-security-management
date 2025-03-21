const mongoose = require("mongoose");

const ProductSchema = new mongoose.Schema({
  pname: { type: String, required: true },
  description: { type: String },
  price: { type: Number, required: true },
  stock: { type: Number, required: true },
  created_at: { type: Date, default: Date.now },
});

module.exports = mongoose.model("Product", ProductSchema);
