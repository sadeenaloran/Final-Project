import CategoryModel from "../models/Category.js";

const CategoryController = {
  async createCategory(req, res, next) {
    try {
      const { name } = req.body;
      const category = await CategoryModel.create(name);
      res.status(201).json({ success: true, category });
    } catch (error) {
      next(error);
    }
  },

  async getAllCategories(req, res, next) {
    try {
      const categories = await CategoryModel.findAll();
      res.json({ success: true, categories });
    } catch (error) {
      next(error);
    }
  },
};
export default CategoryController;
