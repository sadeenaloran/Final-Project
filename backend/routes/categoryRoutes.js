import { Router } from "express";
import CategoryController from "../controllers/categoryController.js";
import { authenticate, authorize } from "../middleware/authMiddleware.js";

const router = Router();

// Public routes
router.get("/", CategoryController.getAllCategories);

// Admin-only routes
router.post(
  "/",
  authenticate,
  authorize(["admin"]),
  CategoryController.createCategory
);

export default router;
