import { Router } from "express";
import CourseController from "../controllers/courseController.js";
import { authenticate, authorize } from "../middleware/authMiddleware.js";

const router = Router();

// Public routes
router.get("/", CourseController.getAllCourses);
router.get("/:id", CourseController.getCourseDetails);

// Protected routes
router.use(authenticate);

// Instructor routes
router.post("/", authorize(["instructor"]), CourseController.createCourse);

router.put("/:id", authorize(["instructor"]), CourseController.updateCourse);

// Admin-only routes
router.delete("/:id", authorize(["admin"]), CourseController.deleteCourse);

router.patch(
  "/:id/approve",
  authorize(["admin"]),
  CourseController.approveCourse
);

export default router;
