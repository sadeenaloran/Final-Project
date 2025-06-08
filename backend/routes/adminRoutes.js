import express from "express";
import AdminController from "../controllers/adminController.js";
import { isAdmin } from "../middleware/roleMiddleware.js";
import { authenticateJWT } from "../middleware/authMiddleware.js";

const router = express.Router();  
router.use(authenticateJWT); // <-- Use this for JWT-protected routes

// User Management
router.post("/users", isAdmin, AdminController.addUser);
router.put("/users/:userId", isAdmin, AdminController.updateUser);
router.delete("/users/:userId", isAdmin, AdminController.deleteUser);

// Course Management
router.get("/courses/pending", isAdmin, AdminController.getPendingCourses);
router.put(
  "/courses/:courseId/approve",
  isAdmin,
  AdminController.approveCourse
);
router.put("/courses/:courseId/reject", isAdmin, AdminController.rejectCourse);

// Admin Dashboard
router.get("/admin/dashboard", authenticateJWT, isAdmin, (req, res) => {
  res.json({ message: "Welcome, admin!" });
});

export default router;
