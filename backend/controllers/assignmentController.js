import AssignmentModel from "../models/Assignment.js";
import LessonModel from "../models/Lesson.js";
import ModuleModel from "../models/Module.js";
import CourseModel from "../models/Course.js";
import { getCourseFromAssignment } from "../utils/helpers.js";

const AssignmentController = {
  async createAssignment(req, res, next) {
    try {
      const { lesson_id, title, description, max_score } = req.body;

      // Verify lesson exists and get course info
      const lesson = await LessonModel.findById(lesson_id);
      if (!lesson) {
        return res.status(404).json({
          success: false,
          message: "Lesson not found",
        });
      }

      const module = await ModuleModel.findById(lesson.module_id);
      const course = await CourseModel.findById(module.course_id);

      // Authorization check
      if (course.instructor_id !== req.user.id) {
        return res.status(403).json({
          success: false,
          message: "Only instructor can create assignments for this course",
        });
      }

      const assignment = await AssignmentModel.create({
        lesson_id,
        title,
        description,
        max_score,
      });

      res.status(201).json({
        success: true,
        assignment,
      });
    } catch (error) {
      next(error);
    }
  },

  async getAssignment(req, res, next) {
    try {
      const assignment = await AssignmentModel.findById(req.params.id);
      if (!assignment) {
        return res.status(404).json({
          success: false,
          message: "Assignment not found",
        });
      }

      res.json({
        success: true,
        assignment,
      });
    } catch (error) {
      next(error);
    }
  },

  async getAssignmentsByLesson(req, res, next) {
    try {
      const assignments = await AssignmentModel.findByLessonId(
        req.params.lessonId
      );
      res.json({
        success: true,
        data: assignments,
      });
    } catch (error) {
      next(error);
    }
  },

  async updateAssignment(req, res, next) {
    try {
      const assignment = await AssignmentModel.findById(req.params.id);
      if (!assignment) {
        return res.status(404).json({
          success: false,
          message: "Assignment not found",
        });
      }

      // Verify course ownership
      const lesson = await LessonModel.findById(assignment.lesson_id);
      const module = await ModuleModel.findById(lesson.module_id);
      const course = await CourseModel.findById(module.course_id);

      if (course.instructor_id !== req.user.id) {
        return res.status(403).json({
          success: false,
          message: "Only instructor can update this assignment",
        });
      }

      const updatedAssignment = await AssignmentModel.update(req.params.id, {
        title: req.body.title,
        description: req.body.description,
        max_score: req.body.max_score,
      });

      res.json({
        success: true,
        assignment: updatedAssignment,
      });
    } catch (error) {
      next(error);
    }
  },

  async deleteAssignment(req, res, next) {
    try {
      const assignment = await AssignmentModel.findById(req.params.id);
      if (!assignment) {
        return res.status(404).json({
          success: false,
          message: "Assignment not found",
        });
      }

      // Use helper to get course
      const course = await getCourseFromAssignment(req.params.id);

      if (req.user.role !== "admin" && course.instructor_id !== req.user.id) {
        return res.status(403).json({
          success: false,
          message: "Unauthorized to delete this assignment",
        });
      }

      await AssignmentModel.delete(req.params.id);
      res.json({
        success: true,
        message: "Assignment deleted successfully",
      });
    } catch (error) {
      next(error);
    }
  },
};

export default AssignmentController;
