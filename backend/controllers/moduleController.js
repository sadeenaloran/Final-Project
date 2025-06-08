import ModuleModel from "../models/Module.js";
import CourseModel from "../models/Course.js";
const ModuleController = {
  async createModule(req, res, next) {
    try {
      const { course_id, title, description, order, duration } = req.body;

      // Verify the course exists and belongs to the instructor
      const course = await CourseModel.findById(course_id);
      if (!course) {
        return res.status(404).json({
          success: false,
          message: "Course not found",
        });
      }

      if (req.user.role !== "admin" && course.instructor_id !== req.user.id) {
        return res.status(403).json({
          success: false,
          message: "Unauthorized: You can only add modules to your own courses",
        });
      }

      const module = await ModuleModel.create({
        course_id,
        title,
        description,
        order,
        duration,
      });

      res.status(201).json({
        success: true,
        module,
      });
    } catch (error) {
      next(error);
    }
  },

  async getModulesByCourse(req, res, next) {
    try {
      const modules = await ModuleModel.findByCourseId(req.params.courseId);
      res.json({
        success: true,
        data: modules,
      });
    } catch (error) {
      next(error);
    }
  },

  async updateModule(req, res, next) {
    try {
      const { title, description, order, duration } = req.body;
      const moduleId = req.params.id;

      // Verify module exists and belongs to the instructor's course
      const module = await ModuleModel.findById(moduleId);
      if (!module) {
        return res.status(404).json({
          success: false,
          message: "Module not found",
        });
      }

      const course = await CourseModel.findById(module.course_id);
      if (req.user.role !== "admin" && course.instructor_id !== req.user.id) {
        return res.status(403).json({
          success: false,
          message:
            "Unauthorized: You can only edit modules in your own courses",
        });
      }

      const updatedModule = await ModuleModel.update(moduleId, {
        title,
        description,
        order,
        duration,
      });
      res.json({
        success: true,
        module: updatedModule,
      });
    } catch (error) {
      next(error);
    }
  },

  async deleteModule(req, res, next) {
    try {
      const moduleId = req.params.id;

      // Verify module exists and belongs to the instructor's course
      const module = await ModuleModel.findById(moduleId);
      if (!module) {
        return res.status(404).json({
          success: false,
          message: "Module not found",
        });
      }

      const course = await CourseModel.findById(module.course_id);
      if (req.user.role !== "admin" && course.instructor_id !== req.user.id) {
        return res.status(403).json({
          success: false,
          message:
            "Unauthorized: You can only delete modules in your own courses",
        });
      }

      await ModuleModel.delete(moduleId);
      res.json({
        success: true,
        message: "Module deleted successfully",
      });
    } catch (error) {
      next(error);
    }
  },
};

export default ModuleController;
