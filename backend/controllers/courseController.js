import CourseModel from "../models/Course.js";
import ModuleModel from "../models/Module.js";

const CourseController = {
  async createCourse(req, res, next) {
    try {
      const { title, description, category_id, thumbnail_url, duration } =
        req.body;

      const course = await CourseModel.create({
        title,
        description,
        instructor_id: req.user.id,
        category_id,
        thumbnail_url,
        duration,
      });

      res.status(201).json({
        success: true,
        course,
      });
    } catch (error) {
      next(error);
    }
  },

  async getAllCourses(req, res, next) {
    try {
      const courses = await CourseModel.findAll();
      res.json({ success: true, data: courses });
    } catch (error) {
      next(error);
    }
  },

  async getCourseDetails(req, res, next) {
    try {
      const course = await CourseModel.findById(req.params.id);
      if (!course) {
        return res.status(404).json({
          success: false,
          message: "Course not found",
        });
      }

      const modules = await ModuleModel.findByCourseId(req.params.id);
      res.json({
        success: true,
        data: { ...course, modules },
      });
    } catch (error) {
      next(error);
    }
  },

  async updateCourse(req, res, next) {
    try {
      const course = await CourseModel.findById(req.params.id);
      if (!course) {
        return res.status(404).json({
          success: false,
          message: "Course not found",
        });
      }

      // Authorization check
      if (req.user.role !== "admin" && course.instructor_id !== req.user.id) {
        return res.status(403).json({
          success: false,
          message: "Unauthorized: You can only edit your own courses",
        });
      }

      const updates = {
        title: req.body.title,
        description: req.body.description,
        category_id: req.body.category_id,
        thumbnail_url: req.body.thumbnail_url,
        duration: req.body.duration,
        is_published: req.body.is_published,
      };

      const updatedCourse = await CourseModel.update(req.params.id, updates);
      res.json({ success: true, course: updatedCourse });
    } catch (error) {
      next(error);
    }
  },

  async deleteCourse(req, res, next) {
    try {
      await CourseModel.delete(req.params.id);
      res.json({
        success: true,
        message: "Course deleted successfully",
      });
    } catch (error) {
      next(error);
    }
  },

  async approveCourse(req, res, next) {
    try {
      const course = await CourseModel.approveCourse(req.params.id);
      res.json({ success: true, course });
    } catch (error) {
      next(error);
    }
  },
};

export default CourseController;
