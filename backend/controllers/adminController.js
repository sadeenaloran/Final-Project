import { query } from "../config/db.js";
import CourseModel from "../models/Course.js";
import bcrypt from "bcryptjs";
import UserModel from "../models/userModel.js"; 

const AdminController = {
 async addUser(req, res, next) {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password || !role) {
      return res.status(400).json({ success: false, error: "Missing required fields" });
    }

    if (!['instructor', 'student'].includes(role)) {
      return res.status(400).json({
        success: false,
        error: "Invalid role. Must be 'instructor' or 'student'"
      });
    }

    const existingUser = await UserModel.findByEmail(email);
    if (existingUser) {
      return res.status(400).json({ success: false, error: "Email already exists" });
    }

    const password_hash = await bcrypt.hash(password, 12);

    const newUser = await UserModel.create({ name, email, password, role });

    if (process.env.SEND_WELCOME_EMAIL === 'true') {
      await sendWelcomeEmail(email, name, role);
    }

    res.status(201).json({
      success: true,
      user: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
        password: newUser.password, // Don't send hashed password back
        role: newUser.role, }});
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: error.message });
  }
},

async updateUser(req, res, next) {
  try {
    const { userId } = req.params;
    const { name, email, role , is_active } = req.body;

    if (role && req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        error: "Only admin can modify roles"
      });
    }

    const user = await UserModel.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: "User not found"
      });
    }

    if (role && !['instructor', 'student'].includes(role)) {
      return res.status(400).json({
        success: false,
        error: "Invalid role. Must be 'instructor' or 'student'"
      });
    }

    if (email && email !== user.email) {
      const emailExists = await UserModel.findByEmail(email);
      if (emailExists) {
        return res.status(400).json({
          success: false,
          error: "Email already in use by another user"
        });
      }
    }

    if (user.role === 'admin' && req.user.id !== user.id) {
      return res.status(403).json({
        success: false,
        error: "Cannot modify other admin accounts"
      });
    }

    const updateData = {
      name: name || user.name,
      email: email || user.email,
      role: (req.user.role === 'admin') ? (role || user.role) : user.role,

      is_active: is_active !== undefined ? is_active : user.is_active
    };

    const updatedUser = await query(
      `UPDATE users 
       SET name = $1, email = $2, role = $3, is_active = $4
       WHERE id = $5 RETURNING *`,
      [
        updateData.name,
        updateData.email,
        updateData.role,
        updateData.is_active,
        userId
      ]
    );
    res.json({
      success: true,
      user: updatedUser.rows[0]
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
},

async deleteUser(req, res, next) {
  try {
    const { userId } = req.params;

    const user = await UserModel.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: "User not found"
      });
    }

    if (user.is_super_admin) {
      return res.status(403).json({
        success: false,
        error: "Cannot delete super admin"
      });
    }

    await query(
      `UPDATE users SET is_active = false, deleted_at = NOW() WHERE id = $1`,
      [userId]
    );

    // await query(`DELETE FROM users WHERE id = $1`, [userId]);

    res.json({
      success: true,
      message: "User deleted successfully"
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
},

  // Course Management
  async approveCourse(req, res, next) {
    try {
      const { courseId } = req.params;

      const course = await CourseModel.findById(courseId);
      if (!course) {
        return res.status(404).json({ success: false, error: "Course not found" });
      }

      await CourseModel.updateStatus(courseId, 'published');

      res.json({
        success: true,
        course: {
          id: course.id,
          title: course.title,
          status: 'published'
        }
      });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  },

  async rejectCourse(req, res, next) {
    try {
      const { courseId } = req.params;

      const course = await CourseModel.findById(courseId);
      if (!course) {
        return res.status(404).json({ success: false, error: "Course not found" });
      }

      await CourseModel.updateStatus(courseId, 'rejected');

      res.json({
        success: true,
        course: {
          id: course.id,
          title: course.title,
          status: 'rejected',
        }
      });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  },

  async getPendingCourses(req, res, next) {
    try {
      const courses = await CourseModel.findAll({ status: 'pending' });
      res.json(courses);
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  },
};

export default AdminController;