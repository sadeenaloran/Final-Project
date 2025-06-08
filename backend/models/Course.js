import { pool } from "../config/db.js";

const CourseModel = {
  async update(id, updates) {
    const {
      title,
      description,
      category_id,
      thumbnail_url,
      is_published,
      duration,
    } = updates;

    const { rows } = await pool.query(
      `UPDATE courses 
       SET title = COALESCE($1, title),
           description = COALESCE($2, description),
           category_id = COALESCE($3, category_id),
           thumbnail_url = COALESCE($4, thumbnail_url),
           is_published = COALESCE($5, is_published),
           duration = COALESCE($6, duration),
           updated_at = NOW()
       WHERE id = $7
       RETURNING *`,
      [
        title,
        description,
        category_id,
        thumbnail_url,
        is_published,
        duration,
        id,
      ]
    );
    return rows[0];
  },

  async create({
    title,
    description,
    instructor_id,
    category_id,
    thumbnail_url = null,
    duration,
  }) {
    const { rows } = await pool.query(
      `INSERT INTO courses 
       (title, description, instructor_id, category_id, thumbnail_url, duration) 
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [title, description, instructor_id, category_id, thumbnail_url, duration]
    );
    return rows[0];
  },

  async findById(id) {
    const { rows } = await pool.query(
      `SELECT c.*, u.name as instructor_name 
       FROM courses c
       JOIN users u ON c.instructor_id = u.id
       WHERE c.id = $1`,
      [id]
    );
    return rows[0];
  },

  async findAll() {
    const { rows } = await pool.query(
      `SELECT c.*, u.name as instructor_name 
       FROM courses c
       JOIN users u ON c.instructor_id = u.id`
    );
    return rows;
  },

  async delete(id) {
    await pool.query("DELETE FROM courses WHERE id = $1", [id]);
    return true;
  },

  async findByInstructor(instructorId) {
    const { rows } = await pool.query(
      "SELECT * FROM courses WHERE instructor_id = $1",
      [instructorId]
    );
    return rows;
  },

  async approveCourse(id) {
    const { rows } = await pool.query(
      `UPDATE courses 
       SET is_approved = true, 
           is_published = true, 
           updated_at = NOW() 
       WHERE id = $1 RETURNING *`,
      [id]
    );
    return rows[0];
  },

  async updateStatus(id, status, feedback = null) {
    const { rows } = await pool.query(
      `UPDATE courses
       SET status = $2,
           feedback = $3,
           updated_at = NOW()
       WHERE id = $1
       RETURNING *`,
      [id, status, feedback]
    );
    return rows[0];
  },
};

export default CourseModel;
