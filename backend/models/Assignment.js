import { pool } from "../config/db.js";

const AssignmentModel = {
  // Create a new assignment and return the created row
  async create({ lesson_id, title, description, max_score }) {
    try {
      const { rows } = await pool.query(
        `INSERT INTO assignments 
       (lesson_id, title, description, max_score) 
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
        [lesson_id, title, description, max_score]
      );
      return rows[0];
    } catch (error) {
      console.error("Error creating assignment:", error);
      throw error;
    }
  },
  //a.*title to show all the col in the databeas
  async findById(id) {
    const { rows } = await pool.query(
      `SELECT a.*, l.title as lesson_title
       FROM assignments a
       JOIN lessons l ON a.lesson_id = l.id
       WHERE a.id = $1`,
      [id]
    );
    return rows[0];
  },

  // Find all assignments for a specific lesson, ordered by creation date
  async findByLessonId(lessonId) {
    const { rows } = await pool.query(
      `SELECT * FROM assignments 
       WHERE lesson_id = $1
       ORDER BY created_at`,
      [lessonId]
    );
    return rows;
  },

  // Update an assignment's fields and return the updated row
  async update(id, updates) {
    const { rows } = await pool.query(
      `UPDATE assignments 
       SET title = COALESCE($1, title),
           description = COALESCE($2, description),
           max_score = COALESCE($3, max_score),
           updated_at = NOW()
       WHERE id = $4
       RETURNING *`,
      [updates.title, updates.description, updates.max_score, id]
    );
    return rows[0];
  },

  // Delete an assignment by its ID
  async delete(id) {
    await pool.query("DELETE FROM assignments WHERE id = $1", [id]);
    return true;
  },
};

export default AssignmentModel;
