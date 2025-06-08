import { pool } from "../config/db.js";

const CategoryModel = {
  async create(name) {
    const { rows } = await pool.query(
      "INSERT INTO categories (name) VALUES ($1) RETURNING *",
      [name]
    );
    return rows[0];
  },

  async findAll() {
    const { rows } = await pool.query("SELECT * FROM categories");
    return rows;
  },

  async findById(id) {
    const { rows } = await pool.query(
      "SELECT * FROM categories WHERE id = $1",
      [id]
    );
    return rows[0];
  },
};

export default CategoryModel;
