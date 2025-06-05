import { pool } from "../config/db.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

// Find user by Google ID
export const findUserByGoogleId = async (googleId) => {
  try {
    const query = 'SELECT * FROM users WHERE oauth_id = $1';
    const result = await pool.query(query, [googleId]);
    return result.rows[0] || null;
  } catch (error) {
    error.status = 500;
    error.message = 'Error finding user by Google ID: ' + error.message;
    throw error;
  }
};

// Find user by ID
export const findUserById = async (id) => {
  try {
    const query = 'SELECT * FROM users WHERE id = $1';
    const result = await pool.query(query, [id]);
    return result.rows[0] || null;
  } catch (error) {
    error.status = 500;
    error.message = 'Error finding user by ID: ' + error.message;
    throw error;
  }
};

// Find user by email
export const findUserByEmail = async (email) => {
  try {
    const query = 'SELECT * FROM users WHERE email = $1';
    const result = await pool.query(query, [email]);
    return result.rows[0] || null;
  } catch (error) {
    error.status = 500;
    error.message = 'Error finding user by email: ' + error.message;
    throw error;
  }
};

// Create new user (OAuth)
export const createUser = async (userData) => {
  try {
    const { oauth_id, email, name, avatar, oauth_provider } = userData; // changed oauth_id to oauth_id
    const query = `
      INSERT INTO users (oauth_id, email, name, avatar, oauth_provider)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
    `;
    const values = [oauth_id, email, name, avatar, oauth_provider];
    const result = await pool.query(query, values);
    return result.rows[0];
  } catch (error) {
    error.status = 500;
    error.message = 'Error creating user: ' + error.message;
    throw error;
  }
};

// Update user
export const updateUser = async (id, userData) => {
  try {
    const { name, avatar } = userData;
    const query = `
      UPDATE users 
      SET name = COALESCE($2, name), 
          avatar = COALESCE($3, avatar),
          updated_at = CURRENT_TIMESTAMP
      WHERE id = $1
      RETURNING *
    `;
    const values = [id, name, avatar];
    const result = await pool.query(query, values);
    return result.rows[0];
  } catch (error) {
    error.status = 500;
    error.message = 'Error updating user: ' + error.message;
    throw error;
  }
};

// Delete user
export const deleteUser = async (id) => {
  try {
    const query = 'DELETE FROM users WHERE id = $1 RETURNING *';
    const result = await pool.query(query, [id]);
    return result.rows[0];
  } catch (error) {
    error.status = 500;
    error.message = 'Error deleting user: ' + error.message;
    throw error;
  }
};

// Get all users (admin function)
export const getAllUsers = async (limit = 50, offset = 0) => {
  try {
    const query = `
      SELECT id, email, name, avatar, oauth_provider, is_verified, created_at, updated_at
      FROM users 
      ORDER BY created_at DESC 
      LIMIT $1 OFFSET $2
    `;
    const result = await pool.query(query, [limit, offset]);
    return result.rows;
  } catch (error) {
    error.status = 500;
    error.message = 'Error getting all users: ' + error.message;
    throw error;
  }
};

const UserModel = {
  async create({ name, email, password, role, avatar }) {
    try {
      if (!email || !password || !name) {
        const error = new Error("Missing required fields");
        error.status = 400;
        throw error;
      }
      const hashedPassword = await bcrypt.hash(
        password,
        parseInt(process.env.BCRYPT_SALT_ROUNDS)
      );
      const { rows } = await pool.query(
        `INSERT INTO users (name, email, password_hash, role, avatar) 
        VALUES ($1, $2, $3, 'student', $5)
        RETURNING id, email, name, role, avatar, created_at
        `,
        [name, email, hashedPassword, name, role, avatar]
      );

      if (!rows || rows.length === 0) {
        const error = new Error("User creation failed");
        error.status = 500;
        throw error;
      }

      return rows[0];
    } catch (error) {
      if (error.code === "23505") {
        error.message = "Email already exists";
        error.status = 409;
      } else {
        error.message = `User creation failed: ${error.message}`;
        error.status = error.status || 500;
      }
      throw error;
    }
  },

  async findByEmail(email) {
    try {
      if (!email) {
        const error = new Error("Email is required");
        error.status = 400;
        throw error;
      }

      const { rows } = await pool.query(
        `SELECT id, email, name, role, password_hash, oauth_provider 
         FROM users
         WHERE email = $1`,
        [email]
      );
      if (rows.length > 0) {
        return rows[0];
      }
      return null;
    } catch (error) {
      error.message = `Failed to find user by email: ${error.message}`;
      error.status = error.status || 500;
      throw error;
    }
  },

  async findById(id) {
    try {
      if (!id) {
        const error = new Error("User ID is required");
        error.status = 400;
        throw error;
      }
      const { rows } = await pool.query(
        `SELECT id, email, name, role, created_at FROM users
         WHERE id = $1`,
        [id]
      );
      return rows[0] || null;
    } catch (error) {
      error.message = `Failed to find user by ID: ${error.message}`;
      error.status = error.status || 500;
      throw error;
    }
  },

  generateToken(userId) {
    if (!userId) {
      const error = new Error("User ID is required for token generation");
      error.status = 400;
      throw error;
    }

    if (!process.env.JWT_SECRET) {
      const error = new Error("JWT secret is not configured");
      error.status = 500;
      throw error;
    }

    return jwt.sign({ id: userId }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN || "1d",
    });
  },

  async verifyPassword(password, hashedPassword) {
    if (!password || !hashedPassword) {
      return false;
    }

    try {
      return await bcrypt.compare(password, hashedPassword);
    } catch (error) {
      console.error("Password verification error:", error);
      return false;
    }
  },

  async updatePassword(userId, newPassword) {
    try {
      if (!newPassword || !userId) {
        const error = new Error("New password and user ID are required");
        error.status = 400;
        throw error;
      }
      const hashedNewPassword = await bcrypt.hash(
        newPassword,
        parseInt(process.env.BCRYPT_SALT_ROUNDS)
      );
      const { rowCount } = await pool.query(
        `UPDATE users SET password_hash = $1 WHERE id = $2`,
        [hashedNewPassword, userId]
      );
      if (rowCount === 0) {
        const error = new Error("User not found or password not updated");
        error.status = 404;
        throw error;
      }
      return true;
    } catch (error) {
      error.message = `Password update failed: ${error.message}`;
      error.status = error.status || 500;
      throw error;
    }
  },

  async updateLastLogin(userId) {
    try {
      if (!userId) {
        const error = new Error("User ID is required");
        error.status = 400;
        throw error;
      }
      await pool.query(
        `UPDATE users SET last_login = NOW() WHERE id = $1`,
        [userId]
      );
      return true;
    } catch (error) {
      error.message = `Failed to update last login: ${error.message}`;
      error.status = error.status || 500;
      throw error;
    }
  },
};

export default UserModel;
