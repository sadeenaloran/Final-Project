import { query } from "../config/db.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

export const findUserByGoogleId = async (googleId) => {
  try {
    const query = 'SELECT * FROM users WHERE google_id = $1';
    const result = await pool.query(query, [googleId]);
    return result.rows[0] || null;
  } catch (error) {
    console.error('Error finding user by Google ID:', error);
    throw error;
  }
};
export const findUserById = async (id) => {
  try {
    const query = 'SELECT * FROM users WHERE id = $1';
    const result = await pool.query(query, [id]);
    return result.rows[0] || null;
  } catch (error) {
    console.error('Error finding user by ID:', error);
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
    console.error('Error finding user by email:', error);
    throw error;
  }
};

// Create new user
export const createUser = async (userData) => {
  try {
    const { google_id, email, name, avatar, provider } = userData;
    const query = `
      INSERT INTO users (google_id, email, name, avatar, provider)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
    `;
    const values = [google_id, email, name, avatar, provider];
    const result = await pool.query(query, values);
    return result.rows[0];
  } catch (error) {
    console.error('Error creating user:', error);
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
    console.error('Error updating user:', error);
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
    console.error('Error deleting user:', error);
    throw error;
  }
};

// Get all users (admin function)
export const getAllUsers = async (limit = 50, offset = 0) => {
  try {
    const query = `
      SELECT id, email, name, avatar, provider, is_verified, created_at, updated_at
      FROM users 
      ORDER BY created_at DESC 
      LIMIT $1 OFFSET $2
    `;
    const result = await pool.query(query, [limit, offset]);
    return result.rows;
  } catch (error) {
    console.error('Error getting all users:', error);
    throw error;
  }
};

const UserModel = {
  async create({ email, password, name }) {
    try {
      if (!email || !password || !name) {
        throw new Error("Missing required fields");
      }
      const hashedPassword = await bcrypt.hash(
        password,
        parseInt(process.env.BCRYPT_SALT_ROUNDS)
      );
      const { rows } = await query(
        `INSERT INTO users (email, password_hash, name, role) 
        VALUES ($1, $2, $3, 'student')
        RETURNING id, email, name, role, created_at
        `,
        [email, hashedPassword, name]
      );

      if (!rows || rows.length === 0) {
        throw new Error("User creation failed");
      }

      return rows[0];
    } catch (error) {
      if (error.code === "23505") {
        throw new Error("Email already exists");
      }
      throw new Error(`User creation failed: ${error.message}`);
    }
  },

  async findByEmail(email) {
    try {
      if (!email) {
        throw new Error("Email is required");
      }

      const { rows } = await query(
        `SELECT id, email, name, role, password_hash, oauth_provider 
         FROM users
         WHERE email = $1`,
        [email]
      );
      if (rows.length > 0) {
        return rows[0];
      }
    } catch (error) {
      throw new Error(`Failed to find user by email: ${error.message}`);
    }
  },

  async findById(id) {
    try {
      if (!id) {
        throw new Error("User ID is required");
      }
      const { rows } = await query(
        `SELECT id, email, name, role, created _at FROM users
         WHERE id = $1`,
        [id]
      );
      return rows[0] || null;
    } catch (error) {
      throw new Error(`Failed to find user by ID: ${error.message}`);
    }
  },

  
  
  generateToken(userId) {
    if (!userId) {
      throw new Error("User ID is required for token generation");
    }

    if (!process.env.JWT_SECRET) {
      throw new Error("JWT secret is not configured");
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

  async updatePassword(newPassword, userId) {
    try {
      if (!newPassword || !userId) {
        throw new Error("New password and user ID are required");
      }
      const hashedNewPassword = bcrypt.hash(
        newPassword,
        parseInt(process.env.BCRYPT_SALT_ROUNDS)
      );
      const { rowCount } = await query(
        `UPDATE users SET password_hash = $1 WHERE id = $2`,
        [hashedNewPassword, userId]
      );
      if (rowCount === 0) {
        throw new Error("User not found or password not updated");
      }
      return true;
    } catch (error) {
      throw new Error(`Password update failed: ${error.message}`);
    }
  },
};

export default UserModel;
