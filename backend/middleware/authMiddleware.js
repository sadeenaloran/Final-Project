import jwt from "jsonwebtoken";
import UserModel from "../models/userModel.js";
import { findUserById } from "../models/userModel.js";
import { createResponse } from "../utils/helpers.js";

export const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers["authorization"];
    const token = authHeader?.split(" ")[1];

    if (!token) {
      throw new Error("Authentication token missing");
    }

    if (!process.env.JWT_SECRET) {
      throw new Error("JWT secret is not configured");
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await UserModel.findById(decoded.id);

    // {
    //   attributes: ["id", "name", "emial", "role"],
    // }

    if (!user) {
      throw new Error("User not found");
    }

    req.user = user;

    next();
  } catch (error) {
    error.statusCode = 401;
    next(error);
  }
};

export const authorize = (roles = []) => {
  return (req, res, next) => {
    if (roles.length && !roles.includes(req.user.role)) {
      const error = new Error("Unauthorized access");
      error.statusCode = 403;
      return next(error);
    }
    next();
  };
};

// Check if user is authenticated (session-based)
export const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated && req.isAuthenticated()) {
    return next();
  }

  return res
    .status(401)
    .json(
      createResponse(
        false,
        "Authentication required",
        null,
        "User not authenticated"
      )
    );
};

// JWT authentication middleware
export const authenticateJWT = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(" ")[1]; // Bearer TOKEN

    if (!token) {
      return res
        .status(401)
        .json(
          createResponse(
            false,
            "Access token required",
            null,
            "No token provided"
          )
        );
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await findUserById(decoded.id);

    if (!user) {
      return res
        .status(401)
        .json(createResponse(false, "Invalid token", null, "User not found"));
    }

    req.user = user;
    next();
  } catch (error) {
    return res
      .status(403)
      .json(createResponse(false, "Invalid token", null, error.message));
  }
};

export const optionalJWT = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(" ")[1];

    if (token) {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await findUserById(decoded.id);
      if (user) {
        req.user = user;
      }
    }
    next();
  } catch (error) {
    next();
  }
};
